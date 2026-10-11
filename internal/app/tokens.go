package app

import (
	"context"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	actionTokenCreate = "token.create"
	actionTokenRevoke = "token.revoke"
	maxTokenName      = 64
	maxTokenScopes    = 64
)

// ListTokens lists the caller's own tokens, revoked ones included. Listing
// one's own tokens is exempt:self (ADR-0012).
func (a *AuthService) ListTokens(ctx context.Context, by Caller) ([]wire.Token, error) {
	if _, err := a.beginRequest(ctx, a.cfg.DB.Reader(), by); err != nil {
		return nil, err
	}
	rows, err := database.ListAPITokens(ctx, a.cfg.DB.Reader(), by.ID)
	if err != nil {
		return nil, err
	}
	out := make([]wire.Token, len(rows))
	for i, row := range rows {
		out[i] = tokenView(row)
	}
	return out, nil
}

// CreateToken issues an API token to the caller (action token.create). The
// token's scopes can only narrow the caller's own, and the plaintext is in the
// answer exactly once. The request never takes an Idempotency-Key (spec §23).
func (a *AuthService) CreateToken(ctx context.Context, by Caller, r wire.CreateTokenRequest) (wire.TokenIssued, error) {
	if by.Idempotency != nil {
		return wire.TokenIssued{}, errIdempotencyKeyRefused()
	}
	now := a.cfg.Clock.Now()
	name, scopes, err := validateTokenRequest(now, r)
	if err != nil {
		return wire.TokenIssued{}, err
	}
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (wire.TokenIssued, error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return wire.TokenIssued{}, err
		}
		self := domain.ResourceRef{Type: domain.ResourceIdentity, ID: by.ID}
		if err := a.requireAllowed(ctx, tx, actor, actionTokenCreate, self); err != nil {
			return wire.TokenIssued{}, err
		}
		narrowed, ok := narrowScopes(by.Credential.Scopes, scopes)
		if !ok {
			res := policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonScopeDenied}
			if err := a.auditDecision(ctx, tx, actor, actionTokenCreate, self, res); err != nil {
				return wire.TokenIssued{}, err
			}
			return wire.TokenIssued{}, reject(smerr.FromReason(smerr.ReasonScopeDenied, "token scopes must narrow the creator's scopes"))
		}
		return a.issueAPIToken(ctx, tx, actor, name, narrowed, r.ExpiresAt)
	})
}

// RevokeToken revokes an API token. Revoking one's own is exempt:self; a
// foreign token needs token.revoke. Revoking twice succeeds and audits once.
func (a *AuthService) RevokeToken(ctx context.Context, by Caller, id domain.ID) error {
	_, err := commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (struct{}, error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return struct{}{}, err
		}
		token, err := database.GetAPIToken(ctx, tx, id)
		if err != nil {
			return struct{}{}, err
		}
		owner := domain.ResourceRef{Type: domain.ResourceIdentity, ID: token.IdentityID}
		if token.IdentityID != by.ID {
			if err := a.requireAllowed(ctx, tx, actor, actionTokenRevoke, owner); err != nil {
				return struct{}{}, err
			}
		}
		first, err := database.RevokeAPIToken(ctx, tx, id, a.cfg.Clock.Now())
		if err != nil || !first {
			return struct{}{}, err
		}
		return struct{}{}, a.emit(ctx, tx, actor, "token.revoked", owner, domain.ResultSucceeded,
			map[string]any{"token_id": id.String(), "name": token.Name})
	})
	return err
}

// requireAllowed evaluates action on target, audits a refusal and rejects it.
func (c core) requireAllowed(ctx context.Context, q database.Querier, actor domain.Actor, action string, target domain.ResourceRef) error {
	res := c.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{{Ref: target}}})
	if err := c.auditDecision(ctx, q, actor, action, target, res); err != nil {
		return err
	}
	if err := decisionError(res); err != nil {
		return reject(err)
	}
	return nil
}

// issueAPIToken mints and stores a token for actor; the plaintext leaves only
// in the returned value.
func (a *AuthService) issueAPIToken(ctx context.Context, tx *database.Tx, actor domain.Actor, name string, scopes []string, expiresAt time.Time) (wire.TokenIssued, error) {
	secret, hash, err := a.tokens.Mint(APITokenKind)
	if err != nil {
		return wire.TokenIssued{}, err
	}
	row := database.APIToken{
		ID: a.cfg.IDs.NewID(), IdentityID: actor.ID, Name: name, TokenHash: hash,
		Scopes: scopes, CreatedAt: a.cfg.Clock.Now(), ExpiresAt: expiresAt,
	}
	if err := database.CreateAPIToken(ctx, tx, row); err != nil {
		return wire.TokenIssued{}, err
	}
	ref := domain.ResourceRef{Type: domain.ResourceIdentity, ID: actor.ID}
	err = a.emit(ctx, tx, actor, "token.created", ref, domain.ResultSucceeded,
		map[string]any{"token_id": row.ID.String(), "name": name, "scopes": scopes, "expires_at": expiresAt})
	if err != nil {
		return wire.TokenIssued{}, err
	}
	return wire.TokenIssued{Token: tokenView(row), Value: secret.Reveal()}, nil
}

func tokenView(t database.APIToken) wire.Token {
	scopes := t.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return wire.Token{
		ID: t.ID, Name: t.Name, Scopes: scopes, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		RevokedAt: t.RevokedAt, LastUsedAt: t.LastUsedAt,
	}
}

func errIdempotencyKeyRefused() error {
	return smerr.New(smerr.CodeInvalidArgument, "", "credential-issuing requests do not accept an Idempotency-Key")
}

// validateTokenRequest checks the border: a clean name, a mandatory expiry
// within the 365-day cap, and scopes that each cover a catalog action.
func validateTokenRequest(now time.Time, r wire.CreateTokenRequest) (string, []string, error) {
	name := strings.TrimSpace(r.Name)
	switch {
	case name == "" || len([]rune(name)) > maxTokenName || textsafe.Line(name) != name:
		return "", nil, smerr.New(smerr.CodeInvalidArgument, "", "token name must be 1-64 printable characters")
	case r.ExpiresAt.IsZero():
		return "", nil, smerr.New(smerr.CodeInvalidArgument, "", "token expiry is mandatory")
	case !r.ExpiresAt.After(now) || r.ExpiresAt.Sub(now) > database.APITokenMaxLifetime:
		return "", nil, smerr.New(smerr.CodeInvalidArgument, "", "token expiry must be within 365 days from now")
	case len(r.Scopes) > maxTokenScopes:
		return "", nil, smerr.New(smerr.CodeInvalidArgument, "", "too many token scopes")
	}
	scopes := dedupe(r.Scopes)
	for _, s := range scopes {
		if !coversCatalogAction(s) {
			return "", nil, smerr.New(smerr.CodeInvalidArgument, "", "token scope "+textsafe.Line(s)+" matches no action")
		}
	}
	return name, scopes, nil
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func coversCatalogAction(scope string) bool {
	for _, spec := range policy.Catalog() {
		if scopeCovers(scope, spec.Name) {
			return true
		}
	}
	return false
}

// narrowScopes is the only way a token gets its scopes: no request gives the
// creator's own scopes, and a request must be covered by them. It reports
// false when the request would widen.
func narrowScopes(creator, requested []string) ([]string, bool) {
	switch {
	case len(creator) == 0:
		return requested, true
	case len(requested) == 0:
		return append([]string{}, creator...), true
	}
	for _, s := range requested {
		if !coveredByAny(creator, s) {
			return nil, false
		}
	}
	return requested, true
}

func coveredByAny(parents []string, scope string) bool {
	for _, p := range parents {
		if scopeCovers(p, scope) {
			return true
		}
	}
	return false
}

// scopeCovers reports whether every action matched by child is matched by
// parent. Patterns are dot-separated; "*" is one segment, a bare "*" is all.
func scopeCovers(parent, child string) bool {
	if parent == "*" {
		return true
	}
	ps, cs := strings.Split(parent, "."), strings.Split(child, ".")
	if len(ps) != len(cs) {
		return false
	}
	for i := range ps {
		if ps[i] != "*" && ps[i] != cs[i] {
			return false
		}
	}
	return true
}
