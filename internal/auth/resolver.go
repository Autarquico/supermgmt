package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Resolver authenticates an HTTPS request's bearer token. Errors are
// UNAUTHENTICATED, or CREDENTIAL_REVOKED / CREDENTIAL_EXPIRED.
type Resolver interface {
	Resolve(ctx context.Context, bearer string) (app.Caller, error)
}

const (
	requestSource = "api"
	// lastUsedGranularity bounds how often a busy token rewrites last_used_at.
	lastUsedGranularity = time.Minute
)

// DBResolver resolves session and API tokens against the database. Nothing is
// cached: a revocation holds on the next request (spec §23). The scopes of
// the Caller come only from the token row, so they can never widen.
type DBResolver struct {
	DB *database.DB
	// Clock defaults to the system clock.
	Clock domain.Clock
}

var _ Resolver = DBResolver{}

// credentialRow is what both token tables have in common.
type credentialRow struct {
	kind       domain.CredentialKind
	id         domain.ID
	identity   domain.ID
	scopes     []string
	expiresAt  time.Time
	revokedAt  *time.Time
	lastUsedAt *time.Time
	touch      func(ctx context.Context, q database.Querier, id domain.ID, at time.Time) error
}

func (r DBResolver) Resolve(ctx context.Context, bearer string) (app.Caller, error) {
	row, err := r.lookup(ctx, bearer)
	if err != nil {
		return app.Caller{}, err
	}
	now := clockOrSystem(r.Clock).Now()
	if err := credentialError(stateAt(now, row.revokedAt, row.expiresAt)); err != nil {
		return app.Caller{}, err
	}
	if err := r.requireEnabled(ctx, row.identity); err != nil {
		return app.Caller{}, err
	}
	r.recordUse(ctx, row, now)
	expires := row.expiresAt
	return app.Caller{
		ID:         row.identity,
		Credential: domain.CredentialContext{Kind: row.kind, ID: row.id.String(), Scopes: row.scopes, ExpiresAt: &expires},
		Source:     requestSource,
	}, nil
}

func (r DBResolver) lookup(ctx context.Context, bearer string) (credentialRow, error) {
	kind, hash, err := Hash(bearer)
	if err != nil {
		return credentialRow{}, err
	}
	switch kind {
	case KindSession:
		s, err := database.GetAuthSessionByHash(ctx, r.DB.Reader(), hash)
		if err != nil {
			return credentialRow{}, unknownCredential(err)
		}
		return credentialRow{domain.CredentialSession, s.ID, s.IdentityID, nil, s.ExpiresAt, s.RevokedAt, s.LastUsedAt, database.TouchAuthSession}, nil
	case KindAPIToken:
		t, err := database.GetAPITokenByHash(ctx, r.DB.Reader(), hash)
		if err != nil {
			return credentialRow{}, unknownCredential(err)
		}
		return credentialRow{domain.CredentialAPIToken, t.ID, t.IdentityID, t.Scopes, t.ExpiresAt, t.RevokedAt, t.LastUsedAt, database.TouchAPIToken}, nil
	case KindBootstrap, KindJoin:
	}
	return credentialRow{}, smerr.New(smerr.CodeUnauthenticated, "", "this token kind cannot authenticate a request")
}

// unknownCredential keeps a lookup failure an infrastructure error and turns
// a miss into UNAUTHENTICATED, which does not say whether the token ever existed.
func unknownCredential(err error) error {
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return smerr.New(smerr.CodeUnauthenticated, "", "invalid credential")
	}
	return fmt.Errorf("look up credential: %w", err)
}

func credentialError(state app.CredentialState) error {
	switch state {
	case app.CredentialActive:
		return nil
	case app.CredentialRevoked:
		return smerr.FromReason(smerr.ReasonCredentialRevoked, "credential was revoked")
	case app.CredentialExpired:
		return smerr.FromReason(smerr.ReasonCredentialExpired, "credential expired")
	}
	return smerr.New(smerr.CodeUnauthenticated, "", "unknown credential state")
}

func (r DBResolver) requireEnabled(ctx context.Context, id domain.ID) error {
	identity, err := database.GetIdentity(ctx, r.DB.Reader(), id)
	if err != nil {
		return unknownCredential(err)
	}
	if identity.DisabledAt != nil {
		return smerr.New(smerr.CodeUnauthenticated, "", "identity is disabled")
	}
	return nil
}

// recordUse stamps last_used_at at most once per lastUsedGranularity. It is
// bookkeeping for the token list: a failed write must not fail an
// authenticated request, so its error is dropped.
func (r DBResolver) recordUse(ctx context.Context, row credentialRow, now time.Time) {
	if row.lastUsedAt != nil && now.Sub(*row.lastUsedAt) < lastUsedGranularity {
		return
	}
	_ = r.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return row.touch(ctx, tx, row.id, now)
	})
}
