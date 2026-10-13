package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

const (
	actionMCPClientRegister = "mcp_client.register"
	actionMCPClientIssue    = "mcp_client.issue_token"
	actionMCPClientDelete   = "mcp_client.delete"

	eventMCPClientRegistered = "mcp_client.registered"
	eventMCPClientIssuance   = "mcp_client.token_issued"
	eventMCPClientDeleted    = "mcp_client.deleted"

	// mcpLocalIssuer is the issuer of the identity of a local MCP client; its
	// subject is the client id (ADR-0032).
	mcpLocalIssuer = "supermgmt:mcp-local"

	// mcpIssuanceWindow is how long after its approval a local client's token
	// may still be issued (spec §11.2).
	mcpIssuanceWindow = 24 * time.Hour

	maxMCPOAuthFieldBytes = 256
)

var mcpClientNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// mcpRegisterParams is what an mcp_client.register plan and job carry. The ids
// are generated when the request is made, so the approved plan names what it
// creates. Issuer is set for a remote client only.
type mcpRegisterParams struct {
	ClientID      domain.ID      `json:"client_id"`
	IdentityID    domain.ID      `json:"identity_id"`
	Name          string         `json:"name"`
	Origin        wire.MCPOrigin `json:"origin"`
	Issuer        string         `json:"issuer,omitempty"`
	Subject       string         `json:"subject,omitempty"`
	OAuthClientID string         `json:"oauth_client_id,omitempty"`
}

func (p mcpRegisterParams) validate() error {
	if !mcpClientNamePattern.MatchString(p.Name) {
		return invalidArgument("name must match %s", mcpClientNamePattern)
	}
	switch p.Origin {
	case wire.MCPOriginLocal:
		if p.Issuer != "" || p.Subject != "" || p.OAuthClientID != "" {
			return invalidArgument("a local MCP client has no issuer, subject or client_id")
		}
	case wire.MCPOriginRemote:
		for _, field := range []struct{ name, value string }{
			{"issuer", p.Issuer}, {"subject", p.Subject}, {"client_id", p.OAuthClientID},
		} {
			if err := validateMCPOAuthField(field.name, field.value); err != nil {
				return err
			}
		}
	default:
		return invalidArgument("origin must be %q or %q", wire.MCPOriginLocal, wire.MCPOriginRemote)
	}
	return nil
}

func validateMCPOAuthField(field, value string) error {
	if value == "" || len(value) > maxMCPOAuthFieldBytes || slices.ContainsFunc([]rune(value), unicode.IsControl) {
		return invalidArgument("%s must be 1-%d bytes without control characters", field, maxMCPOAuthFieldBytes)
	}
	return nil
}

// mcpDeleteParams is what an mcp_client.delete plan and job carry.
type mcpDeleteParams struct {
	ClientID domain.ID `json:"client_id"`
}

// MCPClientsOptions are the collaborators of MCPClientService. RemoteIssuer is
// mcp.oauth.issuer when remote MCP is enabled and empty otherwise: a remote
// client is only registered against it.
type MCPClientsOptions struct {
	Tokens       TokenMinter
	RemoteIssuer string
}

// MCPClientService implements MCPClients (spec §11.1, §11.2; ADR-0032).
// Registration and deletion are direct actions that policy may park for
// approval; the approved change is applied by the control_plane.apply job
// (apply.go). The identity of a client never holds a role.
type MCPClientService struct {
	core
	plans        *Plans
	tokens       TokenMinter
	remoteIssuer string
}

var _ MCPClients = (*MCPClientService)(nil)

// NewMCPClients validates cfg and the options. The job store is the one built
// with this package's Revalidator and LockPlanner.
func NewMCPClients(cfg Config, jobStore *jobs.Store, o MCPClientsOptions) (*MCPClientService, error) {
	plans, err := NewPlans(cfg, jobStore)
	if err != nil {
		return nil, err
	}
	if o.Tokens == nil {
		return nil, errors.New("app: mcp clients need a token minter")
	}
	return &MCPClientService{core: plans.core, plans: plans, tokens: o.Tokens, remoteIssuer: o.RemoteIssuer}, nil
}

func mcpIdentityRef(id domain.ID) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceIdentity, ID: id}
}

// ---- list ---------------------------------------------------------------------------

// List returns every client, deleted ones included (action identity.read).
func (s *MCPClientService) List(ctx context.Context, by Caller) ([]wire.MCPClient, error) {
	q := s.cfg.DB.Reader()
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return nil, err
	}
	res := s.authorize(policy.Request{Actor: actor, Action: "identity.read", Targets: []policy.Target{{Ref: mcpIdentityRef(actor.ID)}}})
	if err := decisionError(res); err != nil {
		return nil, err
	}
	rows, err := database.ListMCPClients(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]wire.MCPClient, len(rows))
	for i, row := range rows {
		if out[i], err = mcpClientView(ctx, q, row); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func mcpClientView(ctx context.Context, q database.Querier, row database.MCPClient) (wire.MCPClient, error) {
	view := wire.MCPClient{
		ID: row.ID, IdentityID: row.IdentityID, Name: row.Name, Origin: wire.MCPOrigin(row.Origin),
		State: wire.MCPClientState(row.State), RequestedBy: row.RequestedBy, ApprovedAt: row.ApprovedAt,
		TokenIssuedAt: row.TokenIssuedAt, TokenExpiresAt: row.TokenExpiresAt, CreatedAt: row.CreatedAt,
	}
	if row.Origin == database.MCPOriginRemote {
		identity, err := database.GetIdentity(ctx, q, row.IdentityID)
		if err != nil {
			return wire.MCPClient{}, err
		}
		view.Subject, view.ClientID = identity.Subject, identity.ClientID
	}
	return view, nil
}

// ---- register -----------------------------------------------------------------------

// Register asks for a new MCP client (action mcp_client.register, high risk).
// Policy parks the request for approval unless it says otherwise; the client
// and its identity exist only once the change is applied.
func (s *MCPClientService) Register(ctx context.Context, by Caller, r wire.RegisterMCPClientRequest) (DirectResult[wire.MCPClient], error) {
	p, err := s.registerParams(r)
	if err != nil {
		return DirectResult[wire.MCPClient]{}, err
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[wire.MCPClient], error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[wire.MCPClient]{}, err
		}
		if err := requireFreeMCPClientName(ctx, tx, p.Name); err != nil {
			return DirectResult[wire.MCPClient]{}, err
		}
		existing, found, err := mcpIdentityOf(ctx, tx, p)
		if err != nil {
			return DirectResult[wire.MCPClient]{}, err
		}
		if found {
			p.IdentityID = existing
		}
		b, err := s.planOf(ctx, tx, by, actionMCPClientRegister, mcpIdentityRef(p.IdentityID), p)
		if err != nil {
			return DirectResult[wire.MCPClient]{}, err
		}
		return s.applyOrSubmit(ctx, tx, by, actor, b, func() (wire.MCPClient, error) {
			row, err := s.applyMCPClientRegister(ctx, tx, actor, p, nil)
			if err != nil {
				return wire.MCPClient{}, err
			}
			return mcpClientView(ctx, tx, row)
		})
	})
}

func (s *MCPClientService) registerParams(r wire.RegisterMCPClientRequest) (mcpRegisterParams, error) {
	p := mcpRegisterParams{
		ClientID: s.cfg.IDs.NewID(), IdentityID: s.cfg.IDs.NewID(), Name: r.Name, Origin: r.Origin,
		Subject: r.Subject, OAuthClientID: r.ClientID,
	}
	if r.Origin == wire.MCPOriginRemote {
		if s.remoteIssuer == "" {
			return mcpRegisterParams{}, invalidArgument("remote MCP is not enabled on this instance")
		}
		p.Issuer = s.remoteIssuer
	}
	return p, p.validate()
}

func requireFreeMCPClientName(ctx context.Context, q database.Querier, name string) error {
	all, err := database.ListMCPClients(ctx, q)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(all, func(c database.MCPClient) bool { return c.Name == name && c.State != database.MCPClientDeleted }) {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("an MCP client named %q already exists", name))
	}
	return nil
}

// mcpIdentityOf finds the identity of a remote registration: the OAuth triple
// is unique, so the identity of a deleted client is found again.
func mcpIdentityOf(ctx context.Context, q database.Querier, p mcpRegisterParams) (domain.ID, bool, error) {
	if p.Origin != wire.MCPOriginRemote {
		return "", false, nil
	}
	var id domain.ID
	err := q.QueryRowContext(ctx, `SELECT COALESCE(
		(SELECT id FROM identities WHERE actor_type = ? AND issuer = ? AND subject = ? AND client_id = ?), '')`,
		domain.ActorMCP, p.Issuer, p.Subject, p.OAuthClientID).Scan(&id)
	if err != nil {
		return "", false, fmt.Errorf("find mcp identity: %w", err)
	}
	return id, id != "", nil
}

// applyMCPClientRegister creates the client and its identity, or re-enables the
// identity of a deleted remote triple under a new client row. The identity gets
// no role. It converges: a client already stored under the id is returned. job
// is the approving job, nil when the request was applied directly.
func (c core) applyMCPClientRegister(ctx context.Context, q database.Querier, actor domain.Actor, p mcpRegisterParams, job *jobs.Job) (database.MCPClient, error) {
	if existing, err := database.GetMCPClient(ctx, q, p.ClientID); err == nil {
		return existing, nil
	} else if smerr.CodeOf(err) != smerr.CodeNotFound {
		return database.MCPClient{}, err
	}
	if err := p.validate(); err != nil {
		return database.MCPClient{}, err
	}
	identityID, err := c.enableMCPIdentity(ctx, q, p)
	if err != nil {
		return database.MCPClient{}, err
	}
	approvedAt, err := c.approvedAt(ctx, q, job)
	if err != nil {
		return database.MCPClient{}, err
	}
	now := c.cfg.Clock.Now()
	client := database.MCPClient{
		ID: p.ClientID, IdentityID: identityID, Name: p.Name, Origin: database.MCPClientOrigin(p.Origin),
		State: database.MCPClientPendingToken, RequestedBy: actor.ID, ApprovedAt: approvedAt, CreatedAt: now, UpdatedAt: now,
	}
	if p.Origin == wire.MCPOriginRemote {
		client.State = database.MCPClientActive
	}
	if job != nil {
		client.RegistrationJobID = &job.ID
	}
	if err := database.CreateMCPClient(ctx, q, client); err != nil {
		return database.MCPClient{}, err
	}
	data := map[string]any{"client_id": p.ClientID.String(), "name": p.Name, "origin": string(p.Origin)}
	if p.Origin == wire.MCPOriginRemote {
		data["issuer"], data["subject"], data["oauth_client_id"] = p.Issuer, p.Subject, p.OAuthClientID
	}
	return client, c.emit(ctx, q, actor, eventMCPClientRegistered, mcpIdentityRef(identityID), domain.ResultSucceeded, data)
}

// enableMCPIdentity returns the identity of the registration: new for a local
// client, found or new for a remote one. Whatever its history, it leaves
// enabled and without role bindings.
func (c core) enableMCPIdentity(ctx context.Context, q database.Querier, p mcpRegisterParams) (domain.ID, error) {
	existing, found, err := mcpIdentityOf(ctx, q, p)
	if err != nil {
		return "", err
	}
	if found {
		return existing, c.resetMCPIdentity(ctx, q, existing)
	}
	identity := database.Identity{
		ID: p.IdentityID, ActorType: domain.ActorMCP, Issuer: mcpLocalIssuer, Subject: p.ClientID.String(),
		DisplayName: p.Name, CreatedAt: c.cfg.Clock.Now(),
	}
	if p.Origin == wire.MCPOriginRemote {
		identity.Issuer, identity.Subject, identity.ClientID = p.Issuer, p.Subject, p.OAuthClientID
	}
	return identity.ID, database.CreateIdentity(ctx, q, identity)
}

func (c core) resetMCPIdentity(ctx context.Context, q database.Querier, id domain.ID) error {
	if _, err := q.ExecContext(ctx, `UPDATE identities SET disabled_at = NULL WHERE id = ?`, id); err != nil {
		return fmt.Errorf("enable mcp identity: %w", err)
	}
	return clearRoleBindings(ctx, q, id)
}

func clearRoleBindings(ctx context.Context, q database.Querier, identity domain.ID) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM role_bindings WHERE identity_id = ?`, identity); err != nil {
		return fmt.Errorf("clear mcp identity roles: %w", err)
	}
	return nil
}

// approvedAt starts the issuance window: the last approval of the job, or now
// when no approval was needed.
func (c core) approvedAt(ctx context.Context, q database.Querier, job *jobs.Job) (time.Time, error) {
	now := c.cfg.Clock.Now()
	if job == nil {
		return now, nil
	}
	decisions, err := database.ListDecisions(ctx, q, job.ID, job.PlanHash)
	if err != nil {
		return time.Time{}, err
	}
	var last time.Time
	for _, d := range decisions {
		if d.Decision != domain.DecisionApprove {
			continue
		}
		at := d.CreatedAt
		if d.RenewedAt != nil && d.RenewedAt.After(at) {
			at = *d.RenewedAt
		}
		if at.After(last) {
			last = at
		}
	}
	if last.IsZero() {
		return now, nil
	}
	return last, nil
}

// ---- issue token --------------------------------------------------------------------

// IssueToken issues the one token of a local client (action
// mcp_client.issue_token): to the identity that requested the client, while
// the client waits for it and within 24 hours of its approval. The plaintext
// is in the answer exactly once. The request never takes an Idempotency-Key.
func (s *MCPClientService) IssueToken(ctx context.Context, by Caller, id domain.ID, r wire.IssueMCPTokenRequest) (wire.MCPTokenIssued, error) {
	if by.Idempotency != nil {
		return wire.MCPTokenIssued{}, errIdempotencyKeyRefused()
	}
	now := s.cfg.Clock.Now()
	if lifetime := r.ExpiresAt.Sub(now); r.ExpiresAt.IsZero() || lifetime <= 0 || lifetime > database.MCPTokenMaxLifetime {
		return wire.MCPTokenIssued{}, invalidArgument("expires_at is required and must be within 365 days from now")
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (wire.MCPTokenIssued, error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return wire.MCPTokenIssued{}, err
		}
		client, err := database.GetMCPClient(ctx, tx, id)
		if err != nil {
			return wire.MCPTokenIssued{}, err
		}
		ref := mcpIdentityRef(client.IdentityID)
		if err := s.requireAllowed(ctx, tx, actor, actionMCPClientIssue, ref); err != nil {
			return wire.MCPTokenIssued{}, err
		}
		if err := s.requireIssuable(ctx, tx, actor, ref, client, now); err != nil {
			return wire.MCPTokenIssued{}, err
		}
		secret, hash, err := s.tokens.Mint(MCPTokenKind)
		if err != nil {
			return wire.MCPTokenIssued{}, err
		}
		stored, err := database.IssueMCPToken(ctx, tx, client.ID, hash, now, r.ExpiresAt)
		if err != nil {
			return wire.MCPTokenIssued{}, err
		}
		err = s.emit(ctx, tx, actor, eventMCPClientIssuance, ref, domain.ResultSucceeded,
			map[string]any{"client_id": client.ID.String(), "name": client.Name, "expires_at": r.ExpiresAt})
		if err != nil {
			return wire.MCPTokenIssued{}, err
		}
		view, err := mcpClientView(ctx, tx, stored)
		return wire.MCPTokenIssued{Client: view, Token: secret.Reveal()}, err
	})
}

func (s *MCPClientService) requireIssuable(ctx context.Context, q database.Querier, actor domain.Actor, ref domain.ResourceRef, client database.MCPClient, now time.Time) error {
	switch {
	case client.RequestedBy != actor.ID:
		denied := policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonNotPlanActor}
		if err := s.auditDecision(ctx, q, actor, actionMCPClientIssue, ref, denied); err != nil {
			return err
		}
		return reject(smerr.FromReason(smerr.ReasonNotPlanActor, "only the identity that requested the client may issue its token"))
	case client.State != database.MCPClientPendingToken:
		return smerr.FromReason(smerr.ReasonInvalidTransition, "mcp client is not waiting for its token")
	case !now.Before(client.ApprovedAt.Add(mcpIssuanceWindow)):
		return smerr.FromReason(smerr.ReasonIssuanceWindowExpired, "the 24-hour window to issue the token has passed; remove the client and add it again")
	}
	return nil
}

// ---- delete -------------------------------------------------------------------------

// Delete removes a client (action mcp_client.delete): its token and OAuth
// access tokens are revoked, its identity is disabled and loses its role
// bindings. The rows stay as history. Policy may park the request for approval.
func (s *MCPClientService) Delete(ctx context.Context, by Caller, id domain.ID) (DirectResult[wire.MCPClient], error) {
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[wire.MCPClient], error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[wire.MCPClient]{}, err
		}
		client, err := database.GetMCPClient(ctx, tx, id)
		if err != nil {
			return DirectResult[wire.MCPClient]{}, err
		}
		p := mcpDeleteParams{ClientID: id}
		b, err := s.planOf(ctx, tx, by, actionMCPClientDelete, mcpIdentityRef(client.IdentityID), p)
		if err != nil {
			return DirectResult[wire.MCPClient]{}, err
		}
		return s.applyOrSubmit(ctx, tx, by, actor, b, func() (wire.MCPClient, error) {
			row, err := s.applyMCPClientDelete(ctx, tx, actor, p)
			if err != nil {
				return wire.MCPClient{}, err
			}
			return mcpClientView(ctx, tx, row)
		})
	})
}

// applyMCPClientDelete converges: a client already deleted is returned unchanged.
func (c core) applyMCPClientDelete(ctx context.Context, q database.Querier, actor domain.Actor, p mcpDeleteParams) (database.MCPClient, error) {
	now := c.cfg.Clock.Now()
	deleted, err := database.DeleteMCPClient(ctx, q, p.ClientID, now)
	if err != nil {
		return database.MCPClient{}, err
	}
	client, err := database.GetMCPClient(ctx, q, p.ClientID)
	if err != nil || !deleted {
		return client, err
	}
	revoked, err := database.RevokeOAuthTokensOfClient(ctx, q, client.ID, now)
	if err != nil {
		return database.MCPClient{}, err
	}
	if err := c.retireMCPIdentity(ctx, q, client.IdentityID, now); err != nil {
		return database.MCPClient{}, err
	}
	return client, c.emit(ctx, q, actor, eventMCPClientDeleted, mcpIdentityRef(client.IdentityID), domain.ResultSucceeded,
		map[string]any{"client_id": client.ID.String(), "name": client.Name, "oauth_tokens_revoked": revoked})
}

func (c core) retireMCPIdentity(ctx context.Context, q database.Querier, id domain.ID, at time.Time) error {
	_, err := q.ExecContext(ctx, `UPDATE identities SET disabled_at = COALESCE(disabled_at, ?) WHERE id = ?`, domain.UnixMillis(at), id)
	if err != nil {
		return fmt.Errorf("disable mcp identity: %w", err)
	}
	return clearRoleBindings(ctx, q, id)
}

// ---- plans --------------------------------------------------------------------------

func (s *MCPClientService) planOf(ctx context.Context, q database.Querier, by Caller, action string, ref domain.ResourceRef, p any) (built, error) {
	params, err := toParams(p)
	if err != nil {
		return built{}, err
	}
	return build(ctx, q, action, by.ID, ref, params)
}

// applyOrSubmit authorizes b and either applies it inside the request
// transaction or, when policy requires approval, wraps it in a job.
func (s *MCPClientService) applyOrSubmit(ctx context.Context, tx *database.Tx, by Caller, actor domain.Actor, b built, apply func() (wire.MCPClient, error)) (DirectResult[wire.MCPClient], error) {
	res, err := s.evaluate(ctx, tx, actor, b)
	if err != nil {
		return DirectResult[wire.MCPClient]{}, err
	}
	if res.ApprovalRequired {
		submission, err := s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		return DirectResult[wire.MCPClient]{Pending: &submission}, err
	}
	out, err := apply()
	if err != nil {
		return DirectResult[wire.MCPClient]{}, err
	}
	return DirectResult[wire.MCPClient]{Applied: &out}, nil
}

// mcpRegisterTarget is the policy view of a registration: the identity it
// creates or, for a remote client seen before, re-enables.
func mcpRegisterTarget(ref domain.ResourceRef, params map[string]any) (policy.Target, *int64, []plan.Input, error) {
	p, err := fromParams[mcpRegisterParams](params)
	if err != nil {
		return policy.Target{}, nil, nil, err
	}
	if p.IdentityID != ref.ID {
		return policy.Target{}, nil, nil, mismatchedTarget("identity_id")
	}
	return policy.Target{Ref: ref}, nil, nil, p.validate()
}

// mcpDeleteTarget is the policy view of a deletion: the identity of the client.
func mcpDeleteTarget(ctx context.Context, q database.Querier, ref domain.ResourceRef, params map[string]any) (policy.Target, *int64, []plan.Input, error) {
	p, err := fromParams[mcpDeleteParams](params)
	if err != nil {
		return policy.Target{}, nil, nil, err
	}
	client, err := database.GetMCPClient(ctx, q, p.ClientID)
	if err != nil {
		return policy.Target{}, nil, nil, err
	}
	if client.IdentityID != ref.ID {
		return policy.Target{}, nil, nil, mismatchedTarget("client_id")
	}
	return policy.Target{Ref: ref}, nil, nil, nil
}
