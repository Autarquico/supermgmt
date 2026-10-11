package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth/oidc"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// Token kind bytes, the letter after "sm" (internal/auth.Kind uses the same).
const (
	SessionTokenKind  byte = 's'
	APITokenKind      byte = 't'
	BootstrapCodeKind byte = 'b'
)

// TokenMinter mints and parses bearer tokens. internal/auth implements it;
// the services take it as a seam because that package imports this one.
type TokenMinter interface {
	Mint(kind byte) (audit.Secret, string, error)
	// Hash parses a presented token and returns its kind and storage hash.
	Hash(token string) (kind byte, hash string, err error)
}

const (
	defaultSessionTTL     = 12 * time.Hour
	defaultBootstrapTTL   = 24 * time.Hour
	bootstrapTokenName    = "bootstrap"
	bootstrapTokenTTL     = 90 * 24 * time.Hour
	maxDisplayName        = 128
	maxEmail              = 256
	maxClient             = 64
	adminRoleName         = "admin"
	bootstrapIssuer       = "bootstrap"
	adminSocketSource     = "admin_socket"
	eventBootstrapIssued  = "bootstrap_code.issued"
	eventBootstrapUsed    = "bootstrap_code.consumed"
	eventSessionCreated   = "session.created"
	eventSessionRevoked   = "session.revoked"
	eventIdentityCreated  = "identity.created"
	eventRoleBindingAdded = "role_binding.created"
)

// AuthOptions are the collaborators of the AuthService.
type AuthOptions struct {
	Tokens TokenMinter // required
	// OIDC is the login adapter; nil means OIDC is not configured, which
	// changes the bootstrap exchange (spec §11.5).
	OIDC             oidc.Login
	SessionTTL       time.Duration // security.session_ttl; default 12h
	BootstrapCodeTTL time.Duration // auth.bootstrap.code_ttl; default 24h
}

// AuthService is login, bootstrap, API tokens and the admin-socket routes
// that mint or grant (ADR-0017, ADR-0018). No method stores an idempotent
// answer: none of them is ever called with Caller.Idempotency set.
type AuthService struct {
	core
	tokens      TokenMinter
	login       oidc.Login
	sessionTTL  time.Duration
	bootstrapTT time.Duration
}

var (
	_ Auth        = (*AuthService)(nil)
	_ AdminSocket = (*AuthService)(nil)
)

// NewAuthService validates cfg and the options.
func NewAuthService(cfg Config, o AuthOptions) (*AuthService, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if o.Tokens == nil {
		return nil, errors.New("app: token minter is required")
	}
	a := &AuthService{core: c, tokens: o.Tokens, login: o.OIDC, sessionTTL: o.SessionTTL, bootstrapTT: o.BootstrapCodeTTL}
	if a.sessionTTL <= 0 {
		a.sessionTTL = defaultSessionTTL
	}
	if a.bootstrapTT <= 0 {
		a.bootstrapTT = defaultBootstrapTTL
	}
	return a, nil
}

// ---- OIDC login ----------------------------------------------------------------

func (a *AuthService) requireOIDC() (oidc.Login, error) {
	if a.login == nil {
		return nil, smerr.New(smerr.CodeNotFound, "", "OIDC login is not configured")
	}
	return a.login, nil
}

func (a *AuthService) OIDCStart(ctx context.Context, r wire.OIDCStartRequest) (wire.OIDCStart, error) {
	login, err := a.requireOIDC()
	if err != nil {
		return wire.OIDCStart{}, err
	}
	if r.RedirectURI == "" || r.CodeChallenge == "" {
		return wire.OIDCStart{}, smerr.New(smerr.CodeInvalidArgument, "", "redirect_uri and code_challenge are required")
	}
	url, state, err := login.Start(ctx, r.RedirectURI, r.CodeChallenge)
	if err != nil {
		return wire.OIDCStart{}, err
	}
	return wire.OIDCStart{AuthorizationURL: url, State: state}, nil
}

func (a *AuthService) OIDCExchange(ctx context.Context, r wire.OIDCExchangeRequest) (wire.LoginSession, error) {
	login, err := a.requireOIDC()
	if err != nil {
		return wire.LoginSession{}, err
	}
	if r.Code == "" || r.State == "" || r.CodeVerifier == "" {
		return wire.LoginSession{}, smerr.New(smerr.CodeInvalidArgument, "", "code, state and code_verifier are required")
	}
	claims, err := login.Exchange(ctx, r.Code, r.State, r.CodeVerifier)
	if err != nil {
		return wire.LoginSession{}, err
	}
	return a.openSession(ctx, claims, r.Client)
}

func (a *AuthService) DeviceStart(ctx context.Context) (wire.DeviceStart, error) {
	login, err := a.requireOIDC()
	if err != nil {
		return wire.DeviceStart{}, err
	}
	txn, err := login.DeviceStart(ctx)
	if err != nil {
		return wire.DeviceStart{}, err
	}
	return wire.DeviceStart{
		TransactionID: txn.ID, UserCode: txn.UserCode, VerificationURI: txn.VerificationURI,
		VerificationURIComplete: txn.VerificationURIComplete, IntervalSeconds: int(txn.Interval.Seconds()), ExpiresAt: txn.ExpiresAt,
	}, nil
}

func (a *AuthService) DevicePoll(ctx context.Context, r wire.DevicePollRequest) (wire.DevicePoll, error) {
	login, err := a.requireOIDC()
	if err != nil {
		return wire.DevicePoll{}, err
	}
	if r.TransactionID == "" {
		return wire.DevicePoll{}, smerr.New(smerr.CodeInvalidArgument, "", "transaction_id is required")
	}
	claims, err := login.DevicePoll(ctx, r.TransactionID)
	var pending oidc.Pending
	if errors.As(err, &pending) {
		if pending.SlowDown {
			return wire.DevicePoll{Status: wire.DeviceSlowDown}, nil
		}
		return wire.DevicePoll{Status: wire.DevicePending}, nil
	}
	if err != nil {
		return wire.DevicePoll{}, err
	}
	session, err := a.openSession(ctx, claims, r.Client)
	if err != nil {
		return wire.DevicePoll{}, err
	}
	return wire.DevicePoll{Status: wire.DeviceComplete, Session: &session}, nil
}

// openSession signs the verified person in: it finds or creates their human
// identity (no roles until one is granted) and issues a session.
func (a *AuthService) openSession(ctx context.Context, claims oidc.Claims, client string) (wire.LoginSession, error) {
	return commit(ctx, a.core, Caller{}, func(ctx context.Context, tx *database.Tx) (wire.LoginSession, error) {
		identity, err := a.humanFor(ctx, tx, claims)
		if err != nil {
			return wire.LoginSession{}, err
		}
		return a.createSession(ctx, tx, identity, database.OriginOIDC, client)
	})
}

// humanFor returns the identity of (issuer, subject), refreshing its display
// metadata, or creates it. A disabled identity cannot sign in.
func (a *AuthService) humanFor(ctx context.Context, tx *database.Tx, claims oidc.Claims) (domain.Actor, error) {
	if claims.Issuer == "" || claims.Subject == "" {
		return domain.Actor{}, smerr.New(smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid, "identity provider sent no subject")
	}
	now := a.cfg.Clock.Now()
	name, email := displayName(claims), limitRunes(textsafe.Line(claims.Email), maxEmail)
	var id domain.ID
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), '') FROM identities WHERE actor_type = ? AND issuer = ? AND subject = ? AND client_id = ''`,
		domain.ActorHuman, claims.Issuer, claims.Subject).Scan(&id)
	switch {
	case err != nil:
		return domain.Actor{}, fmt.Errorf("find identity: %w", err)
	case id == "":
		return a.createHuman(ctx, tx, claims, name, email)
	}
	identity, err := database.GetIdentity(ctx, tx, id)
	if err != nil {
		return domain.Actor{}, err
	}
	if identity.DisabledAt != nil {
		return domain.Actor{}, smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "identity is disabled")
	}
	_, err = tx.ExecContext(ctx, `UPDATE identities SET display_name = ?, email = ?, last_seen_at = ? WHERE id = ?`,
		name, email, domain.UnixMillis(now), id)
	if err != nil {
		return domain.Actor{}, fmt.Errorf("refresh identity: %w", err)
	}
	return domain.Actor{ID: id, Type: domain.ActorHuman}, nil
}

func (a *AuthService) createHuman(ctx context.Context, tx *database.Tx, claims oidc.Claims, name, email string) (domain.Actor, error) {
	now := a.cfg.Clock.Now()
	id := a.cfg.IDs.NewID()
	err := database.CreateIdentity(ctx, tx, database.Identity{
		ID: id, ActorType: domain.ActorHuman, Issuer: claims.Issuer, Subject: claims.Subject,
		DisplayName: name, Email: email, CreatedAt: now, LastSeenAt: &now,
	})
	if err != nil {
		return domain.Actor{}, err
	}
	actor := domain.Actor{ID: id, Type: domain.ActorHuman}
	ref := domain.ResourceRef{Type: domain.ResourceIdentity, ID: id}
	return actor, a.emit(ctx, tx, actor, eventIdentityCreated, ref, domain.ResultSucceeded,
		map[string]any{"issuer": claims.Issuer, "origin": "oidc"})
}

func displayName(c oidc.Claims) string {
	name := c.Name
	if name == "" {
		name = c.Email
	}
	return limitRunes(textsafe.Line(name), maxDisplayName)
}

func limitRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// createSession stores a new session of actor and returns its token.
func (a *AuthService) createSession(ctx context.Context, tx *database.Tx, actor domain.Actor, origin database.SessionOrigin, client string) (wire.LoginSession, error) {
	secret, hash, err := a.tokens.Mint(SessionTokenKind)
	if err != nil {
		return wire.LoginSession{}, err
	}
	now := a.cfg.Clock.Now()
	row := database.AuthSession{
		ID: a.cfg.IDs.NewID(), IdentityID: actor.ID, TokenHash: hash,
		Client: limitRunes(textsafe.Line(client), maxClient), Origin: origin, CreatedAt: now, ExpiresAt: now.Add(a.sessionTTL),
	}
	if err := database.CreateAuthSession(ctx, tx, row); err != nil {
		return wire.LoginSession{}, err
	}
	ref := domain.ResourceRef{Type: domain.ResourceIdentity, ID: actor.ID}
	err = a.emit(ctx, tx, actor, eventSessionCreated, ref, domain.ResultSucceeded,
		map[string]any{"session_id": row.ID.String(), "origin": string(origin), "client": row.Client, "expires_at": row.ExpiresAt})
	if err != nil {
		return wire.LoginSession{}, err
	}
	return wire.LoginSession{SessionID: row.ID, IdentityID: actor.ID, Token: secret.Reveal(), ExpiresAt: row.ExpiresAt}, nil
}

// Logout revokes the session the request presented.
func (a *AuthService) Logout(ctx context.Context, by Caller) error {
	if by.Credential.Kind != domain.CredentialSession {
		return smerr.New(smerr.CodeInvalidArgument, "", "only a session can log out")
	}
	_, err := commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (struct{}, error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return struct{}{}, err
		}
		id := domain.ID(by.Credential.ID)
		first, err := database.RevokeAuthSession(ctx, tx, id, a.cfg.Clock.Now())
		if err != nil || !first {
			return struct{}{}, err
		}
		ref := domain.ResourceRef{Type: domain.ResourceIdentity, ID: actor.ID}
		return struct{}{}, a.emit(ctx, tx, actor, eventSessionRevoked, ref, domain.ResultSucceeded,
			map[string]any{"session_id": id.String(), "reason": "logout"})
	})
	return err
}

// ---- bootstrap (spec §11.5) --------------------------------------------------------

// bootstrapOpen reports whether a code may be issued or exchanged: while no
// admin binding exists, or during restore hold (spec §29.2).
func (a *AuthService) bootstrapOpen(ctx context.Context, q database.Querier) (bool, error) {
	var exists bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM role_bindings b JOIN roles r ON r.id = b.role_id WHERE r.name = ?)`,
		adminRoleName).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("look for an admin binding: %w", err)
	}
	if !exists {
		return true, nil
	}
	return database.GetRestoreHold(ctx, q)
}

// IssueBootstrapCode makes a new one-time code, invalidating any unconsumed
// one, and returns its plaintext once. It refuses once an admin exists.
func (a *AuthService) IssueBootstrapCode(ctx context.Context, peerUID int) (wire.BootstrapCodeIssued, error) {
	return commit(ctx, a.core, Caller{Source: adminSocketSource}, func(ctx context.Context, tx *database.Tx) (wire.BootstrapCodeIssued, error) {
		open, err := a.bootstrapOpen(ctx, tx)
		if err != nil {
			return wire.BootstrapCodeIssued{}, err
		}
		if !open {
			return wire.BootstrapCodeIssued{}, smerr.New(smerr.CodeConflict, "", "an admin already exists; recover with sm admin grant")
		}
		secret, hash, err := a.tokens.Mint(BootstrapCodeKind)
		if err != nil {
			return wire.BootstrapCodeIssued{}, err
		}
		now := a.cfg.Clock.Now()
		code := database.BootstrapCode{ID: a.cfg.IDs.NewID(), CodeHash: hash, CreatedAt: now, ExpiresAt: now.Add(a.bootstrapTT)}
		if err := database.IssueBootstrapCode(ctx, tx, code); err != nil {
			return wire.BootstrapCodeIssued{}, err
		}
		ref := domain.ResourceRef{Type: domain.ResourceInstance, ID: code.ID}
		err = a.emit(ctx, tx, systemActor, eventBootstrapIssued, ref, domain.ResultSucceeded,
			map[string]any{"peer_uid": peerUID, "expires_at": code.ExpiresAt})
		return wire.BootstrapCodeIssued{Code: secret.Reveal(), ExpiresAt: code.ExpiresAt}, err
	})
}

func errInvalidBootstrapCode() error {
	return smerr.New(smerr.CodeUnauthenticated, "", "invalid bootstrap code")
}

// Bootstrap exchanges a one-time code. With OIDC configured the completed
// login in session is bound to admin; without it the exchange creates the
// admin identity and answers with a session and a first API token. The code is
// consumed in the same transaction as everything else, so a failure keeps it.
func (a *AuthService) Bootstrap(ctx context.Context, session *Caller, r wire.BootstrapRequest) (wire.Bootstrapped, error) {
	if session != nil && session.Idempotency != nil {
		return wire.Bootstrapped{}, errIdempotencyKeyRefused()
	}
	kind, hash, err := a.tokens.Hash(r.Code)
	if err != nil {
		return wire.Bootstrapped{}, err
	}
	if kind != BootstrapCodeKind {
		return wire.Bootstrapped{}, errInvalidBootstrapCode()
	}
	if a.login != nil && session == nil {
		return wire.Bootstrapped{}, smerr.New(smerr.CodeUnauthenticated, "", "complete the OIDC login before the bootstrap exchange")
	}
	return commit(ctx, a.core, Caller{}, func(ctx context.Context, tx *database.Tx) (wire.Bootstrapped, error) {
		open, err := a.bootstrapOpen(ctx, tx)
		if err != nil {
			return wire.Bootstrapped{}, err
		}
		if !open {
			return wire.Bootstrapped{}, errInvalidBootstrapCode()
		}
		if a.login != nil {
			return a.bindLogin(ctx, tx, *session, hash)
		}
		return a.createAdmin(ctx, tx, r.DisplayName, hash)
	})
}

// bindLogin binds the identity of a completed OIDC login to admin.
func (a *AuthService) bindLogin(ctx context.Context, tx *database.Tx, session Caller, codeHash string) (wire.Bootstrapped, error) {
	actor, err := a.beginRequest(ctx, tx, session)
	if err != nil {
		return wire.Bootstrapped{}, err
	}
	if actor.Type != domain.ActorHuman {
		return wire.Bootstrapped{}, smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "only a human can be the first admin")
	}
	if err := a.consumeCode(ctx, tx, actor, codeHash); err != nil {
		return wire.Bootstrapped{}, err
	}
	if err := a.bindAdmin(ctx, tx, actor, actor.ID, map[string]any{"via": "bootstrap"}); err != nil {
		return wire.Bootstrapped{}, err
	}
	return wire.Bootstrapped{IdentityID: actor.ID}, nil
}

// createAdmin makes the admin identity named by the caller (OIDC not configured).
func (a *AuthService) createAdmin(ctx context.Context, tx *database.Tx, name, codeHash string) (wire.Bootstrapped, error) {
	name = limitRunes(textsafe.Line(name), maxDisplayName)
	if name == "" {
		return wire.Bootstrapped{}, smerr.New(smerr.CodeInvalidArgument, "", "display_name is required")
	}
	id := a.cfg.IDs.NewID()
	now := a.cfg.Clock.Now()
	err := database.CreateIdentity(ctx, tx, database.Identity{
		ID: id, ActorType: domain.ActorHuman, Issuer: bootstrapIssuer, Subject: id.String(), DisplayName: name, CreatedAt: now,
	})
	if err != nil {
		return wire.Bootstrapped{}, err
	}
	actor := domain.Actor{ID: id, Type: domain.ActorHuman}
	ref := domain.ResourceRef{Type: domain.ResourceIdentity, ID: id}
	if err := a.emit(ctx, tx, actor, eventIdentityCreated, ref, domain.ResultSucceeded, map[string]any{"origin": bootstrapIssuer}); err != nil {
		return wire.Bootstrapped{}, err
	}
	if err := a.consumeCode(ctx, tx, actor, codeHash); err != nil {
		return wire.Bootstrapped{}, err
	}
	if err := a.bindAdmin(ctx, tx, actor, id, map[string]any{"via": "bootstrap"}); err != nil {
		return wire.Bootstrapped{}, err
	}
	session, err := a.createSession(ctx, tx, actor, database.OriginBootstrap, "bootstrap")
	if err != nil {
		return wire.Bootstrapped{}, err
	}
	token, err := a.issueAPIToken(ctx, tx, actor, bootstrapTokenName, nil, now.Add(bootstrapTokenTTL))
	if err != nil {
		return wire.Bootstrapped{}, err
	}
	return wire.Bootstrapped{IdentityID: id, Session: &session, APIToken: &token}, nil
}

func (a *AuthService) consumeCode(ctx context.Context, tx *database.Tx, actor domain.Actor, codeHash string) error {
	code, err := database.ConsumeBootstrapCode(ctx, tx, codeHash, actor.ID, a.cfg.Clock.Now())
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return errInvalidBootstrapCode()
	}
	if err != nil {
		return err
	}
	ref := domain.ResourceRef{Type: domain.ResourceInstance, ID: code.ID}
	return a.emit(ctx, tx, actor, eventBootstrapUsed, ref, domain.ResultSucceeded, nil)
}

// bindAdmin gives identity the admin role. A binding that already exists
// (a bootstrap during restore hold) is left alone and not audited again.
func (a *AuthService) bindAdmin(ctx context.Context, tx *database.Tx, actor domain.Actor, identity domain.ID, data map[string]any) error {
	return a.bindRole(ctx, tx, actor, identity, adminRoleName, data)
}

func (a *AuthService) bindRole(ctx context.Context, tx *database.Tx, actor domain.Actor, identity domain.ID, roleName string, data map[string]any) error {
	role, err := database.GetRoleByName(ctx, tx, roleName)
	if err != nil {
		return err
	}
	err = database.CreateRoleBinding(ctx, tx, database.RoleBinding{
		ID: a.cfg.IDs.NewID(), IdentityID: identity, RoleID: role.ID, CreatedAt: a.cfg.Clock.Now(),
	})
	if smerr.CodeOf(err) == smerr.CodeConflict {
		return nil
	}
	if err != nil {
		return err
	}
	data["identity_id"], data["role"] = identity.String(), roleName
	ref := domain.ResourceRef{Type: domain.ResourceIdentity, ID: identity}
	return a.emit(ctx, tx, actor, eventRoleBindingAdded, ref, domain.ResultSucceeded, data)
}

// Grant binds a role to an identity from the admin socket (recovery path,
// spec §11.5). Granting what is already granted succeeds quietly.
func (a *AuthService) Grant(ctx context.Context, peerUID int, r wire.GrantRequest) error {
	_, err := commit(ctx, a.core, Caller{Source: adminSocketSource}, func(ctx context.Context, tx *database.Tx) (struct{}, error) {
		identity, err := database.GetIdentity(ctx, tx, r.IdentityID)
		if err != nil {
			return struct{}{}, err
		}
		if identity.ActorType == domain.ActorSystem {
			return struct{}{}, smerr.New(smerr.CodeInvalidArgument, "", "the system identity cannot hold roles")
		}
		return struct{}{}, a.bindRole(ctx, tx, systemActor, r.IdentityID, r.Role, map[string]any{"peer_uid": peerUID, "via": adminSocketSource})
	})
	return err
}
