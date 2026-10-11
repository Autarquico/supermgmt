package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Credential-issuing responses carry the plaintext exactly once, in a field
// named "token" or "code". They are never stored as idempotent answers and
// their routes reject Idempotency-Key (spec §23, ADR-0012).

// ---- login (ADR-0017, ADR-0018) --------------------------------------------

// OIDCStartRequest is POST /auth/oidc/start. RedirectURI must be
// http://127.0.0.1:<port>/callback (RFC 8252); CodeChallenge is S256.
type OIDCStartRequest struct {
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge"`
}

// OIDCStart is the answer to POST /auth/oidc/start.
type OIDCStart struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// OIDCExchangeRequest is POST /auth/oidc/exchange.
type OIDCExchangeRequest struct {
	Code         string `json:"code"`
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	Client       string `json:"client"`
}

// LoginSession is a new opaque session token (TTL security.session_ttl).
type LoginSession struct {
	SessionID  domain.ID `json:"session_id"`
	IdentityID domain.ID `json:"identity_id"`
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// DeviceStart is the answer to POST /auth/oidc/device. The IdP device code
// never leaves the server; the client polls with TransactionID only.
type DeviceStart struct {
	TransactionID           string    `json:"transaction_id"`
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete,omitempty"`
	IntervalSeconds         int       `json:"interval_seconds"`
	ExpiresAt               time.Time `json:"expires_at"`
}

// DevicePollRequest is POST /auth/oidc/device/poll.
type DevicePollRequest struct {
	TransactionID string `json:"transaction_id"`
	Client        string `json:"client"`
}

// DeviceStatus is where a device login stands.
type DeviceStatus string

const (
	DevicePending  DeviceStatus = "pending"
	DeviceSlowDown DeviceStatus = "slow_down"
	DeviceComplete DeviceStatus = "complete"
)

// DevicePoll is the answer to a poll. Session is set only with DeviceComplete,
// exactly once per transaction; a later poll is a CONFLICT.
type DevicePoll struct {
	Status  DeviceStatus  `json:"status"`
	Session *LoginSession `json:"session,omitempty"`
}

// BootstrapRequest is POST /auth/bootstrap (spec §11.5). With OIDC configured
// the request carries the session of a completed login, which is bound to
// admin. Without OIDC, DisplayName names the admin identity to create.
type BootstrapRequest struct {
	Code        string `json:"code"`
	DisplayName string `json:"display_name,omitempty"`
}

// Bootstrapped is the answer to POST /auth/bootstrap. Session and APIToken are
// set only when the exchange created the identity (no OIDC).
type Bootstrapped struct {
	IdentityID domain.ID     `json:"identity_id"`
	Session    *LoginSession `json:"session,omitempty"`
	APIToken   *TokenIssued  `json:"api_token,omitempty"`
}

// ---- API tokens (spec §23) -------------------------------------------------

type Token struct {
	ID         domain.ID  `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// CreateTokenRequest is POST /tokens. ExpiresAt is mandatory and at most 365
// days ahead; Scopes may only narrow the creator's permissions.
type CreateTokenRequest struct {
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenIssued is the one response that carries the token value.
type TokenIssued struct {
	Token Token  `json:"metadata"`
	Value string `json:"token"`
}

// ---- admin socket (spec §23.1; not part of /api/v1) -------------------------

// BootstrapCodeIssued is the answer to the admin-socket bootstrap-code route.
type BootstrapCodeIssued struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GrantRequest is the admin-socket grant route (`sm admin grant`).
type GrantRequest struct {
	IdentityID domain.ID `json:"identity_id"`
	Role       string    `json:"role"`
}
