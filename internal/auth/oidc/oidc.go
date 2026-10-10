// Package oidc is the server side of OIDC login (spec §23.1; ADR-0018): the
// server is the confidential client. Discovery and ID-token verification use
// github.com/coreos/go-oidc/v3; PKCE and the device grant use
// golang.org/x/oauth2. Every IdP call goes through a netguard client with
// redirects disabled.
//
// W0 contract: signatures are frozen; bodies land in M2 task T3.
package oidc

import (
	"context"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
)

// Config is auth.oidc plus the resolved client secret and the netguard client.
type Config struct {
	Issuer                 string
	ClientID               string
	ClientSecret           audit.Secret
	AllowedDomains         []string
	AllowedEndpointOrigins []string
	HTTPClient             *http.Client // netguard provider client, no redirects
	Clock                  domain.Clock
}

// Claims is what a verified ID token says about the person.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// DeviceTxn is a device login held by the server; the IdP device code never
// leaves it.
type DeviceTxn struct {
	ID                      string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	Interval                time.Duration
	ExpiresAt               time.Time
}

// Pending answers a device poll that has no result yet. SlowDown means the
// client polled faster than Interval and must add 5 seconds (RFC 8628).
type Pending struct{ SlowDown bool }

func (p Pending) Error() string {
	if p.SlowDown {
		return "slow down"
	}
	return "authorization pending"
}

// Login is the OIDC adapter the app services call.
type Login interface {
	// Start records {state, nonce, redirect, challenge} for 10 minutes and
	// returns the IdP authorization URL.
	Start(ctx context.Context, redirect, challenge string) (authURL, state string, err error)
	// Exchange consumes state once, redeems code with the verifier at the IdP
	// and verifies the ID token (issuer, audience, signature, exp, nonce,
	// verified email in allowed_domains).
	Exchange(ctx context.Context, code, state, verifier string) (Claims, error)
	// DeviceStart opens a device transaction (RFC 8628).
	DeviceStart(ctx context.Context) (DeviceTxn, error)
	// DevicePoll returns Pending until the person approves, then Claims once;
	// later polls of the same transaction are CONFLICT.
	DevicePoll(ctx context.Context, txnID string) (Claims, error)
}

// Scopes are the scopes every login requests: an ID token with a verified
// email is all the server needs (allowed_domains, §23.1 step 5).
var Scopes = []string{gooidc.ScopeOpenID, "email", "profile"}

// ClientAuthStyle is how the server, a confidential client, authenticates at
// the token endpoint: HTTP Basic (client_secret_basic), never auto-detected,
// so a failed attempt is not retried with the secret in a form. The device
// endpoint takes the client credentials as form fields (ADR-0018).
const ClientAuthStyle = oauth2.AuthStyleInHeader

// Client implements Login. Its fields (the go-oidc verifier, the oauth2
// configuration and the login-state store) land with T3.
type Client struct{}

var _ Login = (*Client)(nil)

// New fetches the discovery document through cfg.HTTPClient and checks it:
// the issuer must equal cfg.Issuer and every endpoint must be https on the
// issuer origin or an allowed origin. The userinfo endpoint is never used.
func New(ctx context.Context, cfg Config) (*Client, error) {
	panic("not implemented: M2 T3")
}

func (c *Client) Start(ctx context.Context, redirect, challenge string) (string, string, error) {
	panic("not implemented: M2 T3")
}

func (c *Client) Exchange(ctx context.Context, code, state, verifier string) (Claims, error) {
	panic("not implemented: M2 T3")
}

func (c *Client) DeviceStart(ctx context.Context) (DeviceTxn, error) {
	panic("not implemented: M2 T3")
}

func (c *Client) DevicePoll(ctx context.Context, txnID string) (Claims, error) {
	panic("not implemented: M2 T3")
}
