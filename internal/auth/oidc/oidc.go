// Package oidc is the server side of OIDC login (spec §23.1; ADR-0018): the
// server is the confidential client. Discovery and ID-token verification use
// github.com/coreos/go-oidc/v3; PKCE and the device grant use
// golang.org/x/oauth2. Every IdP call goes through a netguard client with
// redirects disabled.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	// Replay records ID-token jti values (oidc_replay). Nil keeps them in
	// process memory, which does not survive a restart.
	Replay ReplayStore
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

// signingAlgs are the only JWS algorithms an ID token may use (ADR-0018).
var signingAlgs = []string{gooidc.RS256, gooidc.ES256, gooidc.EdDSA}

const (
	loginStateTTL = 10 * time.Minute
	registryLimit = 1000
	// ownerLimit is how many pending logins one client address may hold.
	ownerLimit     = 20
	clockSkew      = time.Minute
	defaultPollGap = 5 * time.Second
)

// Client implements Login.
type Client struct {
	clientID     string
	clientSecret audit.Secret
	allowedMails []string
	clock        domain.Clock
	http         *http.Client
	oauth        oauth2.Config
	verifier     *gooidc.IDTokenVerifier
	replay       ReplayStore
	states       *registry[loginState]
	txns         *registry[*deviceTxn]
}

var _ Login = (*Client)(nil)

// New fetches the discovery document through cfg.HTTPClient and checks it:
// the issuer must equal cfg.Issuer and every endpoint must be https on the
// issuer origin or an allowed origin. The userinfo endpoint is never used.
func New(ctx context.Context, cfg Config) (*Client, error) {
	allowed, err := trustedOrigins(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" || cfg.HTTPClient == nil || cfg.Clock == nil {
		return nil, errors.New("oidc: client id, HTTP client and clock are required")
	}
	ctx = gooidc.ClientContext(ctx, cfg.HTTPClient)
	provider, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	endpoint := provider.Endpoint()
	var extra struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&extra); err != nil {
		return nil, fmt.Errorf("oidc: discovery document: %w", err)
	}
	if err := checkEndpoints(allowed, endpoint, extra.JWKSURI); err != nil {
		return nil, err
	}
	endpoint.AuthStyle = ClientAuthStyle
	replay := cfg.Replay
	if replay == nil {
		replay = newMemoryReplay(cfg.Clock)
	}
	return &Client{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		allowedMails: cfg.AllowedDomains,
		clock:        cfg.Clock,
		http:         cfg.HTTPClient,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret.Reveal(),
			Endpoint:     endpoint,
			Scopes:       Scopes,
		},
		verifier: provider.Verifier(&gooidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: signingAlgs,
			SkipExpiryCheck:      true, // verifyClaims applies exp, iat and nbf with the 60 s skew
			Now:                  cfg.Clock.Now,
		}),
		replay: replay,
		states: newRegistry[loginState](registryLimit, ownerLimit),
		txns:   newRegistry[*deviceTxn](registryLimit, ownerLimit),
	}, nil
}

// withHTTPClient makes oauth2 and go-oidc call the IdP through the netguard
// client.
func (c *Client) withHTTPClient(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, c.http)
}

func parseHTTPS(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, err
	case u.Scheme != "https":
		return nil, fmt.Errorf("%q is not https", raw)
	case u.Hostname() == "":
		return nil, fmt.Errorf("%q has no host", raw)
	case u.User != nil:
		return nil, fmt.Errorf("%q carries userinfo", raw)
	}
	return u, nil
}
