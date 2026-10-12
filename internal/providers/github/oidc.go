package github

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
)

const (
	// oidcMaxIssuedAge is how old a token's iat may be (spec §18).
	oidcMaxIssuedAge = 5 * time.Minute
	// oidcSkew is the clock skew tolerated on iat and nbf (spec §18).
	oidcSkew = 60 * time.Second
	// jwksMinRefresh bounds how often an unknown kid may trigger a fetch, so
	// forged kids cannot turn the server into a request amplifier.
	jwksMinRefresh = 15 * time.Second

	oidcMaxTokenBytes = 16 << 10
	oidcMaxDocBytes   = 1 << 20
	oidcDefaultWait   = 10 * time.Second
)

// ReplayStore remembers token ids so a token is accepted once (oidc_replay).
// internal/auth.OIDCReplay satisfies it.
type ReplayStore interface {
	// Remember records (issuer, jti) until expiresAt and reports whether the
	// pair was new.
	Remember(ctx context.Context, issuer, jti string, expiresAt time.Time) (fresh bool, err error)
}

// OIDCConfig configures NewOIDCVerifier.
type OIDCConfig struct {
	// Audience is the required `aud` (github.oidc_audience).
	Audience string
	Clock    domain.Clock
	Replay   ReplayStore
	// Timeout bounds each request to the issuer; zero means 10s.
	Timeout time.Duration
}

// NewOIDCVerifier verifies GitHub Actions tokens against the Actions issuer.
// Only a build with the ghsim tag can point it elsewhere.
func NewOIDCVerifier(cfg OIDCConfig) (OIDCVerifier, error) {
	override, err := ghsimOIDC()
	if err != nil {
		return nil, err
	}
	issuer := ActionsIssuer
	var guard []netguard.Option
	if override.active() {
		issuer, guard = override.issuer, override.guard()
	}
	return newOIDCVerifier(issuer, cfg, guard...)
}

// ghsimOverride is how the e2e binary (build tag ghsim) points the verifier at
// a simulated issuer and trusts its CA. It is zero in every release build.
type ghsimOverride struct {
	issuer string
	caPEM  []byte
}

func (o ghsimOverride) active() bool { return o.issuer != "" }

func (o ghsimOverride) guard() []netguard.Option {
	if len(o.caPEM) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(o.caPEM)
	return []netguard.Option{netguard.WithRootCAs(pool)}
}

func newOIDCVerifier(issuer string, cfg OIDCConfig, guard ...netguard.Option) (*oidcVerifier, error) {
	switch {
	case cfg.Audience == "":
		return nil, errors.New("github: oidc audience is empty")
	case cfg.Clock == nil:
		return nil, errors.New("github: oidc clock is nil")
	case cfg.Replay == nil:
		return nil, errors.New("github: oidc replay store is nil")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("github: oidc issuer %q is not an https origin", issuer)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = oidcDefaultWait
	}
	allow := netguard.Allow{AllowAllPrivate: issuer != ActionsIssuer}
	return &oidcVerifier{
		issuer: issuer, cfg: cfg,
		http: netguard.NewClient(allow, nil, timeout, oidcMaxDocBytes, guard...),
	}, nil
}

type oidcVerifier struct {
	issuer string
	cfg    OIDCConfig
	http   *http.Client

	mu          sync.Mutex
	keys        map[string]jose.JSONWebKey
	refreshedAt time.Time
}

func oidcInvalid(msg string, cause error) error {
	return smerr.Wrap(cause, smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid, msg)
}

// Verify checks signature, issuer, audience, lifetime and replay, and returns
// the claims. It does not decide whether the claims entitle the caller to
// anything: MatchClaims does.
func (v *oidcVerifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if len(raw) > oidcMaxTokenBytes {
		return Claims{}, oidcInvalid("token is too large", nil)
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(tok.Headers) != 1 {
		return Claims{}, oidcInvalid("token is not an RS256 JWT", err)
	}
	key, err := v.keyFor(ctx, tok.Headers[0].KeyID)
	if err != nil {
		return Claims{}, err
	}
	var std jwt.Claims
	var wire actionsClaims
	if err := tok.Claims(key, &std, &wire); err != nil {
		return Claims{}, oidcInvalid("token signature or payload is invalid", err)
	}
	claims, err := wire.claims(std)
	if err != nil {
		return Claims{}, err
	}
	if err := v.checkRegistered(claims); err != nil {
		return Claims{}, err
	}
	if err := v.rememberJTI(ctx, claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func (v *oidcVerifier) checkRegistered(c Claims) error {
	now := v.cfg.Clock.Now()
	switch {
	case c.Issuer != v.issuer:
		return oidcInvalid("token issuer is not the Actions issuer", nil)
	case !slices.Contains(c.Audience, v.cfg.Audience):
		return oidcInvalid("token audience is not this server", nil)
	case !c.ExpiresAt.After(now):
		return oidcInvalid("token is expired", nil)
	case c.IssuedAt.After(now.Add(oidcSkew)):
		return oidcInvalid("token is issued in the future", nil)
	case c.IssuedAt.Before(now.Add(-oidcMaxIssuedAge)):
		return oidcInvalid("token is older than 5 minutes", nil)
	}
	return nil
}

func (v *oidcVerifier) rememberJTI(ctx context.Context, c Claims) error {
	fresh, err := v.cfg.Replay.Remember(ctx, c.Issuer, c.JTI, c.ExpiresAt)
	switch {
	case err != nil:
		return smerr.Wrap(err, smerr.CodeInternal, "", "record token jti")
	case !fresh:
		return smerr.FromReason(smerr.ReasonOIDCReplay, "token already used")
	}
	return nil
}

// actionsClaims is the payload as GitHub sends it: numeric ids are strings.
type actionsClaims struct {
	RepositoryID      string `json:"repository_id"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Repository        string `json:"repository"`
	Ref               string `json:"ref"`
	SHA               string `json:"sha"`
	EventName         string `json:"event_name"`
	WorkflowRef       string `json:"workflow_ref"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	Environment       string `json:"environment"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
}

func (w actionsClaims) claims(std jwt.Claims) (Claims, error) {
	c := Claims{
		Issuer: std.Issuer, Subject: std.Subject, Audience: std.Audience, JTI: std.ID,
		Repository: w.Repository, Ref: w.Ref, SHA: w.SHA, EventName: w.EventName,
		WorkflowRef: w.WorkflowRef, JobWorkflowRef: w.JobWorkflowRef, Environment: w.Environment,
	}
	if std.IssuedAt != nil {
		c.IssuedAt = std.IssuedAt.Time().UTC()
	}
	if std.Expiry != nil {
		c.ExpiresAt = std.Expiry.Time().UTC()
	}
	required := map[string]string{
		"sub": c.Subject, "jti": c.JTI, "repository": c.Repository, "ref": c.Ref, "sha": c.SHA,
		"event_name": c.EventName, "workflow_ref": c.WorkflowRef,
	}
	for name, value := range required {
		if value == "" {
			return Claims{}, oidcInvalid("token lacks claim "+name, nil)
		}
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return Claims{}, oidcInvalid("token lacks iat or exp", nil)
	}
	ids := []struct {
		name string
		raw  string
		dst  *int64
	}{
		{"repository_id", w.RepositoryID, &c.RepositoryID},
		{"repository_owner_id", w.RepositoryOwnerID, &c.RepositoryOwnerID},
		{"run_id", w.RunID, &c.RunID},
		{"run_attempt", w.RunAttempt, &c.RunAttempt},
	}
	for _, id := range ids {
		n, err := strconv.ParseInt(id.raw, 10, 64)
		if err != nil || n <= 0 {
			return Claims{}, oidcInvalid("token claim "+id.name+" is not a positive integer", nil)
		}
		*id.dst = n
	}
	return c, nil
}

// keyFor returns the signing key for kid, refreshing the key set once when
// the kid is unknown.
func (v *oidcVerifier) keyFor(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	if kid == "" {
		return jose.JSONWebKey{}, oidcInvalid("token has no kid", nil)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	if v.keys != nil && v.cfg.Clock.Now().Sub(v.refreshedAt) < jwksMinRefresh {
		return jose.JSONWebKey{}, oidcInvalid("token kid is unknown", nil)
	}
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return jose.JSONWebKey{}, smerr.Wrap(err, smerr.CodeProviderError, "", "fetch Actions signing keys")
	}
	v.keys, v.refreshedAt = keys, v.cfg.Clock.Now()
	key, ok := keys[kid]
	if !ok {
		return jose.JSONWebKey{}, oidcInvalid("token kid is unknown", nil)
	}
	return key, nil
}

func (v *oidcVerifier) fetchKeys(ctx context.Context) (map[string]jose.JSONWebKey, error) {
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, v.issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, err
	}
	if doc.Issuer != v.issuer {
		return nil, errors.New("discovery document names another issuer")
	}
	if !strings.HasPrefix(doc.JWKSURI, v.issuer+"/") {
		return nil, errors.New("jwks_uri is outside the issuer origin")
	}
	var set jose.JSONWebKeySet
	if err := v.getJSON(ctx, doc.JWKSURI, &set); err != nil {
		return nil, err
	}
	return signingKeys(set), nil
}

// signingKeys keeps the public RS256 signature keys that have a kid.
func signingKeys(set jose.JSONWebKeySet) map[string]jose.JSONWebKey {
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, k := range set.Keys {
		usable := k.IsPublic() && k.Valid() && k.KeyID != "" &&
			(k.Use == "" || k.Use == "sig") && (k.Algorithm == "" || k.Algorithm == string(jose.RS256))
		if usable {
			keys[k.KeyID] = k
		}
	}
	return keys
}

func (v *oidcVerifier) getJSON(ctx context.Context, rawURL string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := v.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcMaxDocBytes))
	if err != nil {
		return fmt.Errorf("read %s: %w", rawURL, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("decode %s: %w", rawURL, err)
	}
	return nil
}

// MatchClaims decides whether verified claims entitle the caller to deploy
// commit under policy p (spec §18). A fork or pull_request* token never
// matches, even if the policy lists the event.
func MatchClaims(c Claims, p CIPolicy, commit string, env EnvRequirement) error {
	checks := []struct {
		claim string
		ok    bool
	}{
		{"repository_id", c.RepositoryID == p.RepositoryID},
		{"repository_owner_id", c.RepositoryOwnerID == p.OwnerID},
		{"ref", c.Ref == "refs/heads/"+p.Branch},
		{"sha", commit != "" && c.SHA == commit},
		{"event_name", eventAllowed(c.EventName, p.AllowedEvents)},
		{"workflow_ref", p.DeployWorkflow != "" && c.WorkflowRef == c.Repository+"/"+p.DeployWorkflow+"@"+c.Ref},
		{"job_workflow_ref", jobWorkflowMatches(c, p)},
		{"run_id", c.RunID > 0},
		{"run_attempt", c.RunAttempt > 0},
		{"environment", !env.Required || c.Environment == env.Name},
	}
	for _, check := range checks {
		if !check.ok {
			return oidcInvalid("token claim "+check.claim+" does not match the CI policy", nil)
		}
	}
	return nil
}

func eventAllowed(event string, allowed []string) bool {
	return !strings.HasPrefix(event, "pull_request") && slices.Contains(allowed, event)
}

// jobWorkflowMatches: with a reusable deploy workflow the claim must name it;
// without one, the job must run in the calling workflow itself.
func jobWorkflowMatches(c Claims, p CIPolicy) bool {
	if p.DeployReusableWorkflow != "" {
		return c.JobWorkflowRef == p.DeployReusableWorkflow
	}
	return c.JobWorkflowRef == "" || c.JobWorkflowRef == c.WorkflowRef
}
