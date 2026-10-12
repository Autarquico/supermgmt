package github

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

const (
	oidcAudience = "https://sm.example"
	oidcCommit   = "cccccccccccccccccccccccccccccccccccccccc"
)

var oidcNow = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

type oidcMemoryReplay struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (r *oidcMemoryReplay) Remember(_ context.Context, issuer, jti string, _ time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return false, r.err
	}
	key := issuer + "|" + jti
	if r.seen[key] {
		return false, nil
	}
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	r.seen[key] = true
	return true, nil
}

type oidcWorld struct {
	issuer *ghfake.OIDCIssuer
	clock  *domaintest.FakeClock
	replay *oidcMemoryReplay
	v      *oidcVerifier
	jtis   int
}

func newOIDCWorld(t *testing.T) *oidcWorld {
	t.Helper()
	w := &oidcWorld{
		issuer: ghfake.NewOIDCIssuer(t), clock: domaintest.NewFakeClock(oidcNow), replay: &oidcMemoryReplay{},
	}
	v, err := newOIDCVerifier(w.issuer.Issuer(),
		OIDCConfig{Audience: oidcAudience, Clock: w.clock, Replay: w.replay, Timeout: testTimeout},
		netguard.WithTestDialer(w.issuer.Dial), netguard.WithRootCAs(oidcPool(t, w.issuer.CAPEM())))
	if err != nil {
		t.Fatal(err)
	}
	w.v = v
	return w
}

// claims is a valid token payload for the issuer, adjusted by edit.
func (w *oidcWorld) claims(edit func(map[string]any)) map[string]any {
	w.jtis++
	c := map[string]any{
		"iss": w.issuer.Issuer(), "aud": oidcAudience, "sub": "repo:acme/shop:ref:refs/heads/main",
		"jti": fmt.Sprintf("jti-%d", w.jtis),
		"iat": oidcNow.Unix(), "nbf": oidcNow.Unix(), "exp": oidcNow.Add(5 * time.Minute).Unix(),
		"repository_id": "123", "repository_owner_id": "987", "repository": "acme/shop",
		"ref": "refs/heads/main", "sha": oidcCommit, "event_name": "push",
		"workflow_ref": "acme/shop/.github/workflows/ci.yml@refs/heads/main",
		"run_id":       "555", "run_attempt": "2",
	}
	if edit != nil {
		edit(c)
	}
	return c
}

func (w *oidcWorld) token(edit func(map[string]any)) string { return w.issuer.Sign(w.claims(edit)) }

func wantOIDCError(t *testing.T, err error, code smerr.Code, reason smerr.Reason) {
	t.Helper()
	var e *smerr.Error
	if !errors.As(err, &e) || e.Code != code || e.Reason != reason {
		t.Fatalf("error = %v, want %s/%s", err, code, reason)
	}
}

func TestOIDC_VerifyReturnsTheClaims(t *testing.T) {
	w := newOIDCWorld(t)
	got, err := w.v.Verify(context.Background(), w.token(func(c map[string]any) {
		c["environment"] = "production"
		c["job_workflow_ref"] = "acme/shop/.github/workflows/ci.yml@refs/heads/main"
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Claims{
		Issuer: w.issuer.Issuer(), Subject: "repo:acme/shop:ref:refs/heads/main", Audience: []string{oidcAudience},
		JTI: "jti-1", IssuedAt: oidcNow, ExpiresAt: oidcNow.Add(5 * time.Minute),
		RepositoryID: 123, RepositoryOwnerID: 987, Repository: "acme/shop", Ref: "refs/heads/main",
		SHA: oidcCommit, EventName: "push",
		WorkflowRef:    "acme/shop/.github/workflows/ci.yml@refs/heads/main",
		JobWorkflowRef: "acme/shop/.github/workflows/ci.yml@refs/heads/main",
		Environment:    "production", RunID: 555, RunAttempt: 2,
	}
	if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", want) {
		t.Errorf("claims = %+v\nwant     %+v", got, want)
	}
}

func TestOIDC_RejectedTokens(t *testing.T) {
	w := newOIDCWorld(t)
	tests := []struct {
		name  string
		token func() string
	}{
		{"wrong audience", func() string { return w.token(func(c map[string]any) { c["aud"] = "https://other.example" }) }},
		{"wrong issuer", func() string {
			return w.token(func(c map[string]any) { c["iss"] = "https://token.actions.example" })
		}},
		{"expired", func() string {
			return w.token(func(c map[string]any) { c["exp"] = oidcNow.Add(-time.Second).Unix() })
		}},
		{"expiring now", func() string { return w.token(func(c map[string]any) { c["exp"] = oidcNow.Unix() }) }},
		{"issued more than 5m ago", func() string {
			return w.token(func(c map[string]any) { c["iat"] = oidcNow.Add(-5*time.Minute - time.Second).Unix() })
		}},
		{"issued beyond the skew", func() string {
			return w.token(func(c map[string]any) { c["iat"] = oidcNow.Add(61 * time.Second).Unix() })
		}},
		{"no jti", func() string { return w.token(func(c map[string]any) { delete(c, "jti") }) }},
		{"no workflow_ref", func() string { return w.token(func(c map[string]any) { delete(c, "workflow_ref") }) }},
		{"no exp", func() string { return w.token(func(c map[string]any) { delete(c, "exp") }) }},
		{"repository_id not numeric", func() string {
			return w.token(func(c map[string]any) { c["repository_id"] = "abc" })
		}},
		{"run_attempt zero", func() string { return w.token(func(c map[string]any) { c["run_attempt"] = "0" }) }},
		{"unpublished key", func() string { return w.issuer.SignUnpublished(w.claims(nil)) }},
		{"alg none", func() string { return ghfake.UnsignedToken(w.claims(nil)) }},
		{"HS256 keyed with a public value", func() string { return oidcHS256(t, w.claims(nil)) }},
		{"not a token", func() string { return "not.a.jwt" }},
		{"oversize", func() string { return string(make([]byte, oidcMaxTokenBytes+1)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := w.v.Verify(context.Background(), tt.token())
			wantOIDCError(t, err, smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid)
		})
	}
}

func TestOIDC_TamperedPayloadIsRejected(t *testing.T) {
	w := newOIDCWorld(t)
	good := w.token(nil)
	other := w.token(func(c map[string]any) { c["repository_id"] = "999" })
	forged := splitJWT(good)[0] + "." + splitJWT(other)[1] + "." + splitJWT(good)[2]

	_, err := w.v.Verify(context.Background(), forged)
	wantOIDCError(t, err, smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid)
}

func TestOIDC_SkewIsTolerated(t *testing.T) {
	w := newOIDCWorld(t)
	for name, iat := range map[string]time.Time{
		"60s ahead":       oidcNow.Add(60 * time.Second),
		"exactly 5m ago":  oidcNow.Add(-5 * time.Minute),
		"just under 5m":   oidcNow.Add(-5*time.Minute + time.Second),
		"issued this sec": oidcNow,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := w.v.Verify(context.Background(), w.token(func(c map[string]any) { c["iat"] = iat.Unix() })); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOIDC_ReplayIsRefused(t *testing.T) {
	w := newOIDCWorld(t)
	token := w.token(nil)

	if _, err := w.v.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	_, err := w.v.Verify(context.Background(), token)
	wantOIDCError(t, err, smerr.CodeUnauthenticated, smerr.ReasonOIDCReplay)
}

func TestOIDC_ReplayIsNotRecordedForAnInvalidToken(t *testing.T) {
	w := newOIDCWorld(t)
	bad := w.token(func(c map[string]any) { c["aud"] = "https://other.example" })

	if _, err := w.v.Verify(context.Background(), bad); err == nil {
		t.Fatal("token for another audience accepted")
	}
	if len(w.replay.seen) != 0 {
		t.Errorf("jti recorded for a rejected token: %v", w.replay.seen)
	}
}

func TestOIDC_ReplayStoreFailureFailsClosed(t *testing.T) {
	w := newOIDCWorld(t)
	w.replay.err = errors.New("disk full")

	_, err := w.v.Verify(context.Background(), w.token(nil))
	wantOIDCError(t, err, smerr.CodeInternal, "")
}

func TestOIDC_KeysAreCachedAndRefreshedOnUnknownKid(t *testing.T) {
	w := newOIDCWorld(t)
	ctx := context.Background()

	for range 3 {
		if _, err := w.v.Verify(ctx, w.token(nil)); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.issuer.JWKSFetches(); got != 1 {
		t.Fatalf("JWKS fetched %d times for 3 tokens, want 1 (cached)", got)
	}

	w.issuer.Rotate()
	w.clock.Advance(jwksMinRefresh)
	if _, err := w.v.Verify(ctx, w.token(nil)); err != nil {
		t.Fatalf("token from a rotated key: %v", err)
	}
	if got := w.issuer.JWKSFetches(); got != 2 {
		t.Errorf("JWKS fetched %d times after rotation, want 2", got)
	}
}

func TestOIDC_UnknownKidsCannotForceRefetchStorms(t *testing.T) {
	w := newOIDCWorld(t)
	ctx := context.Background()
	if _, err := w.v.Verify(ctx, w.token(nil)); err != nil {
		t.Fatal(err)
	}

	for range 5 {
		_, err := w.v.Verify(ctx, w.issuer.SignUnpublished(w.claims(nil)))
		wantOIDCError(t, err, smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid)
	}
	if got := w.issuer.JWKSFetches(); got != 1 {
		t.Errorf("JWKS fetched %d times, want 1: unknown kids must be throttled", got)
	}
}

func TestOIDC_RetiredKeyStopsVerifyingAfterRefresh(t *testing.T) {
	w := newOIDCWorld(t)
	ctx := context.Background()
	if _, err := w.v.Verify(ctx, w.token(nil)); err != nil {
		t.Fatal(err)
	}
	signedByOldKey := w.token(nil)

	w.issuer.Rotate()
	w.issuer.Retire(oidcKid(t, signedByOldKey))
	w.clock.Advance(jwksMinRefresh)
	if _, err := w.v.Verify(ctx, w.token(nil)); err != nil {
		t.Fatal(err)
	}

	_, err := w.v.Verify(ctx, signedByOldKey)
	wantOIDCError(t, err, smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid)
}

func TestOIDC_JWKSOutsideTheIssuerIsRefused(t *testing.T) {
	w := newOIDCWorld(t)
	w.issuer.SetJWKSURI("https://evil.example/keys")

	_, err := w.v.Verify(context.Background(), w.token(nil))
	wantOIDCError(t, err, smerr.CodeProviderError, "")
}

func TestOIDC_UnreachableIssuerIsAProviderError(t *testing.T) {
	w := newOIDCWorld(t)
	v, err := newOIDCVerifier(w.issuer.Issuer(),
		OIDCConfig{Audience: oidcAudience, Clock: w.clock, Replay: w.replay, Timeout: testTimeout},
		netguard.WithTestDialer(func(string, string) (net.Conn, error) { return nil, errors.New("refused") }),
		netguard.WithRootCAs(oidcPool(t, w.issuer.CAPEM())))
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Verify(context.Background(), w.token(nil))
	wantOIDCError(t, err, smerr.CodeProviderError, "")
}

func TestOIDC_ConfigurationIsValidated(t *testing.T) {
	ok := OIDCConfig{Audience: oidcAudience, Clock: domaintest.NewFakeClock(oidcNow), Replay: &oidcMemoryReplay{}}
	tests := []struct {
		name   string
		cfg    func(OIDCConfig) OIDCConfig
		issuer string
	}{
		{"empty audience", func(c OIDCConfig) OIDCConfig { c.Audience = ""; return c }, ActionsIssuer},
		{"no clock", func(c OIDCConfig) OIDCConfig { c.Clock = nil; return c }, ActionsIssuer},
		{"no replay store", func(c OIDCConfig) OIDCConfig { c.Replay = nil; return c }, ActionsIssuer},
		{"http issuer", func(c OIDCConfig) OIDCConfig { return c }, "http://token.actions.githubusercontent.com"},
		{"issuer with a path", func(c OIDCConfig) OIDCConfig { return c }, ActionsIssuer + "/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newOIDCVerifier(tt.issuer, tt.cfg(ok)); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func oidcPolicy() CIPolicy {
	return CIPolicy{
		RepositoryID: 123, OwnerID: 987, Branch: "main", AllowedEvents: []string{"push"},
		DeployWorkflow: ".github/workflows/ci.yml",
	}
}

func oidcMatchable() Claims {
	return Claims{
		RepositoryID: 123, RepositoryOwnerID: 987, Repository: "acme/shop", Ref: "refs/heads/main",
		SHA: oidcCommit, EventName: "push", RunID: 555, RunAttempt: 1,
		WorkflowRef: "acme/shop/.github/workflows/ci.yml@refs/heads/main",
	}
}

func TestMatchClaims(t *testing.T) {
	const reusable = "acme/ci/.github/workflows/deploy.yml@refs/heads/main"
	tests := []struct {
		name   string
		edit   func(*Claims, *CIPolicy, *EnvRequirement)
		commit string
		want   string // claim named by the error; "" = accepted
	}{
		{name: "matching push"},
		{name: "wrong repository id", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.RepositoryID = 124 }, want: "repository_id"},
		{name: "wrong owner id", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.RepositoryOwnerID = 1 }, want: "repository_owner_id"},
		{name: "fork with another repository id", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) {
			c.RepositoryID, c.Repository = 777, "mallory/shop"
		}, want: "repository_id"},
		{name: "other branch", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.Ref = "refs/heads/dev" }, want: "ref"},
		{name: "tag ref", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.Ref = "refs/tags/main" }, want: "ref"},
		{name: "pull request ref", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.Ref = "refs/pull/1/merge" }, want: "ref"},
		{name: "other commit", commit: "dddddddddddddddddddddddddddddddddddddddd", want: "sha"},
		{name: "event not allowed", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.EventName = "workflow_dispatch" }, want: "event_name"},
		{name: "pull_request even if the policy allows it", edit: func(c *Claims, p *CIPolicy, _ *EnvRequirement) {
			c.EventName, p.AllowedEvents = "pull_request", []string{"push", "pull_request"}
		}, want: "event_name"},
		{name: "pull_request_target even if the policy allows it", edit: func(c *Claims, p *CIPolicy, _ *EnvRequirement) {
			c.EventName, p.AllowedEvents = "pull_request_target", []string{"pull_request_target"}
		}, want: "event_name"},
		{name: "wrong workflow", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) {
			c.WorkflowRef = "acme/shop/.github/workflows/evil.yml@refs/heads/main"
		}, want: "workflow_ref"},
		{name: "workflow of another repository", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) {
			c.WorkflowRef = "acme/other/.github/workflows/ci.yml@refs/heads/main"
		}, want: "workflow_ref"},
		{name: "workflow at another ref", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) {
			c.WorkflowRef = "acme/shop/.github/workflows/ci.yml@refs/heads/dev"
		}, want: "workflow_ref"},
		{name: "policy without a deploy workflow", edit: func(c *Claims, p *CIPolicy, _ *EnvRequirement) {
			p.DeployWorkflow, c.WorkflowRef = "", "acme/shop/@refs/heads/main"
		}, want: "workflow_ref"},
		{name: "job_workflow_ref equal to workflow_ref", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) {
			c.JobWorkflowRef = c.WorkflowRef
		}},
		{name: "job inside a reusable workflow when none is configured", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) {
			c.JobWorkflowRef = reusable
		}, want: "job_workflow_ref"},
		{name: "reusable workflow configured and used", edit: func(c *Claims, p *CIPolicy, _ *EnvRequirement) {
			p.DeployReusableWorkflow, c.JobWorkflowRef = reusable, reusable
		}},
		{name: "reusable workflow configured but claim absent", edit: func(_ *Claims, p *CIPolicy, _ *EnvRequirement) {
			p.DeployReusableWorkflow = reusable
		}, want: "job_workflow_ref"},
		{name: "reusable workflow configured but another used", edit: func(c *Claims, p *CIPolicy, _ *EnvRequirement) {
			p.DeployReusableWorkflow, c.JobWorkflowRef = reusable, "acme/ci/.github/workflows/other.yml@refs/heads/main"
		}, want: "job_workflow_ref"},
		{name: "reusable workflow configured, claim is the caller", edit: func(c *Claims, p *CIPolicy, _ *EnvRequirement) {
			p.DeployReusableWorkflow, c.JobWorkflowRef = reusable, c.WorkflowRef
		}, want: "job_workflow_ref"},
		{name: "no run id", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.RunID = 0 }, want: "run_id"},
		{name: "no run attempt", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.RunAttempt = 0 }, want: "run_attempt"},
		{name: "environment required and matching", edit: func(c *Claims, _ *CIPolicy, e *EnvRequirement) {
			c.Environment, *e = "production", EnvRequirement{Required: true, Name: "production"}
		}},
		{name: "environment required and absent", edit: func(_ *Claims, _ *CIPolicy, e *EnvRequirement) {
			*e = EnvRequirement{Required: true, Name: "production"}
		}, want: "environment"},
		{name: "environment required and different", edit: func(c *Claims, _ *CIPolicy, e *EnvRequirement) {
			c.Environment, *e = "staging", EnvRequirement{Required: true, Name: "production"}
		}, want: "environment"},
		{name: "environment not required is ignored", edit: func(c *Claims, _ *CIPolicy, _ *EnvRequirement) { c.Environment = "anything" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, p, env := oidcMatchable(), oidcPolicy(), EnvRequirement{}
			if tt.edit != nil {
				tt.edit(&c, &p, &env)
			}
			commit := tt.commit
			if commit == "" {
				commit = oidcCommit
			}
			err := MatchClaims(c, p, commit, env)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("MatchClaims = %v, want accepted", err)
				}
				return
			}
			wantOIDCError(t, err, smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid)
			if !strings.Contains(err.Error(), "claim "+tt.want+" ") {
				t.Errorf("error %q does not name claim %s", err, tt.want)
			}
		})
	}
}

func TestMatchClaims_EmptyCommitNeverMatches(t *testing.T) {
	c := oidcMatchable()
	c.SHA = ""
	if err := MatchClaims(c, oidcPolicy(), "", EnvRequirement{}); err == nil {
		t.Fatal("an empty commit matched an empty sha claim")
	}
}

func splitJWT(token string) []string { return strings.Split(token, ".") }

func oidcPool(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no certificate in CA PEM")
	}
	return pool
}

func oidcHS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "any"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func oidcKid(t *testing.T, token string) string {
	t.Helper()
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Headers[0].KeyID
}
