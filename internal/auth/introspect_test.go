package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	introspectClientID = "sm-introspector"
	introspectSecret   = "s3cret/with+odd:chars"
)

// oauthIntrospectRig is the JWT rig with its resolver swapped for one that
// validates opaque tokens by introspection only.
type oauthIntrospectRig struct {
	*oauthJWTRig
	introspection *oauthfake.Introspection
}

func newOAuthIntrospectRig(t *testing.T, secret string) *oauthIntrospectRig {
	t.Helper()
	r := &oauthIntrospectRig{oauthJWTRig: newOAuthJWTRig(t)}
	r.introspection = r.fake.EnableIntrospection(introspectClientID, introspectSecret)
	var err error
	r.resolver, err = auth.NewOAuthResolver(context.Background(), auth.OAuthConfig{
		Issuer: r.fake.Issuer, Resource: r.fake.Resource, IntrospectionURL: r.fake.IntrospectionURL(),
		ClientID: introspectClientID, ClientSecret: audit.Secret(secret),
		RequiredScopes: []string{oauthJWTRequiredScope}, HTTP: r.fake.Client(), Clock: r.clock,
	}, r.db)
	must(t, err, "NewOAuthResolver")
	return r
}

// opaque registers an opaque bearer with the fake and returns it.
func (r *oauthIntrospectRig) opaque(bearer string, mutate func(map[string]any)) string {
	response := r.fake.ActiveResponse(r.clock.Now())
	if mutate != nil {
		mutate(response)
	}
	r.introspection.Answer(bearer, response)
	return bearer
}

func TestOAuthIntrospect_ClaimAndResponseRules(t *testing.T) {
	r := newOAuthIntrospectRig(t, introspectSecret)
	secs := func(d time.Duration) int64 { return r.clock.Now().Add(d).Unix() }

	accepted := smerr.Code("")
	const (
		unauthenticated = smerr.CodeUnauthenticated
		forbidden       = smerr.CodePolicyDenied
		bad             = smerr.ReasonOAuthTokenInvalid
	)

	cases := []struct {
		name   string
		mutate func(map[string]any)
		code   smerr.Code
		reason smerr.Reason
	}{
		{"valid", nil, accepted, ""},
		{"token_type access_token", func(m map[string]any) { m["token_type"] = "access_token" }, accepted, ""},
		{"token_type absent", func(m map[string]any) { delete(m, "token_type") }, accepted, ""},
		{"scope as scp array", func(m map[string]any) {
			delete(m, "scope")
			m["scp"] = []string{oauthJWTRequiredScope}
		}, accepted, ""},

		{"inactive", func(m map[string]any) { m["active"] = false }, unauthenticated, bad},
		{"active absent", func(m map[string]any) { delete(m, "active") }, unauthenticated, bad},
		{"active as a string", func(m map[string]any) { m["active"] = "true" }, unauthenticated, bad},
		{"token_type mismatch", func(m map[string]any) { m["token_type"] = "refresh_token" }, unauthenticated, bad},
		{"missing iat", func(m map[string]any) { delete(m, "iat") }, unauthenticated, bad},
		{"iat before the client existed", func(m map[string]any) { m["iat"] = secs(-61 * time.Second) }, unauthenticated, bad},
		{"wrong issuer", func(m map[string]any) { m["iss"] = "https://evil.test" }, unauthenticated, bad},
		{"no issuer", func(m map[string]any) { delete(m, "iss") }, unauthenticated, bad},
		{"audience without the resource", func(m map[string]any) { m["aud"] = []string{"https://other.test"} }, unauthenticated, bad},
		{"expired beyond skew", func(m map[string]any) { m["exp"] = secs(-61 * time.Second) }, unauthenticated, bad},
		{"no exp", func(m map[string]any) { delete(m, "exp") }, unauthenticated, bad},
		{"missing client_id", func(m map[string]any) { delete(m, "client_id") }, unauthenticated, bad},
		{"azp different from client_id", func(m map[string]any) { m["azp"] = "someone-else" }, unauthenticated, bad},

		{"missing required scope", func(m map[string]any) { m["scope"] = "other" }, forbidden, smerr.ReasonScopeDenied},
		{"unregistered subject", func(m map[string]any) { m["sub"] = "stranger" }, forbidden, smerr.ReasonMCPClientUnregistered},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bearer := r.opaque("opaque-"+string(rune('a'+i)), c.mutate)
			err := r.resolve(bearer)
			if c.code == accepted {
				must(t, err, "Resolve")
				return
			}
			r.wantRefused(err, c.code, c.reason)
		})
	}
}

func TestOAuthIntrospect_UnknownTokenIsInactive(t *testing.T) {
	r := newOAuthIntrospectRig(t, introspectSecret)

	r.wantRefused(r.resolve("never-issued"), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)
}

func TestOAuthIntrospect_WithoutClientAuthenticationTheServerRefusesAndSoDoWe(t *testing.T) {
	r := newOAuthIntrospectRig(t, "wrong-secret")
	bearer := r.opaque("opaque-token", nil)

	r.wantRefused(r.resolve(bearer), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)

	if r.fake.IntrospectionCalls() != 1 {
		t.Errorf("introspection calls = %d, want 1", r.fake.IntrospectionCalls())
	}
}

func TestOAuthIntrospect_NothingIsCachedAcrossRequests(t *testing.T) {
	r := newOAuthIntrospectRig(t, introspectSecret)
	bearer := r.opaque("opaque-token", nil)

	must(t, r.resolve(bearer), "first")
	must(t, r.resolve(bearer), "second")
	if got := r.fake.IntrospectionCalls(); got != 2 {
		t.Fatalf("introspection calls = %d, want 2", got)
	}

	r.introspection.Answer(bearer, map[string]any{"active": false})
	r.wantRefused(r.resolve(bearer), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)
}

func TestOAuthIntrospect_AJWTShapedBearerWithoutJWKSIsIntrospected(t *testing.T) {
	r := newOAuthIntrospectRig(t, introspectSecret)
	bearer := r.opaque("aaa.bbb.ccc", nil)

	must(t, r.resolve(bearer), "Resolve")
	if r.fake.IntrospectionCalls() != 1 {
		t.Errorf("introspection calls = %d, want 1", r.fake.IntrospectionCalls())
	}
}

func TestOAuthIntrospect_RevokedTokenCostsNoIntrospectionCall(t *testing.T) {
	r := newOAuthIntrospectRig(t, introspectSecret)
	bearer := r.opaque("opaque-token", nil)
	must(t, r.resolve(bearer), "first use")
	r.revokeClientTokens()
	before := r.fake.IntrospectionCalls()

	r.wantRefused(r.resolve(bearer), smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)

	if got := r.fake.IntrospectionCalls() - before; got != 0 {
		t.Errorf("a revoked token cost %d introspection calls, want 0", got)
	}
}

func TestNewOAuthResolverIntrospectionNeedsClientCredentials(t *testing.T) {
	w := newWorld(t)
	fake := oauthfake.New()
	t.Cleanup(fake.Close)
	base := auth.OAuthConfig{Issuer: "i", Resource: "r", IntrospectionURL: fake.IntrospectionURL(), HTTP: fake.Client()}
	for name, cfg := range map[string]auth.OAuthConfig{
		"no client id": func() auth.OAuthConfig { c := base; c.ClientSecret = "s"; return c }(),
		"no secret":    func() auth.OAuthConfig { c := base; c.ClientID = "id"; return c }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := auth.NewOAuthResolver(context.Background(), cfg, w.db); err == nil {
				t.Error("want an error")
			}
		})
	}
}
