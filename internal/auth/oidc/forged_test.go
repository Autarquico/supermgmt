package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// with returns the valid claims with the given overrides; a nil value deletes
// the claim.
func (p *idp) with(nonce string, overrides map[string]any) map[string]any {
	claims := p.validClaims(nonce)
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	return claims
}

func TestForgedIDTokensAreRefused(t *testing.T) {
	clock := newClock()
	now := clock.Now()
	p := newIdP(t, clock)
	signed := func(over map[string]any) func(string) string {
		return func(nonce string) string { return p.sign("RS256", "rsa1", p.with(nonce, over)) }
	}
	tests := []struct {
		name string
		mint func(nonce string) string
	}{
		{"alg none", func(n string) string { return p.sign("none", "rsa1", p.with(n, nil)) }},
		{"alg none without kid", func(n string) string { return p.sign("none", "", p.with(n, nil)) }},
		{"HS256 signed with the public key (alg confusion)", func(n string) string { return p.sign("HS256", "rsa1", p.with(n, nil)) }},
		{"RS384, an algorithm outside the allowlist", func(n string) string {
			return p.signRaw(map[string]any{"alg": "RS384", "kid": "rsa1"}, p.with(n, nil), "RS256")
		}},
		{"header says ES256 but an RSA key signed", func(n string) string {
			return p.signRaw(map[string]any{"alg": "ES256", "kid": "ec1"}, p.with(n, nil), "RS256")
		}},
		{"unknown kid", func(n string) string { return p.sign("RS256", "nope", p.with(n, nil)) }},
		{"published kid, attacker key", func(n string) string { return attackerToken(t, "rsa1", p.with(n, nil)) }},
		{"payload swapped after signing", func(n string) string {
			good := strings.Split(p.sign("RS256", "rsa1", p.with(n, nil)), ".")
			evil := encodeJSON(p.with(n, map[string]any{"email": "root@example.com"}))
			return good[0] + "." + evil + "." + good[2]
		}},
		{"not a JWT", func(string) string { return "garbage" }},
		{"wrong issuer", signed(map[string]any{"iss": "https://10.0.0.6"})},
		{"issuer with trailing slash", signed(map[string]any{"iss": issuerURL + "/"})},
		{"wrong audience", signed(map[string]any{"aud": "someone-else"})},
		{"several audiences without azp", signed(map[string]any{"aud": []string{testClientID, "other"}})},
		{"azp is another client", signed(map[string]any{"aud": []string{testClientID, "other"}, "azp": "other"})},
		{"azp present but not this client", signed(map[string]any{"azp": "other"})},
		{"wrong nonce", signed(map[string]any{"nonce": "replayed-from-elsewhere"})},
		{"missing nonce", signed(map[string]any{"nonce": nil})},
		{"expired beyond the skew", signed(map[string]any{"exp": now.Add(-61 * time.Second).Unix()})},
		{"no exp", signed(map[string]any{"exp": nil})},
		{"issued in the future beyond the skew", signed(map[string]any{"iat": now.Add(61 * time.Second).Unix()})},
		{"no iat", signed(map[string]any{"iat": nil})},
		{"not yet valid", signed(map[string]any{"nbf": now.Add(10 * time.Minute).Unix()})},
		{"no subject", signed(map[string]any{"sub": nil})},
		{"email not verified", signed(map[string]any{"email_verified": false})},
		{"email_verified missing", signed(map[string]any{"email_verified": nil})},
		{"email_verified as a string", signed(map[string]any{"email_verified": "true"})},
		{"no email", signed(map[string]any{"email": nil})},
		{"domain not allowed", signed(map[string]any{"email": "mallory@evil.example"})},
		{"suffix trick", signed(map[string]any{"email": "mallory@notexample.com"})},
		{"two at-signs", signed(map[string]any{"email": "mallory@evil.example@example.com"})},
		{"empty local part", signed(map[string]any{"email": "@example.com"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p.setIDToken(tt.mint)
			cl := newClient(t, p)
			claims, err := codeLogin(t, cl, p)
			if err == nil {
				t.Fatalf("forged token accepted: %+v", claims)
			}
			wantReason(t, err, smerr.ReasonOIDCInvalid)
		})
	}
}

func TestGenuineIDTokensAreAccepted(t *testing.T) {
	clock := newClock()
	now := clock.Now()
	p := newIdP(t, clock)
	tests := []struct {
		name string
		mint func(nonce string) string
	}{
		{"RS256", func(n string) string { return p.sign("RS256", "rsa1", p.with(n, nil)) }},
		{"ES256", func(n string) string { return p.sign("ES256", "ec1", p.with(n, nil)) }},
		{"EdDSA", func(n string) string { return p.sign("EdDSA", "ed1", p.with(n, nil)) }},
		{"expired within the skew", func(n string) string {
			return p.sign("RS256", "rsa1", p.with(n, map[string]any{"exp": now.Add(-59 * time.Second).Unix()}))
		}},
		{"issued within the skew", func(n string) string {
			return p.sign("RS256", "rsa1", p.with(n, map[string]any{"iat": now.Add(59 * time.Second).Unix()}))
		}},
		{"audience list with matching azp", func(n string) string {
			return p.sign("RS256", "rsa1", p.with(n, map[string]any{"aud": []string{testClientID, "other"}, "azp": testClientID}))
		}},
		{"domain in another case", func(n string) string {
			return p.sign("RS256", "rsa1", p.with(n, map[string]any{"email": "Bob@EXAMPLE.com"}))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p.setIDToken(tt.mint)
			cl := newClient(t, p)
			if _, err := codeLogin(t, cl, p); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEmptyAllowedDomainsStillRequireAVerifiedEmail(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p, func(c *Config) { c.AllowedDomains = nil })
	p.setIDToken(func(n string) string {
		return p.sign("RS256", "rsa1", p.with(n, map[string]any{"email": "anyone@anywhere.example"}))
	})
	if _, err := codeLogin(t, cl, p); err != nil {
		t.Fatalf("any verified email is accepted when allowed_domains is empty: %v", err)
	}
	p.setIDToken(func(n string) string {
		return p.sign("RS256", "rsa1", p.with(n, map[string]any{"email_verified": false}))
	})
	_, err := codeLogin(t, cl, p)
	wantReason(t, err, smerr.ReasonOIDCInvalid)
}

func TestReplayedJTIIsRefused(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	p.setIDToken(func(n string) string { return p.sign("RS256", "rsa1", p.with(n, map[string]any{"jti": "token-1"})) })

	if _, err := codeLogin(t, cl, p); err != nil {
		t.Fatal(err)
	}
	_, err := codeLogin(t, cl, p)
	wantReason(t, err, smerr.ReasonOIDCReplay)

	p.setIDToken(func(n string) string { return p.sign("RS256", "rsa1", p.with(n, map[string]any{"jti": "token-2"})) })
	if _, err := codeLogin(t, cl, p); err != nil {
		t.Fatalf("a different jti is fresh: %v", err)
	}
}

func TestJTIsAreScopedToTheIssuerAndExpire(t *testing.T) {
	clock := newClock()
	store := newMemoryReplay(clock)
	ctx := context.Background()
	exp := clock.Now().Add(time.Hour)

	for _, tc := range []struct {
		issuer, jti string
		fresh       bool
	}{
		{"a", "1", true}, {"a", "1", false}, {"b", "1", true}, {"a", "2", true},
	} {
		if fresh, _ := store.Remember(ctx, tc.issuer, tc.jti, exp); fresh != tc.fresh {
			t.Errorf("Remember(%s, %s) = %v, want %v", tc.issuer, tc.jti, fresh, tc.fresh)
		}
	}
	clock.advance(2 * time.Hour)
	if fresh, _ := store.Remember(ctx, "a", "1", clock.Now().Add(time.Hour)); !fresh {
		t.Error("an expired jti is swept and may be recorded again")
	}
}

type brokenReplay struct{}

func (brokenReplay) Remember(context.Context, string, string, time.Time) (bool, error) {
	return false, errors.New("disk full")
}

func TestReplayStoreFailureRefusesTheLogin(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p, func(c *Config) { c.Replay = brokenReplay{} })
	p.setIDToken(func(n string) string { return p.sign("RS256", "rsa1", p.with(n, map[string]any{"jti": "x"})) })

	_, err := codeLogin(t, cl, p)
	var e *smerr.Error
	if !errors.As(err, &e) || e.Code != smerr.CodeInternal {
		t.Fatalf("error = %v, want INTERNAL (fail closed)", err)
	}
}

func TestInvalidTokenDoesNotSpendItsJTI(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	p.setIDToken(func(n string) string {
		return p.sign("RS256", "rsa1", p.with(n, map[string]any{"jti": "j", "aud": "other"}))
	})
	if _, err := codeLogin(t, cl, p); err == nil {
		t.Fatal("wrong audience accepted")
	}
	p.setIDToken(func(n string) string { return p.sign("RS256", "rsa1", p.with(n, map[string]any{"jti": "j"})) })
	if _, err := codeLogin(t, cl, p); err != nil {
		t.Fatalf("a rejected token must not burn its jti: %v", err)
	}
}
