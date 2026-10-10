package oidc

import (
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	testRedirect = "http://127.0.0.1:5555/callback"
	testVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
)

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64(sum[:])
}

// codeLogin runs the browser-side of a login: Start, the IdP's authorize, and
// the CLI's Exchange.
func codeLogin(t *testing.T, cl *Client, p *idp) (Claims, error) {
	t.Helper()
	authURL, state, err := cl.Start(t.Context(), testRedirect, challengeOf(testVerifier))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	code, echoed := p.authorize(authURL)
	if echoed != state {
		t.Fatalf("state in the URL = %q, returned %q", echoed, state)
	}
	return cl.Exchange(t.Context(), code, state, testVerifier)
}

func wantReason(t *testing.T, err error, reason smerr.Reason) {
	t.Helper()
	var e *smerr.Error
	if !errors.As(err, &e) || e.Reason != reason {
		t.Fatalf("error = %v, want reason %s", err, reason)
	}
}

func TestCodeFlowReturnsVerifiedClaims(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)

	claims, err := codeLogin(t, cl, p)
	if err != nil {
		t.Fatal(err)
	}
	want := Claims{Issuer: issuerURL, Subject: "user-1", Email: "alice@example.com", EmailVerified: true, Name: "Alice"}
	if claims != want {
		t.Fatalf("claims = %+v, want %+v", claims, want)
	}
}

func TestStartBuildsAnAuthorizationURLWithPKCEStateAndNonce(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)

	authURL, state, err := cl.Start(t.Context(), testRedirect, challengeOf(testVerifier))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != issuerURL+"/auth" {
		t.Errorf("authorization URL = %s", authURL)
	}
	checks := map[string]string{
		"response_type": "code", "client_id": testClientID, "redirect_uri": testRedirect,
		"state": state, "code_challenge": challengeOf(testVerifier), "code_challenge_method": "S256",
	}
	for k, want := range checks {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("nonce")) < 16 || len(state) < 16 {
		t.Errorf("state %q and nonce %q must be unguessable", state, q.Get("nonce"))
	}
	for _, scope := range []string{"openid", "email", "profile"} {
		if !strings.Contains(q.Get("scope"), scope) {
			t.Errorf("scope %q lacks %s", q.Get("scope"), scope)
		}
	}
	if strings.Contains(authURL, testSecret) {
		t.Error("the client secret is in the authorization URL")
	}
}

func TestStartRefusesRedirectsOtherThanLoopbackCallback(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	for _, redirect := range []string{
		"https://127.0.0.1:5555/callback",
		"http://localhost:5555/callback",
		"http://[::1]:5555/callback",
		"http://10.0.0.1:5555/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:0/callback",
		"http://127.0.0.1:99999/callback",
		"http://127.0.0.1:5555/other",
		"http://127.0.0.1:5555/callback?x=1",
		"http://127.0.0.1:5555/callback#f",
		"http://user@127.0.0.1:5555/callback",
		"https://evil.example/callback",
		"",
	} {
		_, _, err := cl.Start(t.Context(), redirect, challengeOf(testVerifier))
		var e *smerr.Error
		if !errors.As(err, &e) || e.Code != smerr.CodeInvalidArgument {
			t.Errorf("redirect %q: err = %v, want INVALID_ARGUMENT", redirect, err)
		}
	}
}

func TestStartRefusesMalformedChallenges(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	for _, challenge := range []string{"", "short", testVerifier + "x", strings.Repeat("!", 43), strings.Repeat("a", 44)} {
		if _, _, err := cl.Start(t.Context(), testRedirect, challenge); err == nil {
			t.Errorf("challenge %q accepted", challenge)
		}
	}
}

func TestStateIsSingleUse(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	authURL, state, _ := cl.Start(t.Context(), testRedirect, challengeOf(testVerifier))
	code, _ := p.authorize(authURL)

	if _, err := cl.Exchange(t.Context(), code, state, testVerifier); err != nil {
		t.Fatal(err)
	}
	_, err := cl.Exchange(t.Context(), code, state, testVerifier)
	wantReason(t, err, smerr.ReasonOIDCInvalid)
}

func TestFailedExchangeStillConsumesState(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	authURL, state, _ := cl.Start(t.Context(), testRedirect, challengeOf(testVerifier))
	code, _ := p.authorize(authURL)

	if _, err := cl.Exchange(t.Context(), code, state, strings.Repeat("z", 43)); err == nil {
		t.Fatal("a verifier that does not match the challenge was accepted")
	}
	_, err := cl.Exchange(t.Context(), code, state, testVerifier)
	wantReason(t, err, smerr.ReasonOIDCInvalid)
}

func TestExchangeRefusesUnknownAndExpiredState(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	cl := newClient(t, p)

	_, err := cl.Exchange(t.Context(), "code", "never-issued", testVerifier)
	wantReason(t, err, smerr.ReasonOIDCInvalid)

	authURL, state, _ := cl.Start(t.Context(), testRedirect, challengeOf(testVerifier))
	code, _ := p.authorize(authURL)
	clock.advance(10*time.Minute + time.Second)
	_, err = cl.Exchange(t.Context(), code, state, testVerifier)
	wantReason(t, err, smerr.ReasonOIDCInvalid)
	if got := p.hitCount("/token"); got != 0 {
		t.Fatalf("the IdP was asked to redeem an expired login (%d calls)", got)
	}
}

func TestExchangeChecksTheVerifierBeforeCallingTheIdP(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	for _, verifier := range []string{"", "short", strings.Repeat("z", 43), testVerifier + "!"} {
		authURL, state, _ := cl.Start(t.Context(), testRedirect, challengeOf(testVerifier))
		code, _ := p.authorize(authURL)
		_, err := cl.Exchange(t.Context(), code, state, verifier)
		wantReason(t, err, smerr.ReasonOIDCInvalid)
	}
	if got := p.hitCount("/token"); got != 0 {
		t.Fatalf("token endpoint called %d times", got)
	}
}

func TestExchangeAuthenticatesWithBasicAndSendsTheVerifier(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	if _, err := codeLogin(t, cl, p); err != nil {
		t.Fatal(err)
	}
	form, auth := p.lastTokenRequest()
	if !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("Authorization = %q, want Basic", auth)
	}
	if form.Get("client_secret") != "" {
		t.Error("the client secret was also sent in the form")
	}
	if form.Get("code_verifier") != testVerifier || form.Get("redirect_uri") != testRedirect || form.Get("grant_type") != "authorization_code" {
		t.Errorf("token request = %v", form)
	}
}

func TestIdPRefusalIsOIDCInvalidAndMissingIDTokenIsToo(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)

	p.setTokenError(400, "invalid_grant")
	_, err := codeLogin(t, cl, p)
	wantReason(t, err, smerr.ReasonOIDCInvalid)

	p.setTokenError(0, "")
	p.setIDToken(func(string) string { return "" })
	_, err = codeLogin(t, cl, p)
	wantReason(t, err, smerr.ReasonOIDCInvalid)
}

func TestUnreachableIdPIsAProviderError(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	p.server.Close()
	authURL, state, _ := cl.Start(t.Context(), testRedirect, challengeOf(testVerifier))
	code, _ := p.authorize(authURL)

	_, err := cl.Exchange(t.Context(), code, state, testVerifier)
	var e *smerr.Error
	if !errors.As(err, &e) || e.Code != smerr.CodeProviderError {
		t.Fatalf("error = %v, want PROVIDER_ERROR", err)
	}
}
