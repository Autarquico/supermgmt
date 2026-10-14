package oauthfake_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
)

var fakeNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type publishedKey struct {
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func get(t *testing.T, s *oauthfake.Server, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func fetchKeys(t *testing.T, s *oauthfake.Server) map[string]*rsa.PublicKey {
	t.Helper()
	resp := get(t, s, s.JWKSURL())
	var doc struct {
		Keys []publishedKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		n, _ := base64.RawURLEncoding.DecodeString(k.N)
		e, _ := base64.RawURLEncoding.DecodeString(k.E)
		keys[k.KID] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return keys
}

func segments(t *testing.T, token string) (header, claims map[string]any, input string, sig []byte) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	decode := func(s string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	sig, _ = base64.RawURLEncoding.DecodeString(parts[2])
	return decode(parts[0]), decode(parts[1]), parts[0] + "." + parts[1], sig
}

func verifyRS256(key *rsa.PublicKey, input string, sig []byte) error {
	digest := sha256.Sum256([]byte(input))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig)
}

func newFake(t *testing.T) *oauthfake.Server {
	t.Helper()
	s := oauthfake.New()
	t.Cleanup(s.Close)
	return s
}

func TestAccessTokenIsAnRFC9068JWTSignedByAPublishedKey(t *testing.T) {
	s := newFake(t)
	header, claims, input, sig := segments(t, s.Sign(s.AccessToken(fakeNow)))

	if header["typ"] != "at+jwt" || header["alg"] != "RS256" {
		t.Errorf("header = %v", header)
	}
	for _, name := range []string{"iss", "sub", "aud", "client_id", "scope", "jti", "iat", "exp"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("claim %q missing", name)
		}
	}
	key := fetchKeys(t, s)[header["kid"].(string)]
	if key == nil || verifyRS256(key, input, sig) != nil {
		t.Error("signature does not verify against the published key")
	}
}

func TestEachAccessTokenHasItsOwnJTI(t *testing.T) {
	s := newFake(t)
	_, a, _, _ := segments(t, s.Sign(s.AccessToken(fakeNow)))
	_, b, _, _ := segments(t, s.Sign(s.AccessToken(fakeNow)))
	if a["jti"] == b["jti"] {
		t.Errorf("jti repeated: %v", a["jti"])
	}
}

func TestRotationPublishesTheNewKeyAndRetirementDropsTheOld(t *testing.T) {
	s := newFake(t)
	first := s.Sign(s.AccessToken(fakeNow))
	newID := s.RotateKey()
	second := s.Sign(s.AccessToken(fakeNow))

	if h, _, _, _ := segments(t, second); h["kid"] != newID {
		t.Errorf("signed with %v after rotating to %s", h["kid"], newID)
	}
	if keys := fetchKeys(t, s); len(keys) != 2 {
		t.Fatalf("published keys = %d, want old and new", len(keys))
	}
	s.RetireOldKeys()
	keys := fetchKeys(t, s)
	oldHeader, _, _, _ := segments(t, first)
	if _, still := keys[oldHeader["kid"].(string)]; still || len(keys) != 1 {
		t.Errorf("old key still published: %v", keys)
	}
}

func TestMutationsReachTheSerializedToken(t *testing.T) {
	s := newFake(t)
	token := s.AccessToken(fakeNow)
	delete(token.Header, "typ")
	delete(token.Claims, "iat")
	token.Claims["nonce"] = "n-0S6"

	header, claims, _, _ := segments(t, s.Sign(token))
	if _, ok := header["typ"]; ok {
		t.Error("typ survived its deletion")
	}
	if _, ok := claims["iat"]; ok || claims["nonce"] != "n-0S6" {
		t.Errorf("claims = %v", claims)
	}
}

func TestNoneAndHS256AndUnpublishedKeyTokens(t *testing.T) {
	s := newFake(t)
	published := fetchKeys(t, s)

	none := s.AccessToken(fakeNow)
	none.Alg = "none"
	if h, _, _, sig := segments(t, s.Sign(none)); h["alg"] != "none" || len(sig) != 0 {
		t.Errorf("none token: header %v, signature %d bytes", h, len(sig))
	}

	hs := s.AccessToken(fakeNow)
	hs.Alg = "HS256"
	if h, _, _, sig := segments(t, s.Sign(hs)); h["alg"] != "HS256" || len(sig) != sha256.Size {
		t.Errorf("HS256 token: header %v, signature %d bytes", h, len(sig))
	}

	loose := s.AccessToken(fakeNow)
	loose.Unpublished = true
	h, _, input, sig := segments(t, s.Sign(loose))
	if _, listed := published[h["kid"].(string)]; listed {
		t.Errorf("unpublished kid %v is in the JWKS", h["kid"])
	}
	for _, key := range published {
		if verifyRS256(key, input, sig) == nil {
			t.Error("a published key verifies the unpublished token")
		}
	}
}

func TestEveryRequestIsCounted(t *testing.T) {
	s := newFake(t)
	s.Handle("/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pong") })

	if s.JWKSCalls() != 0 || s.Calls("/ping") != 0 {
		t.Fatal("counters start non-zero")
	}
	fetchKeys(t, s)
	fetchKeys(t, s)
	get(t, s, s.URL()+"/ping")
	if s.JWKSCalls() != 2 || s.Calls("/ping") != 1 {
		t.Errorf("jwks calls = %d, ping calls = %d", s.JWKSCalls(), s.Calls("/ping"))
	}
}
