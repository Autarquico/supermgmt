// Package oauthfake is a fake OAuth 2.0 authorization server for tests: a JWKS
// endpoint with key rotation and a minting kit for RFC 9068 access tokens that
// can be mutated claim by claim and header by header. It counts every request
// so tests can prove which calls a resolver did or did not make. It is for
// tests only (ADR-0033); see PROVENANCE.md for where its behaviour comes from.
package oauthfake

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"time"
)

const (
	// JWKSPath is where the key set is served.
	JWKSPath = "/jwks"

	defaultIssuer   = "https://issuer.test"
	defaultResource = "https://sm.test/mcp"
	defaultClientID = "client-1"
	defaultSubject  = "user-1"
	defaultScope    = "mcp:read"
	rsaBits         = 2048
)

// Server is the fake authorization server. Set Issuer, Resource, ClientID and
// Subject before minting; they are the defaults of AccessToken.
type Server struct {
	Issuer   string
	Resource string
	ClientID string
	Subject  string

	http *httptest.Server
	mux  *http.ServeMux

	mu       sync.Mutex
	keys     []*signingKey // published, newest last
	loose    *signingKey   // signs "unpublished" tokens; never in the JWKS
	calls    map[string]int
	sequence int
}

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

// New starts the server with one published key, "k1".
func New() *Server {
	s := &Server{
		Issuer: defaultIssuer, Resource: defaultResource, ClientID: defaultClientID, Subject: defaultSubject,
		mux: http.NewServeMux(), calls: map[string]int{},
	}
	s.keys = []*signingKey{s.newKey()}
	s.Handle(JWKSPath, s.serveJWKS)
	s.http = httptest.NewServer(s.mux)
	return s
}

// Close stops the server.
func (s *Server) Close() { s.http.Close() }

// URL is the base URL of the server.
func (s *Server) URL() string { return s.http.URL }

// Client is an HTTP client for the server.
func (s *Server) Client() *http.Client { return s.http.Client() }

// JWKSURL is the URL of the key set.
func (s *Server) JWKSURL() string { return s.http.URL + JWKSPath }

// JWKSCalls is how many times the key set was fetched.
func (s *Server) JWKSCalls() int { return s.Calls(JWKSPath) }

// Handle serves path with h and counts its requests.
func (s *Server) Handle(path string, h http.HandlerFunc) {
	s.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls[path]++
		s.mu.Unlock()
		h(w, r)
	})
}

// Calls is how many requests path received.
func (s *Server) Calls(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[path]
}

// newKey must be called with s.mu held, or before the server is shared.
func (s *Server) newKey() *signingKey {
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		panic("oauthfake: generate key: " + err.Error()) // crypto/rand failure: a test cannot continue
	}
	s.sequence++
	return &signingKey{id: "k" + strconv.Itoa(s.sequence), key: key}
}

// RotateKey publishes a new key and signs with it from now on; older keys stay
// published until RetireOldKeys. It returns the new key id.
func (s *Server) RotateKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.newKey()
	s.keys = append(s.keys, k)
	return k.id
}

// RetireOldKeys unpublishes every key but the current one.
func (s *Server) RetireOldKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = s.keys[len(s.keys)-1:]
}

func (s *Server) signingKeyFor(t *Token) *signingKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !t.Unpublished {
		return s.keys[len(s.keys)-1]
	}
	if s.loose == nil {
		s.loose = s.newKey()
	}
	return s.loose
}

func (s *Server) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	keys := make([]map[string]string, 0, len(s.keys))
	for _, k := range s.keys {
		pub := k.key.PublicKey
		keys = append(keys, map[string]string{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.id,
			"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

// Token is a JWT before signing. Mutate Header and Claims freely: delete a
// claim, change `typ`, add a `nonce`.
type Token struct {
	Header map[string]any
	Claims map[string]any
	// Alg is the signing algorithm: "RS256" (default), "none", or "HS256",
	// which MACs with the DER of the current public key (the confusion attack).
	Alg string
	// Unpublished signs with a key that is not in the JWKS.
	Unpublished bool
}

// AccessToken is a valid RFC 9068 access token for the server's defaults,
// issued at now and valid for an hour.
func (s *Server) AccessToken(now time.Time) *Token {
	s.mu.Lock()
	s.sequence++
	jti := "jti-" + strconv.Itoa(s.sequence)
	s.mu.Unlock()
	return &Token{
		Header: map[string]any{"typ": "at+jwt"},
		Claims: map[string]any{
			"iss": s.Issuer, "sub": s.Subject, "aud": []string{s.Resource}, "client_id": s.ClientID,
			"scope": defaultScope, "jti": jti,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		},
	}
}

// Sign returns the compact serialization of t.
func (s *Server) Sign(t *Token) string {
	alg := t.Alg
	if alg == "" {
		alg = "RS256"
	}
	key := s.signingKeyFor(t)
	header := map[string]any{"alg": alg}
	if alg == "RS256" {
		header["kid"] = key.id
	}
	for k, v := range t.Header {
		header[k] = v
	}
	signingInput := encodeSegment(header) + "." + encodeSegment(t.Claims)
	return signingInput + "." + b64(signature(alg, key, signingInput))
}

func signature(alg string, key *signingKey, signingInput string) []byte {
	switch alg {
	case "none":
		return nil
	case "HS256":
		mac := hmac.New(sha256.New, publicKeyDER(&key.key.PublicKey))
		mac.Write([]byte(signingInput))
		return mac.Sum(nil)
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.key, crypto.SHA256, digest[:])
	if err != nil {
		panic("oauthfake: sign: " + err.Error())
	}
	return sig
}

func publicKeyDER(pub *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic("oauthfake: marshal public key: " + err.Error())
	}
	return der
}

func encodeSegment(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic("oauthfake: encode: " + err.Error())
	}
	return b64(raw)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
