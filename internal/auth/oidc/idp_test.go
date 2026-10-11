package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/netguard"
)

const (
	issuerURL    = "https://10.0.0.5"
	foreignURL   = "https://10.0.0.6"
	testClientID = "supermgmt"
	testSecret   = "s3cret"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: epoch} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// authRequest is what the IdP remembers about an authorization code.
type authRequest struct {
	nonce, challenge, redirect string
}

// idp is an in-process OIDC provider. It listens on a TLS server on loopback
// but answers to 10.0.0.5 / 10.0.0.6: tests reach it through the netguard
// test dialer, so the filter runs on the private addresses it would see in
// production.
type idp struct {
	t      *testing.T
	server *httptest.Server
	pool   *x509.CertPool
	clock  *fakeClock

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	edKey  ed25519.PrivateKey

	mu          sync.Mutex
	doc         map[string]any
	codes       map[string]authRequest
	hits        map[string]int
	lastToken   url.Values
	lastAuth    string
	lastDevice  url.Values
	idToken     func(nonce string) string // nil: a valid token
	tokenStatus int                       // non-zero: /token answers this with an error body
	tokenError  string
	device      deviceScript
}

// deviceScript scripts the device endpoints.
type deviceScript struct {
	interval    int // seconds; 0 omits the field
	expiresIn   int
	verifyURI   string
	approved    bool
	errorCode   string // returned by the token endpoint while not approved
	deviceToken func() string
}

func newIdP(t *testing.T, clock *fakeClock) *idp {
	t.Helper()
	p := &idp{t: t, clock: clock, codes: map[string]authRequest{}, hits: map[string]int{}}
	var err error
	if p.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	p.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, p.edKey, _ = ed25519.GenerateKey(rand.Reader)
	p.device = deviceScript{interval: 5, expiresIn: 600, verifyURI: issuerURL + "/device"}
	p.resetDiscovery()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.serveDiscovery)
	mux.HandleFunc("/jwks", p.serveJWKS)
	mux.HandleFunc("/token", p.serveToken)
	mux.HandleFunc("/device/code", p.serveDeviceCode)
	mux.HandleFunc("/userinfo", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/moved/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/.well-known/openid-configuration", http.StatusFound)
	})
	cert, pool := selfSignedCert(t)
	p.pool = pool
	p.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.hits[r.URL.Path]++
		p.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	p.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	p.server.StartTLS()
	t.Cleanup(p.server.Close)
	return p
}

func (p *idp) resetDiscovery() {
	p.doc = map[string]any{
		"issuer":                                issuerURL,
		"authorization_endpoint":                issuerURL + "/auth",
		"token_endpoint":                        issuerURL + "/token",
		"jwks_uri":                              issuerURL + "/jwks",
		"device_authorization_endpoint":         issuerURL + "/device/code",
		"userinfo_endpoint":                     issuerURL + "/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
}

func (p *idp) setDoc(key string, value any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.doc[key] = value
}

func (p *idp) hitCount(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hits[path]
}

func (p *idp) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = json.NewEncoder(w).Encode(p.doc)
}

func (p *idp) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	rsaPub := p.rsaKey.PublicKey
	ecPoint, _ := p.ecKey.PublicKey.Bytes() // 0x04 || X || Y
	keys := []map[string]any{
		{"kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256", "n": b64(rsaPub.N.Bytes()), "e": b64(big.NewInt(int64(rsaPub.E)).Bytes())},
		{"kty": "EC", "kid": "ec1", "use": "sig", "alg": "ES256", "crv": "P-256", "x": b64(ecPoint[1:33]), "y": b64(ecPoint[33:])},
		{"kty": "OKP", "kid": "ed1", "use": "sig", "alg": "EdDSA", "crv": "Ed25519", "x": b64(p.edKey.Public().(ed25519.PublicKey))},
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func pad32(n *big.Int) []byte { return n.FillBytes(make([]byte, 32)) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// authorize plays the browser: it accepts the authorization URL the server
// built and returns the code the IdP would send to the loopback redirect.
func (p *idp) authorize(authURL string) (code, state string) {
	p.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		p.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != testClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		p.t.Fatalf("authorization request is malformed: %s", u.RawQuery)
	}
	code = "code-" + strconv.Itoa(len(p.codes)+1)
	p.mu.Lock()
	p.codes[code] = authRequest{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()
	return code, q.Get("state")
}

func (p *idp) serveToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	p.lastToken, p.lastAuth = r.PostForm, r.Header.Get("Authorization")
	status, errCode := p.tokenStatus, p.tokenError
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.serveCodeGrant(w, r)
	case deviceGrantType:
		p.serveDeviceGrant(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
	}
}

func (p *idp) serveCodeGrant(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	req, ok := p.codes[r.PostForm.Get("code")]
	mint := p.idToken
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || b64(sum[:]) != req.challenge || r.PostForm.Get("redirect_uri") != req.redirect {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	token := p.validToken(req.nonce)
	if mint != nil {
		token = mint(req.nonce)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": token})
}

func (p *idp) serveDeviceCode(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastDevice = r.PostForm
	if r.PostForm.Get("client_id") != testClientID || r.PostForm.Get("client_secret") != testSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	reply := map[string]any{
		"device_code":               "DEVICE-CODE-SECRET",
		"user_code":                 "ABCD-EFGH",
		"verification_uri":          p.device.verifyURI,
		"verification_uri_complete": p.device.verifyURI + "?user_code=ABCD-EFGH",
		"expires_in":                p.device.expiresIn,
	}
	if p.device.interval != 0 {
		reply["interval"] = p.device.interval
	}
	_ = json.NewEncoder(w).Encode(reply)
}

func (p *idp) serveDeviceGrant(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	script := p.device
	p.mu.Unlock()
	if r.PostForm.Get("device_code") != "DEVICE-CODE-SECRET" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	if !script.approved {
		w.WriteHeader(http.StatusBadRequest)
		code := script.errorCode
		if code == "" {
			code = "authorization_pending"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
		return
	}
	token := p.validToken("")
	if script.deviceToken != nil {
		token = script.deviceToken()
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": token})
}

func (p *idp) setDevice(update func(*deviceScript)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	update(&p.device)
}

func (p *idp) setIDToken(mint func(nonce string) string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idToken = mint
}

func (p *idp) setTokenError(status int, code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenStatus, p.tokenError = status, code
}

func (p *idp) lastTokenRequest() (url.Values, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastToken, p.lastAuth
}

func (p *idp) lastDeviceRequest() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastDevice
}

// dialer reaches the test server whatever address the filter vetted.
func (p *idp) dial(network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(context.Background(), network, p.server.Listener.Addr().String())
}

func (p *idp) httpClient() *http.Client {
	return netguard.NewClient(netguard.Allow{AllowAllPrivate: true}, nil, 5*time.Second, 64<<10,
		netguard.WithTestDialer(p.dial), netguard.WithTestRootCAs(p.pool))
}

func (p *idp) config() Config {
	return Config{
		Issuer:         issuerURL,
		ClientID:       testClientID,
		ClientSecret:   audit.Secret(testSecret),
		AllowedDomains: []string{"example.com"},
		HTTPClient:     p.httpClient(),
		Clock:          p.clock,
	}
}

// ---- token minting ------------------------------------------------------

// validClaims are the claims of a token the server accepts.
func (p *idp) validClaims(nonce string) map[string]any {
	now := p.clock.Now()
	claims := map[string]any{
		"iss":            issuerURL,
		"sub":            "user-1",
		"aud":            testClientID,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return claims
}

func (p *idp) validToken(nonce string) string {
	return p.sign("RS256", "rsa1", p.validClaims(nonce))
}

// sign builds a JWS with the key family named by alg.
func (p *idp) sign(alg, kid string, claims map[string]any) string {
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	return p.signRaw(header, claims, alg)
}

// signRaw signs with the key family named by keyAlg, whatever the header says.
func (p *idp) signRaw(header, claims map[string]any, keyAlg string) string {
	input := encodeJSON(header) + "." + encodeJSON(claims)
	return input + "." + b64(p.signature(keyAlg, []byte(input)))
}

func (p *idp) signature(keyAlg string, input []byte) []byte {
	sum := sha256.Sum256(input)
	switch keyAlg {
	case "RS256":
		sig, _ := rsa.SignPKCS1v15(rand.Reader, p.rsaKey, crypto.SHA256, sum[:])
		return sig
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, p.ecKey, sum[:])
		return append(pad32(r), pad32(s)...)
	case "EdDSA":
		return ed25519.Sign(p.edKey, input)
	case "HS256": // alg confusion: the public modulus used as an HMAC secret
		mac := hmac.New(sha256.New, p.rsaKey.N.Bytes())
		mac.Write(input)
		return mac.Sum(nil)
	}
	return nil // "none"
}

func encodeJSON(v any) string {
	raw, _ := json.Marshal(v)
	return b64(raw)
}

// attackerToken is signed by a key the IdP never published but claims a
// published kid.
func attackerToken(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	input := encodeJSON(map[string]any{"alg": "RS256", "kid": kid}) + "." + encodeJSON(claims)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return input + "." + b64(sig)
}

// selfSignedCert issues a certificate for the addresses tests use.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "idp.test"},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.6")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
