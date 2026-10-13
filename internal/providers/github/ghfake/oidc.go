package ghfake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// OIDCServerIP is the host of OIDCIssuer.Issuer. Clients reach the issuer
// through Dial, so the address never has to exist.
const OIDCServerIP = "10.78.0.2"

const rsaBits = 2048

// OIDCIssuer is a fake GitHub Actions OIDC issuer: a discovery document, a
// JWKS and a signer. Like the real one it is unauthenticated and signs with
// RS256. It stands apart from Fake because the real issuer is another host
// that takes no personal access token.
type OIDCIssuer struct {
	srv   *httptest.Server
	caPEM []byte
	t     testing.TB

	mu       sync.Mutex
	keys     []signingKey // published, oldest first
	jwksURI  string
	fetches  int
	rejected []string
}

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

// NewOIDCIssuer starts the issuer with one published key. It is stopped when
// the test ends.
func NewOIDCIssuer(t testing.TB) *OIDCIssuer {
	t.Helper()
	o := &OIDCIssuer{t: t}
	o.jwksURI = o.Issuer() + "/.well-known/jwks"
	o.keys = []signingKey{o.newSigningKey()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", o.serveDiscovery)
	mux.HandleFunc("GET /.well-known/jwks", o.serveJWKS)
	mux.HandleFunc("/", o.serveUnknown)

	cert, caPEM := newIssuerPKI(t)
	o.caPEM = caPEM
	o.srv = httptest.NewUnstartedServer(mux)
	o.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	o.srv.StartTLS()
	t.Cleanup(o.srv.Close)
	return o
}

// Issuer is the value of the `iss` claim and the base URL of the issuer.
func (o *OIDCIssuer) Issuer() string { return "https://" + OIDCServerIP }

// CAPEM is the CA that signed the issuer's certificate.
func (o *OIDCIssuer) CAPEM() []byte { return o.caPEM }

// Dial connects to the issuer whatever the address.
func (o *OIDCIssuer) Dial(network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).Dial(network, o.srv.Listener.Addr().String())
}

// Sign returns an RS256 token over claims, signed with the newest published
// key.
func (o *OIDCIssuer) Sign(claims map[string]any) string {
	o.mu.Lock()
	k := o.keys[len(o.keys)-1]
	o.mu.Unlock()
	return o.signWith(k, claims)
}

// SignUnpublished signs with a key the JWKS never serves, under a fresh kid.
func (o *OIDCIssuer) SignUnpublished(claims map[string]any) string {
	return o.signWith(o.newSigningKey(), claims)
}

// Rotate publishes an additional key, which signs from now on, and returns
// its kid. Earlier keys stay published until Retire.
func (o *OIDCIssuer) Rotate() string {
	k := o.newSigningKey()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.keys = append(o.keys, k)
	return k.id
}

// Retire stops publishing the key with the given kid.
func (o *OIDCIssuer) Retire(kid string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.keys = slices.DeleteFunc(o.keys, func(k signingKey) bool { return k.id == kid })
}

// SetJWKSURI makes the discovery document point at uri.
func (o *OIDCIssuer) SetJWKSURI(uri string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.jwksURI = uri
}

// JWKSFetches is how many times the key set was served.
func (o *OIDCIssuer) JWKSFetches() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.fetches
}

// Rejected lists requests outside the fake's contract, as "METHOD path".
func (o *OIDCIssuer) Rejected() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.rejected)
}

func (o *OIDCIssuer) newSigningKey() signingKey {
	o.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		o.t.Fatal(err)
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		o.t.Fatal(err)
	}
	return signingKey{id: fmt.Sprintf("%x", id), key: key}
}

func (o *OIDCIssuer) signWith(k signingKey, claims map[string]any) string {
	o.t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), k.id)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k.key}, opts)
	if err != nil {
		o.t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		o.t.Fatal(err)
	}
	return raw
}

func (o *OIDCIssuer) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	o.mu.Lock()
	uri := o.jwksURI
	o.mu.Unlock()
	WriteJSON(w, map[string]any{
		"issuer":                                o.Issuer(),
		"jwks_uri":                              uri,
		"subject_types_supported":               []string{"public", "pairwise"},
		"response_types_supported":              []string{"id_token"},
		"claims_supported":                      []string{"sub", "aud", "exp", "iat", "iss", "jti"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid"},
	})
}

func (o *OIDCIssuer) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	o.mu.Lock()
	o.fetches++
	set := jose.JSONWebKeySet{}
	for _, k := range o.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key: &k.key.PublicKey, KeyID: k.id, Algorithm: string(jose.RS256), Use: "sig",
		})
	}
	o.mu.Unlock()
	WriteJSON(w, set)
}

func (o *OIDCIssuer) serveUnknown(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.rejected = append(o.rejected, r.Method+" "+r.URL.Path)
	o.mu.Unlock()
	WriteError(w, http.StatusNotFound, "Not Found")
}

// UnsignedToken builds a token with alg "none" over claims, for tests that
// prove a verifier refuses it.
func UnsignedToken(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "."
}

// newIssuerPKI makes a throwaway CA and a server certificate for
// OIDCServerIP signed by it.
func newIssuerPKI(t testing.TB) (tls.Certificate, []byte) {
	t.Helper()
	caKey := newKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ghfake oidc root ca"},
		NotBefore: validFrom, NotAfter: validUntil,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER := sign(t, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := newKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ghfake oidc"},
		NotBefore: validFrom, NotAfter: validUntil,
		IPAddresses: []net.IP{net.ParseIP(OIDCServerIP)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER := sign(t, leafTmpl, ca, &leafKey.PublicKey, caKey)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
