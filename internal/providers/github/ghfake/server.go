// Package ghfake is a fake GitHub REST API for tests (ADR-0028 fake fidelity
// contract). It is test-only: nothing outside *_test.go files and test
// harnesses may import it, and it imports nothing from the connector.
//
// Fidelity contract:
//   - it serves only the endpoints M4 uses; every other path answers 404 and
//     is listed by Rejected, and an undeclared query parameter answers 422;
//   - a missing or wrong token answers 401 before any routing, with GitHub's
//     {"message": ...} document;
//   - every answer carries X-RateLimit-* headers; after ExhaustRateLimit the
//     answer is 403 "API rate limit exceeded";
//   - list endpoints paginate with per_page (max 100) and a Link header;
//   - redirects configured with Redirect are answered as GitHub does (302 and
//     a Location header) after authentication.
//
// Provenance (REST API version, URL, date) is recorded in
// test/fixtures/github/PROVENANCE.md. Nothing here is verified against the
// live API: field shapes follow the published documentation as the author
// knows it.
package ghfake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	// ServerIP is the host of Endpoint. Clients reach the fake through Dial,
	// so the address never has to exist.
	ServerIP = "10.78.0.1"
	// DefaultToken is the personal access token the fake accepts.
	DefaultToken = "github_pat_ghfake_0123456789abcdef" //nolint:gosec // a fixed test token, not a credential

	maxPerPage     = 100
	defaultPerPage = 30
	rateLimit      = 5000
	rateReset      = 1_800_003_600
)

// Request is one request the fake received.
type Request struct {
	Method        string
	Host          string
	Path          string
	Query         url.Values
	Authorization string
}

// Option adjusts a Fake.
type Option func(*Fake)

// WithToken sets the token the fake accepts.
func WithToken(token string) Option { return func(f *Fake) { f.token = token } }

// Fake is a GitHub API server on a throwaway CA.
type Fake struct {
	srv    *httptest.Server
	caPEM  []byte
	token  string
	routes *http.ServeMux
	t      testing.TB

	mu        sync.Mutex
	requests  []Request
	rejected  []string
	redirects map[string]string
	exhausted bool
	repos     []Repo
	files     map[fileKey]File
}

// New starts the fake. It is stopped when the test ends.
func New(t testing.TB, opts ...Option) *Fake {
	t.Helper()
	f := &Fake{
		t: t, token: DefaultToken, routes: http.NewServeMux(),
		redirects: map[string]string{}, files: map[fileKey]File{},
	}
	for _, opt := range opts {
		opt(f)
	}
	f.routes.HandleFunc("/", f.notFound)
	f.registerRepoRoutes()

	cert, caPEM := newPKI(t)
	f.caPEM = caPEM
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// Endpoint is the API base URL (port 443); its host is ServerIP.
func (f *Fake) Endpoint() string { return "https://" + ServerIP }

// Token is the personal access token the fake accepts.
func (f *Fake) Token() string { return f.token }

// CAPEM is the CA that signed the server certificate.
func (f *Fake) CAPEM() []byte { return f.caPEM }

// Dial connects to the fake whatever the address: pass it to
// netguard.WithTestDialer.
func (f *Fake) Dial(network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).Dial(network, f.srv.Listener.Addr().String())
}

// Handle serves pattern ("GET /repos/{owner}/{repo}/...") for later tasks and
// tests. Every query parameter outside params is refused with 422.
func (f *Fake) Handle(pattern string, params []string, h http.HandlerFunc) {
	f.routes.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if name, bad := undeclared(r.URL.Query(), params); bad {
			f.reject(r, "unknown parameter "+name)
			WriteError(w, http.StatusUnprocessableEntity, "Validation Failed: unknown parameter "+name)
			return
		}
		h(w, r)
	})
}

// Redirect answers GET path with a 302 to location (after authentication).
func (f *Fake) Redirect(path, location string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redirects[path] = location
}

// ExhaustRateLimit makes every later request answer as rate limited.
func (f *Fake) ExhaustRateLimit() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exhausted = true
}

// Requests are the requests received, in order.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// Rejected lists requests the fake refused as outside its contract (unknown
// path or parameter), as "METHOD path: reason".
func (f *Fake) Rejected() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.rejected)
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	remaining, exhausted := f.record(r)
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rateLimit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.Itoa(rateReset))
	switch given := r.Header.Get("Authorization"); {
	case given == "":
		WriteError(w, http.StatusUnauthorized, "Requires authentication")
		return
	case given != "Bearer "+f.token:
		WriteError(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	if to, ok := f.redirectOf(r); ok {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	if exhausted {
		WriteError(w, http.StatusForbidden, "API rate limit exceeded")
		return
	}
	f.routes.ServeHTTP(w, r)
}

func (f *Fake) record(r *http.Request) (remaining int, exhausted bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, Request{
		Method: r.Method, Host: r.Host, Path: r.URL.Path,
		Query: r.URL.Query(), Authorization: r.Header.Get("Authorization"),
	})
	if f.exhausted {
		return 0, true
	}
	return max(rateLimit-len(f.requests), 0), false
}

func (f *Fake) redirectOf(r *http.Request) (string, bool) {
	if r.Method != http.MethodGet {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	to, ok := f.redirects[r.URL.Path]
	return to, ok
}

func (f *Fake) notFound(w http.ResponseWriter, r *http.Request) {
	f.reject(r, "unknown endpoint")
	WriteError(w, http.StatusNotFound, "Not Found")
}

func (f *Fake) reject(r *http.Request, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected = append(f.rejected, fmt.Sprintf("%s %s: %s", r.Method, r.URL.Path, reason))
}

func undeclared(q url.Values, allowed []string) (string, bool) {
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range q {
			if !yield(name) {
				return
			}
		}
	}) {
		if !slices.Contains(allowed, name) {
			return name, true
		}
	}
	return "", false
}

// WriteJSON answers 200 with v.
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError answers in the shape GitHub uses for failures.
func WriteError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":           message,
		"documentation_url": "https://docs.github.com/rest",
	})
}

// Paginate reads per_page and page from the request, sets the Link header for
// a list of total items and returns the slice bounds of the requested page.
// ok is false (and the answer already written) for an invalid page request.
func Paginate(w http.ResponseWriter, r *http.Request, total int) (lo, hi int, ok bool) {
	perPage, okPer := intParam(r, "per_page", defaultPerPage)
	page, okPage := intParam(r, "page", 1)
	if !okPer || !okPage || perPage > maxPerPage {
		WriteError(w, http.StatusUnprocessableEntity, "Validation Failed: invalid pagination")
		return 0, 0, false
	}
	lo = min((page-1)*perPage, total)
	hi = min(lo+perPage, total)
	if hi < total {
		next := *r.URL
		q := next.Query()
		q.Set("page", strconv.Itoa(page+1))
		next.RawQuery = q.Encode()
		w.Header().Set("Link", fmt.Sprintf(`<https://%s%s>; rel="next"`, r.Host, next.RequestURI()))
	}
	return lo, hi, true
}

func intParam(r *http.Request, name string, fallback int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, true
	}
	n, err := strconv.Atoi(raw)
	return n, err == nil && n >= 1
}

// The certificates are valid over a fixed, wide range so the fake never reads
// the wall clock.
var (
	validFrom  = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// newPKI makes a throwaway CA and a server certificate for ServerIP signed by
// it, and returns the certificate and the CA in PEM.
func newPKI(t testing.TB) (tls.Certificate, []byte) {
	t.Helper()
	caKey := newKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ghfake root ca"},
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
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ghfake"},
		NotBefore: validFrom, NotAfter: validUntil,
		IPAddresses: []net.IP{net.ParseIP(ServerIP)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER := sign(t, leafTmpl, ca, &leafKey.PublicKey, caKey)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
