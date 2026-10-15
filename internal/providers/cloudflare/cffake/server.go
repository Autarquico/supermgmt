// Package cffake is a fake Cloudflare v4 API for tests (ADR-0028 fake fidelity
// contract, ADR-0037). It is test-only: nothing outside *_test.go files and
// test harnesses may import it, and it imports nothing from the client.
//
// Fidelity contract:
//   - it serves only the endpoints the Cloudflare client uses; every other
//     path answers 404 and is listed by Rejected, as is an undeclared query
//     parameter or request field (400);
//   - a missing or wrong bearer token answers 401 before any routing, in the
//     v4 envelope ({"success":false,"errors":[...],"result":null});
//   - lists paginate with page and per_page and report result_info; the page
//     size the server honours can be capped (WithPageSize), so a client that
//     assumes it got the size it asked for is caught;
//   - every mutation can be made to fail before it is applied, or to be applied
//     and lose its answer (Inject, Plan); lists can lag behind creations
//     (WithPropagationDelay);
//   - the invariant "a hostname is never routable without its Access
//     application" is checked after every committed mutation (RoutableWithoutAccess).
//
// Provenance and the list of assumptions nothing here verified are in
// PROVENANCE.md next to this file.
package cffake

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// ServerIP is the host of Endpoint. Clients reach the fake through Dial, so
	// the address never has to exist; it is a public address so that the
	// netguard filter lets a default client through.
	ServerIP = "104.16.0.1"
	// BasePath is the API prefix of Endpoint.
	BasePath = "/client/v4"
	// DefaultToken is the API token the fake accepts.
	DefaultToken = "cffake-api-token-0123456789abcdef-ghijklmnop" //nolint:gosec // a fixed test token, not a credential
	// DefaultAccountID and DefaultZone are the account and zone the fake serves.
	DefaultAccountID = "0123456789abcdef0123456789abcdef"
	DefaultZone      = "example.test"
	DefaultZoneID    = "fedcba9876543210fedcba9876543210"

	maxPerPage = 1000
)

// Op names an endpoint, for fault injection and the mutation log.
type Op string

// The endpoints the fake serves.
const (
	OpVerifyAccount    Op = "token.verify.account"
	OpVerifyUser       Op = "token.verify.user"
	OpZoneList         Op = "zone.list"
	OpTunnelCreate     Op = "tunnel.create"
	OpTunnelList       Op = "tunnel.list"
	OpTunnelGet        Op = "tunnel.get"
	OpTunnelDelete     Op = "tunnel.delete"
	OpTunnelCleanup    Op = "tunnel.cleanup"
	OpTunnelConfigPut  Op = "tunnel.config.put"
	OpTunnelConfigGet  Op = "tunnel.config.get"
	OpTunnelToken      Op = "tunnel.token"
	OpDNSCreate        Op = "dns.create"
	OpDNSList          Op = "dns.list"
	OpDNSDelete        Op = "dns.delete"
	OpPolicyCreate     Op = "policy.create"
	OpPolicyList       Op = "policy.list"
	OpPolicyUpdate     Op = "policy.update"
	OpPolicyDelete     Op = "policy.delete"
	OpAppCreate        Op = "app.create"
	OpAppList          Op = "app.list"
	OpAppDelete        Op = "app.delete"
	OpServiceTokenNew  Op = "service_token.create"
	OpServiceTokenList Op = "service_token.list"
	OpServiceTokenDel  Op = "service_token.delete"
)

// Request is one request the fake received.
type Request struct {
	Method        string
	Path          string
	Query         url.Values
	Authorization string
}

// Option adjusts a Fake.
type Option func(*Fake)

// WithToken sets the API token the fake accepts.
func WithToken(token string) Option { return func(f *Fake) { f.token = token } }

// WithAccount sets the account ID the fake serves.
func WithAccount(id string) Option { return func(f *Fake) { f.account = id } }

// WithZone sets the zone the fake serves.
func WithZone(name, id string) Option { return func(f *Fake) { f.zone, f.zoneID = name, id } }

// WithPageSize caps (and defaults) the page size the fake honours, whatever
// per_page asks for, so lists need several pages.
func WithPageSize(n int) Option { return func(f *Fake) { f.pageSize = n } }

// WithPropagationDelay hides a created object from list endpoints for the next
// n requests, as an eventually consistent index would. Reads by ID see it at once.
func WithPropagationDelay(n int) Option { return func(f *Fake) { f.delay = n } }

// WithClock replaces the clock stamping created_at. The default starts at
// 2026-01-01T00:00:00Z and advances one second per reading.
func WithClock(now func() time.Time) Option { return func(f *Fake) { f.clock = now } }

// WithUserOwnedToken makes the account token endpoint refuse the token, as it
// does for a user-owned one; only /user/tokens/verify answers.
func WithUserOwnedToken() Option { return func(f *Fake) { f.userToken = true } }

// WithEchoedCredentials makes every error message repeat the bearer token the
// request carried, and a control sequence: a hostile or buggy server, to prove
// the client never shows either.
func WithEchoedCredentials() Option { return func(f *Fake) { f.echo = true } }

// Fake is a Cloudflare API server on a throwaway CA.
type Fake struct {
	srv   *httptest.Server
	caPEM []byte
	t     testing.TB
	mux   *http.ServeMux

	token, account, zone, zoneID string
	pageSize, delay              int
	clock                        func() time.Time
	userToken, echo              bool

	mu         sync.Mutex
	reqSeq     int
	nextID     int
	requests   []Request
	rejected   []string
	faults     map[Op]*faultQueue
	plan       func(Mutation) Fault
	mutations  []Applied
	mutSeq     int
	violations []string

	tunnels  []Tunnel
	dns      []DNSRecord
	policies []Policy
	apps     []App
	tokens   []ServiceToken
}

// New starts the fake. It is stopped when the test ends.
func New(t testing.TB, opts ...Option) *Fake {
	t.Helper()
	f := &Fake{
		t: t, mux: http.NewServeMux(), token: DefaultToken, account: DefaultAccountID,
		zone: DefaultZone, zoneID: DefaultZoneID, pageSize: 100, faults: map[Op]*faultQueue{},
	}
	for _, opt := range opts {
		opt(f)
	}
	if f.clock == nil {
		tick := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		f.clock = func() time.Time { tick = tick.Add(time.Second); return tick }
	}
	f.mux.HandleFunc("/", f.notFound)
	f.routes()

	cert, caPEM := newPKI(t)
	f.caPEM = caPEM
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// Endpoint is the API base URL; its host is ServerIP.
func (f *Fake) Endpoint() string { return "https://" + ServerIP + BasePath }

// Token is the API token the fake accepts.
func (f *Fake) Token() string { return f.token }

// AccountID is the account the fake serves.
func (f *Fake) AccountID() string { return f.account }

// Zone is the zone name and ID the fake serves.
func (f *Fake) Zone() (name, id string) { return f.zone, f.zoneID }

// CAPEM is the CA that signed the server certificate.
func (f *Fake) CAPEM() []byte { return f.caPEM }

// Dial connects to the fake whatever the address: pass it to
// netguard.WithTestDialer.
func (f *Fake) Dial(network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).Dial(network, f.srv.Listener.Addr().String())
}

// Requests are the requests received, in order.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// Rejected lists requests the fake refused as outside its contract (unknown
// path, parameter or field), as "METHOD path: reason".
func (f *Fake) Rejected() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.rejected)
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqSeq++
	f.requests = append(f.requests, Request{
		Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Authorization: r.Header.Get("Authorization"),
	})
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.out(w, r, fail(http.StatusUnauthorized, 10000, "Authentication error"))
		return
	}
	f.mux.ServeHTTP(w, r)
}

func (f *Fake) notFound(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.rejected = append(f.rejected, fmt.Sprintf("%s %s: unknown endpoint", r.Method, r.URL.Path))
	f.mu.Unlock()
	f.out(w, r, fail(http.StatusNotFound, 7003, "Could not route to "+r.URL.Path+", perhaps your object identifier is invalid?"))
}

// call is one request under the fake's lock.
type call struct {
	f    *Fake
	r    *http.Request
	body []byte
}

func (c *call) path(name string) string { return c.r.PathValue(name) }

// decode reads the request body into v, refusing fields the fake does not model.
func (c *call) decode(v any) *reply {
	dec := json.NewDecoder(bytes.NewReader(c.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		r := c.f.reject(c.r, "request body: "+err.Error())
		return &r
	}
	return nil
}

type handler func(c *call) reply

type wireError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

type reply struct {
	status int
	result any
	info   *resultInfo
	errs   []wireError
	header map[string]string
}

func ok(result any) reply { return reply{status: http.StatusOK, result: result} }

func fail(status, code int, message string) reply {
	return reply{status: status, errs: []wireError{{Code: code, Message: message}}}
}

func (f *Fake) reject(r *http.Request, reason string) reply {
	f.rejected = append(f.rejected, fmt.Sprintf("%s %s: %s", r.Method, r.URL.Path, reason))
	return fail(http.StatusBadRequest, 1004, "Bad request: "+reason)
}

// out writes rep, hostile when WithEchoedCredentials asked for it.
func (f *Fake) out(w http.ResponseWriter, r *http.Request, rep reply) {
	if f.echo && len(rep.errs) > 0 {
		rep.errs[0].Message += " [" + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + "]\x1b[31m"
	}
	write(w, rep)
}

func write(w http.ResponseWriter, rep reply) {
	doc := map[string]any{
		"success": rep.status/100 == 2, "errors": []wireError{}, "messages": []string{}, "result": rep.result,
	}
	if rep.errs != nil {
		doc["errors"] = rep.errs
	}
	if rep.info != nil {
		doc["result_info"] = rep.info
	}
	w.Header().Set("Content-Type", "application/json")
	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(rep.status)
	_ = json.NewEncoder(w).Encode(doc)
}

// handle registers an endpoint. params lists the query parameters it accepts
// besides page and per_page when paged.
func (f *Fake) handle(op Op, pattern string, params []string, h handler) {
	mutation := !strings.HasPrefix(pattern, "GET ")
	f.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		f.mu.Lock()
		defer f.mu.Unlock()
		if name, bad := undeclared(r.URL.Query(), params); bad {
			f.out(w, r, f.reject(r, "unknown parameter "+name))
			return
		}
		if a := r.PathValue("account"); a != "" && a != f.account {
			f.out(w, r, fail(http.StatusForbidden, 10000, "Authentication error"))
			return
		}
		m := Mutation{Op: op, Method: r.Method, Path: r.URL.Path}
		if mutation {
			f.mutSeq++
			m.Seq = f.mutSeq
		}
		fault := f.faultFor(m, mutation)
		finish := func(status int, committed bool) {
			if mutation {
				f.mutations = append(f.mutations, Applied{Mutation: m, Fault: fault, Status: status, Committed: committed})
			}
		}
		switch fault {
		case NoFault, LostResponse:
			// served below; a lost response is dropped after the commit
		case Forbidden:
			finish(http.StatusForbidden, false)
			f.out(w, r, fail(http.StatusForbidden, 10000, "This token lacks the permission for "+string(op)))
			return
		case RateLimited:
			rep := fail(http.StatusTooManyRequests, 971, "Rate limited")
			rep.header = map[string]string{"Retry-After": "1"}
			finish(rep.status, false)
			f.out(w, r, rep)
			return
		case FailBefore:
			finish(http.StatusInternalServerError, false)
			f.out(w, r, fail(http.StatusInternalServerError, 1000, "Internal server error"))
			return
		}
		rep := h(&call{f: f, r: r, body: body})
		committed := mutation && rep.status/100 == 2
		finish(rep.status, committed)
		if committed {
			f.checkInvariant()
		}
		if fault == LostResponse && committed {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		f.out(w, r, rep)
	})
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

// paginate reads page and per_page, caps the page size, and returns the slice
// bounds and result_info of the requested page.
func (c *call) paginate(total int) (lo, hi int, info *resultInfo, bad *reply) {
	q := c.r.URL.Query()
	page, perPage := 1, c.f.pageSize
	if raw := q.Get("page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			r := fail(http.StatusBadRequest, 1004, "invalid page")
			return 0, 0, nil, &r
		}
		page = n
	}
	if raw := q.Get("per_page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxPerPage {
			r := fail(http.StatusBadRequest, 1004, "invalid per_page")
			return 0, 0, nil, &r
		}
		perPage = min(n, c.f.pageSize)
	}
	lo = min((page-1)*perPage, total)
	hi = min(lo+perPage, total)
	pages := (total + perPage - 1) / perPage
	return lo, hi, &resultInfo{Page: page, PerPage: perPage, Count: hi - lo, TotalCount: total, TotalPages: pages}, nil
}

// visible reports whether an object created at request seq shows in lists.
func (f *Fake) visible(createdSeq int) bool { return f.reqSeq-createdSeq > f.delay }

func (f *Fake) newID(kind uint32) string {
	f.nextID++
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", kind, f.nextID)
}

func (f *Fake) newHexID(kind uint32) string {
	f.nextID++
	return fmt.Sprintf("%08x%024x", kind, f.nextID)
}
