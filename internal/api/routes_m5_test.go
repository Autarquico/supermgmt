package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

const (
	m5AdminToken = "admin-token"
	m5MCPToken   = "smm_local-client-token"
)

// m5Credentials accepts every credential kind: the stores of the MCP kinds
// belong to internal/auth, which these tests do not exercise.
type m5Credentials struct{}

func (m5Credentials) Status(context.Context, domain.CredentialContext) (app.CredentialState, error) {
	return app.CredentialActive, nil
}

// m5Resolver maps fixed tokens to callers and records every token it is asked
// to resolve.
type m5Resolver struct {
	mu      sync.Mutex
	callers map[string]app.Caller
	seen    []string
}

func (r *m5Resolver) Resolve(_ context.Context, bearer string) (app.Caller, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, bearer)
	if by, ok := r.callers[bearer]; ok {
		return by, nil
	}
	return app.Caller{}, smerr.New(smerr.CodeUnauthenticated, "", "unknown token")
}

func (r *m5Resolver) resolved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

type m5Options struct {
	https       bool // HTTPS transport (a token resolver) instead of the Unix socket
	realTokens  bool // HTTPS: resolve with auth.DBResolver instead of the fixed tokens
	remote      http.Handler
	remotePaths []string
	noMCPTokens bool // socket: no MCPResolver
	noMCPRoutes bool // no MCPClients service
}

// m5Fixture is a real server over a migrated database with the MCP client
// service, an admin, an mcp identity and a fake clock.
type m5Fixture struct {
	t      *testing.T
	db     *database.DB
	clock  *domaintest.FakeClock
	ids    domain.IDGenerator
	server *Server
	svc    Services
	admin  app.Caller
	mcp    app.Caller
	// tokens resolves m5AdminToken (HTTPS) and m5MCPToken (socket).
	tokens *m5Resolver
	client *http.Client
}

func newM5Fixture(t *testing.T, opts ...func(*m5Options)) *m5Fixture {
	t.Helper()
	var o m5Options
	for _, f := range opts {
		f(&o)
	}
	ctx := context.Background()
	clock, ids := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)), domain.UUIDv7Generator{}
	db, err := database.Open(ctx, t.TempDir()+"/db", database.Options{Clock: clock})
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	must(t, db.Migrate(ctx))
	pol, err := policy.Default()
	must(t, err)
	cfg := app.Config{DB: db, Clock: clock, IDs: ids, Policy: pol, Credentials: m5Credentials{}}
	reval, err := app.NewRevalidator(cfg)
	must(t, err)
	store, err := jobs.NewStore(jobs.Config{DB: db, Clock: clock, IDs: ids, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	must(t, err)

	f := &m5Fixture{t: t, db: db, clock: clock, ids: ids, svc: remoteServices(t, cfg, store)}
	if !o.noMCPRoutes {
		f.svc.MCPClients, err = app.NewMCPClients(cfg, store, app.MCPClientsOptions{Tokens: auth.Minter{}})
		must(t, err)
	}
	f.admin = f.seed(domain.ActorHuman, "admin", domain.CredentialContext{Kind: domain.CredentialLocalSocket})
	f.mcp = f.seed(domain.ActorMCP, "", domain.CredentialContext{Kind: domain.CredentialMCPToken, ID: ids.NewID().String()})
	f.tokens = &m5Resolver{callers: map[string]app.Caller{m5AdminToken: f.admin, m5MCPToken: f.mcp}}

	server := Options{
		Services: f.svc, IDs: ids, DB: db, Clock: clock,
		MCPRemote: o.remote, MCPRemotePaths: o.remotePaths,
	}
	network, address := "unix", filepath.Join(shortTempDir(t), "s")
	switch {
	case o.https && o.realTokens:
		server.Resolver = auth.DBResolver{DB: db, Clock: clock}
		network, address = "tcp", "127.0.0.1:0"
	case o.https:
		server.Resolver = f.tokens
		network, address = "tcp", "127.0.0.1:0"
	default:
		server.Identity = f.admin.ID
		if !o.noMCPTokens {
			server.MCPResolver = f.tokens
		}
	}
	f.server, err = New(server)
	must(t, err)
	listener, err := (&net.ListenConfig{}).Listen(ctx, network, address)
	must(t, err)
	served := listener
	if network == "unix" {
		served = RestrictToUID(listener, uint32(os.Getuid()), PeerUID, nil)
	}
	go func() { _ = f.server.Serve(served) }()
	t.Cleanup(func() { _ = f.server.Shutdown(context.Background()) })
	f.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
	}}
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

// shortTempDir is a temp dir whose path fits in sun_path (104 bytes on macOS).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sma")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// seed creates an identity (with the named role, if any) and returns its caller.
func (f *m5Fixture) seed(actor domain.ActorType, role string, cred domain.CredentialContext) app.Caller {
	f.t.Helper()
	id := f.ids.NewID()
	must(f.t, f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateIdentity(ctx, tx, database.Identity{ID: id, ActorType: actor, Subject: id.String(), CreatedAt: f.clock.Now()})
		if err != nil || role == "" {
			return err
		}
		r, err := database.GetRoleByName(ctx, tx, role)
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: f.ids.NewID(), IdentityID: id, RoleID: r.ID, CreatedAt: f.clock.Now()})
	}))
	return app.Caller{ID: id, Credential: cred, Source: "api"}
}

func (f *m5Fixture) do(method, path, token, body string, headers ...string) reply {
	f.t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "http://sm"+path, reader)
	must(f.t, err)
	if token != "" {
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := f.client.Do(req)
	must(f.t, err)
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	must(f.t, err)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: payload}
}

func (f *m5Fixture) register(token, key, name string) reply {
	f.t.Helper()
	return f.do(http.MethodPost, wire.PathMCPClients, token, `{"name":"`+name+`","origin":"local"}`, wire.HeaderIdempotencyKey, key)
}

func decodeData[T any](t *testing.T, r reply) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(r.Body, &env); err != nil {
		t.Fatalf("not an envelope: %s", r.Body)
	}
	return env.Data
}

// ---- routes ------------------------------------------------------------------

var wantM5Routes = map[string]struct {
	action     string
	keyed      bool
	credential bool
}{
	"GET " + wire.PathMCPClients:      {action: "identity.read"},
	"POST " + wire.PathMCPClients:     {action: "mcp_client.register", keyed: true},
	"POST " + wire.PathMCPClientToken: {action: "mcp_client.issue_token", credential: true},
	"DELETE " + wire.PathMCPClient:    {action: "mcp_client.delete", keyed: true},
}

func TestMCPClientRoutesMapToExactlyOneCatalogAction(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	got := map[string]Route{}
	for _, rt := range f.server.Routes() {
		got[rt.Method+" "+rt.Pattern] = rt
	}
	for key, want := range wantM5Routes {
		rt, ok := got[key]
		if !ok {
			t.Errorf("route %s is not served", key)
			continue
		}
		if _, inCatalog := policy.Lookup(rt.Action); !inCatalog || rt.Action != want.action {
			t.Errorf("%s maps to %q (in catalog: %v), want %q", key, rt.Action, inCatalog, want.action)
		}
		if rt.Keyed != want.keyed || rt.Credential != want.credential {
			t.Errorf("%s: keyed=%v credential=%v, want keyed=%v credential=%v", key, rt.Keyed, rt.Credential, want.keyed, want.credential)
		}
	}
}

func TestMCPClientRoutesAreNotServedWithoutTheService(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true; o.noMCPRoutes = true })
	for _, rt := range f.server.Routes() {
		if _, mcp := wantM5Routes[rt.Method+" "+rt.Pattern]; mcp && rt.Pattern != wire.PathMCPClients {
			t.Errorf("%s %s is served without the MCP clients service", rt.Method, rt.Pattern)
		}
		if rt.Pattern == wire.PathMCPClients {
			t.Errorf("%s %s is served without the MCP clients service", rt.Method, rt.Pattern)
		}
	}
}

func TestListingMCPClientsAnswersAPage(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	r := f.do(http.MethodGet, wire.PathMCPClients, m5AdminToken, "")
	if r.Status != http.StatusOK {
		t.Fatalf("status %d: %s", r.Status, r.Body)
	}
	var env struct {
		Data struct {
			Items []wire.MCPClient `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(r.Body, &env); err != nil || env.Data.Items == nil {
		t.Fatalf("want a page with an empty items array, got %s (%v)", r.Body, err)
	}
}

func TestRegisteringAnMCPClientNeedsApprovalAndIsReplayable(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	first := f.register(m5AdminToken, "key-1", "claude-desktop")
	if first.Status != http.StatusAccepted {
		t.Fatalf("status %d: %s", first.Status, first.Body)
	}
	replay := f.register(m5AdminToken, "key-1", "claude-desktop")
	if replay.Status != http.StatusAccepted || replay.Header.Get(wire.HeaderIdempotentReplayed) != "true" {
		t.Errorf("retry with the same key: status %d replayed=%q, want the stored 202", replay.Status, replay.Header.Get(wire.HeaderIdempotentReplayed))
	}
}

func TestRegisteringAnMCPClientRefusesANameWithAPendingRegistration(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	if r := f.register(m5AdminToken, "key-1", "claude-desktop"); r.Status != http.StatusAccepted {
		t.Fatalf("first registration: status %d: %s", r.Status, r.Body)
	}
	clash := f.register(m5AdminToken, "key-2", "claude-desktop")
	if clash.Status != http.StatusConflict || errorReasonOf(t, clash) != smerr.ReasonResourceLocked {
		t.Errorf("same name, new key: status %d body %s, want 409 RESOURCE_LOCKED", clash.Status, clash.Body)
	}
	if other := f.register(m5AdminToken, "key-3", "claude-code"); other.Status != http.StatusAccepted {
		t.Errorf("another name: status %d: %s, want 202", other.Status, other.Body)
	}
}

func TestIssuingAnMCPTokenRefusesAnIdempotencyKey(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	path := wire.Path(wire.PathMCPClientToken, f.ids.NewID().String())
	r := f.do(http.MethodPost, path, m5AdminToken, `{"expires_at":"2027-01-01T00:00:00Z"}`, wire.HeaderIdempotencyKey, "key-1")
	if r.Status != http.StatusBadRequest {
		t.Errorf("status %d: %s, want 400", r.Status, r.Body)
	}
}

func TestIssuingATokenForAnUnknownClientIsNotFound(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	path := wire.Path(wire.PathMCPClientToken, f.ids.NewID().String())
	r := f.do(http.MethodPost, path, m5AdminToken, `{"expires_at":"2027-01-01T00:00:00Z"}`)
	if r.Status != http.StatusNotFound {
		t.Errorf("status %d: %s, want 404", r.Status, r.Body)
	}
}
