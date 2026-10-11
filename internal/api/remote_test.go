package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// remote is a server on the HTTPS transport (plain TCP here: TLS belongs to
// the daemon's listener) over a migrated database, with real token
// resolution and credential status.
type remote struct {
	t       *testing.T
	db      *database.DB
	clock   *domaintest.FakeClock
	ids     domain.IDGenerator
	server  *Server
	hold    *recordingHold
	enroll  *fakeEnrollments
	auth    *app.AuthService
	baseURL string
	http    *http.Client
}

type remoteOptions struct {
	proxy    *Proxy
	noEnroll bool
	stream   StreamOptions
}

func newRemote(t *testing.T, opts ...func(*remoteOptions)) *remote {
	t.Helper()
	var o remoteOptions
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
	cfg := app.Config{DB: db, Clock: clock, IDs: ids, Policy: pol, Credentials: auth.CredentialStatus{DB: db, Clock: clock}}

	reval, err := app.NewRevalidator(cfg)
	must(t, err)
	store, err := jobs.NewStore(jobs.Config{DB: db, Clock: clock, IDs: ids, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	must(t, err)
	svc := remoteServices(t, cfg, store)
	svc.Auth, err = app.NewAuthService(cfg, app.AuthOptions{Tokens: auth.Minter{}})
	must(t, err)
	holdService, err := app.NewHold(cfg, store)
	must(t, err)
	r := &remote{t: t, db: db, clock: clock, ids: ids, hold: &recordingHold{Hold: holdService}, enroll: &fakeEnrollments{}, auth: svc.Auth.(*app.AuthService)}
	svc.Hold = r.hold
	if !o.noEnroll {
		svc.Enrollments = r.enroll
	}
	if o.stream.Poll == 0 {
		o.stream = StreamOptions{Poll: 10 * time.Millisecond, Revalidate: 40 * time.Millisecond, Heartbeat: time.Hour}
	}
	r.server, err = New(Options{
		Services: svc, IDs: ids, Resolver: auth.DBResolver{DB: db, Clock: clock}, Proxy: o.proxy, DB: db, Clock: clock, Stream: o.stream,
	})
	must(t, err)
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	must(t, err)
	go func() { _ = r.server.Serve(listener) }()
	t.Cleanup(func() { _ = r.server.Shutdown(context.Background()) })
	r.baseURL = "http://" + listener.Addr().String()
	r.http = &http.Client{}
	t.Cleanup(r.http.CloseIdleConnections)
	return r
}

func remoteServices(t *testing.T, cfg app.Config, store *jobs.Store) Services {
	t.Helper()
	plans, err := app.NewPlans(cfg, store)
	must(t, err)
	approvals, err := app.NewApprovals(cfg, store)
	must(t, err)
	governance, err := app.NewGovernance(cfg, store)
	must(t, err)
	actions, err := app.NewServices(cfg, store)
	must(t, err)
	queries, err := app.NewQueries(cfg, store, config.ModeServer)
	must(t, err)
	inventory, err := app.NewInventory(cfg, app.InventoryOptions{Store: store, Connector: app.Connector{}, Mode: config.ModeServer})
	must(t, err)
	sessions, err := app.NewSessions(cfg)
	must(t, err)
	keys, err := NewSSHKeys(func(context.Context) (secrets.Identity, error) { return secrets.Identity{}, nil })
	must(t, err)
	return Services{
		Plans: plans, Approvals: approvals, Governance: governance, Services: actions,
		Queries: queries, Inventory: inventory, Sessions: sessions, SSHKeys: keys,
	}
}

// admin creates an identity with the admin role and an API token for it.
func (r *remote) admin() (identity domain.ID, issued wire.TokenIssued) {
	r.t.Helper()
	identity = r.ids.NewID()
	err := r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		if err := database.CreateIdentity(ctx, tx, database.Identity{ID: identity, ActorType: domain.ActorHuman, Subject: identity.String(), CreatedAt: r.clock.Now()}); err != nil {
			return err
		}
		role, err := database.GetRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: r.ids.NewID(), IdentityID: identity, RoleID: role.ID, CreatedAt: r.clock.Now()})
	})
	must(r.t, err)
	issued, err = r.auth.CreateToken(context.Background(),
		app.Caller{ID: identity, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}},
		wire.CreateTokenRequest{Name: "test", ExpiresAt: r.clock.Now().Add(time.Hour)})
	must(r.t, err)
	return identity, issued
}

// expiry is a token expiry an hour ahead on the server's clock, as JSON.
func (r *remote) expiry() string { return r.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339) }

func (r *remote) setHold(held bool) {
	r.t.Helper()
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.SetRestoreHold(ctx, tx, held, r.clock.Now())
	}))
}

func (r *remote) idempotencyRecords() int {
	r.t.Helper()
	var n int
	must(r.t, r.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM idempotency_records`).Scan(&n))
	return n
}

func (r *remote) request(method, path, token, body string, headers ...string) reply {
	r.t.Helper()
	resp := r.open(method, path, token, body, headers...)
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	must(r.t, err)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: payload}
}

// open sends the request and returns the response with its body unread.
func (r *remote) open(method, path, token, body string, headers ...string) *http.Response {
	r.t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, r.baseURL+path, reader)
	must(r.t, err)
	if token != "" {
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	resp, err := r.http.Do(req)
	must(r.t, err)
	return resp
}

type recordingHold struct {
	app.Hold
	mu      sync.Mutex
	guarded []string
}

func (h *recordingHold) Guard(ctx context.Context, action string, by app.Caller) error {
	h.mu.Lock()
	h.guarded = append(h.guarded, action)
	h.mu.Unlock()
	return h.Hold.Guard(ctx, action, by)
}

func (h *recordingHold) actions() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.guarded...)
}

type fakeEnrollments struct {
	mu      sync.Mutex
	sources []netip.Addr
}

func (f *fakeEnrollments) Create(context.Context, app.Caller, wire.EnrollmentRequest) (wire.EnrollmentIssued, error) {
	return wire.EnrollmentIssued{Token: "smj_fake"}, nil
}

func (f *fakeEnrollments) Enroll(_ context.Context, source netip.Addr, _ wire.EnrollRequest) (wire.Enrolled, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sources = append(f.sources, source)
	return wire.Enrolled{}, nil
}

func (f *fakeEnrollments) lastSource() netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sources) == 0 {
		return netip.Addr{}
	}
	return f.sources[len(f.sources)-1]
}

// frames reads the server-sent events of a stream until it ends.
type frames struct {
	scanner *bufio.Scanner
	body    io.Closer
}

func readFrames(resp *http.Response) *frames {
	return &frames{scanner: bufio.NewScanner(resp.Body), body: resp.Body}
}

// next returns the next frame as its lines, or false at the end of the stream.
func (f *frames) next() ([]string, bool) {
	var lines []string
	for f.scanner.Scan() {
		line := f.scanner.Text()
		if line == "" {
			if len(lines) > 0 {
				return lines, true
			}
			continue
		}
		lines = append(lines, line)
	}
	return nil, false
}

// untilEnd returns every frame up to the end of the stream, or fails after d.
func (f *frames) untilEnd(t *testing.T, d time.Duration) [][]string {
	t.Helper()
	done := make(chan [][]string, 1)
	go func() {
		var all [][]string
		for {
			frame, ok := f.next()
			if !ok {
				done <- all
				return
			}
			all = append(all, frame)
		}
	}()
	select {
	case all := <-done:
		return all
	case <-time.After(d):
		_ = f.body.Close()
		t.Fatal("the event stream did not end")
		return nil
	}
}

func closedReason(t *testing.T, all [][]string) string {
	t.Helper()
	for _, frame := range all {
		if len(frame) == 2 && frame[0] == "event: closed" {
			var env wire.ErrorEnvelope
			if err := json.Unmarshal([]byte(strings.TrimPrefix(frame[1], "data: ")), &env); err != nil {
				t.Fatalf("closing frame: %v", err)
			}
			return string(env.Error.Reason()) + "/" + string(env.Error.Code)
		}
	}
	t.Fatalf("no closing frame in %v", all)
	return ""
}
