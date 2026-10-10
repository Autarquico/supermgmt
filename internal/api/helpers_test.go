package api

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// harness is a real server over a migrated database, listening on a Unix
// socket in a short temp dir (sun_path is 104 bytes on macOS).
type harness struct {
	t      *testing.T
	db     *database.DB
	server *Server
	socket string
	http   *http.Client
	caller domain.ID
	ids    domain.IDGenerator
}

type harnessOptions struct {
	roles  []string // roles of the caller; default admin
	peer   PeerLookup
	uid    *uint32
	cached Residency
}

func newHarness(t *testing.T, opts ...func(*harnessOptions)) *harness {
	t.Helper()
	o := harnessOptions{roles: []string{"admin"}, peer: PeerUID}
	for _, f := range opts {
		f(&o)
	}
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "sma")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	clock, ids := domain.SystemClock{}, domain.UUIDv7Generator{}
	db, err := database.Open(ctx, filepath.Join(dir, "db"), database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: db, ids: ids, socket: filepath.Join(dir, "s"), caller: ids.NewID()}
	h.seedCaller(o.roles, clock)

	pol, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	cfg := app.Config{DB: db, Clock: clock, IDs: ids, Policy: pol, Credentials: app.LocalSocketCredentials{}}
	h.server = h.build(cfg, o)

	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	if o.uid != nil {
		uid = *o.uid
	}
	go func() { _ = h.server.Serve(RestrictToUID(listener, uid, o.peer, nil)) }()
	t.Cleanup(func() { _ = h.server.Shutdown(context.Background()) })
	h.http = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", h.socket)
		},
	}}
	t.Cleanup(h.http.CloseIdleConnections)
	return h
}

func (h *harness) seedCaller(roles []string, clock domain.Clock) {
	h.t.Helper()
	err := h.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateIdentity(ctx, tx, database.Identity{ID: h.caller, ActorType: domain.ActorHuman, Subject: "local:1", CreatedAt: clock.Now()})
		if err != nil {
			return err
		}
		for _, name := range roles {
			role, err := database.GetRoleByName(ctx, tx, name)
			if err != nil {
				return err
			}
			err = database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: h.ids.NewID(), IdentityID: h.caller, RoleID: role.ID, CreatedAt: clock.Now()})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) build(cfg app.Config, o harnessOptions) *Server {
	h.t.Helper()
	reval, err := app.NewRevalidator(cfg)
	must(h.t, err)
	store, err := jobs.NewStore(jobs.Config{DB: cfg.DB, Clock: cfg.Clock, IDs: cfg.IDs, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	must(h.t, err)
	plans, err := app.NewPlans(cfg, store)
	must(h.t, err)
	approvals, err := app.NewApprovals(cfg, store)
	must(h.t, err)
	governance, err := app.NewGovernance(cfg, store)
	must(h.t, err)
	actions, err := app.NewServices(cfg, store)
	must(h.t, err)
	queries, err := app.NewQueries(cfg, store, config.ModeLocal)
	must(h.t, err)
	inventory, err := app.NewInventory(cfg, app.InventoryOptions{Store: store, Connector: app.Connector{}, Mode: config.ModeLocal})
	must(h.t, err)
	sessions, err := app.NewSessions(cfg)
	must(h.t, err)
	keys, err := NewSSHKeys(cfg, func(context.Context) (secrets.Identity, error) {
		return secrets.Identity{Ref: secrets.Ref{Name: "ssh/default", Version: 1}, AuthorizedKey: "ssh-ed25519 AAAA", FingerprintSHA256: "SHA256:x"}, nil
	})
	must(h.t, err)
	server, err := New(Options{
		Services: Services{
			Plans: plans, Approvals: approvals, Governance: governance, Services: actions,
			Queries: queries, Inventory: inventory, Sessions: sessions, SSHKeys: keys,
		},
		IDs: cfg.IDs, Identity: h.caller, Residency: o.cached,
	})
	must(h.t, err)
	return server
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type reply struct {
	Status int
	Header http.Header
	Body   []byte
}

func (h *harness) do(method, path string, body string, headers map[string]string) reply {
	h.t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "http://sm"+path, reader)
	must(h.t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.http.Do(req)
	must(h.t, err)
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	must(h.t, err)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: payload}
}

func (h *harness) post(path, body, key string) reply {
	h.t.Helper()
	headers := map[string]string{}
	if key != "" {
		headers[wire.HeaderIdempotencyKey] = key
	}
	return h.do(http.MethodPost, path, body, headers)
}
