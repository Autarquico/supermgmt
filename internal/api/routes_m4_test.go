package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/github"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	m4AdminToken = "admin-token"
	m4OIDCToken  = "oidc-token"
)

// m4Clients is a GitHubClients with no network: no test here reaches GitHub.
type m4Clients struct{}

func (m4Clients) For(context.Context, domain.ID) (github.Client, error) {
	return nil, smerr.New(smerr.CodeProviderError, "", "no GitHub in route tests")
}

// m4Resolver maps the two fixed test tokens to callers.
type m4Resolver struct{ admin, oidc app.Caller }

func (r m4Resolver) Resolve(_ context.Context, bearer string) (app.Caller, error) {
	switch bearer {
	case m4AdminToken:
		return r.admin, nil
	case m4OIDCToken:
		return r.oidc, nil
	}
	return app.Caller{}, smerr.New(smerr.CodeUnauthenticated, "", "unknown token")
}

type m4Nudges struct {
	mu    sync.Mutex
	calls []nudgeCall
}

type nudgeCall struct {
	repositoryID int64
	sha          string
}

func (n *m4Nudges) Nudge(repositoryID int64, sha string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, nudgeCall{repositoryID, sha})
}

func (n *m4Nudges) seen() []nudgeCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]nudgeCall(nil), n.calls...)
}

type m4Secrets map[string]audit.Secret

func (s m4Secrets) Get(_ context.Context, ref secrets.Ref) (audit.Secret, error) {
	if v, ok := s[ref.Name]; ok {
		return v, nil
	}
	return "", smerr.New(smerr.CodeNotFound, "", "no such secret")
}

// m4Fixture is an HTTPS-transport server with the M4 services, a webhook and
// two callers: an admin and a GitHub Actions OIDC automation identity.
type m4Fixture struct {
	t       *testing.T
	db      *database.DB
	clock   *domaintest.FakeClock
	ids     domain.IDGenerator
	server  *Server
	svc     Services
	nudges  *m4Nudges
	secrets m4Secrets
	baseURL string
	oidc    domain.ID
}

func newM4Fixture(t *testing.T) *m4Fixture {
	t.Helper()
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

	f := &m4Fixture{t: t, db: db, clock: clock, ids: ids, nudges: &m4Nudges{}, secrets: m4Secrets{}}
	f.svc = m4Services(t, cfg, store)
	f.server, err = New(Options{
		Services: f.svc, IDs: ids, DB: db, Clock: clock,
		Resolver:      m4Resolver{admin: f.seedAdmin(), oidc: f.seedOIDC()},
		GitHubWebhook: &GitHubWebhook{DB: db, Secrets: f.secrets, Watcher: f.nudges},
	})
	must(t, err)
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	must(t, err)
	go func() { _ = f.server.Serve(listener) }()
	t.Cleanup(func() { _ = f.server.Shutdown(context.Background()) })
	f.baseURL = "http://" + listener.Addr().String()
	return f
}

func m4Services(t *testing.T, cfg app.Config, store *jobs.Store) Services {
	t.Helper()
	svc := remoteServices(t, cfg, store)
	var err error
	svc.Apps, err = app.NewApps(cfg, store, m4Clients{})
	must(t, err)
	svc.Repositories, err = app.NewRepositories(cfg, m4Clients{})
	must(t, err)
	deployments, err := app.NewDeployments(cfg, svc.Governance, app.CIPolling{Server: true})
	must(t, err)
	svc.Deployments, err = app.NewDeploymentFinalizer(deployments, app.FinalizerDeps{Clients: m4Clients{}, Jobs: store})
	must(t, err)
	return svc
}

func (f *m4Fixture) seedAdmin() app.Caller {
	f.t.Helper()
	id := f.ids.NewID()
	must(f.t, f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		if err := database.CreateIdentity(ctx, tx, database.Identity{ID: id, ActorType: domain.ActorHuman, Subject: id.String(), CreatedAt: f.clock.Now()}); err != nil {
			return err
		}
		role, err := database.GetRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: f.ids.NewID(), IdentityID: id, RoleID: role.ID, CreatedAt: f.clock.Now()})
	}))
	return app.Caller{ID: id, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}, Source: "api"}
}

// seedOIDC registers an automation identity with an open github_oidc credential.
func (f *m4Fixture) seedOIDC() app.Caller {
	f.t.Helper()
	id, credential := f.ids.NewID(), database.GithubOIDCCredentialID(github.ActionsIssuer, "jti-1")
	expires := f.clock.Now().Add(time.Hour)
	must(f.t, f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: id, ActorType: domain.ActorAutomation, Issuer: github.ActionsIssuer, Subject: "repository_id:1:workflow:deploy.yml", CreatedAt: f.clock.Now(),
		})
		if err != nil {
			return err
		}
		return database.InsertGithubOIDCCredential(ctx, tx, database.GithubOIDCCredential{
			ID: credential, IdentityID: id, RepositoryID: 1, IssuedAt: f.clock.Now(), ExpiresAt: expires, CreatedAt: f.clock.Now(),
		})
	}))
	f.oidc = id
	return app.Caller{
		ID:         id,
		Credential: domain.CredentialContext{Kind: domain.CredentialGitHubOIDC, ID: credential, Scopes: auth.GitHubScopes, ExpiresAt: &expires},
		Source:     "api",
	}
}

func (f *m4Fixture) do(method, path, token, body string, headers ...string) reply {
	f.t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, f.baseURL+path, reader)
	must(f.t, err)
	if token != "" {
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	must(f.t, err)
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	must(f.t, err)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: payload}
}

func errorReasonOf(t *testing.T, r reply) smerr.Reason {
	t.Helper()
	var env struct {
		Error struct {
			Details struct {
				Reason smerr.Reason `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(r.Body, &env); err != nil {
		t.Fatalf("not an error envelope: %s", r.Body)
	}
	return env.Error.Details.Reason
}

// wantM4Routes is the M4 surface (spec §23, ADR-0011) and the action each
// route stands for.
var wantM4Routes = map[string]string{
	"GET " + wire.PathApps:                 "app.read",
	"POST " + wire.PathApps:                "app.write",
	"GET " + wire.PathApp:                  "app.read",
	"PATCH " + wire.PathApp:                "app.write",
	"GET " + wire.PathAppTargets:           "app_target.read",
	"POST " + wire.PathAppTargets:          "app_target.write",
	"GET " + wire.PathAppTarget:            "app_target.read",
	"PATCH " + wire.PathAppTarget:          "app_target.write",
	"GET " + wire.PathProviderRepositories: "provider.read",
	"GET " + wire.PathDeployments:          "deployment.read",
	"POST " + wire.PathDeployments:         "deployment.create",
	"GET " + wire.PathDeployment:           "deployment.read",
	"POST " + wire.PathDeploymentRollback:  "deployment.rollback",
	"POST " + wire.PathDeploymentCancel:    "job.cancel",
	"POST " + wire.PathGitHubWebhook:       ExemptWebhook,
}

func TestEveryM4RouteMapsToExactlyOneCatalogActionOrExemption(t *testing.T) {
	f := newM4Fixture(t)
	got := map[string]Route{}
	for _, rt := range f.server.Routes() {
		got[rt.Method+" "+rt.Pattern] = rt
	}
	for key, action := range wantM4Routes {
		rt, ok := got[key]
		if !ok {
			t.Errorf("route %s is not served", key)
			continue
		}
		if rt.Action != action {
			t.Errorf("%s maps to %q, want %q", key, rt.Action, action)
		}
		_, inCatalog := policy.Lookup(rt.Action)
		if inCatalog == (rt.Action == ExemptWebhook) {
			t.Errorf("%s: %q is neither a catalog action nor the webhook exemption", key, rt.Action)
		}
		wantKeyed := rt.Method != http.MethodGet && rt.Action != ExemptWebhook
		if rt.Keyed != wantKeyed {
			t.Errorf("%s: keyed = %v, want %v", key, rt.Keyed, wantKeyed)
		}
	}
}

func TestTheWebhookIsNotServedOnTheLocalSocket(t *testing.T) {
	f := newM4Fixture(t)
	local, err := New(Options{
		Services: f.svc, IDs: f.ids, Identity: f.ids.NewID(),
		GitHubWebhook: &GitHubWebhook{DB: f.db, Secrets: f.secrets, Watcher: f.nudges},
	})
	must(t, err)
	for _, rt := range local.Routes() {
		if rt.Pattern == wire.PathGitHubWebhook {
			t.Errorf("the local socket serves %s %s", rt.Method, rt.Pattern)
		}
	}
}

// pathFor fills the placeholders of a route pattern with valid ids.
func (f *m4Fixture) pathFor(pattern string) string {
	return wire.Path(pattern, f.ids.NewID().String(), f.ids.NewID().String())
}

func TestOIDCTokenIsRefusedOnEveryRouteButDeploymentCreateAndRead(t *testing.T) {
	f := newM4Fixture(t)
	for _, rt := range f.server.Routes() {
		if rt.Action == "deployment.create" || rt.Action == "deployment.read" || rt.Action == ExemptHealth || rt.Action == ExemptWebhook || rt.Action == ExemptAuth || rt.Pattern == wire.PathEnroll {
			continue
		}
		body := ""
		if rt.Method != http.MethodGet {
			body = "{}"
		}
		r := f.do(rt.Method, f.pathFor(rt.Pattern), m4OIDCToken, body)
		if r.Status != http.StatusForbidden || errorReasonOf(t, r) != smerr.ReasonScopeDenied {
			t.Errorf("%s %s: status %d body %s, want 403 SCOPE_DENIED", rt.Method, rt.Pattern, r.Status, r.Body)
		}
	}
}

func TestOIDCTokenReachesDeploymentCreateAndRead(t *testing.T) {
	f := newM4Fixture(t)
	list := f.do(http.MethodGet, wire.PathDeployments, m4OIDCToken, "")
	if list.Status != http.StatusOK {
		t.Errorf("GET /deployments: status %d body %s", list.Status, list.Body)
	}
	create := f.do(http.MethodPost, wire.PathDeployments, m4OIDCToken, `{"kind":"deploy"}`, wire.HeaderIdempotencyKey, "k1")
	if create.Status != http.StatusBadRequest {
		t.Errorf("POST /deployments with an incomplete body: status %d body %s, want it validated (400)", create.Status, create.Body)
	}
}

func TestM4RoutesValidateTheirInput(t *testing.T) {
	f := newM4Fixture(t)
	key := []string{wire.HeaderIdempotencyKey, "k"}
	cases := []struct {
		name         string
		method, path string
		body         string
		headers      []string
		status       int
	}{
		{"apps list", http.MethodGet, wire.PathApps, "", nil, http.StatusOK},
		{"deployments list", http.MethodGet, wire.PathDeployments, "", nil, http.StatusOK},
		{"unknown deployment state", http.MethodGet, wire.PathDeployments + "?state=bogus", "", nil, http.StatusBadRequest},
		{"filter by a non-id", http.MethodGet, wire.PathDeployments + "?app_id=x", "", nil, http.StatusBadRequest},
		{"rollback kind on the create route", http.MethodPost, wire.PathDeployments, `{"kind":"rollback"}`, key, http.StatusBadRequest},
		{"create without an Idempotency-Key", http.MethodPost, wire.PathDeployments, `{"kind":"deploy"}`, nil, http.StatusBadRequest},
		{"unknown field", http.MethodPost, wire.PathDeployments, `{"kind":"deploy","x":1}`, key, http.StatusBadRequest},
		{"app id that is not an id", http.MethodGet, wire.Path(wire.PathApp, "nope"), "", nil, http.StatusBadRequest},
		{"unknown app", http.MethodGet, f.pathFor(wire.PathApp), "", nil, http.StatusNotFound},
		{"patch without If-Match", http.MethodPatch, f.pathFor(wire.PathApp), `{}`, key, http.StatusBadRequest},
		{"cancel unknown deployment", http.MethodPost, f.pathFor(wire.PathDeploymentCancel), "", key, http.StatusNotFound},
	}
	for _, tc := range cases {
		headers := append([]string(nil), tc.headers...)
		if tc.body != "" || tc.method != http.MethodGet {
			headers = append(headers, "Content-Type", "application/json")
		}
		if r := f.do(tc.method, tc.path, m4AdminToken, tc.body, headers...); r.Status != tc.status {
			t.Errorf("%s: status %d body %s, want %d", tc.name, r.Status, r.Body, tc.status)
		}
	}
}

func TestM4RoutesNeedAToken(t *testing.T) {
	f := newM4Fixture(t)
	for _, path := range []string{wire.PathApps, wire.PathDeployments} {
		if r := f.do(http.MethodGet, path, "", ""); r.Status != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: status %d", path, r.Status)
		}
	}
}

func TestM4RoutesAreAbsentWithoutTheirServices(t *testing.T) {
	f := newM4Fixture(t)
	svc := f.svc
	svc.Apps, svc.Repositories, svc.Deployments = nil, nil, nil
	bare, err := New(Options{Services: svc, IDs: f.ids, Resolver: m4Resolver{}})
	must(t, err)
	for _, rt := range bare.Routes() {
		if _, m4 := wantM4Routes[rt.Method+" "+rt.Pattern]; m4 {
			t.Errorf("%s %s is served without its service", rt.Method, rt.Pattern)
		}
	}
}
