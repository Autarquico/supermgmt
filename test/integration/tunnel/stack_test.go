// Package tunnel holds the cross-cutting suites of the Cloudflare tunnel
// transport (docs/specs/cloudflare-tunnel-transport.md, ADR-0037).
//
// They run the real application stack in this process (SQLite, policy, the job
// store and engine, the node.setup and tunnel handlers, the SSH pool with the
// cloudflare dialler) against a hand-written Cloudflare API (cffake) and, where
// a node is needed, a Docker fixture (build tag `fixtures`). The Cloudflare
// carrier is test/fixtures/cloudflared-fake, which pipes its stdio to the
// fixture's sshd. They prove the seams, the state machine and secret handling,
// not Cloudflare's behaviour (the real-account checklist covers that).
package tunnel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/secrets"
	sshtransport "github.com/autarquico/supermgmt/internal/transport/ssh"
)

const (
	instanceName = "tunnel-suite"
	// Distinctive credential values the leak scans look for. The API token is
	// the one cffake accepts; the service token secret and the tunnel token
	// are minted by cffake and read back from it.
	seededAPIToken = "cf-api-token-LEAKCANARY-7c3f9d21e8b45a60"
)

// activeCredentials reports every credential active.
type activeCredentials struct{}

func (activeCredentials) Status(context.Context, domain.CredentialContext) (app.CredentialState, error) {
	return app.CredentialActive, nil
}

// stack is one SuperMgmt instance assembled in this process.
type stack struct {
	t     *testing.T
	dir   string
	clock domain.Clock
	ids   *domaintest.SequentialIDs

	db     *database.DB
	cf     *cffake.Fake
	cfgBlk config.Cloudflare
	store  *secrets.Store
	keys   *secrets.FileKeys
	// commands is every command the control plane ran on a node; logs is what
	// the job engine reported as infrastructure errors.
	commands *transcript
	logs     *transcript
	keysDir  string
	pool     *sshtransport.Pool
	dialer   *sshtransport.CloudflareDialer
	home     string // the carrier's HOME: its behaviour and records live here

	appCfg app.Config
	jobs   *jobs.Store
	plans  *app.Plans
	appr   *app.Approvals
	admin  app.Caller

	// denyAccess makes Access refuse every service token.
	denyAccess atomic.Bool
}

type stackOptions struct {
	// withoutCloudflare builds an instance with no cloudflare: block.
	withoutCloudflare bool
	// carrier is the path of the cloudflared stand-in; empty builds
	// test/fixtures/cloudflared-fake.
	carrier string
	// cfOptions are passed to cffake.New.
	cfOptions []cffake.Option
	// poolConfig overrides the pool settings.
	poolConfig *sshtransport.PoolConfig
}

// newStack assembles the instance and starts its job engine.
func newStack(t *testing.T, o stackOptions) *stack {
	t.Helper()
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "smt") // short: the SSH agent socket path is limited on macOS
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	clock := domain.SystemClock{}
	s := &stack{t: t, dir: dir, clock: clock, ids: domaintest.NewSequentialIDs(), keysDir: filepath.Join(dir, "keys"), home: filepath.Join(dir, "carrier-home")}
	must(t, os.MkdirAll(s.home, 0o700))

	s.db, err = database.Open(ctx, filepath.Join(dir, "sm.db"), database.Options{Clock: clock})
	must(t, err)
	t.Cleanup(func() { _ = s.db.Close() })
	must(t, s.db.Migrate(ctx))
	must(t, s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.CreateInstance(ctx, tx, database.Instance{ID: s.ids.NewID(), Name: instanceName, CreatedAt: clock.Now()})
	}))

	repo := app.NewSecretsKeyRepo(s.db, clock)
	s.keys, err = secrets.OpenFileKeys(ctx, s.keysDir, repo, s.ids)
	must(t, err)
	s.store = secrets.NewStore(s.keys, repo, s.ids, clock)
	s.commands, s.logs = &transcript{}, &transcript{}

	pol, err := policy.Default()
	must(t, err)
	s.appCfg = app.Config{
		DB: s.db, Clock: clock, IDs: s.ids, Policy: pol, Credentials: activeCredentials{},
		AllowSelfApproval: true, DefaultLogsMode: "journal-group",
	}

	poolCfg := defaultPoolConfig()
	if o.poolConfig != nil {
		poolCfg = *o.poolConfig
	}
	s.pool = sshtransport.NewPool(poolCfg, sshtransport.NewCredentials(s.store), clock)
	t.Cleanup(s.pool.Close)

	var tunnelOptions *app.TunnelOptions
	if !o.withoutCloudflare {
		s.cf = cffake.New(t, append([]cffake.Option{cffake.WithToken(seededAPIToken), cffake.WithClock(clock.Now)}, o.cfOptions...)...)
		s.cfgBlk = config.Cloudflare{
			AccountID: s.cf.AccountID(), Zone: zoneOf(s.cf), APITokenRef: config.DefaultCloudflareAPITokenRef,
			AccessTokenRef: config.DefaultCloudflareAccessTokenRef, OwnerEmails: []string{"owner@example.test"},
		}
		s.appCfg.Cloudflare = &s.cfgBlk
		_, err = s.store.Put(ctx, "cloudflare/api-token", audit.Secret(s.cf.Token()), nil)
		must(t, err)

		carrier := o.carrier
		if carrier == "" {
			carrier = buildCarrier(t)
		}
		s.dialer = sshtransport.NewCloudflareDialer(sshtransport.CloudflareConfig{
			Path: carrier, HomeDir: s.home, Tokens: app.AccessTokens(s.store, s.cfgBlk.AccessTokenRef),
			Preflight: s.preflight(), KillGrace: time.Second,
		})
		t.Cleanup(s.dialer.Close)
		s.pool.UseDialer(domain.TransportCloudflare, s.dialer)

		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(s.cf.CAPEM())
		tunnelOptions = &app.TunnelOptions{
			Config: s.cfgBlk, Secrets: s.store,
			NewAPI: func(account string, token audit.Secret) (app.CloudflareAPI, error) {
				return s.cloudflareClient(roots, account, token)
			},
		}
	}

	reval, err := app.NewRevalidator(s.appCfg)
	must(t, err)
	s.jobs, err = jobs.NewStore(jobs.Config{
		DB: s.db, Clock: clock, IDs: s.ids, Revalidator: reval, LockPlanner: app.LockPlanner{}, LeaseTTL: 30 * time.Second,
		BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond, // retries of an idempotent job do not wait seconds
	})
	must(t, err)
	s.plans, err = app.NewPlans(s.appCfg, s.jobs)
	must(t, err)
	s.appr, err = app.NewApprovals(s.appCfg, s.jobs)
	must(t, err)

	conn := app.Connector{Remote: recordingDialer{inner: s.pool, log: s.commands}}
	inventory, err := app.NewInventory(s.appCfg, app.InventoryOptions{Store: s.jobs, Connector: conn, Mode: config.ModeLocal})
	must(t, err)
	prober, err := app.NewProber(s.appCfg, conn, nil)
	must(t, err)
	handlers, err := app.NewHandlers(s.appCfg, app.HandlersOptions{
		Store: s.jobs, Connector: conn, Inventory: inventory, Prober: prober,
		Identity: app.SSHIdentityOf(s.store), Tunnel: tunnelOptions,
	})
	must(t, err)

	s.seedAdmin()
	s.runEngine(handlers.Map())
	return s
}

// zoneOf is the zone cffake serves.
func zoneOf(f *cffake.Fake) string {
	name, _ := f.Zone()
	return name
}

func defaultPoolConfig() sshtransport.PoolConfig {
	return sshtransport.PoolConfig{
		ConnectTimeout: 15 * time.Second, CommandTimeout: 60 * time.Second, KeepaliveInterval: 15 * time.Second,
		MaxDialsInFlight: 4, MaxConnections: 8, MaxSessionsPerConnection: 10, IdleConnectionTTL: time.Minute,
	}
}

// preflight is the Access probe of the dialler against a Cloudflare that
// behaves like Access: it admits a request only when the presented service
// token is a live token of cffake that a Service Auth policy lists, and
// answers the login redirect otherwise (or always, while denyAccess is set).
func (s *stack) preflight() *http.Client {
	return &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if !s.denyAccess.Load() && s.admits(r.Header.Get("CF-Access-Client-Id"), r.Header.Get("CF-Access-Client-Secret")) {
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
		}
		header := http.Header{"Location": []string{"https://team.cloudflareaccess.com/cdn-cgi/access/login/" + r.URL.Hostname()}}
		return &http.Response{StatusCode: http.StatusFound, Body: http.NoBody, Header: header, Request: r}, nil
	})}
}

func (s *stack) admits(clientID, clientSecret string) bool {
	snap := s.cf.Snapshot()
	for _, tok := range snap.ServiceTokens {
		if tok.ClientID != clientID || tok.ClientSecret != clientSecret {
			continue
		}
		for _, p := range snap.Policies {
			if p.Decision == "non_identity" && slices.Contains(p.ServiceTokenIDs, tok.ID) {
				return true
			}
		}
	}
	return false
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var (
	carrierOnce sync.Once
	carrierPath string
	carrierErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if carrierPath != "" {
		_ = os.RemoveAll(filepath.Dir(carrierPath))
	}
	os.Exit(code)
}

// buildCarrier builds test/fixtures/cloudflared-fake once per test binary, into
// a private directory under the package: the dialler refuses a cloudflared
// under /tmp, where the temporary directories live on Linux.
func buildCarrier(t *testing.T) string {
	t.Helper()
	carrierOnce.Do(func() {
		rel, err := os.MkdirTemp(".", ".trusted-carrier-")
		if err != nil {
			carrierErr = err
			return
		}
		dir, err := filepath.Abs(rel)
		if err != nil {
			carrierErr = err
			return
		}
		carrierPath = filepath.Join(dir, "cloudflared")
		build := exec.CommandContext(context.Background(), "go", "build", "-o", carrierPath, "github.com/autarquico/supermgmt/test/fixtures/cloudflared-fake")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			carrierErr = &buildError{out: string(out), err: err}
		}
	})
	if carrierErr != nil {
		t.Fatalf("build the cloudflared stand-in: %v", carrierErr)
	}
	return carrierPath
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

// seedAdmin creates the human who plans, submits and approves.
func (s *stack) seedAdmin() {
	s.t.Helper()
	id := s.ids.NewID()
	must(s.t, s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		now := s.clock.Now()
		if err := database.CreateIdentity(ctx, tx, database.Identity{ID: id, ActorType: domain.ActorHuman, Subject: "root", CreatedAt: now}); err != nil {
			return err
		}
		role, err := database.GetRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: s.ids.NewID(), IdentityID: id, RoleID: role.ID, CreatedAt: now})
	}))
	s.admin = app.Caller{ID: id, Credential: domain.CredentialContext{Kind: domain.CredentialAPIToken, ID: "token-" + id.String(), Scopes: []string{}}}
}

func (s *stack) runEngine(handlers map[string]jobs.Handler) {
	s.t.Helper()
	engine, err := jobs.NewEngine(jobs.EngineConfig{
		Store: s.jobs, Handlers: handlers, Workers: 2,
		PollInterval: 5 * time.Millisecond, HeartbeatInterval: 100 * time.Millisecond, ReconcileInterval: time.Hour,
		OnError: func(err error) { s.logs.add("engine", err.Error()) },
	})
	must(s.t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = engine.Run(ctx)
	}()
	s.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			s.t.Error("the job engine did not stop")
		}
	})
}

// addNode stores an ssh node in a development environment.
func (s *stack) addNode(name string, endpoint domain.NodeEndpoint, credentialRef string) domain.Node {
	s.t.Helper()
	var node domain.Node
	must(s.t, s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		now := s.clock.Now()
		provider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: s.ids.NewID(), Type: "ssh", Name: name, Origin: domain.ProviderStatic, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		env, err := database.CreateEnvironment(ctx, tx, domain.Environment{ID: s.ids.NewID(), Name: "dev-" + name, RiskLevel: domain.EnvironmentDevelopment})
		if err != nil {
			return err
		}
		defer func() {
			if err == nil {
				err = database.SetNodeCapability(ctx, tx, node.ID, database.NodeCapability{Capability: "node.ssh", Available: true, CheckedAt: now})
			}
		}()
		node, err = database.CreateNode(ctx, tx, domain.Node{
			ID: s.ids.NewID(), ProviderID: provider.ID, NativeID: name, Name: name, Kind: "ssh", EnvironmentID: &env.ID,
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown, Endpoint: endpoint,
			CredentialRef: credentialRef, CreatedAt: now, UpdatedAt: now,
		})
		return err
	}))
	return node
}

func (s *stack) node(id domain.ID) domain.Node {
	s.t.Helper()
	n, err := database.GetNode(context.Background(), s.db.Reader(), id)
	must(s.t, err)
	return n
}

// run is tryRun for an action that must be accepted.
func (s *stack) run(action string, target domain.ResourceRef, params map[string]any) jobs.Job {
	s.t.Helper()
	job, err := s.tryRun(action, target, params)
	must(s.t, err)
	return job
}

// tryRun plans, submits and (when policy asks) approves an action, then waits
// for the job to reach a final state. The error is a refusal at planning or
// submission; a job that fails is returned in its failed state.
func (s *stack) tryRun(action string, target domain.ResourceRef, params map[string]any) (jobs.Job, error) {
	s.t.Helper()
	ctx := context.Background()
	created, err := s.plans.Create(ctx, s.admin, app.PlanRequest{Action: action, Target: target, Parameters: params})
	if err != nil {
		return jobs.Job{}, err
	}
	sub, err := s.plans.Submit(ctx, s.admin, created.Record.ID, created.Record.PlanHash)
	if err != nil {
		return jobs.Job{}, err
	}
	job := sub.Job
	if job.State == domain.JobAwaitingApproval {
		if job, err = s.appr.Approve(ctx, s.admin, app.DecisionRequest{JobID: job.ID, PlanHash: job.PlanHash, Reason: "tunnel suite"}); err != nil {
			return jobs.Job{}, err
		}
	}
	return s.wait(job.ID, 3*time.Minute), nil
}

// setRawEndpoint overwrites a node's endpoint JSON, as a hand-edited database
// or a hostile backup would: the write path of the application refuses what
// this puts in.
func (s *stack) setRawEndpoint(id domain.ID, endpointJSON string) {
	s.t.Helper()
	must(s.t, s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE nodes SET endpoint_json = ? WHERE id = ?`, endpointJSON, id)
		return err
	}))
}

// carrierStarts is the number of cloudflared processes the dialler started:
// the stand-in records itself in the dialler's private HOME before anything else.
func (s *stack) carrierStarts() int {
	return len(s.carrierRecords())
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (s *stack) wait(id domain.ID, within time.Duration) jobs.Job {
	s.t.Helper()
	deadline := time.Now().Add(within) //nolint:forbidigo // wall-clock budget of a polling loop
	for time.Now().Before(deadline) {  //nolint:forbidigo // see above
		job, err := s.jobs.Get(context.Background(), s.db.Reader(), id)
		must(s.t, err)
		if slices.Contains([]domain.JobState{domain.JobSucceeded, domain.JobFailed, domain.JobCancelled}, job.State) {
			return job
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatalf("job %s did not finish within %s", id, within)
	return jobs.Job{}
}

func nodeRef(n domain.Node) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceNode, ID: n.ID}
}

func (s *stack) instanceRef() domain.ResourceRef {
	s.t.Helper()
	i, err := database.GetInstance(context.Background(), s.db.Reader())
	must(s.t, err)
	return domain.ResourceRef{Type: domain.ResourceInstance, ID: i.ID}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// carrierRecord is what the cloudflared stand-in saw when it was started.
type carrierRecord struct {
	PID  int      `json:"pid"`
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
}

func (s *stack) carrierRecords() []carrierRecord {
	s.t.Helper()
	files, err := filepath.Glob(filepath.Join(s.home, "record-*.json"))
	must(s.t, err)
	out := make([]carrierRecord, 0, len(files))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		must(s.t, err)
		var r carrierRecord
		must(s.t, json.Unmarshal(raw, &r))
		out = append(out, r)
	}
	return out
}

// outcome describes what a tryRun ended with, for failure messages and logs.
func outcome(job jobs.Job, err error) string {
	switch {
	case err != nil:
		return "refused: " + err.Error()
	case job.Error != nil:
		return string(job.State) + ": " + string(job.Error.Code) + " " + job.Error.Message
	}
	return string(job.State)
}

// setTunnelEndpoint makes the node a cloudflare node with exactly this tunnel
// hostname, valid or not.
func (s *stack) setTunnelEndpoint(id domain.ID, hostname string) {
	s.t.Helper()
	doc, err := json.Marshal(map[string]any{
		"host": "192.0.2.10", "port": 22, "user": "supermgmt", "admin_user": "admin", "admin_credential_ref": "ssh-agent://default",
		"host_public_key": s.node(id).Endpoint.HostPublicKey, "transport": "cloudflare", "tunnel_hostname": hostname,
	})
	must(s.t, err)
	s.setRawEndpoint(id, string(doc))
}

// unreachable is the endpoint of a node nothing answers at (TEST-NET-1).
func unreachable(t *testing.T) domain.NodeEndpoint {
	t.Helper()
	return domain.NodeEndpoint{
		Host: "192.0.2.10", Port: 22, User: "supermgmt", AdminUser: "admin", AdminCredentialRef: "ssh-agent://default",
		HostPublicKey: hostKey(t),
	}
}

func (s *stack) cloudflareClient(roots *x509.CertPool, account string, token audit.Secret) (*cloudflare.Client, error) {
	return cloudflare.New(s.cf.Endpoint(), account, token,
		cloudflare.WithNetguardOptions(netguard.WithRootCAs(roots), netguard.WithTestDialer(s.cf.Dial)))
}

// newCloudflareClient is a client for the test's own reads of the fake.
func (s *stack) newCloudflareClient() (*cloudflare.Client, error) {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(s.cf.CAPEM())
	return s.cloudflareClient(roots, s.cf.AccountID(), audit.Secret(s.cf.Token()))
}
