package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/github"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const mcpRigToken = "smm_integration-rig-token"

// mcpRigGrant lets an mcp actor ask for every action: the writes gate and the
// forbidden set must hold even then (ADR-0032).
const mcpRigGrant = `
  - name: rig-mcp-everything
    subjects: ["type:mcp"]
    allow: ["*"]
`

// mcpRigResolver admits one fixed MCP token on the socket.
type mcpRigResolver struct{ caller app.Caller }

func (r mcpRigResolver) Resolve(_ context.Context, bearer string) (app.Caller, error) {
	if bearer == mcpRigToken {
		return r.caller, nil
	}
	return app.Caller{}, smerr.New(smerr.CodeUnauthenticated, "", "unknown token")
}

// mcpRigGitHub is a GitHubClients with no network: no route here reaches GitHub.
type mcpRigGitHub struct{}

func (mcpRigGitHub) For(context.Context, domain.ID) (github.Client, error) {
	return nil, smerr.New(smerr.CodeProviderError, "", "no GitHub in the rig")
}

// mcpRigRuntime is the only fake of the rig: the SSH boundary to a node. It
// answers every command with a short log and counts the commands, so a test
// can tell that a refused write never reached a node.
type mcpRigRuntime struct{ commands atomic.Int64 }

func (r *mcpRigRuntime) For(ssh.Target) transport.Executor { return r }

func (r *mcpRigRuntime) State(domain.ID) ssh.ConnState { return ssh.ConnState{} }

func (r *mcpRigRuntime) Invalidate(domain.ID, string) {}

func (r *mcpRigRuntime) Run(context.Context, templates.Command) (transport.Result, error) {
	r.commands.Add(1)
	return transport.Result{Stdout: []byte("listening on :8080\nready\n")}, nil
}

// mcpRigReply is one HTTP answer.
type mcpRigReply struct {
	status int
	header http.Header
	body   []byte
}

func (r mcpRigReply) reason(t *testing.T) smerr.Reason {
	t.Helper()
	var env struct {
		Error struct {
			Details struct {
				Reason smerr.Reason `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(r.body, &env); err != nil {
		t.Fatalf("not an error envelope (status %d): %s", r.status, r.body)
	}
	return env.Error.Details.Reason
}

func (r mcpRigReply) data(t *testing.T, into any) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(r.body, &env); err != nil || json.Unmarshal(env.Data, into) != nil {
		t.Fatalf("not a data envelope (status %d): %s", r.status, r.body)
	}
}

// mcpRigTransport is how a request reaches the API: the Unix socket with the
// MCP bearer, or in process with the MCP caller stamped.
type mcpRigTransport string

const (
	mcpRigSocket    mcpRigTransport = "socket"
	mcpRigInProcess mcpRigTransport = "in-process"
	// mcpRigLocalUser is the human on the socket without a token. It only
	// builds fixtures; it is never a subject of the matrix.
	mcpRigLocalUser mcpRigTransport = "local-user"
)

// mcpRig is a real database, real app services (nothing mocked but the
// runtimes, which no route here reaches), the real API server on a Unix
// socket and an `mcp` caller with a `*` grant. Fixtures are a node, a service,
// an app with a target and a plan, so that every route has a concrete valid
// request.
type mcpRig struct {
	t      *testing.T
	db     *database.DB
	clock  *domaintest.FakeClock
	ids    domain.IDGenerator
	server *api.Server
	writes bool

	admin, mcp app.Caller
	fixtures   map[string]string
	runtime    *mcpRigRuntime

	socket *http.Client
	inproc *http.Client
}

func newMCPRig(t *testing.T, writes bool) *mcpRig {
	t.Helper()
	ctx := context.Background()
	clock, ids := domaintest.NewFakeClock(epoch), domain.UUIDv7Generator{}
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	mcpRigMust(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mcpRigMust(t, db.Migrate(ctx))

	pol, err := policy.Parse(append(policy.DefaultYAML(), []byte(mcpRigGrant)...))
	mcpRigMust(t, err)
	cfg := app.Config{DB: db, Clock: clock, IDs: ids, Policy: pol, Credentials: activeCredentials{}, MCPWritesEnabled: writes}

	rig := &mcpRig{t: t, db: db, clock: clock, ids: ids, writes: writes, fixtures: map[string]string{}, runtime: &mcpRigRuntime{}}
	rig.seedIdentities()
	rig.seedInventory()
	rig.server = rig.startServer(ctx, cfg)
	rig.listen()
	rig.seedPlan()
	rig.seedGovernedResources()
	rig.runtime.commands.Store(0)
	return rig
}

func mcpRigMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (rig *mcpRig) inTx(fn func(ctx context.Context, tx *database.Tx) error) {
	rig.t.Helper()
	mcpRigMust(rig.t, rig.db.WithWriteTx(context.Background(), fn))
}

func (rig *mcpRig) seedIdentities() {
	rig.t.Helper()
	rig.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := rig.clock.Now()
		adminID, mcpID := rig.ids.NewID(), rig.ids.NewID()
		for _, identity := range []database.Identity{
			{ID: adminID, ActorType: domain.ActorHuman, Subject: "rig-admin", CreatedAt: now},
			{ID: mcpID, ActorType: domain.ActorMCP, Subject: mcpID.String(), CreatedAt: now},
		} {
			if err := database.CreateIdentity(ctx, tx, identity); err != nil {
				return err
			}
		}
		role, err := database.GetRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		err = database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: rig.ids.NewID(), IdentityID: adminID, RoleID: role.ID, CreatedAt: now})
		rig.admin = app.Caller{ID: adminID, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}, Source: "api"}
		rig.mcp = app.Caller{ID: mcpID, Credential: domain.CredentialContext{Kind: domain.CredentialMCPToken, ID: rig.ids.NewID().String()}, Source: "api"}
		return err
	})
}

func (rig *mcpRig) seedInventory() {
	rig.t.Helper()
	rig.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := rig.clock.Now()
		if err := database.CreateInstance(ctx, tx, database.Instance{ID: rig.ids.NewID(), Name: "rig", CreatedAt: now}); err != nil {
			return err
		}
		provider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: rig.ids.NewID(), Type: "ssh", Name: "ssh-hosts", Origin: domain.ProviderStatic, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		env, err := database.CreateEnvironment(ctx, tx, domain.Environment{ID: rig.ids.NewID(), Name: "dev", RiskLevel: domain.EnvironmentDevelopment})
		if err != nil {
			return err
		}
		if _, err := database.CreateEnvironment(ctx, tx, domain.Environment{ID: rig.ids.NewID(), Name: "staging", RiskLevel: domain.EnvironmentDevelopment}); err != nil {
			return err
		}
		node, err := database.CreateNode(ctx, tx, domain.Node{
			ID: rig.ids.NewID(), ProviderID: provider.ID, NativeID: "dev-1", Name: "dev-1", Kind: "ssh",
			EnvironmentID: &env.ID, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			Tags: []string{"web"}, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		for _, capability := range []string{"node.reboot", "node.read", "service.start", "service.stop", "service.restart", "service.logs", "service.read", "docker.compose.deploy", "node.ssh"} {
			if err := database.SetNodeCapability(ctx, tx, node.ID, database.NodeCapability{Capability: capability, Available: true, CheckedAt: now}); err != nil {
				return err
			}
		}
		if err := rig.completeSetup(ctx, tx, node.ID); err != nil {
			return err
		}
		service, err := rig.seedService(ctx, tx, node.ID, "web")
		if err != nil {
			return err
		}
		prod, err := database.CreateEnvironment(ctx, tx, domain.Environment{ID: rig.ids.NewID(), Name: "prod", RiskLevel: domain.EnvironmentProduction, ApprovalsRequired: 2})
		if err != nil {
			return err
		}
		prodNode, err := database.CreateNode(ctx, tx, domain.Node{
			ID: rig.ids.NewID(), ProviderID: provider.ID, NativeID: "web-1", Name: "web-1", Kind: "ssh",
			EnvironmentID: &prod.ID, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		for _, capability := range []string{"node.read", "service.read", "service.restart"} {
			if err := database.SetNodeCapability(ctx, tx, prodNode.ID, database.NodeCapability{Capability: capability, Available: true, CheckedAt: now}); err != nil {
				return err
			}
		}
		if err := rig.completeSetup(ctx, tx, prodNode.ID); err != nil {
			return err
		}
		prodService, err := rig.seedService(ctx, tx, prodNode.ID, "api")
		if err != nil {
			return err
		}
		proxmox, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: rig.ids.NewID(), Type: "proxmox", Name: "pve", Origin: domain.ProviderAPI, Endpoint: "https://127.0.0.1:1", CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		githubProvider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: rig.ids.NewID(), Type: "github", Name: "gh", Origin: domain.ProviderAPI, Endpoint: "https://127.0.0.1:1", CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		apiNode, err := database.CreateNode(ctx, tx, domain.Node{
			ID: rig.ids.NewID(), ProviderID: proxmox.ID, NativeID: "pve/101", Name: "vm-101", Kind: "proxmox-vm",
			EnvironmentID: &env.ID, ManagementState: domain.ManagementDiscovered, Reachability: domain.ReachabilityUnknown, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		rig.fixtures["prod_service"], rig.fixtures["node_api"] = prodService.ID.String(), apiNode.ID.String()
		rig.fixtures["provider_proxmox"], rig.fixtures["provider_github"] = proxmox.ID.String(), githubProvider.ID.String()
		rig.fixtures["provider"], rig.fixtures["environment"] = provider.ID.String(), env.ID.String()
		rig.fixtures["node"], rig.fixtures["service"] = node.ID.String(), service.ID.String()
		return nil
	})
}

// completeSetup records node.setup as done, with Docker access, so that the
// service actions of a container are granted on the node.
func (rig *mcpRig) completeSetup(ctx context.Context, tx *database.Tx, node domain.ID) error {
	return database.SetNodeCapability(ctx, tx, node, database.NodeCapability{
		Capability: "node.setup", Available: true, CheckedAt: rig.clock.Now(),
		Metadata: map[string]any{
			"setup_version": 1, "systemctl_path": "/usr/bin/systemctl", "units": []any{}, "logs_mode": "journal-group",
			"docker_access": true, "key_ref": "secret://ssh/rig", "key_version": 1, "key_fingerprint": "SHA256:rig",
		},
	})
}

func (rig *mcpRig) seedService(ctx context.Context, tx *database.Tx, node domain.ID, name string) (domain.Service, error) {
	now := rig.clock.Now()
	runtime := domain.Runtime{ID: rig.ids.NewID(), NodeID: node, Type: "docker", NativeID: "docker", Status: "running", LastSeenAt: &now}
	if err := database.CreateRuntime(ctx, tx, runtime); err != nil {
		return domain.Service{}, err
	}
	return database.CreateService(ctx, tx, domain.Service{
		ID: rig.ids.NewID(), RuntimeID: runtime.ID, NodeID: node, NativeID: "c-" + name, Name: name, Kind: string(domain.ServiceDockerContainer),
		Status: "running", Health: "healthy", LastSeenAt: &now,
	})
}

// startServer builds the real services the daemon would, except the ones that
// need the network (GitHub clients, the Proxmox sync's HTTP), and serves them.
func (rig *mcpRig) startServer(ctx context.Context, cfg app.Config) *api.Server {
	t := rig.t
	reval, err := app.NewRevalidator(cfg)
	mcpRigMust(t, err)
	store, err := jobs.NewStore(jobs.Config{DB: rig.db, Clock: rig.clock, IDs: rig.ids, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	mcpRigMust(t, err)

	keysDir := filepath.Join(t.TempDir(), "keys")
	repo := app.NewSecretsKeyRepo(rig.db, rig.clock)
	keys, err := secrets.OpenFileKeys(ctx, keysDir, repo, rig.ids)
	mcpRigMust(t, err)
	secretStore := secrets.NewStore(keys, repo, rig.ids, rig.clock)
	_, err = app.EnsureInstanceIdentity(ctx, cfg, secretStore)
	mcpRigMust(t, err)

	var svc api.Services
	svc.Plans, err = app.NewPlans(cfg, store)
	mcpRigMust(t, err)
	svc.Approvals, err = app.NewApprovals(cfg, store)
	mcpRigMust(t, err)
	svc.Governance, err = app.NewGovernance(cfg, store)
	mcpRigMust(t, err)
	svc.Services, err = app.NewServices(cfg, store)
	mcpRigMust(t, err)
	svc.Queries, err = app.NewQueries(cfg, store, config.ModeLocal)
	mcpRigMust(t, err)
	svc.Inventory, err = app.NewInventory(cfg, app.InventoryOptions{Store: store, Connector: app.Connector{Remote: rig.runtime}, Mode: config.ModeLocal})
	mcpRigMust(t, err)
	svc.Sessions, err = app.NewSessions(cfg)
	mcpRigMust(t, err)
	svc.SSHKeys, err = api.NewSSHKeys(app.SSHIdentityOf(secretStore))
	mcpRigMust(t, err)
	svc.Proxmox, err = app.NewProxmoxSync(cfg, app.ProxmoxSyncOptions{Token: app.SecretToken(secretStore)})
	mcpRigMust(t, err)
	svc.Apps, err = app.NewApps(cfg, store, mcpRigGitHub{})
	mcpRigMust(t, err)
	svc.Repositories, err = app.NewRepositories(cfg, mcpRigGitHub{})
	mcpRigMust(t, err)
	deployments, err := app.NewDeployments(cfg, svc.Governance, app.CIPolling{})
	mcpRigMust(t, err)
	svc.Deployments, err = app.NewDeploymentFinalizer(deployments, app.FinalizerDeps{Clients: mcpRigGitHub{}, Jobs: store})
	mcpRigMust(t, err)
	svc.Auth, err = app.NewAuthService(cfg, app.AuthOptions{Tokens: auth.Minter{}})
	mcpRigMust(t, err)
	svc.Keys, err = app.NewKeyManager(cfg, store, secrets.NewKeyAdmin(keys, repo, rig.ids, backup.Archives{Dir: t.TempDir()}), secretStore, config.ModeLocal)
	mcpRigMust(t, err)
	svc.Backups, err = app.NewBackupService(cfg, svc.Plans, svc.Queries, store, app.BackupOptions{
		Directory: t.TempDir(), Retention: 3, KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"), SMVersion: "rig", Keys: keys,
	})
	mcpRigMust(t, err)
	svc.Hold, err = app.NewHold(cfg, store)
	mcpRigMust(t, err)
	svc.Enrollments, err = app.NewEnrollments(cfg, auth.Minter{}, app.SSHIdentityOf(secretStore))
	mcpRigMust(t, err)
	svc.MCPClients, err = app.NewMCPClients(cfg, store, app.MCPClientsOptions{Tokens: auth.Minter{}})
	mcpRigMust(t, err)

	server, err := api.New(api.Options{
		Services: svc, IDs: rig.ids, Identity: rig.admin.ID, DB: rig.db, Clock: rig.clock,
		MCPResolver: mcpRigResolver{caller: rig.mcp},
	})
	mcpRigMust(t, err)
	return server
}

// seedPlan stores a plan the mcp identity itself created, so submit has a
// concrete target (and a concrete hash).
func (rig *mcpRig) seedPlan() {
	rig.t.Helper()
	body, err := json.Marshal(wire.CreatePlanRequest{
		Action: "service.restart", Targets: []wire.ResourceRef{{Type: domain.ResourceService, ID: domain.ID(rig.fixtures["service"])}},
	})
	mcpRigMust(rig.t, err)
	r := rig.send(mcpRigInProcess, http.MethodPost, wire.PathPlans, string(body), rig.keyed()...)
	if r.status != http.StatusCreated {
		rig.t.Fatalf("seed plan: status %d: %s", r.status, r.body)
	}
	var plan wire.CreatedPlan
	r.data(rig.t, &plan)
	rig.fixtures["plan"], rig.fixtures["plan_hash"] = plan.PlanID.String(), plan.PlanHash
}

func (rig *mcpRig) listen() {
	rig.t.Helper()
	dir, err := os.MkdirTemp("", "smi")
	mcpRigMust(rig.t, err)
	rig.t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	mcpRigMust(rig.t, err)
	go func() {
		_ = rig.server.Serve(api.RestrictToUID(listener, uint32(os.Getuid()), api.PeerUID, nil))
	}()
	rig.t.Cleanup(func() { _ = rig.server.Shutdown(context.Background()) })
	rig.socket = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	rig.t.Cleanup(rig.socket.CloseIdleConnections)
	rig.inproc = &http.Client{Transport: rig.server.InProcess(rig.mcp)}
}

// keyed is the header list of a mutation that takes an Idempotency-Key.
func (rig *mcpRig) keyed(headers ...string) []string {
	return append([]string{wire.HeaderIdempotencyKey, rig.ids.NewID().String()}, headers...)
}

// send makes one request as the MCP client over the given transport. Each call
// first lets the rate limits refill, so a long matrix never trips them by
// accident (the limits have their own tests).
func (rig *mcpRig) send(via mcpRigTransport, method, path, body string, headers ...string) mcpRigReply {
	rig.t.Helper()
	return rig.sendCtx(context.Background(), via, method, path, body, headers, false)
}

// sendCtx is send under ctx. A stream is answered as soon as its response
// headers arrive: its body never ends by itself, so it is not read.
func (rig *mcpRig) sendCtx(ctx context.Context, via mcpRigTransport, method, path, body string, headers []string, stream bool) mcpRigReply {
	t := rig.t
	t.Helper()
	rig.clock.Advance(time.Minute)
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://sm"+path, reader)
	mcpRigMust(t, err)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	var client *http.Client
	switch via {
	case mcpRigInProcess:
		client = rig.inproc
	case mcpRigSocket:
		client = rig.socket
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+mcpRigToken)
	case mcpRigLocalUser:
		client = rig.socket
	}
	resp, err := client.Do(req)
	mcpRigMust(t, err)
	defer func() { _ = resp.Body.Close() }()
	if stream {
		return mcpRigReply{status: resp.StatusCode, header: resp.Header}
	}
	payload, err := io.ReadAll(resp.Body)
	mcpRigMust(t, err)
	return mcpRigReply{status: resp.StatusCode, header: resp.Header, body: payload}
}

// count is the number of rows in a table the rig is allowed to watch.
func (rig *mcpRig) count(table string) int {
	rig.t.Helper()
	var n int
	mcpRigMust(rig.t, rig.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&n))
	return n
}

// expand fills the {name} placeholders of s from the fixtures.
func (rig *mcpRig) expand(s string) string {
	s = strings.ReplaceAll(s, "{deployment_body}", rig.deploymentBody())
	s = strings.ReplaceAll(s, "{bootstrap_code}", rig.unknownToken(auth.KindBootstrap))
	s = strings.ReplaceAll(s, "{join_token}", rig.unknownToken(auth.KindJoin))
	s = strings.ReplaceAll(s, "{expires_at}", rig.clock.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	for name, value := range rig.fixtures {
		s = strings.ReplaceAll(s, "{"+name+"}", value)
	}
	return s
}

// fixture sends a request as the local user and requires it to succeed.
func (rig *mcpRig) fixture(method, path, body string) mcpRigReply {
	rig.t.Helper()
	var headers []string
	if method != http.MethodGet && path != wire.PathTokens {
		headers = rig.keyed()
	}
	r := rig.send(mcpRigLocalUser, method, path, body, headers...)
	if r.status < 200 || r.status > 299 {
		rig.t.Fatalf("fixture %s %s: status %d: %s", method, path, r.status, r.body)
	}
	return r
}

// seedGovernedResources adds what the remaining routes address: an app with a
// target, a queued job, an API token and a local MCP client.
func (rig *mcpRig) seedGovernedResources() {
	rig.t.Helper()
	var app struct {
		Applied wire.App `json:"applied"`
	}
	rig.fixture(http.MethodPost, wire.PathApps, `{"name":"shop","deployed_service":"web","compose_source":"control-plane",`+
		`"compose_content":"services:\n  web:\n    image: example/web\n","image_policy":{"deployed":"web"}}`).data(rig.t, &app)
	var target struct {
		Applied wire.AppTarget `json:"applied"`
	}
	rig.fixture(http.MethodPost, wire.Path(wire.PathAppTargets, app.Applied.ID.String()),
		`{"environment":"dev","node_id":"`+rig.fixtures["node"]+`","deployment_policy":{"rollback":"manual"}}`).data(rig.t, &target)
	rig.fixtures["app"], rig.fixtures["app_target"] = app.Applied.ID.String(), target.Applied.ID.String()

	var deployment wire.Deployment
	rig.fixture(http.MethodPost, wire.PathDeployments, rig.deploymentBody()).data(rig.t, &deployment)
	rig.fixtures["deployment"] = deployment.ID.String()

	var session wire.SessionOpened
	opened := rig.send(mcpRigInProcess, http.MethodPost, wire.Path(wire.PathNodeSessions, rig.fixtures["node"]), `{"tool":"shell"}`, rig.keyed()...)
	if opened.status != http.StatusCreated {
		rig.t.Fatalf("seed session: status %d: %s", opened.status, opened.body)
	}
	opened.data(rig.t, &session)
	rig.fixtures["session"] = session.Session.ID.String()

	var keys wire.Page[wire.MasterKey]
	rig.fixture(http.MethodGet, wire.PathMasterKeys, "").data(rig.t, &keys)
	rig.fixtures["kek"] = keys.Items[0].ID.String()

	var plan wire.CreatedPlan
	rig.fixture(http.MethodPost, wire.PathPlans, `{"action":"service.restart","targets":[{"type":"service","id":"`+rig.fixtures["prod_service"]+`"}]}`).data(rig.t, &plan)
	var submitted wire.Submission
	rig.fixture(http.MethodPost, wire.Path(wire.PathPlanSubmit, plan.PlanID.String()), `{"plan_hash":"`+plan.PlanHash+`"}`).data(rig.t, &submitted)
	rig.fixtures["job"], rig.fixtures["job_plan_hash"] = submitted.Job.ID.String(), plan.PlanHash

	var token wire.TokenIssued
	rig.fixture(http.MethodPost, wire.PathTokens, `{"name":"fixture","expires_at":"`+rig.clock.Now().Add(24*time.Hour).UTC().Format(time.RFC3339)+`"}`).data(rig.t, &token)
	rig.fixtures["api_token"] = token.Token.ID.String()

	rig.inTx(func(ctx context.Context, tx *database.Tx) error {
		now, identity, client := rig.clock.Now(), rig.ids.NewID(), rig.ids.NewID()
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: "supermgmt:mcp-local", Subject: client.String(), CreatedAt: now,
		})
		if err != nil {
			return err
		}
		rig.fixtures["mcp_client"] = client.String()
		return database.CreateMCPClient(ctx, tx, database.MCPClient{
			ID: client, IdentityID: identity, Name: "fixture-client", Origin: database.MCPOriginLocal,
			State: database.MCPClientPendingToken, RequestedBy: rig.admin.ID, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
		})
	})
}

// deploymentBody is a valid POST /deployments body for the fixture target.
func (rig *mcpRig) deploymentBody() string {
	return `{"app_target_id":"` + rig.fixtures["app_target"] + `","kind":"deploy","commit_sha":"` + strings.Repeat("a", 40) +
		`","images":[{"service":"web","digest":"sha256:` + strings.Repeat("b", 64) + `"}]}`
}

// unknownToken is a well-formed token of the kind that no table has ever
// stored, so it is refused for being unknown, not for being malformed.
func (rig *mcpRig) unknownToken(kind auth.Kind) string {
	rig.t.Helper()
	token, _, err := auth.Mint(kind)
	mcpRigMust(rig.t, err)
	return string(token)
}
