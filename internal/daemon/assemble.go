package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/github"
	"github.com/autarquico/supermgmt/internal/providers/local"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

const (
	focusLeaseFactor = 2
	staleAfterFactor = 3

	// healthCheckTimeout bounds one control_plane health request; it is the
	// upper bound of health.timeout.
	healthCheckTimeout = 30 * time.Second
	healthMaxBody      = 64 << 10
)

// background is what runs next to the HTTP servers for the daemon's lifetime.
type background struct {
	engine    *jobs.Engine
	refresher *app.Refresher
	proxmox   *app.ProxmoxSync
	sweeper   *app.Sweeper
	backups   *backupSchedule // nil when no schedule is configured
	authSweep *authSweep
	ci        app.CIWatcher
}

// system is the assembled daemon: every service wired to one database, ready
// to serve once a listener exists. A local daemon has the Unix socket API, a
// server has the HTTPS API and the admin socket.
type system struct {
	db        *database.DB
	pool      *ssh.Pool
	residency *Residency
	work      background
	local     *api.Server
	remote    *api.Server
	admin     *api.AdminServer
}

// close releases what assemble opened. Background work must have stopped.
func (s *system) close() error {
	s.pool.Close()
	return s.db.Close()
}

// assemble performs the startup of ADR-0020 after the locks: Prepare (restore
// recovery, database, instance row, key files), then the instance SSH
// identity, the static configuration and the identities of the mode, and the
// wiring of the services.
func assemble(ctx context.Context, o Options) (*system, error) {
	prepared, err := Prepare(ctx, o)
	if err != nil {
		return nil, err
	}
	sys, err := wireUp(ctx, o, prepared)
	if err != nil {
		_ = prepared.Close()
		return nil, err
	}
	return sys, nil
}

// recoverRestore runs the journal recovery with the same spelling of the data
// directory as the restore command, so both find the same journal.
func recoverRestore(cfg *config.Config) error {
	dataDir, err := filepath.Abs(cfg.Instance.DataDir)
	if err != nil {
		return fmt.Errorf("data_dir %q: %w", cfg.Instance.DataDir, err)
	}
	if err := backup.Recover(dataDir); err != nil {
		return fmt.Errorf("finish the interrupted restore before starting: %w", err)
	}
	return nil
}

func openDatabase(ctx context.Context, cfg *config.Config, clock domain.Clock) (*database.DB, error) {
	db, err := database.Open(ctx, cfg.Storage.SQLite.Path, database.Options{BusyTimeout: cfg.Storage.SQLite.BusyTimeout, Clock: clock})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return db, nil
}

func ensureInstance(ctx context.Context, db *database.DB, cfg *config.Config, clock domain.Clock, ids domain.IDGenerator) error {
	_, err := database.GetInstance(ctx, db.Reader())
	if err == nil {
		return nil
	}
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		return err
	}
	return db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateInstance(ctx, tx, database.Instance{ID: ids.NewID(), Name: cfg.Instance.Name, CreatedAt: clock.Now()})
		if err != nil && smerr.CodeOf(err) != smerr.CodeConflict { // a conflict means the row appeared meanwhile
			return err
		}
		return nil
	})
}

// keyKit is the secret store with the key files and the key administrator
// that share one set of keys.
type keyKit struct {
	store *secrets.Store
	keys  *secrets.FileKeys
	admin *secrets.KeyAdmin
}

func openSecrets(ctx context.Context, cfg *config.Config, db *database.DB, clock domain.Clock, ids domain.IDGenerator) (keyKit, error) {
	repo := app.NewSecretsKeyRepo(db, clock)
	keys, err := secrets.OpenFileKeys(ctx, cfg.Security.KeysDir, repo, ids)
	if err != nil {
		return keyKit{}, fmt.Errorf("open encryption keys: %w", err)
	}
	return keyKit{
		store: secrets.NewStore(keys, repo, ids, clock),
		keys:  keys,
		admin: secrets.NewKeyAdmin(keys, repo, ids, backup.Archives{Dir: cfg.Backup.Directory}),
	}, nil
}

func wireUp(ctx context.Context, o Options, prepared *Prepared) (*system, error) {
	cfg, clock := o.Config, o.Clock
	db, kit := prepared.db, prepared.kit
	appCfg, policyBytes, err := appConfig(db, o)
	if err != nil {
		return nil, err
	}
	if _, err := app.EnsureInstanceIdentity(ctx, appCfg, kit.store); err != nil {
		return nil, fmt.Errorf("ensure the instance SSH identity: %w", err)
	}
	b := &builder{o: o, cfg: cfg, app: appCfg, db: db, kit: kit}
	if err := b.openGate(ctx); err != nil {
		return nil, err
	}
	if err := activateConfig(ctx, appCfg, o, policyBytes); err != nil {
		return nil, err
	}
	if err := b.ensureIdentities(ctx); err != nil {
		return nil, err
	}
	b.pool = ssh.NewPool(poolConfig(cfg), ssh.NewCredentials(kit.store), clock)
	sys, err := b.build(ctx)
	if err != nil {
		b.pool.Close()
		return nil, err
	}
	o.Log.Info("daemon assembled", slog.String("mode", string(cfg.Instance.Mode)), slog.String("identity", b.caller.String()))
	return sys, nil
}

// builder holds what the services are wired from, in the order they exist.
type builder struct {
	o    Options
	cfg  *config.Config
	app  app.Config
	db   *database.DB
	kit  keyKit
	pool *ssh.Pool

	jobs   *jobs.Store
	hold   *app.HoldService
	caller domain.ID // local mode: the identity of the OS user

	plans     *app.Plans
	queries   *app.Queries
	keys      *app.KeyManager
	backups   *app.BackupService
	auth      *app.AuthService
	inventory *app.Inventory
	conn      app.Connector
	focus     *app.Focus
	prober    *app.Prober
	proxmox   *app.ProxmoxSync

	governance *app.Governance
	apps       *app.Apps
	repos      *app.Repositories
	finalizer  *app.DeploymentFinalizer // the deployments service of the API and the Finalizer of the CI watcher
	ci         app.CIWatcher
}

// openGate builds the job store and loads the restore hold into it: from here
// on a persisted hold keeps every claim closed, and a hold that cannot be read
// refuses the start. It runs before anything can submit or claim a job.
func (b *builder) openGate(ctx context.Context) error {
	revalidator, err := app.NewRevalidator(b.app)
	if err != nil {
		return err
	}
	deployPolicy, err := app.NewDeploymentPolicy(b.app, revalidator)
	if err != nil {
		return err
	}
	cfg := b.cfg
	b.jobs, err = jobs.NewStore(jobs.Config{
		DB: b.db, Clock: b.o.Clock, IDs: b.o.IDs, Revalidator: revalidator, LockPlanner: app.LockPlanner{},
		LeaseTTL: cfg.Jobs.Lease, BackoffBase: cfg.Jobs.RetryBase, ReconcileGrace: cfg.Jobs.ReconcileGrace,
		TypePolicies: deployPolicy.TypePolicies(),
	})
	if err != nil {
		return err
	}
	if b.hold, err = app.NewHold(b.app, b.jobs); err != nil {
		return err
	}
	held, err := b.hold.Load(ctx)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	if held {
		b.o.Log.Warn("restore hold in force: no job is claimed and no schedule runs until an admin runs sm admin restore-complete")
	}
	return nil
}

// ensureIdentities creates what the mode needs. The system identity exists in
// both. Only local mode creates `local:<uid>` and binds it to admin: a server
// gets its first admin from the bootstrap exchange (spec §11.5), which would
// be refused forever if the daemon had bound one already.
func (b *builder) ensureIdentities(ctx context.Context) error {
	if err := EnsureSystemIdentity(ctx, b.db, b.o.Clock); err != nil {
		return err
	}
	if b.cfg.Instance.Mode != config.ModeLocal {
		return nil
	}
	caller, err := EnsureLocalIdentity(ctx, b.db, b.o.Clock, b.o.IDs, b.o.UID)
	if err != nil {
		return err
	}
	b.caller = caller
	return nil
}

func (b *builder) build(ctx context.Context) (*system, error) {
	if err := b.coreServices(); err != nil {
		return nil, err
	}
	handlers, err := b.handlers()
	if err != nil {
		return nil, err
	}
	work, err := b.background(handlers)
	if err != nil {
		return nil, err
	}
	activity, err := app.NewActivity(b.app, b.jobs)
	if err != nil {
		return nil, err
	}
	cfg := b.cfg
	sys := &system{db: b.db, pool: b.pool, work: work, residency: NewResidency(ResidencyConfig{
		Clock: b.o.Clock, IdleExit: cfg.Daemon.IdleExit, Resident: cfg.Daemon.Resident, Busy: loggedBusy(activity, b.o.Log),
	})}
	services, err := b.apiServices()
	if err != nil {
		return nil, err
	}
	if cfg.Instance.Mode == config.ModeLocal {
		sys.local, err = b.localServer(services, sys.residency)
	} else {
		sys.remote, sys.admin, err = b.serverServers(services)
	}
	if err != nil {
		return nil, err
	}
	return sys, nil
}

// coreServices builds the services other services depend on. The key manager
// comes before the inventory, which executes approved key operations.
func (b *builder) coreServices() error {
	var err error
	if b.plans, err = app.NewPlans(b.app, b.jobs); err != nil {
		return err
	}
	if b.queries, err = app.NewQueries(b.app, b.jobs, b.cfg.Instance.Mode); err != nil {
		return err
	}
	if b.keys, err = app.NewKeyManager(b.app, b.jobs, b.kit.admin, b.kit.store, b.cfg.Instance.Mode); err != nil {
		return err
	}
	if b.backups, err = app.NewBackupService(b.app, b.plans, b.queries, b.jobs, app.BackupOptions{
		Directory: b.cfg.Backup.Directory, Retention: b.cfg.Backup.Retention,
		KnownHostsPath: b.cfg.SSH.KnownHostsFile, SMVersion: b.o.SMVersion, Keys: b.kit.keys,
	}); err != nil {
		return err
	}
	login, err := b.login()
	if err != nil {
		return err
	}
	cfg := b.cfg
	if b.auth, err = app.NewAuthService(b.app, app.AuthOptions{
		Tokens: auth.Minter{}, OIDC: login, SessionTTL: cfg.Security.SessionTTL, BootstrapCodeTTL: cfg.Auth.Bootstrap.CodeTTL,
	}); err != nil {
		return err
	}
	b.conn = app.Connector{Remote: b.pool, Local: local.Executor{CommandTimeout: cfg.SSH.CommandTimeout}}
	b.focus = app.NewFocus(b.o.Clock, focusLeaseFactor*cfg.Refresh.FocusedInterval)
	if b.inventory, err = app.NewInventory(b.app, app.InventoryOptions{
		Store: b.jobs, Connector: b.conn, Mode: cfg.Instance.Mode, Focus: b.focus, Keys: b.keys,
		StaleAfter: staleAfterFactor * cfg.Refresh.MetricsInterval, KeepLogsRaw: !cfg.Security.RedactCommandOutput,
	}); err != nil {
		return err
	}
	if b.prober, err = app.NewProber(b.app, b.conn, nil); err != nil {
		return err
	}
	b.proxmox, err = app.NewProxmoxSync(b.app, app.ProxmoxSyncOptions{
		Token: app.SecretToken(b.kit.store),
		OnError: func(provider domain.ID, err error) {
			b.o.Log.Warn("proxmox sync", slog.String("provider", provider.String()), slog.Any("error", err))
		},
	})
	if err != nil {
		return err
	}
	return b.deploymentServices()
}

// deploymentServices builds the M4 services: apps, repositories, the
// deployments service with its finalizer, and the CI watcher that hands
// deployments whose CI passed to that same finalizer (ADR-0011).
func (b *builder) deploymentServices() error {
	clients := app.NewGitHubClients(b.db, b.kit.store)
	var err error
	if b.governance, err = app.NewGovernance(b.app, b.jobs); err != nil {
		return err
	}
	if b.apps, err = app.NewApps(b.app, b.jobs, clients); err != nil {
		return err
	}
	if b.repos, err = app.NewRepositories(b.app, clients); err != nil {
		return err
	}
	attestations, err := b.attestations()
	if err != nil {
		return err
	}
	poll := b.ciPolling()
	deployments, err := app.NewDeployments(b.app, b.governance, poll)
	if err != nil {
		return err
	}
	deps := app.FinalizerDeps{Clients: clients, Attestations: attestations, Jobs: b.jobs}
	if b.finalizer, err = app.NewDeploymentFinalizer(deployments, deps); err != nil {
		return err
	}
	b.ci, err = app.NewCIWatcher(b.app, clients, b.finalizer, poll, app.CIWatcherOptions{
		OnError: func(err error) { b.o.Log.Warn("ci watcher", slog.Any("error", err)) },
	})
	return err
}

// ciPolling is github.ci_* with the mode: a server is driven by webhooks and
// polls only as a backstop.
func (b *builder) ciPolling() app.CIPolling {
	g := b.cfg.GitHub
	return app.CIPolling{Initial: g.CIPollInitial, Max: g.CIPollMax, Timeout: g.CITimeout, Server: b.cfg.Instance.Mode == config.ModeServer}
}

// attestations verifies artifact attestations against the Sigstore public-good
// and GitHub trusted roots, refreshed over TUF and cached under the data
// directory. A root that cannot be vouched for rejects, never passes.
func (b *builder) attestations() (github.AttestationVerifier, error) {
	roots := github.NewTrustRoots(github.TrustRootsConfig{
		CacheDir: filepath.Join(b.cfg.Instance.DataDir, "sigstore"), Clock: b.o.Clock,
		Sources: []github.TUFSource{github.PublicGoodSource(), github.GitHubSource()},
	})
	return github.NewAttestationVerifier(roots)
}

// healthClient runs the control_plane health checks: only the destinations
// health.allowed_private_cidrs lets through, plain HTTP allowed, no redirects.
func (b *builder) healthClient() (*http.Client, error) {
	var private []netip.Prefix
	for _, s := range b.cfg.Health.AllowedPrivateCIDRs {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("health.allowed_private_cidrs %q: %w", s, err)
		}
		private = append(private, prefix)
	}
	return netguard.NewClient(netguard.Allow{PrivateCIDRs: private, AllowHTTP: true}, nil, healthCheckTimeout, healthMaxBody), nil
}

// bearerResolver authenticates HTTPS bearers: native tokens always, GitHub
// Actions OIDC tokens when github.oidc_audience (default server.public_url)
// is set.
func (b *builder) bearerResolver() (auth.Resolver, error) {
	tokens := auth.DBResolver{DB: b.db, Clock: b.o.Clock}
	audience := b.cfg.GitHub.OIDCAudience
	if audience == "" {
		b.o.Log.Info("github.oidc_audience and server.public_url are empty: GitHub Actions tokens are not accepted")
		return tokens, nil
	}
	verifier, err := github.NewOIDCVerifier(github.OIDCConfig{Audience: audience, Clock: b.o.Clock, Replay: auth.OIDCReplay{DB: b.db}})
	if err != nil {
		return nil, fmt.Errorf("GitHub OIDC verifier: %w", err)
	}
	return auth.BearerResolver{Tokens: tokens, GitHub: auth.GitHubResolver{DB: b.db, Verifier: verifier, Clock: b.o.Clock}}, nil
}

// githubWebhook is POST /github/webhook (server mode): a verified delivery
// nudges the CI watcher.
func (b *builder) githubWebhook() *api.GitHubWebhook {
	return &api.GitHubWebhook{DB: b.db, Secrets: b.kit.store, Watcher: b.ci, Audit: app.NewWebhookAudit(b.app).Record}
}

// handlers is the job type table: the M1 handlers, the deployment types and
// backup.create.
func (b *builder) handlers() (map[string]jobs.Handler, error) {
	health, err := b.healthClient()
	if err != nil {
		return nil, err
	}
	h, err := app.NewHandlers(b.app, app.HandlersOptions{
		Store: b.jobs, Connector: b.conn, Inventory: b.inventory, Prober: b.prober, Identity: app.SSHIdentityOf(b.kit.store),
		Proxmox: b.proxmox, Apps: b.apps, Deploy: &app.DeployOptions{Secrets: b.kit.store, HTTP: health},
	})
	if err != nil {
		return nil, err
	}
	table := h.Map()
	table[app.JobBackupCreate] = b.backups.Handler()
	return table, nil
}

func (b *builder) background(handlers map[string]jobs.Handler) (background, error) {
	cfg, log := b.cfg, b.o.Log
	pveEvidence, err := app.NewProxmoxEvidence(b.app, b.proxmox, 0)
	if err != nil {
		return background{}, err
	}
	deployEvidence, err := app.NewDeploymentEvidence(b.app, b.conn, b.jobs)
	if err != nil {
		return background{}, err
	}
	evidence, err := app.NewEvidenceRouter(b.app, b.conn, nil,
		app.WithProxmoxEvidence(pveEvidence), app.WithDeploymentEvidence(deployEvidence))
	if err != nil {
		return background{}, err
	}
	engine, err := jobs.NewEngine(jobs.EngineConfig{
		Store: b.jobs, Handlers: handlers, Evidence: evidence,
		Workers: cfg.Jobs.Workers, HeartbeatInterval: cfg.Jobs.Heartbeat,
		OnError: func(err error) { log.Error("job engine", slog.Any("error", err)) },
	})
	if err != nil {
		return background{}, err
	}
	refresher, err := app.NewRefresher(b.app, app.RefresherOptions{
		Prober: b.prober, Focus: b.focus, Refresh: cfg.Refresh,
		OnError: func(node domain.ID, err error) {
			log.Warn("refresh", slog.String("node", node.String()), slog.Any("error", err))
		},
	})
	if err != nil {
		return background{}, err
	}
	sweeper, err := app.NewSweeper(b.app, app.SweeperOptions{
		Store: b.jobs, OnError: func(err error) { log.Error("sweeper", slog.Any("error", err)) },
	})
	if err != nil {
		return background{}, err
	}
	schedule, err := b.backupSchedule()
	if err != nil {
		return background{}, err
	}
	return background{engine: engine, refresher: refresher, proxmox: b.proxmox, sweeper: sweeper, backups: schedule, authSweep: b.authSweep(), ci: b.ci}, nil
}

func (b *builder) apiServices() (api.Services, error) {
	approvals, err := app.NewApprovals(b.app, b.jobs)
	if err != nil {
		return api.Services{}, err
	}
	actions, err := app.NewServices(b.app, b.jobs)
	if err != nil {
		return api.Services{}, err
	}
	sessions, err := app.NewSessions(b.app)
	if err != nil {
		return api.Services{}, err
	}
	sshKeys, err := api.NewSSHKeys(app.SSHIdentityOf(b.kit.store))
	if err != nil {
		return api.Services{}, err
	}
	enrollments, err := app.NewEnrollments(b.app, auth.Minter{}, app.SSHIdentityOf(b.kit.store))
	if err != nil {
		return api.Services{}, err
	}
	return api.Services{
		Plans: b.plans, Approvals: approvals, Governance: b.governance, Services: actions,
		Queries: b.queries, Inventory: b.inventory, Sessions: sessions, SSHKeys: sshKeys, Proxmox: b.proxmox,
		Apps: b.apps, Repositories: b.repos, Deployments: b.finalizer,
		Auth: b.auth, Keys: b.keys, Backups: b.backups, Hold: b.hold, Enrollments: enrollments,
	}, nil
}

func (b *builder) ready() func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := database.GetInstance(ctx, b.db.Reader())
		return err
	}
}

func (b *builder) localServer(services api.Services, residency *Residency) (*api.Server, error) {
	return api.New(api.Options{
		Services: services, IDs: b.o.IDs, Identity: b.caller, DB: b.db, Clock: b.o.Clock,
		Residency: residency, Log: b.o.Log, Ready: b.ready(),
	})
}

func appConfig(db *database.DB, o Options) (app.Config, []byte, error) {
	pol, policyBytes, err := loadPolicy(o.Config.Security.PolicyFile)
	if err != nil {
		return app.Config{}, nil, err
	}
	allowSelf := o.Config.Security.AllowSelfApproval != nil && *o.Config.Security.AllowSelfApproval
	return app.Config{
		DB: db, Clock: o.Clock, IDs: o.IDs, Policy: pol, Credentials: auth.CredentialStatus{DB: db, Clock: o.Clock},
		ApprovalTTL: o.Config.Security.ApprovalTTL, DefaultLogsMode: runtimes.LogsMode(o.Config.SSH.LogsMode), AllowSelfApproval: allowSelf,
	}, policyBytes, nil
}

// loadPolicy reads security.policy_file, which replaces the built-in default
// entirely (spec §11.2); without one the embedded default applies and there
// are no policy bytes to snapshot.
func loadPolicy(path string) (*policy.Policy, []byte, error) {
	if path == "" {
		pol, err := policy.Default()
		return pol, nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator configuration
	if err != nil {
		return nil, nil, fmt.Errorf("read policy file: %w", err)
	}
	pol, err := policy.Parse(data)
	return pol, data, err
}

// activateConfig reconciles the static configuration and stores the exact
// bytes of the configuration and policy in force, in one transaction.
func activateConfig(ctx context.Context, appCfg app.Config, o Options, policyBytes []byte) error {
	configBytes, err := o.configBytes()
	if err != nil {
		return err
	}
	reconciler, err := app.NewStaticReconciler(appCfg, o.Config.Instance.Mode)
	if err != nil {
		return err
	}
	src := app.ConfigSources{Config: configBytes, Policy: policyBytes}
	if err := reconciler.Activate(ctx, src, o.Config.Environments, o.Config.Providers); err != nil {
		return fmt.Errorf("reconcile the configuration file: %w", err)
	}
	return nil
}

// configBytes are the bytes the snapshot stores: the configuration file as it
// is on disk. A daemon started without a file (the built-in local defaults,
// or a caller that only has the parsed value) stores the effective
// configuration re-encoded.
func (o Options) configBytes() ([]byte, error) {
	if o.ConfigFile != "" {
		data, err := os.ReadFile(o.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("read the configuration file for its snapshot: %w", err)
		}
		return data, nil
	}
	data, err := yaml.Marshal(o.Config)
	if err != nil {
		return nil, fmt.Errorf("encode the effective configuration for its snapshot: %w", err)
	}
	return data, nil
}

func poolConfig(cfg *config.Config) ssh.PoolConfig {
	return ssh.PoolConfig{
		ConnectTimeout: cfg.SSH.ConnectTimeout, CommandTimeout: cfg.SSH.CommandTimeout,
		KeepaliveInterval: cfg.SSH.KeepaliveInterval, MaxDialsInFlight: cfg.SSH.MaxDialsInFlight,
		MaxConnections: cfg.SSH.MaxConnections, MaxSessionsPerConnection: cfg.SSH.MaxSessionsPerConnection,
		IdleConnectionTTL: cfg.SSH.IdleConnectionTTL,
	}
}

// loggedBusy asks for active work and logs a failure of the question, which
// the residency treats as "busy".
func loggedBusy(activity *app.Activity, log *slog.Logger) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		busy, err := activity.Busy(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Warn("cannot tell whether jobs are active; staying alive", slog.Any("error", err))
		}
		return busy, err
	}
}
