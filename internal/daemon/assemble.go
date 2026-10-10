package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/local"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

const (
	focusLeaseFactor = 2
	staleAfterFactor = 3
)

// background is what runs next to the HTTP server for the daemon's lifetime.
type background struct {
	engine    *jobs.Engine
	refresher *app.Refresher
	sweeper   *app.Sweeper
}

// system is the assembled daemon: every service wired to one database, ready
// to serve once a listener exists.
type system struct {
	db        *database.DB
	pool      *ssh.Pool
	server    *api.Server
	residency *Residency
	work      background
}

// close releases what assemble opened. Background work must have stopped.
func (s *system) close() error {
	s.pool.Close()
	return s.db.Close()
}

// assemble performs the startup of ADR-0014 after the locks: it opens and
// migrates the database, makes the instance row, opens the key files, ensures
// the instance SSH identity, reconciles the static configuration and the
// `local:<uid>` administrator, and wires the services (T8-wiring order).
func assemble(ctx context.Context, o Options) (*system, error) {
	cfg := o.Config
	db, err := openDatabase(ctx, cfg, o.Clock)
	if err != nil {
		return nil, err
	}
	sys, err := wireUp(ctx, o, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return sys, nil
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

func wireUp(ctx context.Context, o Options, db *database.DB) (*system, error) {
	cfg, clock, ids, log := o.Config, o.Clock, o.IDs, o.Log
	if err := ensureInstance(ctx, db, cfg, clock, ids); err != nil {
		return nil, fmt.Errorf("create the instance row: %w", err)
	}
	appCfg, err := appConfig(db, o)
	if err != nil {
		return nil, err
	}
	store, err := openSecrets(ctx, cfg, db, clock, ids)
	if err != nil {
		return nil, err
	}
	if _, err := app.EnsureInstanceIdentity(ctx, appCfg, store); err != nil {
		return nil, fmt.Errorf("ensure the instance SSH identity: %w", err)
	}
	if err := reconcileStatic(ctx, appCfg, cfg); err != nil {
		return nil, err
	}
	caller, err := EnsureLocalIdentity(ctx, db, clock, ids, o.UID)
	if err != nil {
		return nil, err
	}

	pool := ssh.NewPool(poolConfig(cfg), ssh.NewCredentials(store), clock)
	sys, err := services(ctx, o, appCfg, db, store, pool, caller)
	if err != nil {
		pool.Close()
		return nil, err
	}
	log.Info("daemon assembled", slog.String("identity", caller.String()))
	return sys, nil
}

func services(ctx context.Context, o Options, appCfg app.Config, db *database.DB, store *secrets.Store, pool *ssh.Pool, caller domain.ID) (*system, error) {
	cfg := o.Config
	revalidator, err := app.NewRevalidator(appCfg)
	if err != nil {
		return nil, err
	}
	jobStore, err := jobs.NewStore(jobs.Config{
		DB: db, Clock: o.Clock, IDs: o.IDs, Revalidator: revalidator, LockPlanner: app.LockPlanner{},
		LeaseTTL: cfg.Jobs.Lease, BackoffBase: cfg.Jobs.RetryBase, ReconcileGrace: cfg.Jobs.ReconcileGrace,
	})
	if err != nil {
		return nil, err
	}
	conn := app.Connector{Remote: pool, Local: local.Executor{CommandTimeout: cfg.SSH.CommandTimeout}}
	focus := app.NewFocus(o.Clock, focusLeaseFactor*cfg.Refresh.FocusedInterval)
	inventory, err := app.NewInventory(appCfg, app.InventoryOptions{
		Store: jobStore, Connector: conn, Mode: cfg.Instance.Mode, Focus: focus,
		StaleAfter: staleAfterFactor * cfg.Refresh.MetricsInterval,
	})
	if err != nil {
		return nil, err
	}
	prober, err := app.NewProber(appCfg, conn, nil)
	if err != nil {
		return nil, err
	}
	handlers, err := app.NewHandlers(appCfg, app.HandlersOptions{
		Store: jobStore, Connector: conn, Inventory: inventory, Prober: prober, Identity: app.SSHIdentityOf(store),
	})
	if err != nil {
		return nil, err
	}
	work, err := backgroundWork(appCfg, o, jobStore, conn, focus, prober, handlers)
	if err != nil {
		return nil, err
	}
	activity, err := app.NewActivity(appCfg, jobStore)
	if err != nil {
		return nil, err
	}
	residency := NewResidency(ResidencyConfig{
		Clock: o.Clock, IdleExit: cfg.Daemon.IdleExit, Resident: cfg.Daemon.Resident, Busy: loggedBusy(activity, o.Log),
	})
	server, err := apiServer(o, appCfg, db, jobStore, inventory, store, caller, residency)
	if err != nil {
		return nil, err
	}
	return &system{db: db, pool: pool, server: server, residency: residency, work: work}, nil
}

func backgroundWork(appCfg app.Config, o Options, jobStore *jobs.Store, conn app.Connector, focus *app.Focus, prober *app.Prober, handlers *app.Handlers) (background, error) {
	cfg, log := o.Config, o.Log
	evidence, err := app.NewEvidenceRouter(appCfg, conn, nil)
	if err != nil {
		return background{}, err
	}
	engine, err := jobs.NewEngine(jobs.EngineConfig{
		Store: jobStore, Handlers: handlers.Map(), Evidence: evidence,
		Workers: cfg.Jobs.Workers, HeartbeatInterval: cfg.Jobs.Heartbeat,
		OnError: func(err error) { log.Error("job engine", slog.Any("error", err)) },
	})
	if err != nil {
		return background{}, err
	}
	refresher, err := app.NewRefresher(appCfg, app.RefresherOptions{
		Prober: prober, Focus: focus, Refresh: cfg.Refresh,
		OnError: func(node domain.ID, err error) {
			log.Warn("refresh", slog.String("node", node.String()), slog.Any("error", err))
		},
	})
	if err != nil {
		return background{}, err
	}
	sweeper, err := app.NewSweeper(appCfg, app.SweeperOptions{
		Store: jobStore, OnError: func(err error) { log.Error("sweeper", slog.Any("error", err)) },
	})
	if err != nil {
		return background{}, err
	}
	return background{engine: engine, refresher: refresher, sweeper: sweeper}, nil
}

func apiServer(o Options, appCfg app.Config, db *database.DB, jobStore *jobs.Store, inventory *app.Inventory, store *secrets.Store, caller domain.ID, residency *Residency) (*api.Server, error) {
	cfg := o.Config
	plans, err := app.NewPlans(appCfg, jobStore)
	if err != nil {
		return nil, err
	}
	approvals, err := app.NewApprovals(appCfg, jobStore)
	if err != nil {
		return nil, err
	}
	governance, err := app.NewGovernance(appCfg, jobStore)
	if err != nil {
		return nil, err
	}
	actions, err := app.NewServices(appCfg, jobStore)
	if err != nil {
		return nil, err
	}
	queries, err := app.NewQueries(appCfg, jobStore, cfg.Instance.Mode)
	if err != nil {
		return nil, err
	}
	sessions, err := app.NewSessions(appCfg)
	if err != nil {
		return nil, err
	}
	sshKeys, err := api.NewSSHKeys(appCfg, app.SSHIdentityOf(store))
	if err != nil {
		return nil, err
	}
	return api.New(api.Options{
		Services: api.Services{
			Plans: plans, Approvals: approvals, Governance: governance, Services: actions,
			Queries: queries, Inventory: inventory, Sessions: sessions, SSHKeys: sshKeys,
		},
		IDs: o.IDs, Identity: caller, Residency: residency, Log: o.Log,
		Ready: func(ctx context.Context) error {
			_, err := database.GetInstance(ctx, db.Reader())
			return err
		},
	})
}

func appConfig(db *database.DB, o Options) (app.Config, error) {
	pol, err := loadPolicy(o.Config.Security.PolicyFile)
	if err != nil {
		return app.Config{}, err
	}
	allowSelf := o.Config.Security.AllowSelfApproval != nil && *o.Config.Security.AllowSelfApproval
	return app.Config{
		DB: db, Clock: o.Clock, IDs: o.IDs, Policy: pol, Credentials: app.LocalSocketCredentials{},
		ApprovalTTL: o.Config.Security.ApprovalTTL, AllowSelfApproval: allowSelf,
	}, nil
}

// loadPolicy reads security.policy_file, which replaces the built-in default
// entirely (spec §11.2); without one the embedded default applies.
func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return policy.Default()
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator configuration
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return policy.Parse(data)
}

func openSecrets(ctx context.Context, cfg *config.Config, db *database.DB, clock domain.Clock, ids domain.IDGenerator) (*secrets.Store, error) {
	repo := app.NewSecretsRepo(db, clock)
	keys, err := secrets.OpenFileKeys(ctx, cfg.Security.KeysDir, repo, ids)
	if err != nil {
		return nil, fmt.Errorf("open encryption keys: %w", err)
	}
	return secrets.NewStore(keys, repo, ids, clock), nil
}

func reconcileStatic(ctx context.Context, appCfg app.Config, cfg *config.Config) error {
	reconciler, err := app.NewStaticReconciler(appCfg, cfg.Instance.Mode)
	if err != nil {
		return err
	}
	if err := reconciler.Reconcile(ctx, cfg.Environments, cfg.Providers); err != nil {
		return fmt.Errorf("reconcile the configuration file: %w", err)
	}
	return nil
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
