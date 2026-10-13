package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/version"
)

const (
	defaultIdleCheck       = time.Second
	defaultShutdownTimeout = 20 * time.Second
)

// Options configure Run and RunServer. Config is required, and Socket for Run.
type Options struct {
	Config *config.Config
	// ConfigFile is the file Config was loaded from. The configuration
	// snapshot of a backup stores its exact bytes (spec §29.1); without it the
	// effective configuration is stored re-encoded.
	ConfigFile string
	// Socket is the resolved socket path (daemon.socket or the local default).
	// Run only.
	Socket string

	Clock     domain.Clock       // default: the system clock
	IDs       domain.IDGenerator // default: UUIDv7
	UID       uint32             // the only peer UID of the local socket, and the service user of the admin socket; default: the process UID
	Log       *slog.Logger       // default: discard
	Peer      api.PeerLookup     // default: the platform lookup
	SMVersion string             // recorded in backup manifests; default: the build version

	// IdleCheck is how often the idle-exit condition is evaluated; default 1s.
	IdleCheck time.Duration
	// ScheduleCheck is how often the backup schedule is looked at; default 30s.
	ScheduleCheck time.Duration
	// SweepEvery is how often expired credentials are deleted; default 1h.
	SweepEvery time.Duration
	// OnListening is called once the local socket accepts connections.
	OnListening func(socket string)

	// Reload asks RunServer to re-read the TLS certificate pair (SIGHUP).
	Reload <-chan struct{}
	// OnServing is called once RunServer accepts connections.
	OnServing func(Endpoints)
}

// Endpoints are where a server listens.
type Endpoints struct {
	HTTP  net.Addr
	Admin string
}

func (o Options) withDefaults() (Options, error) {
	if o.Config == nil {
		return Options{}, errors.New("daemon: configuration is required")
	}
	if o.Clock == nil {
		o.Clock = domain.SystemClock{}
	}
	if o.IDs == nil {
		o.IDs = domain.UUIDv7Generator{}
	}
	if o.UID == 0 && os.Getuid() != 0 {
		o.UID = uint32(os.Getuid()) //nolint:gosec // a uid is never negative
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Peer == nil {
		o.Peer = api.PeerUID
	}
	if o.IdleCheck <= 0 {
		o.IdleCheck = defaultIdleCheck
	}
	if o.SMVersion == "" {
		o.SMVersion = version.Info().Version
	}
	return o, nil
}

// Run is the life of one local daemon (spec §2.1.1, ADR-0014). In order:
// verify the socket path and directory, take the database lock and the socket
// lock, assemble the services (restore recovery, database, hold, keys,
// identity, reconciliation), unlink a stale socket under the lock, bind, and
// serve until ctx ends or the idle timer fires. A daemon that loses a lock
// returns *database.LockHeldError or *SocketInUseError before touching
// anything.
func Run(ctx context.Context, o Options) error {
	o, err := o.withDefaults()
	if err != nil {
		return err
	}
	if o.Socket == "" {
		return errors.New("daemon: the socket path is required")
	}
	if o.Config.Instance.Mode != config.ModeLocal {
		return errors.New("daemon: instance.mode is server: start it with sm server")
	}
	if err := CheckSocketPath(o.Socket); err != nil {
		return err
	}
	dir, err := PrepareSocketDir(o.Socket, int(o.UID))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	locks, err := AcquireLocks(o.Config.Storage.SQLite.Path, o.Socket)
	if err != nil {
		return err
	}
	defer func() { _ = locks.Release() }()

	sys, err := assemble(ctx, o)
	if err != nil {
		return err
	}
	defer func() { _ = sys.close() }()

	if err := dir.Recheck(); err != nil {
		return err
	}
	listener, err := Bind(ctx, o.Socket)
	if err != nil {
		return err
	}
	if err := dir.Recheck(); err != nil {
		_ = listener.Close()
		return err
	}
	bounds := []bound{{name: "api", server: sys.local, listener: api.RestrictToUID(listener, o.UID, o.Peer, o.Log)}}
	o.Log.Info("daemon listening", slog.String("socket", o.Socket))
	return serve(ctx, o, sys, bounds, func() {
		if o.OnListening != nil {
			o.OnListening(o.Socket)
		}
	})
}

// bound is a server with the listener it serves.
type bound struct {
	name   string
	server interface {
		Serve(net.Listener) error
		Shutdown(context.Context) error
	}
	listener net.Listener
}

// serve runs the servers and the background work until ctx ends, a server
// fails or (local mode) the daemon is idle. ready is called once the servers
// are serving, and then shuts down in order:
// stop accepting, let requests in flight finish, stop the workers.
func serve(ctx context.Context, o Options, sys *system, bounds []bound, ready func()) error {
	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	var work sync.WaitGroup
	sys.work.start(runCtx, &work)
	if sys.local != nil { // only a local daemon exits when it is idle
		work.Go(func() {
			sys.residency.Watch(runCtx, o.IdleCheck, func() {
				o.Log.Info("idle: no clients, no active jobs; exiting", slog.Duration("idle_exit", o.Config.Daemon.IdleExit))
				stop()
			})
		})
	}

	served := make(chan error, len(bounds))
	for _, b := range bounds {
		go func() { served <- b.server.Serve(b.listener) }()
	}
	ready()

	var serveErr error
	remaining := len(bounds)
	select {
	case <-runCtx.Done():
	case serveErr = <-served:
		remaining--
	}
	shutdownErr := shutdown(ctx, o, bounds, stop)
	for _, b := range bounds {
		_ = b.listener.Close() // Serve closes it too; this covers a Serve that never ran
	}
	work.Wait()
	sys.work.refresher.Wait()
	for range remaining {
		if err := <-served; err != nil && serveErr == nil {
			serveErr = err
		}
	}
	return errors.Join(serveErr, shutdownErr)
}

func (w background) start(ctx context.Context, work *sync.WaitGroup) {
	work.Go(func() { _ = w.engine.Run(ctx) })
	work.Go(func() { _ = w.refresher.Run(ctx) })
	work.Go(func() { _ = w.proxmox.Run(ctx) })
	work.Go(func() { _ = w.sweeper.Run(ctx) })
	work.Go(func() { w.authSweep.run(ctx) })
	if w.backups != nil {
		work.Go(func() { w.backups.run(ctx) })
	}
	if w.ci != nil {
		work.Go(func() { _ = w.ci.Run(ctx) })
	}
}

func shutdown(ctx context.Context, o Options, bounds []bound, stop context.CancelFunc) error {
	timeout := o.Config.Server.ShutdownTimeout
	if timeout <= 0 {
		timeout = defaultShutdownTimeout
	}
	graceful, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	var errs []error
	for _, b := range bounds {
		if err := b.server.Shutdown(graceful); err != nil {
			errs = append(errs, fmt.Errorf("shut down the %s server: %w", b.name, err))
		}
	}
	stop()
	return errors.Join(errs...)
}
