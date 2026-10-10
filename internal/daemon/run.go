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
)

const (
	defaultIdleCheck       = time.Second
	defaultShutdownTimeout = 20 * time.Second
)

// Options configure Run. Config and Socket are required.
type Options struct {
	Config *config.Config
	// Socket is the resolved socket path (daemon.socket or the local default).
	Socket string

	Clock domain.Clock       // default: the system clock
	IDs   domain.IDGenerator // default: UUIDv7
	UID   uint32             // the only peer UID served; default: the process UID
	Log   *slog.Logger       // default: discard
	Peer  api.PeerLookup     // default: the platform lookup

	// IdleCheck is how often the idle-exit condition is evaluated; default 1s.
	IdleCheck time.Duration
	// OnListening is called once the socket accepts connections.
	OnListening func(socket string)
}

func (o Options) withDefaults() (Options, error) {
	if o.Config == nil || o.Socket == "" {
		return Options{}, errors.New("daemon: configuration and socket path are required")
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
	return o, nil
}

// Run is the life of one daemon (spec §2.1.1, ADR-0014). In order: verify the
// socket path and directory, take the database lock and the socket lock,
// assemble the services (database, keys, identity, reconciliation), unlink a
// stale socket under the lock, bind, and serve until ctx ends or the idle
// timer fires. A daemon that loses a lock returns *database.LockHeldError or
// *SocketInUseError before touching anything.
func Run(ctx context.Context, o Options) error {
	o, err := o.withDefaults()
	if err != nil {
		return err
	}
	if err := CheckSocketPath(o.Socket); err != nil {
		return err
	}
	if err := PrepareSocketDir(o.Socket, int(o.UID)); err != nil {
		return err
	}
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

	listener, err := Bind(ctx, o.Socket)
	if err != nil {
		return err
	}
	return serve(ctx, o, sys, listener)
}

// serve runs the server and the background work until ctx ends, the server
// fails or the daemon is idle, and then shuts down in order: stop accepting,
// let requests in flight finish, stop the workers.
func serve(ctx context.Context, o Options, sys *system, listener net.Listener) error {
	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	var work sync.WaitGroup
	work.Go(func() { _ = sys.work.engine.Run(runCtx) })
	work.Go(func() { _ = sys.work.refresher.Run(runCtx) })
	work.Go(func() { _ = sys.work.sweeper.Run(runCtx) })
	work.Go(func() {
		sys.residency.Watch(runCtx, o.IdleCheck, func() {
			o.Log.Info("idle: no clients, no active jobs; exiting", slog.Duration("idle_exit", o.Config.Daemon.IdleExit))
			stop()
		})
	})

	served := make(chan error, 1)
	go func() { served <- sys.server.Serve(api.RestrictToUID(listener, o.UID, o.Peer, o.Log)) }()
	o.Log.Info("daemon listening", slog.String("socket", o.Socket))
	if o.OnListening != nil {
		o.OnListening(o.Socket)
	}

	var serveErr error
	select {
	case <-runCtx.Done():
	case serveErr = <-served:
		served <- serveErr // the shutdown below reads it again
	}
	shutdownErr := shutdown(ctx, o, sys, stop)
	work.Wait()
	sys.work.refresher.Wait()
	if err := <-served; err != nil && serveErr == nil {
		serveErr = err
	}
	return errors.Join(serveErr, shutdownErr)
}

func shutdown(ctx context.Context, o Options, sys *system, stop context.CancelFunc) error {
	timeout := o.Config.Server.ShutdownTimeout
	if timeout <= 0 {
		timeout = defaultShutdownTimeout
	}
	graceful, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	err := sys.server.Shutdown(graceful)
	stop()
	if err != nil {
		return fmt.Errorf("shut down the API server: %w", err)
	}
	return nil
}
