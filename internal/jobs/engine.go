package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	defaultWorkers           = 4
	defaultPollInterval      = time.Second
	defaultReconcileInterval = 10 * time.Second
)

// EngineConfig tunes an Engine. Handlers maps a job type to its executor.
type EngineConfig struct {
	Store    *Store
	Handlers map[string]Handler
	Evidence EvidenceSource // nil: the reconciler never finds evidence

	Workers           int           // default 4
	PollInterval      time.Duration // idle wait between claim attempts; default 1s
	HeartbeatInterval time.Duration // default LeaseTTL/3
	ReconcileInterval time.Duration // takeover + reconcile period; default 10s
	OnError           func(error)   // infrastructure errors; default: ignored
}

// Engine runs N workers and the takeover/reconcile loop until its context ends.
type Engine struct {
	cfg EngineConfig
	id  string
}

// NewEngine validates cfg and applies defaults.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("jobs: engine needs a store")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = defaultWorkers
	}
	cfg.PollInterval = orDefault(cfg.PollInterval, defaultPollInterval)
	cfg.HeartbeatInterval = orDefault(cfg.HeartbeatInterval, cfg.Store.leaseTTL/3)
	cfg.ReconcileInterval = orDefault(cfg.ReconcileInterval, defaultReconcileInterval)
	if cfg.OnError == nil {
		cfg.OnError = func(error) {}
	}
	return &Engine{cfg: cfg, id: cfg.Store.ids.NewID().String()}, nil
}

// Run blocks until ctx is cancelled and every goroutine it started has returned.
func (e *Engine) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := range e.cfg.Workers {
		wg.Go(func() { e.workerLoop(ctx, fmt.Sprintf("worker:%s:%d", e.id, i)) })
	}
	wg.Go(func() { e.reconcileLoop(ctx) })
	wg.Wait()
	return nil
}

func (e *Engine) workerLoop(ctx context.Context, owner string) {
	for ctx.Err() == nil {
		claimed, ok, err := e.cfg.Store.Claim(ctx, owner)
		switch {
		case err != nil:
			e.report(ctx, err)
			sleep(ctx, e.cfg.PollInterval)
		case !ok:
			sleep(ctx, e.cfg.PollInterval)
		default:
			e.execute(ctx, claimed)
		}
	}
}

// reconcileLoop waits one interval before its first pass: a lease must expire
// before takeover can act on it, so an immediate pass at startup finds nothing new.
func (e *Engine) reconcileLoop(ctx context.Context) {
	for sleep(ctx, e.cfg.ReconcileInterval); ctx.Err() == nil; sleep(ctx, e.cfg.ReconcileInterval) {
		if _, err := e.cfg.Store.Takeover(ctx, e.id); err != nil {
			e.report(ctx, err)
		}
		if _, err := e.cfg.Store.Reconcile(ctx, e.cfg.Evidence); err != nil {
			e.report(ctx, err)
		}
	}
}

// report forwards err unless it is only the engine shutting down.
func (e *Engine) report(ctx context.Context, err error) {
	if ctx.Err() == nil {
		e.cfg.OnError(err)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// execute runs one claimed job and records how it ended. If the engine stops
// while the handler runs, the job is left running: its lease expires and the
// takeover path handles it, exactly as after a crash.
func (e *Engine) execute(ctx context.Context, c Claimed) {
	handler, known := e.cfg.Handlers[c.Job.Type]
	if !known {
		e.finish(ctx, c.Lease, func(ctx context.Context) error {
			return e.cfg.Store.FailTerminal(ctx, c.Lease, smerr.New(smerr.CodeInternal, "", "no handler for job type "+c.Job.Type))
		})
		return
	}

	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var heartbeats sync.WaitGroup
	heartbeats.Go(func() { e.heartbeatLoop(jobCtx, cancel, c.Lease) })

	runErr := safeRun(jobCtx, handler, c.Lease)
	cancel()
	heartbeats.Wait()

	switch {
	case ctx.Err() != nil && runErr != nil:
		return // shutdown interrupted the handler; leave the job to takeover
	case runErr == nil:
		e.finish(ctx, c.Lease, func(ctx context.Context) error { return e.cfg.Store.Succeed(ctx, c.Lease) })
	case errors.Is(runErr, ErrOutcomeUnknown):
		e.finish(ctx, c.Lease, func(ctx context.Context) error { return e.cfg.Store.Interrupt(ctx, c.Lease, runErr) })
	case errors.Is(runErr, errHandlerPanic):
		e.finish(ctx, c.Lease, func(ctx context.Context) error { return e.cfg.Store.FailTerminal(ctx, c.Lease, runErr) })
	default:
		e.finish(ctx, c.Lease, func(ctx context.Context) error { return e.cfg.Store.Fail(ctx, c.Lease, runErr) })
	}
}

// finish runs a finishing write even when the engine is shutting down, so a
// completed handler is not lost; a lost lease is the expected, silent outcome.
func (e *Engine) finish(ctx context.Context, lease Lease, write func(context.Context) error) {
	err := write(context.WithoutCancel(ctx))
	if err != nil && !errors.Is(err, ErrLeaseLost) {
		e.cfg.OnError(fmt.Errorf("finish job %s: %w", lease.JobID, err))
	}
}

func (e *Engine) heartbeatLoop(ctx context.Context, cancelJob context.CancelFunc, lease Lease) {
	ticker := time.NewTicker(e.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := e.cfg.Store.Heartbeat(ctx, lease)
			switch {
			case err == nil, ctx.Err() != nil:
			case errors.Is(err, ErrLeaseLost):
				cancelJob()
				return
			default:
				e.cfg.OnError(err)
			}
		}
	}
}

var errHandlerPanic = errors.New("handler panicked")

// safeRun converts a handler panic into an error wrapping errHandlerPanic.
func safeRun(ctx context.Context, h Handler, lease Lease) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%w: %v", errHandlerPanic, p)
		}
	}()
	return h.Run(ctx, lease)
}
