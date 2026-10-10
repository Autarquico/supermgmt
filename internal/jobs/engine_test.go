package jobs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

type handlerFunc func(ctx context.Context, lease Lease) error

func (f handlerFunc) Run(ctx context.Context, lease Lease) error { return f(ctx, lease) }

// running starts an engine and returns a stop function that cancels it and
// waits for Run to return, failing the test if it does not.
func running(t *testing.T, e *env, handlers map[string]Handler, tune ...func(*EngineConfig)) (stop func()) {
	t.Helper()
	cfg := EngineConfig{
		Store: e.store, Handlers: handlers, Workers: 3,
		PollInterval: 2 * time.Millisecond, HeartbeatInterval: 2 * time.Millisecond, ReconcileInterval: time.Hour,
	}
	for _, f := range tune {
		f(&cfg)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := engine.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("engine did not stop: goroutine leak")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func TestEngineRunsJobsToCompletion(t *testing.T) {
	e := newEnv(t)
	var ran atomic.Int32
	handler := handlerFunc(func(_ context.Context, lease Lease) error {
		ran.Add(1)
		return nil
	})
	var ids []domain.ID
	for range 6 {
		ids = append(ids, e.enqueue().ID)
	}
	stop := running(t, e, map[string]Handler{"test.job": handler})
	eventually(t, "all jobs succeeded", func() bool {
		for _, id := range ids {
			if e.state(id) != domain.JobSucceeded {
				return false
			}
		}
		return true
	})
	stop()
	if ran.Load() != 6 {
		t.Fatalf("handler ran %d times, want 6", ran.Load())
	}
	for _, id := range ids {
		if e.lockCount(id) != 0 {
			t.Fatalf("job %s kept its locks", id)
		}
	}
}

func TestEngineFailsJobsWhoseHandlerErrors(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	running(t, e, map[string]Handler{"test.job": handlerFunc(func(context.Context, Lease) error { return errBoom })})
	eventually(t, "job failed", func() bool { return e.state(job.ID) == domain.JobFailed })
	if got := e.get(job.ID).Error; got == nil || got.Message != "boom" {
		t.Fatalf("error = %+v", got)
	}
}

func TestEngineRetriesIdempotentJobsAfterBackoff(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 2 })
	var calls atomic.Int32
	handler := handlerFunc(func(context.Context, Lease) error {
		if calls.Add(1) == 1 {
			return errBoom
		}
		return nil
	})
	running(t, e, map[string]Handler{"test.job": handler})

	eventually(t, "first attempt requeued", func() bool {
		j := e.get(job.ID)
		return j.State == domain.JobQueued && j.Attempts == 1
	})
	time.Sleep(20 * time.Millisecond) // the fake clock has not moved: still backing off
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times during backoff", calls.Load())
	}
	e.clock.Advance(backoffBase)
	eventually(t, "second attempt succeeded", func() bool { return e.state(job.ID) == domain.JobSucceeded })
}

func TestEngineRecoversFromHandlerPanics(t *testing.T) {
	e := newEnv(t)
	panicking := e.enqueue(func(nj *NewJob) { nj.Type = "panics"; nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 5 })
	fine := e.enqueue()
	handlers := map[string]Handler{
		"panics":   handlerFunc(func(context.Context, Lease) error { panic("kaboom") }),
		"test.job": handlerFunc(func(context.Context, Lease) error { return nil }),
	}
	running(t, e, handlers)
	eventually(t, "both jobs settled", func() bool {
		return e.state(panicking.ID) == domain.JobFailed && e.state(fine.ID) == domain.JobSucceeded
	})
	if msg := e.get(panicking.ID).Error.Message; !strings.Contains(msg, "kaboom") {
		t.Fatalf("failure message = %q", msg)
	}
	if e.get(panicking.ID).Attempts != 1 {
		t.Fatal("a panicking job must not be retried")
	}
}

func TestEngineFailsJobsWithoutAHandler(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.Type = "unknown.type" })
	running(t, e, map[string]Handler{})
	eventually(t, "job failed", func() bool { return e.state(job.ID) == domain.JobFailed })
	if got := e.get(job.ID).Error; got == nil || !strings.Contains(got.Message, "unknown.type") {
		t.Fatalf("error = %+v", got)
	}
}

func TestEngineHonoursRestoreHold(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	e.store.SetRestoreHold(true)
	var ran atomic.Bool
	running(t, e, map[string]Handler{"test.job": handlerFunc(func(context.Context, Lease) error {
		ran.Store(true)
		return nil
	})})
	time.Sleep(30 * time.Millisecond)
	if ran.Load() || e.state(job.ID) != domain.JobQueued {
		t.Fatalf("job ran during restore hold (state %s)", e.state(job.ID))
	}
	e.store.SetRestoreHold(false)
	eventually(t, "job succeeded after the hold", func() bool { return e.state(job.ID) == domain.JobSucceeded })
}

func TestEngineCancelsAHandlerWhoseLeaseWasLost(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	started := make(chan struct{})
	cancelled := make(chan struct{})
	handler := handlerFunc(func(ctx context.Context, _ Lease) error {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	running(t, e, map[string]Handler{"test.job": handler})
	<-started

	e.clock.Advance(leaseTTL + time.Second) // the next heartbeat finds the lease expired
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("handler context was not cancelled after the lease was lost")
	}
	time.Sleep(20 * time.Millisecond)
	if got := e.get(job.ID); got.State != domain.JobRunning || got.FinishedAt != nil {
		t.Fatalf("a worker without a lease changed the job: %+v", got)
	}
	taken, err := e.store.Takeover(context.Background(), "r1")
	if err != nil || len(taken) != 1 {
		t.Fatalf("Takeover = %v, %v", taken, err)
	}
}

func TestEngineHeartbeatsKeepALongHandlerAlive(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	release := make(chan struct{})
	started := make(chan struct{})
	handler := handlerFunc(func(context.Context, Lease) error {
		close(started)
		<-release
		return nil
	})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	running(t, e, map[string]Handler{"test.job": handler})
	<-started

	for range 3 { // each step is within one lease TTL, but the total is not
		before := e.get(job.ID).HeartbeatAt
		e.clock.Advance(leaseTTL / 2)
		eventually(t, "a heartbeat", func() bool { return e.get(job.ID).HeartbeatAt.After(*before) })
	}
	taken, err := e.store.Takeover(context.Background(), "r1")
	if err != nil || len(taken) != 0 {
		t.Fatalf("Takeover = %v, %v; the lease should still be live", taken, err)
	}
	releaseOnce.Do(func() { close(release) })
	eventually(t, "job succeeded", func() bool { return e.state(job.ID) == domain.JobSucceeded })
}

func TestEngineShutdownLeavesARunningJobToTakeover(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	started := make(chan struct{})
	stop := running(t, e, map[string]Handler{"test.job": handlerFunc(func(ctx context.Context, _ Lease) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})})
	<-started
	stop()
	if got := e.state(job.ID); got != domain.JobRunning {
		t.Fatalf("state after shutdown = %s, want running (crash-equivalent)", got)
	}
}

func TestEngineReconcilesAnInterruptedJobEndToEnd(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 3 })
	e.interrupt("dead-worker")

	var ran atomic.Bool
	running(t, e, map[string]Handler{"test.job": handlerFunc(func(context.Context, Lease) error {
		ran.Store(true)
		return nil
	})}, func(c *EngineConfig) { c.ReconcileInterval = 5 * time.Millisecond })

	eventually(t, "requeued job to succeed", func() bool { return e.state(job.ID) == domain.JobSucceeded })
	if !ran.Load() {
		t.Fatal("handler never ran")
	}
}

func TestNewEngineValidatesAndDefaults(t *testing.T) {
	if _, err := NewEngine(EngineConfig{}); err == nil {
		t.Fatal("NewEngine without a store succeeded")
	}
	e := newEnv(t)
	engine, err := NewEngine(EngineConfig{Store: e.store})
	if err != nil {
		t.Fatal(err)
	}
	if engine.cfg.Workers != 4 || engine.cfg.HeartbeatInterval != leaseTTL/3 {
		t.Fatalf("defaults = %+v", engine.cfg)
	}
}

func TestNewStoreRequiresItsDependencies(t *testing.T) {
	e := newEnv(t)
	good := Config{DB: e.db, Clock: e.clock, IDs: e.ids, Revalidator: e.reval, LockPlanner: e.planner}
	for name, mutate := range map[string]func(*Config){
		"db":          func(c *Config) { c.DB = nil },
		"clock":       func(c *Config) { c.Clock = nil },
		"ids":         func(c *Config) { c.IDs = nil },
		"revalidator": func(c *Config) { c.Revalidator = nil },
		"planner":     func(c *Config) { c.LockPlanner = nil },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := NewStore(cfg); err == nil {
			t.Errorf("NewStore without %s succeeded", name)
		}
	}
	if _, err := NewStore(good); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
}

func TestFailureOfKeepsTypedErrors(t *testing.T) {
	typed := FailureOf(fmtWrap(errBoom))
	if typed.Code != "INTERNAL" || typed.Message == "" {
		t.Fatalf("plain error failure = %+v", typed)
	}
	if !errors.Is(ErrLeaseLost, ErrLeaseLost) {
		t.Fatal("ErrLeaseLost does not match itself")
	}
}

func fmtWrap(err error) error { return errors.Join(errors.New("ctx"), err) }
