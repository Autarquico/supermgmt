package integration

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

type handlerFunc func(ctx context.Context, lease jobs.Lease) error

func (f handlerFunc) Run(ctx context.Context, lease jobs.Lease) error { return f(ctx, lease) }

// runEngine starts an engine over w's store and stops it when the test ends.
func runEngine(t *testing.T, w *world, handlers map[string]jobs.Handler) {
	t.Helper()
	engine, err := jobs.NewEngine(jobs.EngineConfig{
		Store: w.store, Handlers: handlers, Workers: 2,
		PollInterval: 2 * time.Millisecond, HeartbeatInterval: 2 * time.Millisecond, ReconcileInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = engine.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("engine did not stop")
		}
	})
}

func TestSpecRevisionChangeInvalidatesApproval(t *testing.T) {
	t.Run("a spec_revision bump before the claim fails the job with PLAN_STALE and an event", func(t *testing.T) {
		w := newWorld(t)
		job := w.approveToQuorum(w.submitReboot(w.prodNode))
		if job.State != domain.JobQueued {
			t.Fatalf("approved job state = %s, want queued", job.State)
		}

		w.bumpSpecRevision(w.prodNode.ID)

		_, ok, err := w.store.Claim(context.Background(), "worker-1")
		if err != nil || ok {
			t.Fatalf("Claim = ok %v, err %v; want nothing claimed", ok, err)
		}
		got := w.job(job.ID)
		if got.State != domain.JobFailed || got.Error == nil || got.Error.Code != smerr.CodeConflict || got.Error.Reason != smerr.ReasonPlanStale {
			t.Fatalf("job = %s %+v, want failed CONFLICT/PLAN_STALE", got.State, got.Error)
		}
		if !slices.ContainsFunc(w.events(), func(e domain.Event) bool {
			return e.Action == "job.failed" && e.ResourceID == job.ID && e.Data["error_reason"] == string(smerr.ReasonPlanStale)
		}) {
			t.Error("no job.failed event with error_reason PLAN_STALE")
		}
		if n := w.lockCount(context.Background()); n != 0 {
			t.Errorf("a stale job left %d locks", n)
		}
	})

	t.Run("observation writes do not invalidate it and the handler runs to succeeded", func(t *testing.T) {
		w := newWorld(t)
		job := w.approveToQuorum(w.submitReboot(w.prodNode))
		w.inTx(func(ctx context.Context, tx *database.Tx) error {
			if err := database.SetNodeReachability(ctx, tx, w.prodNode.ID, domain.ReachabilityReachable); err != nil {
				return err
			}
			if err := database.TouchLastSeen(ctx, tx, w.prodNode.ID, w.clock.Now()); err != nil {
				return err
			}
			return database.RecordObservation(ctx, tx, database.Observation{
				ID: w.ids.NewID(), ResourceType: domain.ResourceNode, ResourceID: w.prodNode.ID,
				Kind: "uptime", Value: 42, ObservedAt: w.clock.Now(),
			})
		})
		var ran atomic.Bool
		runEngine(t, w, map[string]jobs.Handler{"node.reboot": handlerFunc(func(context.Context, jobs.Lease) error {
			ran.Store(true)
			return nil
		})})

		eventually(t, "job to succeed", func() bool { return w.job(job.ID).State == domain.JobSucceeded })
		if !ran.Load() {
			t.Error("handler did not run")
		}
	})
}

// evidenceFake answers Collect with a fixed verdict.
type evidenceFake struct{ evidence jobs.Evidence }

func (e evidenceFake) Collect(context.Context, jobs.Intent) (jobs.Evidence, error) {
	return e.evidence, nil
}

// interruptedReboot submits a dev reboot, claims it as worker-A, dispatches an
// intent, lets the lease expire and takes the job over.
func interruptedReboot(t *testing.T) (*world, jobs.Claimed) {
	t.Helper()
	ctx := context.Background()
	w := newWorld(t)
	w.approveToQuorum(w.submitReboot(w.devNode))
	a, ok, err := w.store.Claim(ctx, "worker-A")
	if err != nil || !ok {
		t.Fatalf("Claim = ok %v, err %v", ok, err)
	}
	intent, err := w.store.RecordIntent(ctx, a.Lease, jobs.NewIntent{
		Step: "reboot", Operation: "ssh.reboot", TargetType: "node", TargetID: w.devNode.ID.String(),
		DeadlineAt: w.clock.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("RecordIntent: %v", err)
	}
	if err := w.store.MarkDispatched(ctx, a.Lease, intent.ID); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	w.clock.Advance(leaseTTL + time.Second)
	taken, err := w.store.Takeover(ctx, "r1")
	if err != nil || !slices.Equal(taken, []domain.ID{a.Job.ID}) {
		t.Fatalf("Takeover = %v, %v", taken, err)
	}
	return w, a
}

func TestLeaseFencing(t *testing.T) {
	t.Run("every write by the old worker is rejected with ErrLeaseLost", func(t *testing.T) {
		w, a := interruptedReboot(t)
		ctx := context.Background()
		writes := map[string]func() error{
			"heartbeat": func() error { return w.store.Heartbeat(ctx, a.Lease) },
			"intent": func() error {
				_, err := w.store.RecordIntent(ctx, a.Lease, jobs.NewIntent{
					Step: "again", Operation: "ssh.reboot", TargetType: "node", TargetID: "x", DeadlineAt: w.clock.Now().Add(time.Minute),
				})
				return err
			},
			"succeed": func() error { return w.store.Succeed(ctx, a.Lease) },
			"fail":    func() error { return w.store.Fail(ctx, a.Lease, errors.New("boom")) },
		}
		for name, write := range writes {
			if err := write(); !errors.Is(err, jobs.ErrLeaseLost) {
				t.Errorf("old worker %s = %v, want ErrLeaseLost", name, err)
			}
		}
		if got := w.job(a.Job.ID); got.State != domain.JobInterrupted || got.FinishedAt != nil {
			t.Errorf("old worker changed the job: %s finished %v", got.State, got.FinishedAt)
		}
	})

	t.Run("locks stay held while interrupted and block a conflicting job", func(t *testing.T) {
		w, _ := interruptedReboot(t)
		held := w.lockCount(context.Background())
		rival := w.approveToQuorum(w.submitReboot(w.devNode))

		_, ok, err := w.store.Claim(context.Background(), "worker-B")

		if err != nil || ok {
			t.Fatalf("Claim = ok %v, err %v; want the rival blocked", ok, err)
		}
		if got := w.job(rival.ID).State; got != domain.JobQueued {
			t.Errorf("rival state = %s, want queued", got)
		}
		if after := w.lockCount(context.Background()); after != held || held == 0 {
			t.Errorf("locks = %d, want %d (non-zero) kept by the interrupted job", after, held)
		}
	})

	t.Run("reconcile follows the evidence and never redispatches", func(t *testing.T) {
		cases := []struct {
			name      string
			evidence  jobs.Evidence
			want      jobs.ReconcileAction
			wantState domain.JobState
			wantLocks bool
		}{
			{"exit status 0 completes the job and frees its locks", jobs.Evidence{Done: true}, jobs.ReconcileSucceeded, domain.JobSucceeded, false},
			{"no completion signal holds the job and its locks", jobs.Evidence{}, jobs.ReconcileHeld, domain.JobInterrupted, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				w, a := interruptedReboot(t)

				got, err := w.store.Reconcile(context.Background(), evidenceFake{tc.evidence})

				if err != nil || len(got) != 1 || got[0].Action != tc.want {
					t.Fatalf("Reconcile = %v, %v; want one %s", got, err, tc.want)
				}
				if state := w.job(a.Job.ID).State; state != tc.wantState {
					t.Errorf("state = %s, want %s", state, tc.wantState)
				}
				if holds := w.lockCount(context.Background()) > 0; holds != tc.wantLocks {
					t.Errorf("locks held = %v, want %v", holds, tc.wantLocks)
				}
			})
		}
	})

	t.Run("the engine cancels a handler whose lease was taken over", func(t *testing.T) {
		w := newWorld(t)
		job := w.approveToQuorum(w.submitReboot(w.devNode))
		started, cancelled := make(chan struct{}), make(chan struct{})
		runEngine(t, w, map[string]jobs.Handler{"node.reboot": handlerFunc(func(ctx context.Context, _ jobs.Lease) error {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		})})
		<-started

		w.clock.Advance(leaseTTL + time.Second)
		if _, err := w.store.Takeover(context.Background(), "r1"); err != nil {
			t.Fatal(err)
		}

		select {
		case <-cancelled:
		case <-time.After(10 * time.Second):
			t.Fatal("handler was not cancelled after takeover")
		}
		if got := w.job(job.ID).State; got != domain.JobInterrupted {
			t.Errorf("state = %s, want interrupted", got)
		}
	})
}

func TestEndToEndHappyPath(t *testing.T) {
	w := newWorld(t)
	job := w.submit("node.probe", w.devNode)
	if job.State != domain.JobQueued {
		t.Fatalf("dev probe state = %s, want queued without approval", job.State)
	}
	var locksDuringRun atomic.Int64
	runEngine(t, w, map[string]jobs.Handler{"node.probe": handlerFunc(func(ctx context.Context, _ jobs.Lease) error {
		locksDuringRun.Store(int64(w.lockCount(ctx)))
		return nil
	})})

	eventually(t, "job to succeed", func() bool { return w.job(job.ID).State == domain.JobSucceeded })

	if locksDuringRun.Load() == 0 {
		t.Error("handler ran without holding locks")
	}
	if n := w.lockCount(context.Background()); n != 0 {
		t.Errorf("%d locks left after success", n)
	}
	want := []string{"job.queued", "job.running", "job.succeeded"}
	if got := w.jobActions(job.ID); !slices.Equal(got, want) {
		t.Errorf("job events = %v, want %v", got, want)
	}
}
