package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// dispatchThenLoseTheConnection is a handler that sends an operation and then
// cannot tell how it ended.
func dispatchThenLoseTheConnection(e *env) Handler {
	return handlerFunc(func(ctx context.Context, lease Lease) error {
		intent, err := e.store.RecordIntent(ctx, lease, sampleIntent(e))
		if err != nil {
			return err
		}
		if err := e.store.MarkDispatched(ctx, lease, intent.ID); err != nil {
			return err
		}
		return fmt.Errorf("observe restart: %w", fmt.Errorf("connection lost: %w", ErrOutcomeUnknown))
	})
}

func TestEngineInterruptsAJobWhoseOutcomeIsUnknown(t *testing.T) {
	for _, class := range []domain.RetryClass{domain.RetryNonRetryable, domain.RetryIdempotent} {
		t.Run(string(class), func(t *testing.T) {
			e := newEnv(t)
			job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = class, 3 })
			before := e.get(job.ID).LeaseGeneration
			running(t, e, map[string]Handler{"test.job": dispatchThenLoseTheConnection(e)})
			eventually(t, "job interrupted", func() bool { return e.state(job.ID) == domain.JobInterrupted })

			got := e.get(job.ID)
			if got.Error != nil || got.FinishedAt != nil {
				t.Fatalf("interrupted job must not carry a failure: %+v", got)
			}
			if e.lockCount(job.ID) == 0 {
				t.Fatal("interrupted job released its locks")
			}
			if got.LeaseGeneration < before+2 || got.LeaseUntil == nil || got.LeaseUntil.After(e.clock.Now()) {
				t.Fatalf("lease = generation %d until %v: want a bumped generation and an expired lease", got.LeaseGeneration, got.LeaseUntil)
			}
			intents, err := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
			if err != nil || len(intents) != 1 || intents[0].State != IntentRecorded || !intents[0].Dispatched() {
				t.Fatalf("intents = %+v, %v; want one dispatched, still recorded", intents, err)
			}
		})
	}
}

func TestInterruptedOutcomeUnknownIsSettledByEvidenceOrAHuman(t *testing.T) {
	setup := func(t *testing.T) (*env, Job) {
		e := newEnv(t)
		job := e.enqueue(func(nj *NewJob) { nj.PlanHash = planHash })
		running(t, e, map[string]Handler{"test.job": dispatchThenLoseTheConnection(e)})
		eventually(t, "job interrupted", func() bool { return e.state(job.ID) == domain.JobInterrupted })
		return e, job
	}

	t.Run("reconciler with confirmed proof", func(t *testing.T) {
		e, job := setup(t)
		intents, _ := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
		src := &evidenceStub{byIntent: map[domain.ID]Evidence{intents[0].ID: proof(ClassComplete)}}
		if got := reconcile(e, src); len(got) != 1 || got[0].Action != ReconcileSucceeded {
			t.Fatalf("Reconcile = %v", got)
		}
	})
	t.Run("reconciler without evidence holds it", func(t *testing.T) {
		e, job := setup(t)
		if got := reconcile(e, nil); len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
			t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
		}
	})
	t.Run("job.resolve after the deadline", func(t *testing.T) {
		e, job := setup(t)
		e.clock.Advance(time.Minute)
		got, err := e.resolve(resolveRequest(job, ResolveFailed))
		if err != nil || got.State != domain.JobFailed {
			t.Fatalf("Resolve = %+v, %v", got, err)
		}
	})
}

func TestInterruptFencesTheOldWorker(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	c := e.claim("w1")
	if err := e.store.Interrupt(context.Background(), c.Lease, ErrOutcomeUnknown); err != nil {
		t.Fatalf("Interrupt: %v", err)
	}
	if err := e.store.Heartbeat(context.Background(), c.Lease); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Heartbeat after Interrupt = %v, want ErrLeaseLost", err)
	}
	if err := e.store.Interrupt(context.Background(), c.Lease, ErrOutcomeUnknown); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("second Interrupt = %v, want ErrLeaseLost", err)
	}
}

func TestOtherHandlerErrorsStillFailTheJob(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	running(t, e, map[string]Handler{"test.job": handlerFunc(func(context.Context, Lease) error {
		return errors.New("proven failure: exit 3")
	})})
	eventually(t, "job failed", func() bool { return e.state(job.ID) == domain.JobFailed })
}

func TestTwoEmptyFingerprintsNeverPair(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedAwaitingEvidence(e)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: {Done: true, Classification: ClassComplete}}}
	for range 3 {
		if got := reconcileOnce(e, src); got != ReconcileHeld {
			t.Fatalf("fingerprint-less evidence = %s, want held", got)
		}
		e.clock.Advance(sampleGap)
	}
	if e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("state = %s", e.state(job.ID))
	}
}
