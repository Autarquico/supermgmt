package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

const settledEvidence = `{"done":true,"exit_status":0,"classification":"complete"}`

func TestSettledEarlierStepsDoNotBlockRecoveryOfAMultiStepJob(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 5 })
	c := e.claim("w1")
	step1 := dispatchedIntent(e, c.Lease)
	if err := e.store.CompleteIntent(ctx, c.Lease, step1.ID, OutcomeSucceeded, json.RawMessage(settledEvidence)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.RecordIntent(ctx, c.Lease, sampleIntent(e)); err != nil { // step 2, never dispatched
		t.Fatal(err)
	}
	e.clock.Advance(10*time.Minute + leaseTTL) // long past step 1's deadline and evidence window
	if _, err := e.store.Takeover(ctx, "r1"); err != nil {
		t.Fatal(err)
	}

	if got := reconcile(e, nil); len(got) != 1 || got[0].Action != ReconcileRequeued || e.state(job.ID) != domain.JobQueued {
		t.Fatalf("first interruption: Reconcile = %v, state %s", got, e.state(job.ID))
	}

	// Second interruption after the requeue: step 1 is still settled, the new step is undispatched.
	c2 := e.claim("w2")
	if _, err := e.store.RecordIntent(ctx, c2.Lease, sampleIntent(e)); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(10*time.Minute + leaseTTL)
	if _, err := e.store.Takeover(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if got := reconcile(e, nil); len(got) != 1 || got[0].Action != ReconcileRequeued || e.state(job.ID) != domain.JobQueued {
		t.Fatalf("second interruption: Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestReconciledIntentStaysSettledOnLaterInterruptions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 5 })
	c := e.claim("w1")
	step1 := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{step1.ID: proof(ClassComplete)}}
	if got := reconcile(e, src); len(got) != 1 || got[0].Action != ReconcileRequeued {
		t.Fatalf("first interruption: Reconcile = %v", got)
	}

	c2 := e.claim("w2")
	step2 := dispatchedIntent(e, c2.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	src = &evidenceStub{byIntent: map[domain.ID]Evidence{step2.ID: proof(ClassComplete)}}
	if got := reconcile(e, src); len(got) != 1 || got[0].Action != ReconcileRequeued || e.state(job.ID) != domain.JobQueued {
		t.Fatalf("second interruption: Reconcile = %v, state %s", got, e.state(job.ID))
	}
	if src.calls != 2 { // two samples of step 2; step 1 is never collected again
		t.Fatalf("collected %d times, want 2", src.calls)
	}
}

func TestReconcilerStillRequiresFreshProofForUnsettledEvidence(t *testing.T) {
	for name, evidence := range map[string]string{
		"nonzero exit status": `{"done":true,"exit_status":1}`,
		"proof unclassified":  `{"done":true,"exit_status":0}`,
		"partial state":       `{"done":true,"exit_status":0,"classification":"partial_stable"}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 5 })
			c := e.claim("w1")
			intent := dispatchedIntent(e, c.Lease)
			if err := e.store.CompleteIntent(context.Background(), c.Lease, intent.ID, OutcomeSucceeded, json.RawMessage(evidence)); err != nil {
				t.Fatal(err)
			}
			e.clock.Advance(leaseTTL + time.Second)
			if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
				t.Fatal(err)
			}
			if got := reconcile(e, nil); len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
				t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
			}
		})
	}
}

func TestSamplesDoNotSurviveAcrossInterruptions(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassComplete)}}
	if got, _ := e.store.Reconcile(context.Background(), src); got[0].Action != ReconcileHeld {
		t.Fatalf("first sample = %v", got)
	}

	// Another interruption happened since (the generation moved on): the old sample is stale.
	e.inTx(func(tx *database.Tx) {
		if _, err := tx.ExecContext(context.Background(), `UPDATE jobs SET lease_generation = lease_generation + 2 WHERE id = ?`, job.ID); err != nil {
			t.Fatal(err)
		}
	})
	e.clock.Advance(sampleGap)
	if got, _ := e.store.Reconcile(context.Background(), src); got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("a stale sample confirmed a new interruption: %v", got)
	}
}

func TestReconcilerForgetsJobsItHasSettledOrLost(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	settled := e.enqueue()
	c := e.claim("w1")
	a := dispatchedIntent(e, c.Lease)
	gone := e.enqueue()
	c2 := e.claim("w2")
	b := dispatchedIntent(e, c2.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if taken, err := e.store.Takeover(ctx, "r1"); err != nil || len(taken) != 2 {
		t.Fatalf("Takeover = %v, %v", taken, err)
	}
	e.clock.Advance(time.Minute)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{a.ID: proof(ClassComplete), b.ID: proof(ClassPartialStable)}}
	if _, err := e.store.Reconcile(ctx, src); err != nil { // first sample of a, held entry for b
		t.Fatal(err)
	}
	e.clock.Advance(sampleGap)
	if _, err := e.store.Reconcile(ctx, src); err != nil { // a succeeds
		t.Fatal(err)
	}
	if e.state(settled.ID) != domain.JobSucceeded {
		t.Fatalf("settled job state = %s", e.state(settled.ID))
	}
	e.inTx(func(tx *database.Tx) { // b is resolved elsewhere
		if _, err := e.store.move(ctx, tx, move{id: gone.ID, from: domain.JobInterrupted, to: domain.JobFailed, actor: systemActor}); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := e.store.Reconcile(ctx, src); err != nil {
		t.Fatal(err)
	}
	e.store.reconcileMu.Lock()
	defer e.store.reconcileMu.Unlock()
	if len(e.store.samples) != 0 || len(e.store.held) != 0 {
		t.Fatalf("leftover state: samples %v, held %v", e.store.samples, e.store.held)
	}
}
