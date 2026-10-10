package jobs

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// evidenceStub answers Collect per intent id and counts the calls.
type evidenceStub struct {
	byIntent map[domain.ID]Evidence
	err      error
	calls    int
}

func (s *evidenceStub) Collect(_ context.Context, in Intent) (Evidence, error) {
	s.calls++
	return s.byIntent[in.ID], s.err
}

// dispatchedIntent records and dispatches an intent under the lease, as a worker
// would just before sending the operation.
func dispatchedIntent(e *env, lease Lease) Intent {
	e.t.Helper()
	ctx := context.Background()
	intent, err := e.store.RecordIntent(ctx, lease, sampleIntent(e))
	if err != nil {
		e.t.Fatalf("RecordIntent: %v", err)
	}
	if err := e.store.MarkDispatched(ctx, lease, intent.ID); err != nil {
		e.t.Fatalf("MarkDispatched: %v", err)
	}
	return intent
}

const sampleGap = 30 * time.Second

// reconcile runs the reconciler the way the engine would over time: a pass once
// every intent is past deadline + grace, and a second one sampleGap later when
// the first did not already settle the job. It returns the last pass that did anything.
func reconcile(e *env, src EvidenceSource) []Resolution {
	e.t.Helper()
	pass := func() []Resolution {
		got, err := e.store.Reconcile(context.Background(), src)
		if err != nil {
			e.t.Fatalf("Reconcile: %v", err)
		}
		return got
	}
	e.clock.Advance(time.Minute) // sample intents expire after 1s; grace is 45s
	first := pass()
	for _, r := range first {
		if r.Action != ReconcileHeld {
			return first
		}
	}
	e.clock.Advance(sampleGap)
	return pass()
}

func proof(c Classification) Evidence { return Evidence{Done: true, Classification: c} }

func TestReconcilerWithoutDispatchedIntents(t *testing.T) {
	cases := []struct {
		name       string
		class      domain.RetryClass
		withIntent bool // a recorded but never dispatched intent
		want       ReconcileAction
		wantState  domain.JobState
		wantLocks  int // locks are kept until terminal (spec §20.5)
	}{
		{"idempotent is requeued", domain.RetryIdempotent, false, ReconcileRequeued, domain.JobQueued, 1},
		{"resumable resumes", domain.RetryResumable, false, ReconcileRequeued, domain.JobQueued, 1},
		{"resumable with an undispatched intent resumes", domain.RetryResumable, true, ReconcileRequeued, domain.JobQueued, 1},
		{"non_retryable with nothing mutated fails", domain.RetryNonRetryable, false, ReconcileFailed, domain.JobFailed, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = tc.class, 3 })
			c := e.claim("w1")
			if tc.withIntent {
				if _, err := e.store.RecordIntent(context.Background(), c.Lease, sampleIntent(e)); err != nil {
					t.Fatal(err)
				}
			}
			e.clock.Advance(leaseTTL + time.Second)
			if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
				t.Fatal(err)
			}

			got := reconcile(e, nil)
			if len(got) != 1 || got[0].JobID != job.ID || got[0].Action != tc.want {
				t.Fatalf("Reconcile = %v, want %s", got, tc.want)
			}
			if e.state(job.ID) != tc.wantState || e.lockCount(job.ID) != tc.wantLocks {
				t.Fatalf("state %s locks %d, want %s with %d locks", e.state(job.ID), e.lockCount(job.ID), tc.wantState, tc.wantLocks)
			}
		})
	}
}

func TestReconcilerContinuesWhenEvidenceProvesCompletion(t *testing.T) {
	cases := []struct {
		name      string
		class     domain.RetryClass
		observed  Classification
		want      ReconcileAction
		wantState domain.JobState
		outcome   string
	}{
		{"resumable resumes at the next step", domain.RetryResumable, ClassComplete, ReconcileRequeued, domain.JobQueued, OutcomeSucceeded},
		{"idempotent is requeued", domain.RetryIdempotent, ClassComplete, ReconcileRequeued, domain.JobQueued, OutcomeSucceeded},
		{"non_retryable completes when the adapter classifies complete", domain.RetryNonRetryable, ClassComplete, ReconcileSucceeded, domain.JobSucceeded, OutcomeSucceeded},
		{"non_retryable fails when the operation never started", domain.RetryNonRetryable, ClassNotStarted, ReconcileFailed, domain.JobFailed, OutcomeNotStarted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = tc.class, 3 })
			c := e.claim("w1")
			intent := dispatchedIntent(e, c.Lease)
			e.clock.Advance(leaseTTL + time.Second)
			if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
				t.Fatal(err)
			}

			src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(tc.observed)}}
			got := reconcile(e, src)
			if len(got) != 1 || got[0].Action != tc.want || e.state(job.ID) != tc.wantState {
				t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
			}
			intents, err := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
			if err != nil || len(intents) != 1 || intents[0].State != IntentCompleted || intents[0].Outcome != tc.outcome ||
				!strings.Contains(string(intents[0].Evidence), `"classification":"`+string(tc.observed)+`"`) {
				t.Fatalf("intent after reconcile = %+v, %v", intents, err)
			}
		})
	}
}

func TestReconcilerNeverRedispatchesWithoutEvidence(t *testing.T) {
	sources := map[string]func(intent domain.ID) EvidenceSource{
		"no evidence source": func(domain.ID) EvidenceSource { return nil },
		"completion signal missing": func(domain.ID) EvidenceSource {
			return &evidenceStub{}
		},
		"nonzero exit status": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: {Done: true, ExitStatus: 1, Classification: ClassComplete}}}
		},
		"done flag unset": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: {Classification: ClassComplete}}}
		},
		"proof without a classification": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: {Done: true}}}
		},
		"partial_stable state": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: proof(ClassPartialStable)}}
		},
		"unknown state": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: proof(ClassUnknown)}}
		},
		"adapter error (node offline)": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: proof(ClassComplete)}, err: errors.New("node unreachable")}
		},
	}
	for name, source := range sources {
		for _, class := range domain.AllRetryClasses() {
			t.Run(name+"/"+string(class), func(t *testing.T) {
				e := newEnv(t)
				job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = class, 3 })
				c := e.claim("w1")
				intent := dispatchedIntent(e, c.Lease)
				e.clock.Advance(leaseTTL + time.Second)
				if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
					t.Fatal(err)
				}

				got := reconcile(e, source(intent.ID))
				if len(got) != 1 || got[0].Action != ReconcileHeld {
					t.Fatalf("Reconcile = %v, want held", got)
				}
				if e.state(job.ID) != domain.JobInterrupted || e.lockCount(job.ID) != 1 {
					t.Fatalf("state %s locks %d, want interrupted with its lock", e.state(job.ID), e.lockCount(job.ID))
				}
				intents, _ := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
				if intents[0].State != IntentRecorded {
					t.Fatalf("intent was completed without evidence: %+v", intents[0])
				}
				// The held job keeps blocking: nothing else may claim its node.
				e.planner.setLocks("rival", domain.LockSpec{Key: "node:" + job.Resource.ID.String(), Mode: domain.LockShared})
				e.enqueue(func(nj *NewJob) { nj.Type, nj.Resource = "rival", job.Resource })
				e.claimNothing("w2")
			})
		}
	}
}

func TestHeldJobIsReportedOnEntryAndOnReasonChangeOnly(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	first := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	heldEvents := func() int {
		n := 0
		for _, a := range e.actions(job.ID) {
			if a == "job.reconcile_held" {
				n++
			}
		}
		return n
	}

	for range 3 {
		reconcile(e, nil)
	}
	if heldEvents() != 1 {
		t.Fatalf("held events after repeated passes = %d, want 1", heldEvents())
	}

	// A different reason is news again: the intent now has proof, but a partial state.
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{first.ID: proof(ClassPartialStable)}}
	e.store.reconcileMu.Lock()
	e.store.held[job.ID] = "an older reason"
	e.store.reconcileMu.Unlock()
	reconcile(e, src)
	if heldEvents() != 2 {
		t.Fatalf("held events after a reason change = %d, want 2", heldEvents())
	}
}

func TestReconcilerNeedsTwoIdenticalSamples(t *testing.T) {
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
	pass := func() []Resolution {
		got, err := e.store.Reconcile(context.Background(), src)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	if got := pass(); len(got) != 1 || got[0].Action != ReconcileHeld {
		t.Fatalf("first sample = %v, want held", got)
	}
	e.clock.Advance(sampleGap - time.Second) // too soon for the second sample
	if got := pass(); got[0].Action != ReconcileHeld {
		t.Fatalf("early second sample = %v, want held", got)
	}
	src.byIntent[intent.ID] = proof(ClassNotStarted) // the state moved: start over
	e.clock.Advance(time.Second)
	if got := pass(); got[0].Action != ReconcileHeld {
		t.Fatalf("differing sample = %v, want held", got)
	}
	e.clock.Advance(sampleGap)
	if got := pass(); got[0].Action != ReconcileFailed || e.state(job.ID) != domain.JobFailed {
		t.Fatalf("confirmed sample = %v, state %s", got, e.state(job.ID))
	}
}

func TestReconcilerWaitsForDeadlineAndGraceBeforeCollecting(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease) // deadline: 1s after creation
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassComplete)}}
	eventsBefore := len(e.actions(job.ID))

	e.clock.Set(intent.DeadlineAt.Add(defaultReconcileGrace)) // lease long expired, grace not yet past
	got, err := e.store.Reconcile(context.Background(), src)
	if err != nil || len(got) != 0 || src.calls != 0 || len(e.actions(job.ID)) != eventsBefore {
		t.Fatalf("Reconcile = %v, %v; collected %d times; events %v", got, err, src.calls, e.actions(job.ID))
	}
	e.clock.Advance(time.Millisecond)
	if got, _ := e.store.Reconcile(context.Background(), src); len(got) != 1 || src.calls != 1 {
		t.Fatalf("Reconcile after grace = %v, collected %d times", got, src.calls)
	}
}

func TestReconcilerStopsCollectingAfterTheEvidenceWindow(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassComplete)}}
	e.clock.Set(intent.DeadlineAt.Add(evidenceWindow + time.Second))

	got, err := e.store.Reconcile(context.Background(), src)
	if err != nil || len(got) != 1 || got[0].Action != ReconcileHeld || src.calls != 0 || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("Reconcile = %v, %v; collected %d times", got, err, src.calls)
	}
}

func TestReconcilerHoldsWorkerCompletedIntentsWithoutProof(t *testing.T) {
	for _, outcome := range []string{OutcomeSucceeded, OutcomeFailed} {
		t.Run("recorded outcome "+outcome, func(t *testing.T) {
			e := newEnv(t)
			job := e.enqueue()
			c := e.claim("w1")
			intent := dispatchedIntent(e, c.Lease)
			if err := e.store.CompleteIntent(context.Background(), c.Lease, intent.ID, outcome, nil); err != nil {
				t.Fatal(err)
			}
			e.clock.Advance(leaseTTL + time.Second)
			if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
				t.Fatal(err)
			}
			got := reconcile(e, nil)
			if len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
				t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
			}
		})
	}
}

func TestReconcilerKeepsProofSeparateFromTheRecordedOutcome(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	if err := e.store.CompleteIntent(context.Background(), c.Lease, intent.ID, OutcomeFailed, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassComplete)}}
	got := reconcile(e, src) // the platform says complete, the worker said failed
	if len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestReconcilerOneMissingProofHoldsTheWholeJob(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 3 })
	c := e.claim("w1")
	proven := dispatchedIntent(e, c.Lease)
	unproven := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{proven.ID: proof(ClassComplete)}}
	got := reconcile(e, src)
	if len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
	intents, _ := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
	for _, in := range intents {
		if in.State != IntentRecorded {
			t.Fatalf("intent %s completed although %s has no proof", in.ID, unproven.ID)
		}
	}
}

func TestReconcilerNonRetryableMixedOutcomesAreHeld(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	done := dispatchedIntent(e, c.Lease)
	never := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{done.ID: proof(ClassComplete), never.ID: proof(ClassNotStarted)}}
	if got := reconcile(e, src); len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestReconcilerIdempotentJobOutOfAttemptsFails(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 1 })
	e.interrupt("w1")
	got := reconcile(e, nil)
	if len(got) != 1 || got[0].Action != ReconcileFailed || e.state(job.ID) != domain.JobFailed || e.lockCount(job.ID) != 0 {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestReconcilerResumableJobOutOfAttemptsIsHeldNotFailed(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 1 })
	e.interrupt("w1")
	got := reconcile(e, nil)
	if len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted || e.lockCount(job.ID) != 1 {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestRequeuedInterruptedJobIsRevalidatedLikeANewClaim(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 3 })
	e.interrupt("w1")
	reconcile(e, nil)
	before := e.reval.callCount()

	c := e.claim("w2")
	if c.Job.ID != job.ID || c.Lease.Generation != 3 || e.reval.callCount() != before+1 {
		t.Fatalf("resume claim = %+v (generation %d), revalidations %d -> %d",
			c.Job.ID, c.Lease.Generation, before, e.reval.callCount())
	}
}

func TestReconcilerIgnoresJobsThatAreNotQuiescent(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 3 })
	e.interrupt("w1")
	e.inTx(func(tx *database.Tx) { // a lease that has not expired yet
		_, err := tx.ExecContext(context.Background(), `UPDATE jobs SET lease_until = ? WHERE id = ?`,
			domain.UnixMillis(e.clock.Now().Add(time.Hour)), job.ID)
		if err != nil {
			t.Fatal(err)
		}
	})
	if got := reconcile(e, nil); len(got) != 0 || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestReconcilerSkipsEvidenceCollectionForQuiescentJobsOnly(t *testing.T) {
	e := newEnv(t)
	e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 3 })
	c := e.claim("w1")
	dispatchedIntent(e, c.Lease)
	src := &evidenceStub{}
	if _, err := e.store.Reconcile(context.Background(), src); err != nil { // still running: nothing interrupted yet
		t.Fatal(err)
	}
	if src.calls != 0 {
		t.Fatalf("collected evidence %d times for a running job", src.calls)
	}
}

func TestReconcilerResolutionsAreAudited(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 3 })
	e.interrupt("w1")
	reconcile(e, nil)
	want := []string{"job.queued", "job.running", "job.interrupted", "job.queued"}
	if got := e.actions(job.ID); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestFailureMessagesAreScrubbed(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	if err := e.store.Fail(context.Background(), c.Lease, errors.New("ssh failed: Authorization: Bearer abc123def456ghi789")); err != nil {
		t.Fatal(err)
	}
	got := e.get(job.ID).Error
	if got == nil || strings.Contains(got.Message, "abc123def456ghi789") {
		t.Fatalf("stored failure = %+v, want the token scrubbed", got)
	}
}
