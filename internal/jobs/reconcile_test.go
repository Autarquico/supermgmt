package jobs

import (
	"context"
	"errors"
	"slices"
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

func reconcile(e *env, src EvidenceSource) []Resolution {
	e.t.Helper()
	got, err := e.store.Reconcile(context.Background(), src)
	if err != nil {
		e.t.Fatalf("Reconcile: %v", err)
	}
	return got
}

func TestReconcilerWithoutDispatchedIntents(t *testing.T) {
	cases := []struct {
		name       string
		class      domain.RetryClass
		withIntent bool // a recorded but never dispatched intent
		want       ReconcileAction
		wantState  domain.JobState
	}{
		{"idempotent is requeued", domain.RetryIdempotent, false, ReconcileRequeued, domain.JobQueued},
		{"resumable resumes", domain.RetryResumable, false, ReconcileRequeued, domain.JobQueued},
		{"resumable with an undispatched intent resumes", domain.RetryResumable, true, ReconcileRequeued, domain.JobQueued},
		{"non_retryable with nothing mutated fails", domain.RetryNonRetryable, false, ReconcileFailed, domain.JobFailed},
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
			if e.state(job.ID) != tc.wantState || e.lockCount(job.ID) != 0 {
				t.Fatalf("state %s locks %d, want %s without locks", e.state(job.ID), e.lockCount(job.ID), tc.wantState)
			}
		})
	}
}

func TestReconcilerContinuesWhenEvidenceProvesCompletion(t *testing.T) {
	proof := Evidence{Done: true, ExitStatus: 0}
	cases := []struct {
		name      string
		class     domain.RetryClass
		want      ReconcileAction
		wantState domain.JobState
	}{
		{"resumable resumes at the next step", domain.RetryResumable, ReconcileRequeued, domain.JobQueued},
		{"idempotent is requeued", domain.RetryIdempotent, ReconcileRequeued, domain.JobQueued},
		{"non_retryable completes with the recorded outcome", domain.RetryNonRetryable, ReconcileSucceeded, domain.JobSucceeded},
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

			src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof}}
			got := reconcile(e, src)
			if len(got) != 1 || got[0].Action != tc.want || e.state(job.ID) != tc.wantState {
				t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
			}
			intents, err := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
			if err != nil || len(intents) != 1 || intents[0].State != IntentCompleted || intents[0].Outcome != OutcomeSucceeded ||
				string(intents[0].Evidence) != `{"done":true,"exit_status":0}` {
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
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: {Done: true, ExitStatus: 1}}}
		},
		"done flag unset": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: {Done: false}}}
		},
		"adapter error (node offline)": func(id domain.ID) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{id: {Done: true}}, err: errors.New("node unreachable")}
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
				events := e.actions(job.ID)
				if events[len(events)-1] != "job.reconcile_held" {
					t.Fatalf("events = %v, want a trailing job.reconcile_held", events)
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

func TestReconcilerOneMissingProofHoldsTheWholeJob(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass = domain.RetryResumable })
	c := e.claim("w1")
	proven := dispatchedIntent(e, c.Lease)
	unproven := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{proven.ID: {Done: true}}}
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

func TestReconcilerNonRetryableFailsWhenARecordedOperationFailed(t *testing.T) {
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
	got := reconcile(e, nil)
	if len(got) != 1 || got[0].Action != ReconcileFailed || e.state(job.ID) != domain.JobFailed {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestReconcilerIdempotentJobOutOfAttemptsFails(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 1 })
	e.interrupt("w1")
	got := reconcile(e, nil)
	if len(got) != 1 || got[0].Action != ReconcileFailed || e.state(job.ID) != domain.JobFailed {
		t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
	}
}

func TestRequeuedInterruptedJobIsRevalidatedLikeANewClaim(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass = domain.RetryResumable })
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
			domain.UnixMillis(e.clock.Now().Add(time.Minute)), job.ID)
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
	e.enqueue(func(nj *NewJob) { nj.RetryClass = domain.RetryIdempotent })
	c := e.claim("w1")
	dispatchedIntent(e, c.Lease)
	src := &evidenceStub{}
	reconcile(e, src) // still running: nothing interrupted yet
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
