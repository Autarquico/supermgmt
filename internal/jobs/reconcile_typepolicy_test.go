package jobs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// interruptedPolicyJob leaves a retryable job interrupted with one dispatched
// intent, under a Store that applies p.
func interruptedPolicyJob(e *env, p *fakePolicy) (Job, Intent) {
	e.t.Helper()
	e.withPolicy(p)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 3 })
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + 1)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		e.t.Fatal(err)
	}
	return job, intent
}

func TestReconcileTypePolicy_PartialStableReachesPolicy(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	p.verdict = Verdict{Action: VerdictRequeuedRecovery, Reason: "partial deployment, rollback available"}
	job, intent := interruptedPolicyJob(e, p)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassPartialStable)}}

	got := reconcile(e, src)

	if len(got) != 1 || got[0].Action != ReconcileRequeued || e.state(job.ID) != domain.JobQueued {
		t.Fatalf("Reconcile = %v, state %s; want requeued", got, e.state(job.ID))
	}
	if len(p.observed) != 1 || p.observed[0][intent.ID].Classification != ClassPartialStable {
		t.Fatalf("policy saw %v; want the partial_stable evidence", p.observed)
	}
	intents, err := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
	if err != nil || intents[0].State != IntentCompleted || intents[0].Outcome != OutcomeFailed {
		t.Fatalf("intent = %+v, %v; want completed with outcome failed", intents, err)
	}
	last := p.mirrored()[len(p.mirrored())-1]
	if last.to != domain.JobQueued || last.mode != ClaimRecovery {
		t.Fatalf("requeue mirror = %+v; want queued under recovery", last)
	}
	if e.lockCount(job.ID) == 0 {
		t.Fatal("recovery requeue released the job's locks")
	}
}

func TestReconcileTypePolicy_PartialStableIsHeldWhenThePolicyDoesNotAdmitIt(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	p.admit = func(ev Evidence) bool { return ev.Classification == ClassComplete }
	job, intent := interruptedPolicyJob(e, p)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassPartialStable)}}

	got := reconcile(e, src)

	if len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted || len(p.observed) != 0 {
		t.Fatalf("Reconcile = %v, state %s, policy calls %d; want held without the policy", got, e.state(job.ID), len(p.observed))
	}
}

func TestReconcileTypePolicy_MissingOrNonzeroDoneIsHeldDespiteStableSamples(t *testing.T) {
	cases := []struct {
		name string
		ev   Evidence
	}{
		{"no .done file", Evidence{Done: false, Classification: ClassPartialStable, Fingerprint: json.RawMessage(`{"s":1}`)}},
		{".done with exit status 1", Evidence{Done: true, ExitStatus: 1, Classification: ClassPartialStable, Fingerprint: json.RawMessage(`{"s":1}`)}},
		{"complete without .done", Evidence{Done: false, Classification: ClassComplete, Fingerprint: json.RawMessage(`{"s":1}`)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			p := newFakePolicy()
			p.admit = func(Evidence) bool { return true } // a policy cannot weaken Proven()
			p.verdict = Verdict{Action: VerdictRequeuedRecovery}
			job, intent := interruptedPolicyJob(e, p)
			src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: tc.ev}}

			got := reconcile(e, src)

			if len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
				t.Fatalf("Reconcile = %v, state %s; want held", got, e.state(job.ID))
			}
			if len(p.observed) != 0 || p.recovery[job.ID] || e.lockCount(job.ID) == 0 {
				t.Fatalf("policy calls %d, recovery %v, locks %d; want policy untouched and locks kept",
					len(p.observed), p.recovery[job.ID], e.lockCount(job.ID))
			}
		})
	}
}

func TestReconcileTypePolicy_VerdictsAreApplied(t *testing.T) {
	cases := []struct {
		name      string
		verdict   Verdict
		want      ReconcileAction
		wantState domain.JobState
		wantCode  smerr.Code
	}{
		{"succeeded", Verdict{Action: VerdictSucceeded, Reason: "healthy"}, ReconcileSucceeded, domain.JobSucceeded, ""},
		{"failed with its failure", Verdict{
			Action: VerdictFailed, Reason: "before deploy",
			Failure: &Failure{Code: smerr.CodeConflict, Message: "interrupted before deploy"},
		}, ReconcileFailed, domain.JobFailed, smerr.CodeConflict},
		{"failed without a failure", Verdict{Action: VerdictFailed, Reason: "no failure given"}, ReconcileFailed, domain.JobFailed, smerr.CodeInternal},
		{"forward requeue", Verdict{Action: VerdictRequeued, Reason: "resume"}, ReconcileRequeued, domain.JobQueued, ""},
		{"held", Verdict{Action: VerdictHeld, Reason: "human"}, ReconcileHeld, domain.JobInterrupted, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			p := newFakePolicy()
			p.verdict = tc.verdict
			job, intent := interruptedPolicyJob(e, p)
			src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassComplete)}}

			got := reconcile(e, src)

			if len(got) != 1 || got[0].Action != tc.want || e.state(job.ID) != tc.wantState {
				t.Fatalf("Reconcile = %v, state %s", got, e.state(job.ID))
			}
			if failure := e.get(job.ID).Error; tc.wantCode != "" && (failure == nil || failure.Code != tc.wantCode) {
				t.Fatalf("failure = %+v, want code %s", failure, tc.wantCode)
			}
			if p.recovery[job.ID] {
				t.Fatal("a verdict other than recovery wrote a recovery record")
			}
		})
	}
}

func TestReconcileTypePolicy_UnknownVerdictAndPolicyErrorLeaveTheJobInterrupted(t *testing.T) {
	cases := map[string]func(*fakePolicy){
		"unknown action": func(p *fakePolicy) { p.verdict = Verdict{Action: "explode"} },
		"policy error": func(p *fakePolicy) {
			p.verdict, p.reconcileErr = Verdict{Action: VerdictSucceeded}, context.DeadlineExceeded
		},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			p := newFakePolicy()
			script(p)
			job, intent := interruptedPolicyJob(e, p)
			src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassComplete)}}

			e.clock.Advance(2 * sampleGap)
			_, _ = e.store.Reconcile(context.Background(), src)
			e.clock.Advance(sampleGap)
			if _, err := e.store.Reconcile(context.Background(), src); err == nil {
				t.Fatal("Reconcile succeeded; want the policy failure reported")
			}
			if e.state(job.ID) != domain.JobInterrupted {
				t.Fatalf("state = %s, want interrupted", e.state(job.ID))
			}
			intents, err := e.store.Intents(context.Background(), e.db.Reader(), job.ID)
			if err != nil || intents[0].State == IntentCompleted {
				t.Fatalf("intent = %+v, %v; the failed verdict must roll back its proof", intents, err)
			}
		})
	}
}

func TestReconcileWithoutPolicyStillHoldsPartialStable(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryResumable, 3 })
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + 1)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassPartialStable)}}

	got := reconcile(e, src)

	if len(got) != 1 || got[0].Action != ReconcileHeld || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("Reconcile = %v, state %s; want held (M0-M3 behavior)", got, e.state(job.ID))
	}
}
