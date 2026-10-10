package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const planHash = "sha256:aa"

// interruptedWithDispatchedIntent is a job the reconciler had to hold: its
// intent was dispatched and nothing proves how it ended.
func interruptedWithDispatchedIntent(e *env) (Job, Intent) {
	e.t.Helper()
	job := e.enqueue(func(nj *NewJob) { nj.PlanHash = planHash })
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		e.t.Fatal(err)
	}
	return job, intent
}

func (e *env) resolve(r ResolveRequest) (Job, error) {
	e.t.Helper()
	var (
		job Job
		err error
	)
	txErr := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		job, err = e.store.Resolve(ctx, tx, r)
		return err
	})
	if txErr != nil && err == nil {
		e.t.Fatalf("transaction: %v", txErr)
	}
	return job, err
}

func resolveRequest(job Job, outcome ResolveOutcome) ResolveRequest {
	return ResolveRequest{
		JobID: job.ID, PlanHash: planHash, Outcome: outcome, Note: "checked on the node",
		By: domain.Actor{ID: job.ActorID, Type: domain.ActorHuman},
	}
}

func TestResolveSettlesAnInterruptedJobAndReleasesItsLocks(t *testing.T) {
	cases := []struct {
		outcome    ResolveOutcome
		wantState  domain.JobState
		wantIntent string
		wantCode   smerr.Code
	}{
		{ResolveSucceeded, domain.JobSucceeded, OutcomeSucceeded, ""},
		{ResolveFailed, domain.JobFailed, OutcomeFailed, smerr.CodeInternal},
		{ResolveRollbackFailed, domain.JobFailed, OutcomeFailed, smerr.CodeRollbackFailed},
	}
	for _, tc := range cases {
		t.Run(string(tc.outcome), func(t *testing.T) {
			e := newEnv(t)
			job, intent := interruptedWithDispatchedIntent(e)
			e.clock.Advance(time.Minute) // past the intent's deadline + grace: quiescent
			if e.lockCount(job.ID) == 0 {
				t.Fatal("precondition: the interrupted job holds its locks")
			}

			got, err := e.resolve(resolveRequest(job, tc.outcome))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got.State != tc.wantState || e.lockCount(job.ID) != 0 || got.FinishedAt == nil {
				t.Fatalf("job = %+v, locks %d; want %s, no locks", got, e.lockCount(job.ID), tc.wantState)
			}
			if tc.wantCode == "" && got.Error != nil || tc.wantCode != "" && (got.Error == nil || got.Error.Code != tc.wantCode) {
				t.Fatalf("job error = %+v, want code %q", got.Error, tc.wantCode)
			}
			detail, err := e.store.Detail(context.Background(), e.db.Reader(), job.ID)
			if err != nil || detail.Intents[0].ID != intent.ID || detail.Intents[0].State != IntentCompleted ||
				detail.Intents[0].Outcome != tc.wantIntent {
				t.Fatalf("intent after resolve = %+v, %v; want completed as %s", detail.Intents, err, tc.wantIntent)
			}
			if got.Attempts != job.Attempts+1 {
				t.Fatalf("attempts = %d: resolving must not run the job again", got.Attempts)
			}
		})
	}
}

func TestResolveRecordsWhoDecidedAndWhy(t *testing.T) {
	e := newEnv(t)
	job, _ := interruptedWithDispatchedIntent(e)
	e.clock.Advance(time.Minute)
	if _, err := e.resolve(resolveRequest(job, ResolveSucceeded)); err != nil {
		t.Fatal(err)
	}

	events, err := database.ListEvents(context.Background(), e.db.Reader(), 0, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last.Action != "job.succeeded" || last.ActorType != domain.ActorHuman || last.ActorID != job.ActorID ||
		last.Data["resolved_by_human"] != true || last.Data["outcome"] != "succeeded" ||
		last.Data["note"] != "checked on the node" || last.Data["assume_quiescent"] != false {
		t.Fatalf("resolution event = %+v", last)
	}
}

func TestResolveRequiresQuiescenceUnlessAssumed(t *testing.T) {
	e := newEnv(t)
	job, _ := interruptedWithDispatchedIntent(e) // still inside the intent's deadline + grace

	_, err := e.resolve(resolveRequest(job, ResolveSucceeded))
	if !isCode(err, smerr.CodeConflict) {
		t.Fatalf("Resolve while not quiescent = %v, want CONFLICT", err)
	}
	if e.state(job.ID) != domain.JobInterrupted || e.lockCount(job.ID) == 0 {
		t.Fatalf("refused resolve changed the job: %s, %d locks", e.state(job.ID), e.lockCount(job.ID))
	}

	assumed := resolveRequest(job, ResolveFailed)
	assumed.AssumeQuiescent = true
	got, err := e.resolve(assumed)
	if err != nil || got.State != domain.JobFailed {
		t.Fatalf("Resolve with assume_quiescent = %+v, %v", got, err)
	}
	events, _ := database.ListEvents(context.Background(), e.db.Reader(), 0, 10_000)
	if events[len(events)-1].Data["assume_quiescent"] != true {
		t.Fatalf("assume_quiescent was not audited: %+v", events[len(events)-1].Data)
	}
}

func TestResolveRefusesWhatIsNotAHeldInterruptedJob(t *testing.T) {
	t.Run("job in another state", func(t *testing.T) {
		e := newEnv(t)
		queued := e.enqueue(func(nj *NewJob) { nj.PlanHash = planHash })
		_, err := e.resolve(resolveRequest(queued, ResolveSucceeded))
		if !isReason(err, smerr.ReasonInvalidTransition) || e.state(queued.ID) != domain.JobQueued {
			t.Fatalf("Resolve(queued) = %v, state %s", err, e.state(queued.ID))
		}
	})
	t.Run("plan hash the human did not see", func(t *testing.T) {
		e := newEnv(t)
		job, _ := interruptedWithDispatchedIntent(e)
		e.clock.Advance(time.Minute)
		r := resolveRequest(job, ResolveSucceeded)
		r.PlanHash = "sha256:bb"
		if _, err := e.resolve(r); !isReason(err, smerr.ReasonPlanStale) || e.state(job.ID) != domain.JobInterrupted {
			t.Fatalf("Resolve with a stale hash = %v, state %s", err, e.state(job.ID))
		}
	})
	t.Run("unknown outcome", func(t *testing.T) {
		e := newEnv(t)
		job, _ := interruptedWithDispatchedIntent(e)
		e.clock.Advance(time.Minute)
		if _, err := e.resolve(resolveRequest(job, "rolled_back")); !isCode(err, smerr.CodeInvalidArgument) {
			t.Fatalf("Resolve(rolled_back) = %v, want INVALID_ARGUMENT", err)
		}
	})
	t.Run("missing job", func(t *testing.T) {
		e := newEnv(t)
		r := resolveRequest(Job{ID: e.ids.NewID(), ActorID: e.actor}, ResolveSucceeded)
		if _, err := e.resolve(r); !isCode(err, smerr.CodeNotFound) {
			t.Fatalf("Resolve(missing) = %v, want NOT_FOUND", err)
		}
	})
}

func TestResolveKeepsUndispatchedIntentsUntouched(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.PlanHash = planHash })
	c := e.claim("w1")
	pending, err := e.store.RecordIntent(context.Background(), c.Lease, sampleIntent(e))
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.resolve(resolveRequest(job, ResolveFailed)); err != nil {
		t.Fatal(err)
	}
	detail, _ := e.store.Detail(context.Background(), e.db.Reader(), job.ID)
	if detail.Intents[0].ID != pending.ID || detail.Intents[0].State != IntentRecorded {
		t.Fatalf("undispatched intent = %+v, want it left recorded", detail.Intents[0])
	}
}

func isCode(err error, code smerr.Code) bool { return errors.Is(err, smerr.New(code, "", "")) }
func isReason(err error, reason smerr.Reason) bool {
	return errors.Is(err, smerr.FromReason(reason, ""))
}
