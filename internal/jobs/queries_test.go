package jobs

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// pendingWithPlan enqueues a job bound to a new plan that expires at expiresAt.
func pendingWithPlan(e *env, expiresAt time.Time, awaiting bool) Job {
	e.t.Helper()
	planID := e.ids.NewID()
	e.inTx(func(tx *database.Tx) {
		err := database.InsertPlan(context.Background(), tx, database.PlanRecord{
			ID: planID, Action: "service.restart", ActorID: e.actor,
			Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: "cred"},
			PlanJSON:   []byte("{}"), PlanHash: planHash,
			FinalizedAt: e.clock.Now(), CreatedAt: e.clock.Now(), ExpiresAt: expiresAt,
		})
		if err != nil {
			e.t.Fatalf("InsertPlan: %v", err)
		}
	})
	return e.enqueue(func(nj *NewJob) {
		nj.PlanID, nj.PlanHash, nj.AwaitingApproval = &planID, planHash, awaiting
	})
}

func TestExpirePlansFailsOnlyExpiredJobsAwaitingApproval(t *testing.T) {
	e := newEnv(t)
	now := e.clock.Now()
	expired := pendingWithPlan(e, now.Add(-time.Second), true)
	atBoundary := pendingWithPlan(e, now, true)
	valid := pendingWithPlan(e, now.Add(time.Hour), true)
	alreadyApproved := pendingWithPlan(e, now.Add(-time.Hour), false) // queued: claim-time revalidation owns it
	noPlan := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })

	got, err := e.store.ExpirePlans(context.Background())
	if err != nil {
		t.Fatalf("ExpirePlans: %v", err)
	}
	want := []domain.ID{expired.ID, atBoundary.ID}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("expired = %v, want %v", got, want)
	}
	for _, id := range want {
		job := e.get(id)
		if job.State != domain.JobFailed || job.Error == nil || job.Error.Code != smerr.CodeConflict ||
			job.Error.Reason != smerr.ReasonPlanExpired {
			t.Fatalf("expired job = %+v", job)
		}
	}
	for _, untouched := range []Job{valid, noPlan} {
		if e.state(untouched.ID) != domain.JobAwaitingApproval {
			t.Fatalf("job %s moved to %s", untouched.ID, e.state(untouched.ID))
		}
	}
	if e.state(alreadyApproved.ID) != domain.JobQueued {
		t.Fatalf("approved job moved to %s", e.state(alreadyApproved.ID))
	}
	if actions := e.actions(expired.ID); actions[len(actions)-1] != "job.failed" {
		t.Fatalf("events of the expired job = %v, want a job.failed", actions)
	}

	if again, err := e.store.ExpirePlans(context.Background()); err != nil || len(again) != 0 {
		t.Fatalf("second sweep = %v, %v; want nothing", again, err)
	}
}

func TestExpirePlansCatchesJobsOnceTheClockPassesTheirExpiry(t *testing.T) {
	e := newEnv(t)
	job := pendingWithPlan(e, e.clock.Now().Add(time.Hour), true)
	if got, _ := e.store.ExpirePlans(context.Background()); len(got) != 0 {
		t.Fatalf("expired early: %v", got)
	}
	e.clock.Advance(time.Hour)
	if got, err := e.store.ExpirePlans(context.Background()); err != nil || !slices.Equal(got, []domain.ID{job.ID}) {
		t.Fatalf("ExpirePlans = %v, %v; want [%s]", got, err, job.ID)
	}
}

func TestDetailReturnsTheJobWithItsIntentsInOrder(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	first := dispatchedIntent(e, c.Lease)
	second, err := e.store.RecordIntent(context.Background(), c.Lease, sampleIntent(e))
	if err != nil {
		t.Fatal(err)
	}

	detail, err := e.store.Detail(context.Background(), e.db.Reader(), job.ID)
	if err != nil {
		t.Fatalf("Detail: %v", err)
	}
	if detail.Job.ID != job.ID || len(detail.Intents) != 2 || detail.Intents[0].ID != first.ID ||
		detail.Intents[1].ID != second.ID || string(detail.Intents[0].PreState) != `{"containers":2}` {
		t.Fatalf("Detail = %+v", detail)
	}

	_, err = e.store.Detail(context.Background(), e.db.Reader(), e.ids.NewID())
	if !isCode(err, smerr.CodeNotFound) {
		t.Fatalf("Detail(missing) = %v, want NOT_FOUND", err)
	}
	bare := e.enqueue()
	if d, err := e.store.Detail(context.Background(), e.db.Reader(), bare.ID); err != nil || len(d.Intents) != 0 {
		t.Fatalf("Detail(no intents) = %+v, %v", d, err)
	}
}
