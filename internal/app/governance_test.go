package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

func (f *fixture) governance(t *testing.T) *Governance {
	t.Helper()
	g, err := NewGovernance(f.cfg, f.store)
	mustf(t, err, "NewGovernance")
	return g
}

func TestCancelStopsAJobThatHasNotStarted(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()

	job, err := f.governance(t).Cancel(context.Background(), f.caller(f.bob), sub.Job.ID, sub.Job.PlanHash)

	if err != nil || job.State != domain.JobCancelled {
		t.Errorf("Cancel = %s, %v", job.State, err)
	}
}

func TestCancelNeedsThePermissionAndTheCurrentPlanHash(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	g := f.governance(t)

	_, denied := g.Cancel(context.Background(), f.caller(f.dave), sub.Job.ID, sub.Job.PlanHash)
	_, stale := g.Cancel(context.Background(), f.caller(f.bob), sub.Job.ID, "not-the-hash")

	if smerr.CodeOf(denied) != smerr.CodePolicyDenied {
		t.Errorf("caller without a role: %v", denied)
	}
	wantError(t, stale, smerr.CodeConflict, smerr.ReasonPlanStale)
	if f.job(sub.Job.ID).State != domain.JobAwaitingApproval {
		t.Error("a refused cancel changed the job")
	}
}

func TestCancelOfARunningJobIsAnInvalidTransition(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.approveToQuorum(sub.Job)
	f.claim()

	_, err := f.governance(t).Cancel(context.Background(), f.caller(f.bob), sub.Job.ID, sub.Job.PlanHash)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
}

// interrupted returns a node reboot job that lost its worker, long past its deadline.
func (f *fixture) interrupted() jobs.Job { return f.interruptedAfter(time.Hour) }

// interruptedAfter is a job whose worker died: its lease expired after wait
// and the reconciler took it over. Its intent's deadline is a minute away.
func (f *fixture) interruptedAfter(wait time.Duration) jobs.Job {
	f.t.Helper()
	sub, _ := f.submitReboot()
	f.approveToQuorum(sub.Job)
	claimed, ok := f.claim()
	if !ok {
		f.t.Fatal("not claimed")
	}
	intent, err := f.store.RecordIntent(context.Background(), claimed.Lease, jobs.NewIntent{
		Step: "reboot", Operation: "node.reboot", TargetType: "node", TargetID: f.node.ID.String(),
		DeadlineAt: f.clock.Now().Add(time.Minute),
	})
	mustf(f.t, err, "RecordIntent")
	mustf(f.t, f.store.MarkDispatched(context.Background(), claimed.Lease, intent.ID), "MarkDispatched")
	f.clock.Advance(wait)
	_, err = f.store.Takeover(context.Background(), "test")
	mustf(f.t, err, "Takeover")
	return f.job(sub.Job.ID)
}

func TestResolveSettlesAnInterruptedJob(t *testing.T) {
	f := newFixture(t)
	job := f.interrupted()

	resolved, err := f.governance(t).Resolve(context.Background(), f.caller(f.bob), ResolveRequest{
		JobID: job.ID, PlanHash: job.PlanHash, Outcome: jobs.ResolveFailed, Note: "checked by hand",
	})

	if err != nil || resolved.State != domain.JobFailed {
		t.Errorf("Resolve = %s, %v", resolved.State, err)
	}
}

func TestResolveByTheRequesterNeedsSelfApproval(t *testing.T) {
	denied := newFixture(t)
	job := denied.interrupted()
	_, err := denied.governance(t).Resolve(context.Background(), denied.caller(denied.alice), ResolveRequest{
		JobID: job.ID, PlanHash: job.PlanHash, Outcome: jobs.ResolveSucceeded,
	})
	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonSelfApproval)

	allowed := newFixture(t, func(c *Config) { c.AllowSelfApproval = true })
	job = allowed.interrupted()
	resolved, err := allowed.governance(t).Resolve(context.Background(), allowed.caller(allowed.alice), ResolveRequest{
		JobID: job.ID, PlanHash: job.PlanHash, Outcome: jobs.ResolveSucceeded,
	})
	if err != nil || resolved.State != domain.JobSucceeded {
		t.Errorf("local mode self-resolution = %s, %v", resolved.State, err)
	}
}

func TestResolveNeedsQuiescenceUnlessAssumed(t *testing.T) {
	f := newFixture(t)
	job := f.interruptedAfter(31 * time.Second) // the remote command may still be running
	g := f.governance(t)

	_, refused := g.Resolve(context.Background(), f.caller(f.bob), ResolveRequest{
		JobID: job.ID, PlanHash: job.PlanHash, Outcome: jobs.ResolveFailed,
	})
	resolved, err := g.Resolve(context.Background(), f.caller(f.bob), ResolveRequest{
		JobID: job.ID, PlanHash: job.PlanHash, Outcome: jobs.ResolveFailed, AssumeQuiescent: true,
	})

	if smerr.CodeOf(refused) != smerr.CodeConflict {
		t.Errorf("resolving before quiescence: %v, want CONFLICT", refused)
	}
	if err != nil || resolved.State != domain.JobFailed {
		t.Errorf("Resolve with assume_quiescent = %s, %v", resolved.State, err)
	}
}

func TestResolveOfAJobThatIsNotInterruptedIsRefused(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()

	_, err := f.governance(t).Resolve(context.Background(), f.caller(f.bob), ResolveRequest{
		JobID: sub.Job.ID, PlanHash: sub.Job.PlanHash, Outcome: jobs.ResolveFailed,
	})

	wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
}
