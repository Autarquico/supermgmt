package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestJobStaysAwaitingUntilTheQuorumIsMet(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()

	afterOne, err := f.approve(f.bob, sub.Job)
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if afterOne.State != domain.JobAwaitingApproval {
		t.Fatalf("after 1 of 2 approvals state = %s, want awaiting_approval", afterOne.State)
	}

	afterTwo, err := f.approve(f.carol, sub.Job)
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if afterTwo.State != domain.JobQueued {
		t.Fatalf("after 2 of 2 approvals state = %s, want queued", afterTwo.State)
	}
	if n := len(f.events("approval.grant")); n != 2 {
		t.Errorf("want 2 approval.grant events, got %d", n)
	}
	if n := len(f.events("job.queued")); n != 1 {
		t.Errorf("want one job.queued event, got %d", n)
	}
}

func TestTheSameApproverCannotApproveTwice(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	if _, err := f.approve(f.bob, sub.Job); err != nil {
		t.Fatal(err)
	}

	_, err := f.approve(f.bob, sub.Job)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonAlreadyDecided)
}

func TestRequesterCannotApproveOwnPlanUnlessAllowed(t *testing.T) {
	t.Run("forbidden by default", func(t *testing.T) {
		f := newFixture(t)
		sub, _ := f.submitReboot()

		_, err := f.approve(f.alice, sub.Job)

		wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonSelfApproval)
		if len(f.events("policy.deny")) != 1 {
			t.Errorf("refused self-approval not audited")
		}
	})
	t.Run("counts once when allowed", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.AllowSelfApproval = true })
		sub, _ := f.submitReboot()
		if _, err := f.approve(f.alice, sub.Job); err != nil {
			t.Fatalf("self approval: %v", err)
		}

		job, err := f.approve(f.bob, sub.Job)
		if err != nil {
			t.Fatal(err)
		}
		if job.State != domain.JobQueued {
			t.Errorf("requester + bob = quorum 2, state = %s, want queued", job.State)
		}
	})
}

func TestApproverWithoutApprovalPermissionIsDeniedAndAudited(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()

	_, err := f.approve(f.dave, sub.Job)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if got := f.events("policy.deny"); len(got) != 1 || got[0].ActorID != f.dave {
		t.Errorf("want one policy.deny event by dave, got %+v", got)
	}
}

func TestSystemAndMCPIdentitiesCanNeverApprove(t *testing.T) {
	f := newFixture(t)
	var system, mcp domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		operator := f.role(ctx, tx, "operator")
		system = f.identity(ctx, tx, "daemon", domain.ActorSystem, "")
		mcp = f.identity(ctx, tx, "assistant", domain.ActorMCP, operator)
		return nil
	})
	sub, _ := f.submitReboot()

	for name, approver := range map[string]domain.ID{"system": system, "mcp": mcp} {
		t.Run(name, func(t *testing.T) {
			_, err := f.approve(approver, sub.Job)

			wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
		})
	}
}

func TestDecisionOnADifferentPlanHashIsStale(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()

	_, err := f.appr.Approve(context.Background(), f.caller(f.bob),
		DecisionRequest{JobID: sub.Job.ID, PlanHash: "sha256:00"})

	wantError(t, err, smerr.CodeConflict, smerr.ReasonPlanStale)
}

func TestRejectionFailsTheJobAsRejected(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()

	job, err := f.appr.Reject(context.Background(), f.caller(f.bob),
		DecisionRequest{JobID: sub.Job.ID, PlanHash: sub.Job.PlanHash, Reason: "not now"})
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if job.State != domain.JobFailed || job.Error == nil || job.Error.Reason != smerr.ReasonRejected {
		t.Errorf("job = %s %+v, want failed/REJECTED", job.State, job.Error)
	}
	if len(f.events("approval.reject")) != 1 {
		t.Errorf("rejection not audited")
	}
	_, err = f.approve(f.carol, job)
	wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
}

func TestRejectionIsAcceptedOnAQueuedJob(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	queued := f.approveToQuorum(sub.Job)

	job, err := f.appr.Reject(context.Background(), f.caller(f.alice),
		DecisionRequest{JobID: queued.ID, PlanHash: queued.PlanHash})
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if job.State != domain.JobFailed {
		t.Errorf("state = %s, want failed", job.State)
	}
}

func TestApprovingAJobThatIsNotAwaitingIsAnInvalidTransition(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	queued := f.approveToQuorum(sub.Job)

	_, err := f.approve(f.dave, queued)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
}

func TestApprovalAfterPlanExpiryFailsTheJob(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.clock.Advance(24 * time.Hour)

	_, err := f.approve(f.bob, sub.Job)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonPlanExpired)
	job := f.job(sub.Job.ID)
	if job.State != domain.JobFailed || job.Error == nil || job.Error.Reason != smerr.ReasonPlanExpired {
		t.Errorf("job = %s %+v, want failed/PLAN_EXPIRED", job.State, job.Error)
	}
}

func TestApprovalWithRevokedCredentialFails(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.creds.set("token-"+f.bob.String(), CredentialRevoked)

	_, err := f.approve(f.bob, sub.Job)

	wantError(t, err, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}
