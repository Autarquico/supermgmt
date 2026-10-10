package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

func TestSystemActorIsLimitedToItsAllowlistAndNeverArrivesAsARequest(t *testing.T) {
	f := newFixture(t)
	var system domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		system = f.identity(ctx, tx, "daemon", domain.ActorSystem, "")
		return nil
	})
	by := Caller{ID: system, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}}

	_, err := f.plans.Create(context.Background(), by, f.reboot())
	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)

	core := f.plans.core
	actor := domain.Actor{Type: domain.ActorSystem}
	target := policy.Target{Ref: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID}}
	if res := core.authorize(policy.Request{Actor: actor, Action: "node.reboot", Targets: []policy.Target{target}}); res.Decision != policy.DecisionDeny {
		t.Errorf("system node.reboot = %s, want deny", res.Decision)
	}
	if res := core.authorize(policy.Request{Actor: actor, Action: "backup.create", Targets: []policy.Target{target}}); res.Decision != policy.DecisionAllow || res.ApprovalRequired {
		t.Errorf("system backup.create = %+v, want allow without approval", res)
	}
}

func TestPlanActorMismatchIsAuditedAsADenial(t *testing.T) {
	f := newFixture(t)
	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.plans.Submit(context.Background(), f.caller(f.bob), created.Record.ID, created.Record.PlanHash)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonNotPlanActor)
	got := f.events("policy.deny")
	if len(got) != 1 || got[0].ActorID != f.bob || got[0].Data["reason"] != string(smerr.ReasonNotPlanActor) {
		t.Errorf("want one policy.deny by bob with reason NOT_PLAN_ACTOR, got %+v", got)
	}
}

func TestAnUnauthorizedApproverCannotExpireAPlan(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.clock.Advance(24 * time.Hour)

	_, err := f.approve(f.dave, sub.Job)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if got := f.job(sub.Job.ID).State; got != domain.JobAwaitingApproval {
		t.Errorf("state = %s; a denied approver must not fail the job", got)
	}
}

func TestApprovalIsRecordedEvenIfTheRequesterIsNowDeniedAndTheJobStaysAwaiting(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE identity_id = ?`, f.alice)
		return err
	})

	job, err := f.approve(f.bob, sub.Job)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if job.State != domain.JobAwaitingApproval {
		t.Errorf("state = %s, want awaiting_approval", job.State)
	}
	decisions, _ := database.ListDecisions(context.Background(), f.db.Reader(), job.ID, job.PlanHash)
	if len(decisions) != 1 {
		t.Errorf("want the approval recorded, got %d decisions", len(decisions))
	}
}

func TestServiceLocksUseTheComposeProjectWhenRecordedAndFailTypedWhenUnlockable(t *testing.T) {
	f := newFixture(t)
	set := func(kind string, metadata string) {
		f.inTx(func(ctx context.Context, tx *database.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE services SET kind = ?, metadata_json = ? WHERE id = ?`, kind, metadata, f.service.ID)
			return err
		})
	}
	job := jobs.Job{Type: "service.restart", Resource: domain.ResourceRef{Type: domain.ResourceService, ID: f.service.ID}}

	set("container", `{"compose_project":"sm-shop-prod"}`)
	got, err := LockPlanner{}.PlanLocks(context.Background(), f.db.Reader(), job)
	if err != nil {
		t.Fatal(err)
	}
	if want := domain.ComposeProjectLock(f.node.ID, "sm-shop-prod", domain.LockExclusive); got[0] != want {
		t.Errorf("lock = %v, want %v", got[0], want)
	}

	set("container", `{}`)
	_, err = LockPlanner{}.PlanLocks(context.Background(), f.db.Reader(), job)
	wantError(t, err, smerr.CodeInvalidArgument, "")
}
