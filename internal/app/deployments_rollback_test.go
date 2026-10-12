package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (f *finFixture) rowCount(table string) int {
	f.t.Helper()
	var n int
	err := f.db.Reader().QueryRowContext(context.Background(), `SELECT count(*) FROM `+table).Scan(&n)
	mustf(f.t, err, "count %s", table)
	return n
}

// goodDeployment finalizes a deployment of the commit and marks it known good.
func (f *finFixture) goodDeployment(commit string) database.Deployment {
	f.t.Helper()
	created := f.create(func(r *CreateDeployment) { r.CommitSHA = commit })
	f.mustFinalize(created.ID)
	f.markKnownGood(created.ID)
	f.clock.Advance(1e9)
	return f.row(created.ID)
}

func (f *finFixture) rollback(id domain.ID, req wire.RollbackRequest) (DeploymentView, error) {
	return f.final.Rollback(context.Background(), f.caller(f.deployer), id, req)
}

func (f *finFixture) mustRollback(id domain.ID, req wire.RollbackRequest) DeploymentView {
	f.t.Helper()
	view, err := f.rollback(id, req)
	mustf(f.t, err, "Rollback")
	return view
}

func TestRollbackPlan_BindsKnownGoodSnapshot(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	good := f.goodDeployment(depCommit)
	goodPlan := f.planOf(good.ID)
	f.putSecret(finSecretName) // rotation: version 2 is now the newest
	edited := strings.Replace(appsWebCompose, "DATABASE_URL: ${secret:db}", "DATABASE_URL: ${secret:db}\n      EDITED: \"yes\"", 1)
	f.exec(`UPDATE apps SET compose_content = ?, spec_revision = spec_revision + 1 WHERE id = ?`, edited, f.app.ID)
	newer := f.create(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })
	f.mustFinalize(newer.ID)
	f.markKnownGood(newer.ID)
	if got := f.planOf(newer.ID).Content.SecretBindings[0].Version; got != 2 {
		t.Fatalf("the newer deployment bound version %d, want 2", got)
	}

	view := f.mustRollback(newer.ID, wire.RollbackRequest{})

	if view.Kind != deployments.KindRollback || view.State != string(deployments.StateQueued) || view.JobID == nil || view.PlanHash == nil {
		t.Fatalf("view = %+v, want a queued rollback with a job", view)
	}
	if view.PreviousDeploymentID == nil || *view.PreviousDeploymentID != good.ID || view.RollbackOfDeploymentID == nil || *view.RollbackOfDeploymentID != newer.ID {
		t.Errorf("previous %v rollback_of %v; want to return to %s and revert %s", view.PreviousDeploymentID, view.RollbackOfDeploymentID, good.ID, newer.ID)
	}
	p := f.planOf(view.ID)
	if p.Action != "deployment.rollback" || p.Content.RollbackTarget != nil {
		t.Errorf("action %s rollback_target %+v; want a rollback that never rolls back", p.Action, p.Content.RollbackTarget)
	}
	if *p.Content.ComposeHash != *goodPlan.Content.ComposeHash || *p.Content.CommitSHA != depCommit ||
		!slices.Equal(p.Content.HostPorts, goodPlan.Content.HostPorts) || p.Content.Images[0] != goodPlan.Content.Images[0] {
		t.Errorf("content %+v differs from the known-good %+v", p.Content, goodPlan.Content)
	}
	if got := p.Content.SecretBindings[0].Version; got != 1 {
		t.Errorf("secret version %d, want the known-good's exact version 1", got)
	}
	for _, in := range p.Inputs {
		if in.Type == "app" || in.Type == "repository" {
			t.Errorf("a rollback reads no live app configuration but its plan lists %s", in.Type)
		}
		if in.Type == "secret" && *in.Version != 1 {
			t.Errorf("secret input at version %d, want 1", *in.Version)
		}
	}
	if view.ComposeHash == nil || *view.ComposeHash != *goodPlan.Content.ComposeHash {
		t.Errorf("compose_hash = %v", view.ComposeHash)
	}
	if created := f.events(eventDeploymentCreated); len(created) != 3 || created[2].Data["rollback_of"] != newer.ID.String() {
		t.Errorf("created events = %+v", created)
	}
}

func TestRollback_ASpecificKnownGoodDeploymentCanBeChosen(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	first := f.goodDeployment(depCommit)
	second := f.goodDeployment(depOtherCommit)
	third := f.goodDeployment("1111111111111111111111111111111111111111")

	view := f.mustRollback(third.ID, wire.RollbackRequest{ToDeploymentID: &first.ID})

	if view.PreviousDeploymentID == nil || *view.PreviousDeploymentID != first.ID || view.CommitSHA != depCommit {
		t.Errorf("rolled back to %v (%s), want %s", view.PreviousDeploymentID, view.CommitSHA, first.ID)
	}
	newest := f.mustRollback(third.ID, wire.RollbackRequest{})
	if newest.PreviousDeploymentID == nil || *newest.PreviousDeploymentID != second.ID {
		t.Errorf("default target %v, want the newest older than the reverted deployment (%s)", newest.PreviousDeploymentID, second.ID)
	}
}

func TestRollback_ATargetThatIsNotKnownGoodIsRefused(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	good := f.goodDeployment(depCommit)
	plain := f.create(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })
	f.mustFinalize(plain.ID)

	_, err := f.rollback(good.ID, wire.RollbackRequest{ToDeploymentID: &plain.ID})

	wantAppsCode(t, err, smerr.CodeInvalidArgument)
}

func TestRollback_WithoutAKnownGoodDeploymentItIsUnavailable(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	only := f.goodDeployment(depCommit)
	deployments, jobs := f.rowCount("deployments"), f.rowCount("jobs")

	_, err := f.rollback(only.ID, wire.RollbackRequest{})

	wantRollbackCause(t, err, "NO_KNOWN_GOOD")
	if f.rowCount("deployments") != deployments || f.rowCount("jobs") != jobs {
		t.Error("a refused rollback left a deployment or a job")
	}
}

func TestRollback_MissingVersionIsUnavailableBeforeAnythingIsEnqueued(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(f *finFixture, good database.Deployment)
		cause   string
	}{
		{"secret version", func(f *finFixture, _ database.Deployment) {
			f.exec(`DELETE FROM secrets WHERE name = ? AND version = 1`, finSecretName)
		}, deployments.CauseSecretVersionGone},
		{"snapshot", func(f *finFixture, good database.Deployment) {
			f.exec(`DROP TRIGGER execution_snapshots_no_delete`)
			f.exec(`DELETE FROM execution_snapshots WHERE hash = ?`, good.ComposeHash)
		}, deployments.CauseSnapshotGone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{pinned: true})
			good := f.goodDeployment(depCommit)
			f.putSecret(finSecretName)
			newer := f.goodDeployment(depOtherCommit)
			tc.breakIt(f, good)
			deploymentRows, jobRows, planRows := f.rowCount("deployments"), f.rowCount("jobs"), f.rowCount("plans")

			_, err := f.rollback(newer.ID, wire.RollbackRequest{})

			wantRollbackCause(t, err, tc.cause)
			if f.rowCount("deployments") != deploymentRows || f.rowCount("jobs") != jobRows || f.rowCount("plans") != planRows {
				t.Error("a refused rollback left a deployment, a plan or a job behind")
			}
		})
	}
}

func TestRollback_PolicyDecidesWhoMayRollBack(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.goodDeployment(depCommit)
	newer := f.goodDeployment(depOtherCommit)
	deploymentRows := f.rowCount("deployments")

	_, err := f.final.Rollback(context.Background(), f.caller(f.alice), newer.ID, wire.RollbackRequest{})

	wantAppsCode(t, err, smerr.CodePolicyDenied)
	if f.rowCount("deployments") != deploymentRows {
		t.Error("a denied rollback left a deployment")
	}
	if denied := f.events("policy.deny"); len(denied) == 0 {
		t.Error("the refusal was not audited")
	}
}

func TestRollback_ProductionRollbackWaitsForApproval(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	target := f.mustTarget(f.app, "prod", finHTTPHealth)
	first := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })
	f.mustFinalize(first.ID)
	f.markKnownGood(first.ID)
	f.clock.Advance(1e9)
	second := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID; r.CommitSHA = depOtherCommit })
	f.mustFinalize(second.ID)
	f.markKnownGood(second.ID)

	view := f.mustRollback(second.ID, wire.RollbackRequest{})

	if view.State != string(deployments.StateAwaitingApproval) {
		t.Fatalf("state = %s, want awaiting_approval", view.State)
	}
	if job := f.job(*view.JobID); job.State != domain.JobAwaitingApproval || job.Type != "deployment.rollback" {
		t.Errorf("job = %+v", job)
	}
}

func TestRollback_ABackupConfiguredWhenItRanIsPlannedAgain(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	target := f.mustTarget(f.app, "prod", finHTTPHealth)
	backup := `,"pre_deploy_backup":{"template":"postgres-dump","args":{"container":"db","database":"app"},"timeout":"5m0s"}`
	f.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, fmt.Sprintf(finStatefulPolicy, backup), target.ID)
	first := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })
	f.mustFinalize(first.ID)
	f.markKnownGood(first.ID)
	f.clock.Advance(1e9)
	second := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID; r.CommitSHA = depOtherCommit })
	f.mustFinalize(second.ID)
	f.markKnownGood(second.ID)

	view := f.mustRollback(second.ID, wire.RollbackRequest{})

	p := f.planOf(view.ID)
	if len(p.SubActions) != 1 || !slices.Contains(p.Steps, deployments.StepPreDeployBackup) {
		t.Errorf("sub_actions %+v steps %v; want the backup of the known-good policy", p.SubActions, p.Steps)
	}
}

func TestRollback_UnknownDeploymentIsNotFound(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})

	_, err := f.rollback("nope", wire.RollbackRequest{})

	wantAppsCode(t, err, smerr.CodeNotFound)
}

func TestRollback_ARevokedCredentialIsRefused(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.goodDeployment(depCommit)
	newer := f.goodDeployment(depOtherCommit)
	f.creds.set(f.caller(f.deployer).Credential.ID, CredentialRevoked)

	_, err := f.rollback(newer.ID, wire.RollbackRequest{})

	if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
		t.Errorf("error = %v, want UNAUTHENTICATED", err)
	}
}
