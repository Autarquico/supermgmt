package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// interruptedDeployment is a finalized deployment whose plan froze a known-good
// rollback target and whose reconcile verdict requeued it for safety recovery.
func (f *finFixture) interruptedDeployment(target AppTargetView) (interrupted, good database.Deployment) {
	f.t.Helper()
	firstView := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })
	f.mustFinalize(firstView.ID)
	f.markKnownGood(firstView.ID)
	f.clock.Advance(time.Second)
	secondView := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID; r.CommitSHA = depOtherCommit })
	interrupted = f.mustFinalize(secondView.ID)
	good = f.row(firstView.ID)
	f.recordRecovery(interrupted.ID, &good.ID)
	return f.row(interrupted.ID), good
}

func (f *finFixture) recordRecovery(id domain.ID, target *domain.ID) {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetDeploymentRecovery(ctx, tx, id, deployments.Recovery{
			Mode: deployments.RecoverySafetyRecovery, ResumeStep: deployments.StepRestorePull, Reason: "partial_stable", Target: target,
		}, f.clock.Now())
	})
}

func (f *finFixture) revalidateRecovery(dep database.Deployment) error {
	f.t.Helper()
	reval, err := NewRevalidator(f.cfg)
	mustf(f.t, err, "NewRevalidator")
	return reval.RevalidateRecovery(context.Background(), f.db.Reader(), f.job(*dep.JobID))
}

func TestRevalidateRecovery_IgnoresPlanCredentialPolicyAndQuorum(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	prod := f.mustTarget(f.app, "prod", finHTTPHealth)
	dep, _ := f.interruptedDeployment(prod)
	// Every input the forward claim judges has moved: the plan is stale and
	// expired, the requester's credential is revoked and the production
	// deployment never reached its approval quorum.
	f.bumpNodeRevision()
	f.exec(`UPDATE apps SET spec_revision = spec_revision + 1 WHERE id = ?`, f.app.ID)
	f.creds.set(dep.Credential.ID, CredentialRevoked)
	f.clock.Advance(48 * time.Hour)

	if err := f.revalidateJob(dep.ID); err == nil {
		t.Fatal("the forward claim accepted a plan whose inputs all moved")
	}
	mustf(t, f.revalidateRecovery(dep), "RevalidateRecovery")
}

func TestRevalidateRecovery_FailsOnlyWhenTheTargetCannotBeRestored(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(f *finFixture, good database.Deployment)
		cause  string
	}{
		{"secret version", func(f *finFixture, _ database.Deployment) {
			f.exec(`DELETE FROM secrets WHERE name = ? AND version = 1`, finSecretName)
		}, deployments.CauseSecretVersionGone},
		{"snapshot row", func(f *finFixture, good database.Deployment) { f.dropSnapshotRow(good.ComposeHash) }, deployments.CauseSnapshotGone},
		{"node host key", func(f *finFixture, _ database.Deployment) {
			f.exec(`UPDATE nodes SET endpoint_json = json_set(endpoint_json, '$.host_public_key', ?) WHERE id = ?`, finFixedHostKey, f.node.ID)
		}, causeNodePinChanged},
		{"target model", func(f *finFixture, good database.Deployment) {
			f.exec(`UPDATE deployments SET compose_hash = ? WHERE id = ?`, "sha256:"+finOtherSum[7:], good.ID)
		}, deployments.CauseSnapshotMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{pinned: true})
			dep, good := f.interruptedDeployment(f.target)

			tc.break_(f, good)

			wantRollbackCause(t, f.revalidateRecovery(dep), tc.cause)
		})
	}
}

func TestRevalidateRecovery_RestoresTheFrozenTargetNotTheNewestKnownGood(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	dep, _ := f.interruptedDeployment(f.target)
	newer := f.goodDeployment("2222222222222222222222222222222222222222")

	f.recordRecovery(dep.ID, &newer.ID)

	if got := smerr.CodeOf(f.revalidateRecovery(dep)); got != smerr.CodeInternal {
		t.Fatalf("code = %s, want INTERNAL: the record names a target the plan did not freeze", got)
	}
}

func TestRevalidateRecovery_NeedsASafetyRecoveryRecord(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.goodDeployment(depCommit)
	dep := f.finalizedDeployment()

	if got := smerr.CodeOf(f.revalidateRecovery(dep)); got != smerr.CodeInternal {
		t.Fatalf("code = %s, want INTERNAL without a recovery record", got)
	}
}
