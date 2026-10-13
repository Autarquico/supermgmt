package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// revalidateJob runs the production Revalidator on the job of a deployment, as
// the claim transaction does.
func (f *finFixture) revalidateJob(id domain.ID) error {
	f.t.Helper()
	reval, err := NewRevalidator(f.cfg)
	mustf(f.t, err, "NewRevalidator")
	row := f.row(id)
	if row.JobID == nil {
		f.t.Fatalf("deployment %s has no job", id)
	}
	return reval.Revalidate(context.Background(), f.db.Reader(), f.job(*row.JobID))
}

func (f *finFixture) finalizedDeployment() database.Deployment {
	f.t.Helper()
	created := f.create()
	return f.mustFinalize(created.ID)
}

func (f *finFixture) dropSnapshotRow(hash string) {
	f.exec(`DROP TRIGGER execution_snapshots_no_delete`)
	f.exec(`DELETE FROM execution_snapshots WHERE hash = ?`, hash)
}

func wantStagingCause(t *testing.T, err error, cause string) {
	t.Helper()
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Reason != smerr.ReasonStagingFailed || typed.Details["cause"] != cause {
		t.Fatalf("error = %v, want STAGING_FAILED with cause %s", err, cause)
	}
}

func wantRevalidateReason(t *testing.T, err error, reason smerr.Reason) {
	t.Helper()
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Reason != reason {
		t.Fatalf("error = %v, want reason %s", err, reason)
	}
}

// ---- forward --------------------------------------------------------------------------------

func TestRevalidateDeploy_UnchangedPlanMayRun(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	row := f.finalizedDeployment()

	mustf(t, f.revalidateJob(row.ID), "Revalidate")
}

func TestRevalidateDeploy_StaleInputs(t *testing.T) {
	tests := []struct {
		name   string
		change func(f *finFixture)
	}{
		{"app", func(f *finFixture) {
			f.exec(`UPDATE apps SET spec_revision = spec_revision + 1 WHERE id = ?`, f.app.ID)
		}},
		{"app target", func(f *finFixture) {
			f.exec(`UPDATE app_targets SET spec_revision = spec_revision + 1 WHERE id = ?`, f.target.ID)
		}},
		{"environment", func(f *finFixture) {
			f.exec(`UPDATE environments SET spec_revision = spec_revision + 1 WHERE id = ?`, f.dev.ID)
		}},
		{"node", func(f *finFixture) { f.bumpNodeRevision() }},
		{"node host key", func(f *finFixture) {
			f.exec(`UPDATE nodes SET endpoint_json = json_set(endpoint_json, '$.host_public_key', ?) WHERE id = ?`, finFixedHostKey, f.node.ID)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{pinned: true})
			row := f.finalizedDeployment()

			tc.change(f)

			wantRevalidateReason(t, f.revalidateJob(row.ID), smerr.ReasonPlanStale)
		})
	}
}

func TestRevalidateDeploy_ObservationsIgnored(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	row := f.finalizedDeployment()

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		if err := database.SetNodeReachability(ctx, tx, f.node.ID, domain.ReachabilityReachable); err != nil {
			return err
		}
		return database.TouchLastSeen(ctx, tx, f.node.ID, f.clock.Now())
	})

	mustf(t, f.revalidateJob(row.ID), "Revalidate")
}

func TestRevalidateDeploy_RotationDoesNotChangeTheBoundVersion(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	row := f.finalizedDeployment()

	f.putSecret(finSecretName)

	mustf(t, f.revalidateJob(row.ID), "Revalidate")
}

func TestRevalidateDeploy_MissingSecretVersionOrSnapshotStopsTheClaim(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(f *finFixture, row database.Deployment)
		cause  string
	}{
		{"secret version", func(f *finFixture, _ database.Deployment) {
			f.exec(`DELETE FROM secrets WHERE name = ? AND version = 1`, finSecretName)
		}, deployments.CauseSecretVersionGone},
		{"snapshot row", func(f *finFixture, row database.Deployment) { f.dropSnapshotRow(row.ComposeHash) }, deployments.CauseSnapshotGone},
		{"altered snapshot", func(f *finFixture, row database.Deployment) {
			f.exec(`DROP TRIGGER execution_snapshots_no_update`)
			f.exec(`UPDATE execution_snapshots SET content = '{}' WHERE hash = ?`, row.ComposeHash)
		}, deployments.CauseSnapshotMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{pinned: true})
			row := f.finalizedDeployment()

			tc.break_(f, row)

			wantStagingCause(t, f.revalidateJob(row.ID), tc.cause)
		})
	}
}

func TestRevalidateDeploy_RequesterChecksStillApply(t *testing.T) {
	t.Run("expired plan", func(t *testing.T) {
		f := newFinFixture(t, finOptions{pinned: true})
		row := f.finalizedDeployment()
		f.clock.Advance(25 * time.Hour)

		wantRevalidateReason(t, f.revalidateJob(row.ID), smerr.ReasonPlanExpired)
	})
	t.Run("revoked credential", func(t *testing.T) {
		f := newFinFixture(t, finOptions{pinned: true})
		row := f.finalizedDeployment()
		f.creds.set(row.Credential.ID, CredentialRevoked)

		if err := f.revalidateJob(row.ID); err == nil {
			t.Fatal("a revoked requester credential was accepted")
		}
	})
	t.Run("approval quorum", func(t *testing.T) {
		f := newFinFixture(t, finOptions{pinned: true})
		target := f.mustTarget(f.app, "prod", finHTTPHealth)
		created := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })
		row := f.mustFinalize(created.ID)

		if got := smerr.CodeOf(f.revalidateJob(row.ID)); got != smerr.CodeApprovalRequired {
			t.Fatalf("code = %s, want APPROVAL_REQUIRED for an unapproved production deployment", got)
		}
	})
}

// ---- rollback -------------------------------------------------------------------------------

// requestedRollback is a rollback of newer to the known-good deployment, with
// the app and target as they were when it was requested.
func (f *finFixture) requestedRollback() (view DeploymentView, newer database.Deployment) {
	f.t.Helper()
	f.goodDeployment(depCommit)
	newer = f.goodDeployment(depOtherCommit)
	return f.mustRollback(newer.ID, wire.RollbackRequest{}), newer
}

func TestRevalidateRollback_AfterSourceEditAndRotation(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	view, _ := f.requestedRollback()

	f.putSecret(finSecretName)
	edited := strings.Replace(appsWebCompose, "DATABASE_URL: ${secret:db}", "DATABASE_URL: ${secret:db}\n      EDITED: \"yes\"", 1)
	f.exec(`UPDATE apps SET compose_content = ?, spec_revision = spec_revision + 1 WHERE id = ?`, edited, f.app.ID)
	f.exec(`UPDATE app_targets SET deployment_policy_json = ?, spec_revision = spec_revision + 1 WHERE id = ?`,
		`{"rollback":"manual","health":{"type":"http","scope":"node","port":8080,"path":"/other","timeout":"5s","interval":"2s","attempts":3}}`, f.target.ID)

	mustf(t, f.revalidateJob(view.ID), "Revalidate")
}

func TestRevalidateRollback_MissingVersionBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(f *finFixture, good database.Deployment)
		cause  string
	}{
		{"secret version", func(f *finFixture, _ database.Deployment) {
			f.exec(`DELETE FROM secrets WHERE name = ? AND version = 1`, finSecretName)
		}, deployments.CauseSecretVersionGone},
		{"snapshot", func(f *finFixture, good database.Deployment) { f.dropSnapshotRow(good.ComposeHash) }, deployments.CauseSnapshotGone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{pinned: true})
			view, _ := f.requestedRollback()
			tc.break_(f, f.row(*view.PreviousDeploymentID))

			wantRollbackCause(t, f.revalidateJob(view.ID), tc.cause)
		})
	}
}

func TestRevalidateRollback_AuthorizationInputsStillGoStale(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	view, _ := f.requestedRollback()

	f.bumpNodeRevision()

	wantRevalidateReason(t, f.revalidateJob(view.ID), smerr.ReasonPlanStale)
}

func TestRevalidateRollback_ProductionNeedsItsApprovals(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	target := f.mustTarget(f.app, "prod", finHTTPHealth)
	for _, commit := range []string{depCommit, depOtherCommit} {
		created := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID; r.CommitSHA = commit })
		f.mustFinalize(created.ID)
		f.markKnownGood(created.ID)
		f.clock.Advance(1e9)
	}
	newest, err := database.NewestKnownGood(context.Background(), f.db.Reader(), target.ID, nil)
	mustf(t, err, "NewestKnownGood")
	view := f.mustRollback(newest.ID, wire.RollbackRequest{})

	if got := smerr.CodeOf(f.revalidateJob(view.ID)); got != smerr.CodeApprovalRequired {
		t.Fatalf("code = %s, want APPROVAL_REQUIRED", got)
	}
}
