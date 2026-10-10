package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// approvedReboot is a production node.reboot approved to quorum and queued.
func approvedReboot(f *fixture) domain.ID {
	f.t.Helper()
	sub, _ := f.submitReboot()
	return f.approveToQuorum(sub.Job).ID
}

// wantFailedAtClaim asserts that the next claim hands out nothing and left the
// job failed with reason, recorded on its job.failed event.
func wantFailedAtClaim(f *fixture, id domain.ID, code smerr.Code, reason smerr.Reason) {
	f.t.Helper()
	if _, ok := f.claim(); ok {
		f.t.Fatalf("claim succeeded, want the job to fail with %s/%s", code, reason)
	}
	job := f.job(id)
	if job.State != domain.JobFailed || job.Error == nil || job.Error.Code != code || job.Error.Reason != reason {
		f.t.Fatalf("job = %s %+v, want failed %s/%s", job.State, job.Error, code, reason)
	}
	for _, e := range f.events("job.failed") {
		if e.ResourceID == id && e.Data["error_code"] == string(code) && e.Data["error_reason"] == string(reason) {
			return
		}
	}
	f.t.Fatalf("no job.failed event records %s/%s", code, reason)
}

func TestClaimFailsPlanStaleWhenAConfiguredInputChangedAfterApproval(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.bumpNodeRevision()

	wantFailedAtClaim(f, id, smerr.CodeConflict, smerr.ReasonPlanStale)
	if n := len(f.locks()); n != 0 {
		t.Errorf("a failed claim left %d locks", n)
	}
}

func TestClaimFailsPlanStaleWhenTheEnvironmentChanged(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE environments SET spec_revision = spec_revision + 1 WHERE id = ?`, f.env.ID)
		return err
	})

	wantFailedAtClaim(f, id, smerr.CodeConflict, smerr.ReasonPlanStale)
}

func TestClaimSucceedsWhenOnlyObservationsChanged(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		if err := database.SetNodeReachability(ctx, tx, f.node.ID, domain.ReachabilityReachable); err != nil {
			return err
		}
		if err := database.TouchLastSeen(ctx, tx, f.node.ID, f.clock.Now()); err != nil {
			return err
		}
		return database.RecordObservation(ctx, tx, database.Observation{
			ID: f.ids.NewID(), ResourceType: domain.ResourceNode, ResourceID: f.node.ID,
			Kind: "uptime", Value: 42, ObservedAt: f.clock.Now(),
		})
	})

	claimed, ok := f.claim()
	if !ok {
		t.Fatalf("claim failed after observation-only writes: %+v", f.job(id).Error)
	}
	if claimed.Job.ID != id || claimed.Job.State != domain.JobRunning {
		t.Errorf("claimed %s in state %s", claimed.Job.ID, claimed.Job.State)
	}
	held := f.locks()
	if held["node:"+f.node.ID.String()] != domain.LockExclusive {
		t.Errorf("locks = %v, want the node held exclusively", held)
	}
	if held["environment:"+f.env.ID.String()] != domain.LockShared {
		t.Errorf("locks = %v, want the environment held shared", held)
	}
}

func TestClaimFailsWhenTheCredentialWasRevokedAfterSubmit(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.creds.set("token-"+f.alice.String(), CredentialRevoked)

	wantFailedAtClaim(f, id, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestClaimFailsWhenAnAPITokenExpiredButNotWhenASessionDid(t *testing.T) {
	tests := []struct {
		kind    domain.CredentialKind
		expires bool
	}{
		{domain.CredentialAPIToken, true},
		{domain.CredentialMCPToken, true},
		{domain.CredentialOAuthAccessToken, true},
		{domain.CredentialSession, false},
		{domain.CredentialGitHubOIDC, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			f := newFixture(t)
			by := Caller{ID: f.alice, Credential: domain.CredentialContext{Kind: tt.kind, ID: "cred-1"}}
			created, err := f.plans.Create(context.Background(), by, f.reboot())
			if err != nil {
				t.Fatal(err)
			}
			sub, err := f.plans.Submit(context.Background(), by, created.Record.ID, created.Record.PlanHash)
			if err != nil {
				t.Fatal(err)
			}
			f.approveToQuorum(sub.Job)

			f.creds.set("cred-1", CredentialExpired)

			if tt.expires {
				wantFailedAtClaim(f, sub.Job.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialExpired)
			} else if _, ok := f.claim(); !ok {
				t.Errorf("a naturally expired %s must not fail the job: %+v", tt.kind, f.job(sub.Job.ID).Error)
			}
		})
	}
}

func TestClaimSendsTheJobBackToAwaitingApprovalWhenTheQuorumLapsed(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.clock.Advance(16 * time.Minute) // approval_ttl is 15m, the plan lives 24h

	if _, ok := f.claim(); ok {
		t.Fatal("claim succeeded with expired approvals")
	}
	if got := f.job(id).State; got != domain.JobAwaitingApproval {
		t.Fatalf("state = %s, want awaiting_approval", got)
	}

	// The same approvers renew and the job can run.
	for _, approver := range []domain.ID{f.bob, f.carol} {
		if _, err := f.approve(approver, f.job(id)); err != nil {
			t.Fatalf("renewal by %s: %v", approver, err)
		}
	}
	if _, ok := f.claim(); !ok {
		t.Fatalf("claim failed after renewal: %+v", f.job(id).Error)
	}
}

func TestClaimSendsTheJobBackWhenAnApproverLostTheirPermission(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE identity_id = ?`, f.carol)
		return err
	})

	if _, ok := f.claim(); ok {
		t.Fatal("claim succeeded although one approver no longer holds approval.grant")
	}
	if got := f.job(id).State; got != domain.JobAwaitingApproval {
		t.Fatalf("state = %s, want awaiting_approval", got)
	}
}

func TestClaimFailsWhenThePlanExpired(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.clock.Advance(24 * time.Hour)

	wantFailedAtClaim(f, id, smerr.CodeConflict, smerr.ReasonPlanExpired)
}

func TestClaimFailsWhenPolicyNoLongerAllowsTheRequester(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE identity_id = ?`, f.alice)
		return err
	})

	wantFailedAtClaim(f, id, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
}

func TestClaimFailsWhenTheCapabilityDisappeared(t *testing.T) {
	f := newFixture(t)
	id := approvedReboot(f)

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: "node.reboot", Available: false, CheckedAt: f.clock.Now(),
		})
	})

	wantFailedAtClaim(f, id, smerr.CodeCapabilityUnavailable, "")
}

func TestClaimWithoutApprovalRequirementNeedsNoQuorum(t *testing.T) {
	f := newFixture(t)
	created, err := f.plans.Create(context.Background(), f.caller(f.alice), PlanRequest{
		Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.plans.Submit(context.Background(), f.caller(f.alice), created.Record.ID, created.Record.PlanHash); err != nil {
		t.Fatal(err)
	}

	if _, ok := f.claim(); !ok {
		t.Fatal("a probe needs no approval and must be claimable")
	}
	if got := f.locks()["node:"+f.node.ID.String()]; got != domain.LockShared {
		t.Errorf("probe holds the node %q, want shared", got)
	}
}

func TestSystemRequesterIsNotSubjectToPolicyOrApproval(t *testing.T) {
	f := newFixture(t)
	var system domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		system = f.identity(ctx, tx, "daemon", domain.ActorSystem, "")
		return nil
	})
	by := Caller{ID: system, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}}
	created, err := f.plans.Create(context.Background(), by, f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sub, err := f.plans.Submit(context.Background(), by, created.Record.ID, created.Record.PlanHash)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if sub.Job.State != domain.JobQueued {
		t.Fatalf("state = %s, want queued without approval", sub.Job.State)
	}

	if _, ok := f.claim(); !ok {
		t.Fatalf("system job failed revalidation: %+v", f.job(sub.Job.ID).Error)
	}
}

// locks returns the held locks as key -> mode.
func (f *fixture) locks() map[string]domain.LockMode {
	f.t.Helper()
	rows, err := f.db.Reader().QueryContext(context.Background(), `SELECT resource_type, resource_id, mode FROM resource_locks`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	held := map[string]domain.LockMode{}
	for rows.Next() {
		var typ, id string
		var mode domain.LockMode
		if err := rows.Scan(&typ, &id, &mode); err != nil {
			f.t.Fatal(err)
		}
		held[typ+":"+id] = mode
	}
	return held
}
