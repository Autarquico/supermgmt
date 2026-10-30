package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// teardownOps are the Cloudflare mutations of a complete teardown: the route closes, then Access goes, the
// tunnel last.
var teardownOps = []cffake.Op{cffake.OpDNSDelete, cffake.OpTunnelConfigPut, cffake.OpAppDelete, cffake.OpTunnelCleanup, cffake.OpTunnelDelete}

// provisionedEnrollment is an enrollment whose Cloudflare side is built (waiting for the node).
func provisionedEnrollment(t *testing.T) (*tunnelSetting, *tunnelRun, *enrollmentRecord) {
	t.Helper()
	ts := newTunnelSetting(t)
	r, rec := ts.enrollmentRun()
	_, err := r.provisionCloudflare(context.Background())
	mustf(t, err, "provisionCloudflare")
	return ts, r, rec
}

// resumedRun is a new worker over the stored row of the enrollment, as after a restart.
func (ts *tunnelSetting) resumedRun(prev *tunnelRun) (*tunnelRun, *enrollmentRecord) {
	ts.t.Helper()
	row, err := database.GetTunnelEnrollment(context.Background(), ts.db.Reader(), enrollmentTestID)
	mustf(ts.t, err, "GetTunnelEnrollment")
	r, err := ts.handler.tunnel.newRun(context.Background(), prev.lease, prev.job, prev.node, prev.hostname)
	mustf(ts.t, err, "newRun")
	rec := newEnrollmentRecord(row, prev.lease, r.write, ts.clock.Now)
	r.rec = rec
	return r, rec
}

// reclaimedRun is resumedRun under a lease claimed after the previous one expired.
func (ts *tunnelSetting) reclaimedRun(prev *tunnelRun) (*tunnelRun, *enrollmentRecord) {
	ts.t.Helper()
	claimed, ok := ts.claim()
	if !ok {
		ts.t.Fatal("no job to claim")
	}
	prev.lease, prev.job = claimed.Lease, claimed.Job
	return ts.resumedRun(prev)
}

func (ts *tunnelSetting) enrollment() database.TunnelEnrollment {
	ts.t.Helper()
	row, err := database.GetTunnelEnrollment(context.Background(), ts.db.Reader(), enrollmentTestID)
	mustf(ts.t, err, "GetTunnelEnrollment")
	return row
}

func (ts *tunnelSetting) wantNothingLeft() {
	ts.t.Helper()
	snap := ts.cf.Snapshot()
	if len(snap.Tunnels) != 0 || len(snap.Apps) != 0 || len(snap.DNSRecords) != 0 {
		ts.t.Errorf("left in Cloudflare: %d tunnels, %d apps, %d dns records", len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords))
	}
	if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		ts.t.Errorf("routable without Access at some point: %v", routable)
	}
}

func TestTeardownOfAnEnrollmentFollowsTheOrderAndKeepsTheSharedObjects(t *testing.T) {
	ts, r, rec := provisionedEnrollment(t)
	shared, base := ts.instanceObjects(), len(ts.cf.Mutations())

	mustf(t, r.removeEnrollment(context.Background(), rec, "expired", database.PhaseExpired), "removeEnrollment")

	if got := ts.committedOps(base); !slices.Equal(got, teardownOps) {
		t.Errorf("Cloudflare mutations = %v, want %v", got, teardownOps)
	}
	ts.wantNothingLeft()
	if after := ts.instanceObjects(); len(after.policies) != len(shared.policies) || len(after.tokens) != len(shared.tokens) || after.secrets != shared.secrets {
		t.Errorf("shared policies, service token or secret changed: %+v -> %+v", shared, after)
	}
	row := ts.enrollment()
	if row.Phase != database.PhaseExpired || row.TerminalReason != "expired" {
		t.Errorf("enrollment = %s / %q, want expired / expired", row.Phase, row.TerminalReason)
	}
	if _, err := database.OpenTunnelEnrollmentByName(context.Background(), ts.db.Reader(), "vps1"); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("the name is still held after the enrollment ended: %v", err)
	}
	for _, action := range []string{"cloudflare.dns_record.deleted", "cloudflare.tunnel.ingress_closed", "cloudflare.access_app.deleted", "cloudflare.tunnel.deleted", eventEnrollmentEnded} {
		if len(ts.events(action)) != 1 {
			t.Errorf("%d %s events, want 1", len(ts.events(action)), action)
		}
	}
}

func TestTeardownResumesAfterACrashFollowingEachDelete(t *testing.T) {
	for k := 1; k <= len(teardownOps); k++ {
		t.Run(string(teardownOps[k-1]), func(t *testing.T) {
			ts, r, rec := provisionedEnrollment(t)
			base := len(ts.cf.Mutations())
			ts.arm("crash", k)

			err := r.removeEnrollment(context.Background(), rec, "cancelled", database.PhaseCancelled)
			if err == nil {
				t.Fatal("the crash did not surface")
			}
			if got := ts.enrollment().Phase; database.EnrollmentFinished(got) {
				t.Fatalf("phase = %s after a crash: terminal before the teardown completed", got)
			}

			r, rec = ts.resumedRun(r)
			mustf(t, r.removeEnrollment(context.Background(), rec, "cancelled", database.PhaseCancelled), "resumed removeEnrollment")

			ts.wantNothingLeft()
			if got := ts.enrollment().Phase; got != database.PhaseCancelled {
				t.Errorf("phase = %s, want cancelled", got)
			}
			// the cleanup of the connections belongs to the tunnel's delete step, which a crash repeats
			if got := slices.Compact(ts.committedOps(base)); !slices.Equal(got, teardownOps) {
				t.Errorf("Cloudflare mutations = %v, want %v with nothing deleted twice", got, teardownOps)
			}
		})
	}
}

func TestAFailedDeleteLeavesTheEnrollmentOpenAndHoldingItsName(t *testing.T) {
	ts, r, rec := provisionedEnrollment(t)
	ts.arm("refused before", len(teardownOps)) // the tunnel delete

	err := r.removeEnrollment(context.Background(), rec, "expired", database.PhaseExpired)
	if err == nil {
		t.Fatal("removeEnrollment succeeded although the tunnel delete failed")
	}

	if row := ts.enrollment(); row.Phase != database.PhaseAccessRemoved {
		t.Errorf("phase = %s, want access_removed: the steps before the failure stay recorded", row.Phase)
	}
	if _, err := database.OpenTunnelEnrollmentByName(context.Background(), ts.db.Reader(), "vps1"); err != nil {
		t.Errorf("the name was released with a tunnel left behind: %v", err)
	}
	if len(ts.events(eventEnrollmentEnded)) != 0 {
		t.Error("an enrollment_ended event was emitted before the teardown completed")
	}

	r, rec = ts.resumedRun(r)
	mustf(t, r.removeEnrollment(context.Background(), rec, "expired", database.PhaseExpired), "retry")
	ts.wantNothingLeft()
	if got := ts.enrollment().Phase; got != database.PhaseExpired {
		t.Errorf("phase = %s, want expired", got)
	}
}

func TestTeardownBeforeAnythingWasCreatedEndsWithoutCloudflareMutations(t *testing.T) {
	ts := newTunnelSetting(t)
	r, rec := ts.enrollmentRun()

	mustf(t, r.removeEnrollment(context.Background(), rec, "cancelled", database.PhaseCancelled), "removeEnrollment")

	if len(ts.cf.Mutations()) != 0 {
		t.Errorf("mutations = %v on an enrollment that created nothing", cloudflareOps(ts.cf))
	}
	if got := ts.enrollment().Phase; got != database.PhaseCancelled {
		t.Errorf("phase = %s, want cancelled", got)
	}
}

// An enrollment that stopped between the create and its record: the object exists unrecorded. It is adopted
// under the adoption rule, recorded, and then deleted.
func TestTeardownReconcilesATunnelCreatedButNotRecorded(t *testing.T) {
	ts := newTunnelSetting(t)
	r, rec := ts.enrollmentRun()
	ctx := context.Background()
	mustf(t, r.advance(ctx, database.PhaseTokenReady, database.TunnelObjects{}, "", nil), "advance")
	_, err := r.api.CreateTunnel(ctx, cloudflare.TunnelName(r.instanceID, r.node.ID.String()))
	mustf(t, err, "CreateTunnel")

	mustf(t, r.removeEnrollment(ctx, rec, "expired", database.PhaseExpired), "removeEnrollment")

	ts.wantNothingLeft()
	if len(ts.events("cloudflare.tunnel.adopted")) != 1 {
		t.Errorf("%d tunnel.adopted events, want 1: the unrecorded tunnel is recorded before it is deleted", len(ts.events("cloudflare.tunnel.adopted")))
	}
	if got := ts.enrollment(); got.Phase != database.PhaseExpired || got.Objects.TunnelID == "" {
		t.Errorf("enrollment = %s with tunnel %q, want expired with the adopted tunnel recorded", got.Phase, got.Objects.TunnelID)
	}
}

func TestTeardownReconcilesAnAccessApplicationCreatedButNotRecorded(t *testing.T) {
	ts := newTunnelSetting(t)
	r, rec := ts.enrollmentRun()
	ctx := context.Background()
	state, err := r.ensureInstanceAccess(ctx)
	mustf(t, err, "ensureInstanceAccess")
	mustf(t, r.advance(ctx, database.PhaseTokenReady, database.TunnelObjects{}, "", nil), "advance")
	mustf(t, r.ensureTunnel(ctx, state), "ensureTunnel")
	mustf(t, r.ensureIngress(ctx, state), "ensureIngress")
	idps, err := r.api.ResolveAllowedIdPs(ctx, r.opts.Config.AccessIdentityProviders)
	mustf(t, err, "ResolveAllowedIdPs")
	_, err = r.api.CreateAccessApp(ctx, cloudflare.AppSpec{
		Name: cloudflare.AccessAppName(r.instanceID, r.node.ID.String()), Domain: r.hostname,
		PolicyIDs: []string{state.ServicePolicyID, state.OwnersPolicyID}, AllowedIdPs: idps,
	})
	mustf(t, err, "CreateAccessApp")

	mustf(t, r.removeEnrollment(ctx, rec, "expired", database.PhaseExpired), "removeEnrollment")

	ts.wantNothingLeft()
	if len(ts.events("cloudflare.access_app.adopted")) != 1 {
		t.Errorf("%d access_app.adopted events, want 1", len(ts.events("cloudflare.access_app.adopted")))
	}
}

// A same-name tunnel the enrollment cannot have created is never deleted.
func TestTeardownLeavesAForeignTunnelAloneAndStopsOnAnAmbiguousOne(t *testing.T) {
	foreign := func(t *testing.T) (*tunnelSetting, *tunnelRun, *enrollmentRecord, string) {
		ts := newTunnelSetting(t)
		ctx := context.Background()
		r, _ := ts.enrollmentRun()
		name := cloudflare.TunnelName(r.instanceID, r.node.ID.String())
		old, err := r.api.CreateTunnel(ctx, name)
		mustf(t, err, "CreateTunnel (foreign)")
		ts.clock.Advance(10 * time.Minute) // the tunnel predates the phase by more than the clock skew allowance
		interruptAndRequeue(t, ts.fixture, ts.queued.ID)
		r, rec := ts.reclaimedRun(r)
		mustf(t, r.advance(ctx, database.PhaseTokenReady, database.TunnelObjects{}, "", nil), "advance")
		return ts, r, rec, old.ID
	}

	t.Run("foreign only", func(t *testing.T) {
		ts, r, rec, id := foreign(t)
		mustf(t, r.removeEnrollment(context.Background(), rec, "expired", database.PhaseExpired), "removeEnrollment")
		if tunnels := ts.cf.Snapshot().Tunnels; len(tunnels) != 1 || tunnels[0].ID != id {
			t.Errorf("tunnels = %+v, want the foreign one untouched", tunnels)
		}
		if len(ts.events(eventObjectLeft)) != 1 {
			t.Errorf("%d %s events, want 1", len(ts.events(eventObjectLeft)), eventObjectLeft)
		}
	})

	t.Run("foreign next to one that passes", func(t *testing.T) {
		ts, r, rec, _ := foreign(t)
		ctx := context.Background()
		ts.cf.SeedTunnel(cloudflare.TunnelName(r.instanceID, r.node.ID.String()))
		before := len(ts.cf.Snapshot().Tunnels)

		err := r.removeEnrollment(ctx, rec, "expired", database.PhaseExpired)

		var conflict *ownershipConflict
		if !errors.As(err, &conflict) {
			t.Fatalf("error = %v, want an ownership conflict", err)
		}
		if got := len(ts.cf.Snapshot().Tunnels); got != before {
			t.Errorf("%d tunnels after the refusal, want %d: nothing is touched", got, before)
		}
		if database.EnrollmentFinished(ts.enrollment().Phase) || ts.enrollment().Phase == database.PhaseRemoving {
			t.Errorf("phase = %s, want the enrollment left as it was", ts.enrollment().Phase)
		}
	})
}

func TestDisableRefusesATunnelOnlyNodeBeforeAnythingChanges(t *testing.T) {
	for _, adminUser := range []string{"admin", ""} {
		t.Run("admin_user="+adminUser, func(t *testing.T) {
			ts := newEnabledTunnel(t)
			ts.setAdminUser(adminUser)
			ts.planDisable() // asked before the node was marked: planning refuses a node already marked
			ts.markProvenance()
			ops, base, dialed := len(ts.operations()), len(ts.cf.Mutations()), len(ts.dialer.targets())

			err := ts.attempt()

			if err == nil || !strings.Contains(err.Error(), "no direct path") {
				t.Fatalf("error = %v, want a refusal that says the node has no direct path", err)
			}
			if len(ts.operations()) != ops || len(ts.cf.Mutations()) != base || len(ts.dialer.targets()) != dialed {
				t.Errorf("the refusal changed state: %d operations, %d mutations, %d dials", len(ts.operations())-ops, len(ts.cf.Mutations())-base, len(ts.dialer.targets())-dialed)
			}
			if n := ts.currentNode(); n.Endpoint.Transport != domain.TransportCloudflare {
				t.Errorf("transport = %s, want the node left on the tunnel", n.Endpoint.Transport)
			}
		})
	}
}

// A directly joined node has no admin_user either; that is not what refuses the disable.
func TestDisableOfADirectNodeWithoutAnAdminUserKeepsItsOwnRefusal(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.setAdminUser("")
	ts.planDisable()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "no admin_user") || strings.Contains(err.Error(), "no direct path") {
		t.Fatalf("error = %v, want the admin_user refusal of today", err)
	}
}

func TestTunnelOnlySurvivesALaterSetup(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.markTunnelOnly("admin")

	ts.plan()
	mustf(t, ts.attempt(), "setup again")

	if !tunnelOnly(ts.currentNode()) {
		t.Errorf("metadata = %v: a later setup dropped the provenance", ts.currentNode().Metadata)
	}
}

func TestWithTunnelOnlyKeepsTheOtherMetadata(t *testing.T) {
	in := map[string]any{"k": "v"}
	out := withTunnelOnly(in)
	if !tunnelOnly(domain.Node{Metadata: out}) || out["k"] != "v" || len(in) != 1 {
		t.Errorf("withTunnelOnly(%v) = %v", in, out)
	}
	if !tunnelOnly(domain.Node{Metadata: withTunnelOnly(nil)}) || tunnelOnly(domain.Node{}) {
		t.Error("the provenance reader disagrees with its writer")
	}
}

// markTunnelOnly writes the provenance the enrollment commit writes, and sets the node's admin_user.
func (ts *tunnelSetting) markTunnelOnly(adminUser string) {
	ts.t.Helper()
	ts.markProvenance()
	ts.setAdminUser(adminUser)
}

// markProvenance marks the node tunnel-only without touching its spec revision, so a plan made before
// stays valid and the job itself is what refuses.
func (ts *tunnelSetting) markProvenance() {
	ts.t.Helper()
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE nodes SET metadata_json = '{"tunnel_only":true}' WHERE id = ?`, ts.node.ID)
		return err
	})
}

func (ts *tunnelSetting) setAdminUser(adminUser string) {
	ts.t.Helper()
	node := ts.currentNode()
	node.Endpoint.AdminUser = adminUser
	node.UpdatedAt = ts.clock.Now()
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
		return err
	})
}
