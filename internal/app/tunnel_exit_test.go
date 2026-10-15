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
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// breakTunnelVerification makes the verification over the tunnel fail, so an
// enable stops at phase installed with every object recorded.
func (ts *tunnelSetting) breakTunnelVerification() {
	ts.dialer.mu.Lock()
	defer ts.dialer.mu.Unlock()
	delete(ts.dialer.tunnel, "supermgmt")
}

func (ts *tunnelSetting) repairTunnelVerification() {
	ts.dialer.through("supermgmt")
	scriptDedicated(ts.dialer.through("supermgmt"))
}

// abandonQueuedJob ends the job that ran last, as an operator who gave up on it.
func (ts *tunnelSetting) abandonQueuedJob() {
	ts.t.Helper()
	mustf(ts.t, ts.store.FailTerminal(context.Background(), ts.lease, errors.New("abandoned")), "abandon the job")
}

// failedEnable leaves the node's enable halted as failed: the tunnel it recorded
// vanished from Cloudflare before the commit.
func failedEnable(t *testing.T) (*tunnelSetting, database.TunnelObjects) {
	t.Helper()
	ts := newTunnelSetting(t)
	ts.breakTunnelVerification()
	ts.plan()
	if err := ts.attempt(); err == nil {
		t.Fatal("the verification over the tunnel should have failed")
	}
	recorded := ts.operations()[0].Objects
	mustf(t, ts.chaos.CloudflareAPI.DeleteTunnel(context.Background(), recorded.TunnelID), "delete the tunnel")
	ts.repairTunnelVerification()
	interruptAndRequeue(t, ts.fixture, ts.queued.ID)
	err := ts.attempt()
	wantError(t, err, smerr.CodeConflict, "")
	return ts, recorded
}

func TestAVanishedRecordedObjectEndsTheEnableAsFailedAndANewSetupRepairsIt(t *testing.T) { // CODE-1, PROD-1, CODE-7
	ts, old := failedEnable(t)

	ops := ts.operations()
	if len(ops) != 1 || ops[0].Phase != database.PhaseFailed || ops[0].HaltedPhase != database.PhaseInstalled {
		t.Fatalf("operations = %+v, want the enable halted as failed at installed", ops)
	}
	if len(ts.events("node.tunnel.failed")) != 1 {
		t.Errorf("%d node.tunnel.failed events, want 1", len(ts.events("node.tunnel.failed")))
	}
	interruptAndRequeue(t, ts.fixture, ts.queued.ID)
	err := ts.attempt() // an automatic retry does not undo the halt
	wantError(t, err, smerr.CodeConflict, "")
	if !strings.Contains(err.Error(), "sm nodes tunnel disable web-1") || strings.Contains(err.Error(), "reconcile") {
		t.Errorf("error %q must name the real command to abandon the tunnel", err)
	}
	if got := ts.operations()[0].Phase; got != database.PhaseFailed {
		t.Fatalf("phase after an automatic retry = %s, want failed", got)
	}

	ts.abandonQueuedJob()
	ts.plan()
	ts.converge(3)

	ts.wantOneOfEach()
	ops = ts.operations()
	if len(ops) != 2 || ops[0].Generation != 2 || ops[0].Phase != database.PhaseCommitted || ops[1].Phase != database.PhaseCommitted {
		t.Fatalf("operations = %+v, want the abandoned generation 1 and a committed generation 2", ops)
	}
	if ops[0].Objects.TunnelID == old.TunnelID || ops[0].Objects.AccessAppID != old.AccessAppID {
		t.Errorf("generation 2 holds %+v: want a new tunnel and the inherited Access application (was %+v)", ops[0].Objects, old)
	}
	if len(ts.events("node.tunnel.enable_abandoned")) != 1 {
		t.Errorf("%d enable_abandoned events, want 1", len(ts.events("node.tunnel.enable_abandoned")))
	}
	if got := ts.currentNode().Endpoint.Transport; got != domain.TransportCloudflare {
		t.Errorf("transport = %q after the repair", got)
	}
}

func TestDisableAbandonsAnEnableThatIsUnfinishedHaltedOrFailing(t *testing.T) { // PROD-1, CODE-1
	tests := []struct {
		name  string
		setup bool // the node completed a plain setup before
		stuck func(t *testing.T) *tunnelSetting
		// foreign is the number of tunnels that are not ours and must survive.
		foreign int
	}{
		{"interrupted mid-enable", true, func(t *testing.T) *tunnelSetting {
			ts := newTunnelSetting(t)
			ts.inject("crash", 2)
			ts.plan()
			if err := ts.attempt(); err == nil {
				t.Fatal("the enable should have crashed")
			}
			ts.chaos.k = 0
			return ts
		}, 0},
		{"first setup that never completed", false, func(t *testing.T) *tunnelSetting {
			ts := newTunnelSetting(t)
			ts.inject("crash", 3)
			ts.plan()
			if err := ts.attempt(); err == nil {
				t.Fatal("the enable should have crashed")
			}
			ts.chaos.k = 0
			return ts
		}, 0},
		{"failed on a vanished object", true, func(t *testing.T) *tunnelSetting {
			ts, _ := failedEnable(t)
			return ts
		}, 0},
		{"halted on an object that is not ours", true, func(t *testing.T) *tunnelSetting {
			ts := newTunnelSetting(t)
			instance, err := database.GetInstance(context.Background(), ts.db.Reader())
			mustf(t, err, "GetInstance")
			ts.cf.SeedTunnel("sm-" + instance.ID.String() + "-" + ts.node.ID.String())
			ts.clock.Advance(time.Hour)
			ts.plan()
			wantError(t, ts.attempt(), smerr.CodeConflict, "")
			return ts
		}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := tc.stuck(t)
			ts.abandonQueuedJob()
			if tc.setup {
				ts.grantSetup()
			}
			node, base := ts.currentNode(), len(ts.cf.Mutations())
			ts.planDisable()

			mustf(t, ts.attempt(), "disable")

			snap := ts.cf.Snapshot()
			if len(snap.Tunnels) != tc.foreign || len(snap.Apps) != 0 || len(snap.DNSRecords) != 0 {
				t.Errorf("left in Cloudflare: %d tunnels (want %d foreign), %d apps, %d dns records", len(snap.Tunnels), tc.foreign, len(snap.Apps), len(snap.DNSRecords))
			}
			if after := ts.currentNode(); after.Endpoint != node.Endpoint || after.SpecRevision != node.SpecRevision {
				t.Errorf("node = %+v, want the direct endpoint untouched: the enable never switched it", after)
			}
			ops := ts.operations()
			if len(ops) < 2 || ops[0].Kind != database.TunnelDisable || ops[0].Phase != database.PhaseDone || ops[1].Kind != database.TunnelEnable || !ops[1].Phase.Finished() {
				t.Errorf("operations = %+v, want a finished disable above a closed enable", ops)
			}
			if _, err := database.ActiveTunnelOperation(context.Background(), ts.db.Reader(), ts.node.ID); smerr.CodeOf(err) != smerr.CodeNotFound {
				t.Errorf("the node is still held by an operation: %v", err)
			}
			if got := len(ts.events("node.tunnel.enable_abandoned")); got != 1 {
				t.Errorf("%d enable_abandoned events, want 1", got)
			}
			if tc.foreign > 0 && slices.Contains(ts.committedOps(base), cffake.OpTunnelDelete) {
				t.Error("the tunnel that is not ours was deleted")
			}
		})
	}
}

func TestADisableOfANodeWithoutAnyEnableStillSaysThereIsNothingToDisable(t *testing.T) { // PROD-1: no regression
	ts := newTunnelSetting(t)
	ts.grantSetup()
	ts.planDisable()

	wantError(t, ts.attempt(), smerr.CodeInvalidArgument, "")
}

func TestARecreatedConflictHaltResumesWithoutResettingThePhaseStart(t *testing.T) { // CODE-4
	ts := newTunnelSetting(t)
	started := ts.clock.Now()
	var op database.TunnelOperation
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		op, err = database.CreateTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: domain.UUIDv7Generator{}.NewID(), NodeID: ts.node.ID, Kind: database.TunnelEnable, AccountID: ts.cfg.AccountID,
			Zone: ts.cfg.Zone, InstanceID: "instance", Hostname: ts.hostname(), CreatedAt: started,
		})
		if err != nil {
			return err
		}
		op, err = database.AdvanceTunnelPhase(ctx, tx, op.ID, op.Generation, database.PhaseStarted, database.PhaseTokenReady, database.TunnelObjects{}, started)
		if err != nil {
			return err
		}
		_, err = database.HaltTunnelOperation(ctx, tx, op.ID, op.Generation, op.Phase, database.PhaseConflict, "foreign object", started)
		return err
	})
	ts.clock.Advance(time.Hour)

	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.ResumeHaltedTunnelOperation(ctx, tx, op.ID, op.Generation, database.PhaseConflict, ts.clock.Now())
		return err
	})

	got := ts.operations()[0]
	if got.Phase != database.PhaseTokenReady || got.HaltedPhase != "" || got.LastError != "" {
		t.Errorf("operation = %+v, want it back at token_ready, no longer halted", got)
	}
	if !got.PhaseStartedAt.Equal(started) {
		t.Errorf("phase_started_at = %v, want the original %v: objects of the earlier attempt stay adoptable", got.PhaseStartedAt, started)
	}
}

func TestAnOperatorWhoResolvesAConflictResumesTheSameOperation(t *testing.T) { // CODE-4
	ts := newTunnelSetting(t)
	instance, err := database.GetInstance(context.Background(), ts.db.Reader())
	mustf(t, err, "GetInstance")
	foreign := ts.cf.SeedTunnel("sm-" + instance.ID.String() + "-" + ts.node.ID.String())
	ts.clock.Advance(time.Hour)
	ts.plan()
	wantError(t, ts.attempt(), smerr.CodeConflict, "")
	ts.abandonQueuedJob()
	mustf(t, ts.chaos.CloudflareAPI.DeleteTunnel(context.Background(), foreign.ID), "the operator removes the foreign tunnel")

	ts.plan()
	mustf(t, ts.attempt(), "run after resolving")

	ts.wantOneOfEach()
	if ops := ts.operations(); len(ops) != 1 || ops[0].Phase != database.PhaseCommitted {
		t.Errorf("operations = %+v, want the one halted operation resumed and committed", ops)
	}
}

func TestTheLookupAfterAnAmbiguousCreateBacksOffThroughTheInjectedSleeper(t *testing.T) { // CODE-4
	ts := newTunnelSetting(t, cffake.WithPropagationDelay(2))
	ts.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Op == cffake.OpTunnelCreate {
			return cffake.LostResponse
		}
		return cffake.NoFault
	})
	ts.plan()

	ts.converge(3)

	ts.wantOneOfEach()
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if len(ts.slept) < len(want) || !slices.Equal(ts.slept[:len(want)], want) {
		t.Errorf("waits = %v, want to start with %v", ts.slept, want)
	}
}

func TestAnObjectThatStaysInvisibleAfterAnAmbiguousCreateIsRetriedNotHalted(t *testing.T) { // CODE-4
	ts := newTunnelSetting(t, cffake.WithPropagationDelay(1000))
	ts.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Op == cffake.OpTunnelCreate {
			return cffake.LostResponse
		}
		return cffake.NoFault
	})
	ts.plan()

	err := ts.attempt()

	if err == nil || !cloudflare.IsAmbiguous(err) {
		t.Fatalf("error = %v, want the ambiguous create error, which the retry looks at again", err)
	}
	if ops := ts.operations(); len(ops) != 1 || ops[0].Phase.Halted() {
		t.Errorf("operations = %+v, want the operation still running: the object may be this operation's own", ops)
	}
}

func TestTheNodeInstallIsPrecededByALeaseCheck(t *testing.T) { // CODE-5
	ts := newTunnelSetting(t)
	ts.chaos.onToken = func() { ts.clock.Advance(time.Minute) } // the lease expires after the last Cloudflare step
	ts.plan()

	err := ts.attempt()

	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("error = %v, want ErrLeaseLost", err)
	}
	if len(ts.files) != 0 {
		t.Errorf("a worker that lost its lease installed on the node: %v", ts.files)
	}
}

func TestAFinishedRotationOverwritesThePendingCredential(t *testing.T) { // CODE-8
	ts := newEnabledTunnel(t)
	ts.planRotation()

	mustf(t, ts.attempt(), "rotation")

	pending, err := ts.secrets.Get(context.Background(), secrets.Ref{Name: "cloudflare/access-service-token-pending"})
	mustf(t, err, "Get the pending secret")
	active, err := ts.secrets.Get(context.Background(), secrets.Ref{Name: "cloudflare/access-service-token"})
	mustf(t, err, "Get the active secret")
	if pending != retiredCredential || strings.Contains(string(pending), strings.SplitN(active.Reveal(), ":", 2)[0]) {
		t.Errorf("the pending secret still holds a credential after the rotation")
	}
}

func TestADisableResumedAfterTheDirectPathWasProvenProvesItAgain(t *testing.T) { // CODE-9
	ts := newEnabledTunnel(t)
	enable := ts.operations()[0]
	ts.planDisable()
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		op, err := database.CreateTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: domain.UUIDv7Generator{}.NewID(), NodeID: ts.node.ID, Kind: database.TunnelDisable, AccountID: enable.AccountID,
			Zone: enable.Zone, InstanceID: enable.InstanceID, Hostname: enable.Hostname, CreatedAt: ts.clock.Now(),
		})
		if err != nil {
			return err
		}
		_, err = database.AdvanceTunnelPhase(ctx, tx, op.ID, op.Generation, database.PhaseStarted, database.PhaseDirectVerified, enable.Objects, ts.clock.Now())
		return err
	})
	node, base := ts.currentNode(), len(ts.cf.Mutations())
	ts.dialer.as("supermgmt").reply("setup.verify_id", "someone-else\n") // the direct path broke since the proof

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "verification of the direct path (dedicated account)") {
		t.Fatalf("error = %v, want the direct path verified again", err)
	}
	if after := ts.currentNode(); after.Endpoint != node.Endpoint || len(ts.cf.Mutations()) != base {
		t.Errorf("the disable switched or mutated on an old proof: %+v", after.Endpoint)
	}
}

func TestFindLastEnabledGathersTheObjectsOfFinishedEnablesUntilADisable(t *testing.T) { // CODE-10
	ts := newEnabledTunnel(t)
	objects := ts.operations()[0].Objects
	last := func() database.TunnelOperation {
		r := &tunnelRun{tunnelEngine: ts.handler.tunnel, node: ts.node}
		mustf(t, r.findLastEnabled(context.Background()), "findLastEnabled")
		return r.lastEnabled
	}

	if got := last().Objects; got != objects {
		t.Errorf("after an enable: %+v, want %+v", got, objects)
	}
	ts.planDisable()
	mustf(t, ts.attempt(), "disable")
	if got := last(); got.ID != "" {
		t.Errorf("after a disable: %+v, want nothing: its objects were taken down", got)
	}
}

func TestRecreatingAVanishedInstancePolicyReattachesTheOwnedAccessApplications(t *testing.T) { // CODE-11
	ts := newEnabledTunnel(t)
	dead := ts.state().ServicePolicyID
	client, ok := ts.chaos.CloudflareAPI.(*cloudflare.Client)
	if !ok {
		t.Fatalf("the fixture's client is %T", ts.chaos.CloudflareAPI)
	}
	app := ts.cf.Snapshot().Apps[0]
	_, err := client.UpdateAccessApp(context.Background(), app.ID, cloudflare.AppSpec{
		Name: app.Name, Domain: app.Domain, PolicyIDs: []string{ts.state().OwnersPolicyID}, AllowedIdPs: app.AllowedIdPs,
	})
	mustf(t, err, "detach the Service Auth policy from the application") // Cloudflare refuses to delete an attached policy
	mustf(t, client.DeleteAccessPolicy(context.Background(), dead), "delete the Service Auth policy")
	ts.planRotation() // an instance-wide job: no node is being enabled

	mustf(t, ts.attempt(), "rotation")

	fresh := ts.state().ServicePolicyID
	apps := ts.cf.Snapshot().Apps
	if fresh == dead || len(apps) != 1 || slices.Contains(apps[0].PolicyIDs, dead) || !slices.Contains(apps[0].PolicyIDs, fresh) {
		t.Errorf("policy %s -> %s, Access applications %+v: the application must point at the new policy", dead, fresh, apps)
	}
}

func TestADisablePlanGoesStaleWhenTheNodeChangesBeforeTheClaim(t *testing.T) { // SEC-6
	ts := newEnabledTunnel(t)
	job := ts.planDisable()

	ts.bumpNodeRevision()

	if _, ok := ts.claim(); ok {
		t.Fatal("a disable approved for another revision of the node was claimed")
	}
	if got := ts.job(job.ID); got.State != domain.JobFailed || got.Error == nil || got.Error.Reason != smerr.ReasonPlanStale {
		t.Errorf("job = %s %+v, want failed with PLAN_STALE", got.State, got.Error)
	}
}

func TestADisablePlanBindsTheNodeRevision(t *testing.T) { // SEC-6
	ts := newEnabledTunnel(t)
	created, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{Action: policy.ActionNodeTunnelDisable, Target: ts.nodeRef()})
	mustf(t, err, "Create")

	target := created.Plan.Targets[0]
	if target.SpecRevision == nil || *target.SpecRevision != ts.currentNode().SpecRevision {
		t.Errorf("target revision = %v, want the node's %d", target.SpecRevision, ts.currentNode().SpecRevision)
	}
}

func TestATunnelPlanForANodeWhoseNameIsNoDNSLabelIsRefusedBeforeApproval(t *testing.T) { // PROD-4
	for _, name := range []string{"web_1", "web.1", "web 1", strings.Repeat("a", 60)} {
		t.Run(name, func(t *testing.T) {
			ts := newTunnelSetting(t)
			ts.inTx(func(ctx context.Context, tx *database.Tx) error {
				node, err := database.GetNode(ctx, tx, ts.node.ID)
				if err != nil {
					return err
				}
				node.Name = name
				_, err = database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
				return err
			})
			params := defaultSetup()
			params["tunnel"] = "true"

			for _, req := range []PlanRequest{
				{Action: policy.ActionNodeSetup, Target: ts.nodeRef(), Parameters: params},
				{Action: policy.ActionNodeTunnelDisable, Target: ts.nodeRef()},
			} {
				_, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), req)
				wantError(t, err, smerr.CodeInvalidArgument, "")
				if err != nil && !strings.Contains(err.Error(), "rename the node") {
					t.Errorf("%s: error %q does not say what to change", req.Action, err)
				}
			}
		})
	}
}
