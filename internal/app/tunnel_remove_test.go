package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// newRemovableTunnel is a node that completed `setup --tunnel`, with admins allowed to remove nodes.
func newRemovableTunnel(t *testing.T) *tunnelSetting {
	t.Helper()
	ts := newTunnelSettingWith(t, destructiveAdmins)
	ts.plan()
	mustf(t, ts.attempt(), "tunnel setup")
	return ts
}

// submitRemoval asks to remove the node as the admin; the job it becomes waits for approval.
func (ts *tunnelSetting) submitRemoval() jobs.Job {
	ts.t.Helper()
	res, err := ts.inv.RemoveNode(context.Background(), ts.caller(ts.admin), ts.node.ID, ts.currentNode().SpecRevision)
	mustf(ts.t, err, "RemoveNode")
	if res.Pending == nil {
		ts.t.Fatalf("RemoveNode = %+v, want a job", res)
	}
	return res.Pending.Job
}

// approveRemoval approves the removal job and makes attempt run it.
func (ts *tunnelSetting) approveRemoval(job jobs.Job) jobs.Job {
	ts.t.Helper()
	var err error
	for _, approver := range []domain.ID{ts.bob, ts.carol} {
		if job.State != domain.JobAwaitingApproval {
			break
		}
		job, err = ts.approve(approver, job)
		mustf(ts.t, err, "approve the removal")
	}
	ts.queued = job
	ts.current = applyHandler{inv: ts.inv, tunnel: ts.handler.tunnel}
	return job
}

// requestRemoval submits the removal and approves it.
func (ts *tunnelSetting) requestRemoval() jobs.Job { return ts.approveRemoval(ts.submitRemoval()) }

// wantRemovedWithItsTunnel fails unless the node's own Cloudflare objects are gone, the instance's stay, the
// hostname was never routable without Access and the node is retired after a finished disable record.
func (ts *tunnelSetting) wantRemovedWithItsTunnel(before instanceObjects) {
	ts.t.Helper()
	snap := ts.cf.Snapshot()
	if len(snap.Tunnels) != 0 || len(snap.Apps) != 0 || len(snap.DNSRecords) != 0 {
		ts.t.Errorf("left in Cloudflare: %d tunnels, %d apps, %d dns records", len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords))
	}
	ts.wantInstanceObjectsKept(before)
	if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		ts.t.Errorf("routable without Access at some point: %v", routable)
	}
	if state := ts.currentNode().ManagementState; state != domain.ManagementRetired {
		ts.t.Errorf("node is %s, want retired", state)
	}
	if ops := ts.operations(); len(ops) < 2 || ops[0].Kind != database.TunnelDisable || ops[0].Phase != database.PhaseDone {
		ts.t.Errorf("operations = %+v, want the newest to be a finished disable", ops)
	}
}

// wantUntouched fails unless the node is managed, its tunnel operations are those of before and Cloudflare
// has seen no mutation since base.
func (ts *tunnelSetting) wantUntouched(base int, opsBefore int) {
	ts.t.Helper()
	if state := ts.currentNode().ManagementState; state != domain.ManagementManaged {
		ts.t.Errorf("node is %s, want it still managed", state)
	}
	if got := len(ts.cf.Mutations()) - base; got != 0 {
		ts.t.Errorf("%d Cloudflare mutations, want none", got)
	}
	if got := len(ts.operations()); got != opsBefore {
		ts.t.Errorf("%d tunnel operations, want the %d it had", got, opsBefore)
	}
}

func TestRemovingANodeWithATunnelTakesItsCloudflareObjectsDownBeforeRetiringIt(t *testing.T) {
	ts := newRemovableTunnel(t)
	before, base, dialed := ts.instanceObjects(), len(ts.cf.Mutations()), len(ts.dialer.targets())

	job := ts.requestRemoval()

	if job.Type != JobControlPlaneApply {
		t.Errorf("job type = %s, want %s", job.Type, JobControlPlaneApply)
	}
	rec, err := database.GetPlan(context.Background(), ts.db.Reader(), *job.PlanID)
	mustf(t, err, "GetPlan")
	if !strings.Contains(string(rec.PlanJSON), `"tunnel":"true"`) || !strings.Contains(string(rec.PlanJSON), "delete the Cloudflare Access application") {
		t.Errorf("plan %s does not tell the approver that the tunnel goes", rec.PlanJSON)
	}
	if state := ts.currentNode().ManagementState; state != domain.ManagementManaged || len(ts.cf.Mutations()) != base {
		t.Fatalf("node %s with %d Cloudflare mutations before the job ran, want it managed and untouched", state, len(ts.cf.Mutations())-base)
	}

	mustf(t, ts.attempt(), "removal")

	ts.wantRemovedWithItsTunnel(before)
	want := []cffake.Op{cffake.OpDNSDelete, cffake.OpTunnelConfigPut, cffake.OpAppDelete, cffake.OpTunnelCleanup, cffake.OpTunnelDelete}
	if got := ts.committedOps(base); !slices.Equal(got, want) {
		t.Errorf("Cloudflare mutations = %v, want %v: the route closes, then Access goes, the tunnel last", got, want)
	}
	if got := ts.dialer.targets(); len(got) != dialed {
		t.Errorf("%d connections to the node, want none: the removal needs no SSH", len(got)-dialed)
	}
	for _, action := range []string{"cloudflare.dns_record.deleted", "cloudflare.access_app.deleted", "cloudflare.tunnel.deleted", "node.tunnel.taken_down", "node.remove"} {
		if len(ts.events(action)) == 0 {
			t.Errorf("no %s event", action)
		}
	}
}

func TestANodeRemovedWithItsTunnelCanBeSetUpAgainWithATunnelUnderTheSameName(t *testing.T) {
	ts := newRemovableTunnel(t)
	ts.requestRemoval()
	mustf(t, ts.attempt(), "removal")

	again := ts.addApplied("web-1", "")
	first := ts.node
	ts.inTx(func(ctx context.Context, tx *database.Tx) error { // the new node is reached as the scripted one is
		node, err := database.GetNode(ctx, tx, again.ID)
		if err != nil {
			return err
		}
		node.Endpoint, node.CredentialRef, node.EnvironmentID = first.Endpoint, first.CredentialRef, first.EnvironmentID
		if _, err := database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision); err != nil {
			return err
		}
		return database.SetNodeCapability(ctx, tx, node.ID, database.NodeCapability{Capability: "node.ssh", Available: true, CheckedAt: ts.clock.Now()})
	})
	node, err := database.GetNode(context.Background(), ts.db.Reader(), again.ID)
	mustf(t, err, "GetNode")
	ts.node, ts.current = node, nil
	ts.plan()

	mustf(t, ts.attempt(), "tunnel setup of the node added under the freed name")

	if got := ts.currentNode().Endpoint.TunnelHostname; got != ts.hostname() {
		t.Errorf("tunnel hostname = %q, want %q", got, ts.hostname())
	}
	if len(ts.events("node.tunnel.conflict")) != 0 {
		t.Error("the new node's setup met the old node's DNS record as an ownership conflict")
	}
}

func TestRemovingANodeWithoutATunnelRetiresItWithoutTouchingCloudflare(t *testing.T) {
	ts := newTunnelSettingWith(t, destructiveAdmins)

	res, err := ts.inv.RemoveNode(context.Background(), ts.caller(ts.admin), ts.node.ID, ts.node.SpecRevision)
	mustf(t, err, "RemoveNode")
	if res.Pending == nil {
		t.Fatalf("RemoveNode = %+v, want the destructive gate to wait for approval", res)
	}
	rec, err := database.GetPlan(context.Background(), ts.db.Reader(), *res.Pending.Job.PlanID)
	mustf(t, err, "GetPlan")
	if strings.Contains(string(rec.PlanJSON), "tunnel") {
		t.Errorf("plan %s mentions a tunnel for a node that has none", rec.PlanJSON)
	}
	ts.queued = ts.approveToQuorum(res.Pending.Job)
	ts.current = applyHandler{inv: ts.inv, tunnel: ts.handler.tunnel}
	if _, ok := ts.claim(); !ok {
		t.Fatal("no job to claim")
	}
	if _, held := ts.locks()["cloudflare:instance"]; held {
		t.Error("a removal of a node without a tunnel holds the instance's Cloudflare lock")
	}
	interruptAndRequeue(t, ts.fixture, ts.queued.ID)

	mustf(t, ts.attempt(), "removal")

	if state := ts.currentNode().ManagementState; state != domain.ManagementRetired {
		t.Errorf("node is %s, want retired", state)
	}
	if got := len(ts.cf.Mutations()); got != 0 {
		t.Errorf("%d Cloudflare mutations, want none", got)
	}
	if got := len(ts.operations()); got != 0 {
		t.Errorf("%d tunnel operations, want none", got)
	}
}

func TestARemovalThatTakesATunnelDownHoldsTheNodeAndTheCloudflareInstance(t *testing.T) {
	ts := newRemovableTunnel(t)
	ts.requestRemoval()
	if _, ok := ts.claim(); !ok {
		t.Fatal("no job to claim")
	}

	held := ts.locks()

	if got := held["node:"+ts.node.ID.String()]; got != domain.LockExclusive {
		t.Errorf("node lock = %q, want exclusive", got)
	}
	if got := held["cloudflare:instance"]; got != domain.LockExclusive {
		t.Errorf("Cloudflare instance lock = %q, want exclusive: the ingress is written under it", got)
	}
}

func TestRemovingANodeThatStillHasRoutesIsRefusedBeforeAnythingChanges(t *testing.T) {
	rs := newRouteSettingOn(newRemovableTunnel(t))
	rs.addRoute("app."+cffake.DefaultZone, 8080, "owners", database.NodeRouteActive)
	base, ops := len(rs.cf.Mutations()), len(rs.operations())

	_, err := rs.inv.RemoveNode(context.Background(), rs.caller(rs.admin), rs.node.ID, rs.currentNode().SpecRevision)

	wantError(t, err, smerr.CodeConflict, "")
	if !strings.Contains(err.Error(), "app."+cffake.DefaultZone) || !strings.Contains(err.Error(), "unexpose") {
		t.Errorf("error %q does not name the route or the command that removes it", err)
	}
	rs.wantUntouched(base, ops)
}

func TestARouteAdmittedWhileTheRemovalWaitedStopsItBeforeAnythingChanges(t *testing.T) {
	rs := newRouteSettingOn(newRemovableTunnel(t))
	base, ops := len(rs.cf.Mutations()), len(rs.operations())
	rs.requestRemoval()
	rs.addRoute("app."+cffake.DefaultZone, 8080, "owners", database.NodeRouteActive)

	err := rs.attempt()

	wantError(t, err, smerr.CodeConflict, "")
	rs.wantUntouched(base, ops)
}

func TestARouteExposedWhileTheRemovalLooksUpTheZoneIsNeverStrandedByTheRemoval(t *testing.T) {
	rs := newRouteSettingOn(newRemovableTunnel(t))
	rs.exec(`UPDATE environments SET risk_level = 'development'`) // an owners expose needs no approval there
	rs.requestRemoval()
	var exposed error
	rs.chaos.onZone = func() {
		rs.chaos.onZone = nil
		_, exposed = rs.expose(webRequest(shop))
	}

	err := rs.attempt()

	if exposed != nil {
		t.Fatalf("Expose between the check and the takedown record = %v, want it admitted", exposed)
	}
	wantError(t, err, smerr.CodeConflict, "")
	if state := rs.currentNode().ManagementState; state != domain.ManagementManaged {
		t.Errorf("node is %s, want it still managed with its route", state)
	}
	if got := rs.operations()[0].Kind; got == database.TunnelDisable {
		t.Errorf("a disable record was opened over a live route")
	}
}

func TestRemovingANodeWithATunnelIsRefusedWhenCloudflareCannotBeReached(t *testing.T) {
	t.Run("without a cloudflare block the request is refused", func(t *testing.T) {
		ts := newRemovableTunnel(t)
		base, ops := len(ts.cf.Mutations()), len(ts.operations())
		cfg := ts.fixture.cfg
		cfg.Cloudflare = nil
		inv := ts.inventoryOver(cfg)

		_, err := inv.RemoveNode(context.Background(), ts.caller(ts.admin), ts.node.ID, ts.currentNode().SpecRevision)

		wantError(t, err, smerr.CodeCapabilityUnavailable, "")
		if !strings.Contains(err.Error(), "cloudflare: block") {
			t.Errorf("error %q does not say which configuration brings the removal back", err)
		}
		ts.wantUntouched(base, ops)
	})
	t.Run("the account or zone of the tunnel is not the configured one", func(t *testing.T) {
		ts := newRemovableTunnel(t)
		base, ops := len(ts.cf.Mutations()), len(ts.operations())
		cfg := ts.fixture.cfg
		other := *cfg.Cloudflare
		other.Zone = "elsewhere.example.test"
		cfg.Cloudflare = &other
		inv := ts.inventoryOver(cfg)

		_, err := inv.RemoveNode(context.Background(), ts.caller(ts.admin), ts.node.ID, ts.currentNode().SpecRevision)

		wantError(t, err, smerr.CodeConflict, "")
		if !strings.Contains(err.Error(), "another Cloudflare account or zone") {
			t.Errorf("error %q does not say the tunnel belongs to another account or zone", err)
		}
		ts.wantUntouched(base, ops)
	})
	t.Run("the API token left the secret store", func(t *testing.T) {
		ts := newRemovableTunnel(t)
		base, ops := len(ts.cf.Mutations()), len(ts.operations())
		ts.requestRemoval()
		mustf(t, ts.secrets.Purge(context.Background(), "cloudflare/api-token"), "Purge")

		err := ts.attempt()

		wantError(t, err, smerr.CodeCapabilityUnavailable, "")
		if !strings.Contains(err.Error(), "cloudflare.api_token_ref") {
			t.Errorf("error %q does not say where to store the token", err)
		}
		ts.wantUntouched(base, ops)
	})
	t.Run("the cloudflare block was removed while the job waited", func(t *testing.T) {
		ts := newRemovableTunnel(t)
		base, ops := len(ts.cf.Mutations()), len(ts.operations())
		ts.requestRemoval()
		ts.current = applyHandler{inv: ts.inv}

		err := ts.attempt()

		wantError(t, err, smerr.CodeCapabilityUnavailable, "")
		ts.wantUntouched(base, ops)
	})
}

// inventoryOver is an inventory with the configuration cfg over the same database, as a restarted daemon
// with another cloudflare: block builds one.
func (ts *tunnelSetting) inventoryOver(cfg Config) *Inventory {
	ts.t.Helper()
	inv, err := NewInventory(cfg, InventoryOptions{Store: ts.store, Connector: ts.conn, Mode: config.ModeLocal})
	mustf(ts.t, err, "NewInventory")
	return inv
}

func TestATunnelRecordedAfterTheRemovalWasRequestedMakesTheJobAskForANewRemoval(t *testing.T) {
	ts := newTunnelSettingWith(t, destructiveAdmins)
	job := ts.submitRemoval() // the node has no tunnel: the plan does not hold the Cloudflare lock
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: ts.ids.NewID(), NodeID: ts.node.ID, AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, InstanceID: "instance",
			Hostname: ts.hostname(), CreatedAt: ts.clock.Now(), Objects: database.TunnelObjects{TunnelID: "t", DNSRecordID: "d", AccessAppID: "a"},
		})
		return err
	})
	base, ops := len(ts.cf.Mutations()), len(ts.operations())
	ts.approveRemoval(job)

	err := ts.attempt()

	wantError(t, err, smerr.CodeConflict, "")
	if !strings.Contains(err.Error(), "remove the node again") {
		t.Errorf("error %q does not say to ask again", err)
	}
	ts.wantUntouched(base, ops)
}

func TestEveryFaultAfterEveryMutationOfATunnelNodeRemovalConverges(t *testing.T) {
	clean := newRemovableTunnel(t)
	base := len(clean.cf.Mutations())
	clean.requestRemoval()
	mustf(t, clean.attempt(), "clean removal")
	total := len(clean.cf.Mutations()) - base
	if total != 5 {
		t.Fatalf("a clean removal made %d mutations, want 5 (DNS, ingress, app, connections, tunnel)", total)
	}

	for _, mode := range []string{"lost response", "refused before", "crash", "lease loss"} {
		for k := 1; k <= total; k++ {
			t.Run(fmt.Sprintf("%s at mutation %d", mode, k), func(t *testing.T) {
				ts := newRemovableTunnel(t)
				before, base := ts.instanceObjects(), len(ts.cf.Mutations())
				ts.requestRemoval()
				ts.arm(mode, k)

				failures := ts.converge(5)

				if len(failures) == 0 && (mode == "crash" || mode == "lease loss") {
					t.Fatal("the fault changed nothing")
				}
				ts.wantRemovedWithItsTunnel(before)
				ops := ts.committedOps(base)
				dns, ingress, app, tunnel := slices.Index(ops, cffake.OpDNSDelete), slices.Index(ops, cffake.OpTunnelConfigPut),
					slices.Index(ops, cffake.OpAppDelete), slices.Index(ops, cffake.OpTunnelDelete)
				if dns < 0 || ingress < 0 || app < 0 || tunnel < 0 || dns > app || ingress > app || tunnel != len(ops)-1 {
					t.Errorf("committed mutations %v: the route must close before Access goes and the tunnel must go last", ops)
				}
				if mode == "lease loss" && !errors.Is(failures[0], jobs.ErrLeaseLost) {
					t.Errorf("first failure = %v, want the lease loss", failures[0])
				}
			})
		}
	}
}

func TestAFailedTeardownLeavesTheNodeManagedAndANewRemovalResumesIt(t *testing.T) {
	ts := newRemovableTunnel(t)
	before := ts.instanceObjects()
	ts.requestRemoval()
	ts.arm("refused before", 3) // the Access application cannot be deleted
	wantFailure := ts.attempt()
	if wantFailure == nil {
		t.Fatal("the removal should have failed")
	}
	if state := ts.currentNode().ManagementState; state != domain.ManagementManaged {
		t.Fatalf("node is %s after a failed teardown, want it still managed", state)
	}
	mustf(t, ts.store.FailTerminal(context.Background(), ts.lease, wantFailure), "the job gives up")

	ts.requestRemoval()
	mustf(t, ts.attempt(), "second removal")

	ts.wantRemovedWithItsTunnel(before)
	if ops := ts.operations(); len(ops) != 2 {
		t.Errorf("%d tunnel operations, want the enable and one disable that both removals worked on: %+v", len(ops), ops)
	}
}

func TestADisableDoesNotResumeTheTeardownARefusedRemovalLeftBehind(t *testing.T) {
	ts := newRemovableTunnel(t)
	before := ts.instanceObjects()
	ts.requestRemoval()
	ts.arm("refused before", 3)
	failure := ts.attempt()
	if failure == nil {
		t.Fatal("the removal should have failed")
	}
	mustf(t, ts.store.FailTerminal(context.Background(), ts.lease, failure), "the job gives up")
	opsBefore, nodeBefore := ts.operations(), ts.currentNode()

	ts.planDisable()
	err := ts.attempt()
	if smerr.CodeOf(err) != smerr.CodeConflict || !strings.Contains(err.Error(), "sm nodes remove") {
		t.Fatalf("disable err = %v, want a conflict that names `sm nodes remove`", err)
	}
	mustf(t, ts.store.FailTerminal(context.Background(), ts.lease, err), "the refused disable gives up")
	if got := ts.currentNode(); got.Endpoint != nodeBefore.Endpoint || got.ManagementState != nodeBefore.ManagementState {
		t.Errorf("the refused disable changed the node: %+v -> %+v", nodeBefore, got)
	}
	if got := ts.operations(); !reflect.DeepEqual(got, opsBefore) {
		t.Errorf("the refused disable changed the records: %+v -> %+v", opsBefore, got)
	}

	ts.current = nil
	ts.requestRemoval()
	mustf(t, ts.attempt(), "the removal finishes")
	ts.wantRemovedWithItsTunnel(before)
}

func TestRemovingANodeTakesOverAnUnfinishedEnableAndItsUnrecordedObjects(t *testing.T) {
	ts := newTunnelSettingWith(t, destructiveAdmins)
	ts.inject("crash", 2)
	ts.plan()
	if err := ts.attempt(); err == nil {
		t.Fatal("the enable should have crashed")
	}
	ts.chaos.k = 0
	ts.abandonQueuedJob()
	before := ts.instanceObjects()

	ts.requestRemoval()
	mustf(t, ts.attempt(), "removal")

	ts.wantRemovedWithItsTunnel(before)
	ops := ts.operations()
	if len(ops) < 2 || ops[1].Kind != database.TunnelEnable || !ops[1].Phase.Finished() {
		t.Errorf("operations = %+v, want a finished disable above the enable it closed", ops)
	}
	if got := len(ts.events("node.tunnel.enable_abandoned")); got != 1 {
		t.Errorf("%d enable_abandoned events, want 1", got)
	}
}

// A node set up before whose new enable installed cloudflared but failed its verification stays direct with
// the service on it. A removal takes that enable over and fails at the Access delete; the disable that
// follows resumes the record the removal left and must still take the service off the node.
func TestADisableAfterAFailedRemovalOfAnInstalledEnableStillRemovesTheNodeService(t *testing.T) {
	ts := newRemovableTunnel(t)
	ts.planDisable()
	mustf(t, ts.attempt(), "first disable")
	ts.current = nil
	ts.breakTunnelVerification()
	ts.plan()
	if err := ts.attempt(); err == nil {
		t.Fatal("the re-enable should fail at verification")
	}
	ts.abandonQueuedJob()
	ts.repairTunnelVerification()
	if _, installed := ts.files[templates.CloudflaredUnitPath]; !installed {
		t.Fatal("the failed enable should have left the service on the node")
	}

	ts.requestRemoval()
	ts.arm("refused before", 3)
	failure := ts.attempt()
	if failure == nil {
		t.Fatal("the removal should have failed")
	}
	mustf(t, ts.store.FailTerminal(context.Background(), ts.lease, failure), "the removal gives up")

	ts.planDisable()
	mustf(t, ts.attempt(), "the disable")
	if ops := ts.operations(); ops[0].Phase != database.PhaseDone {
		t.Errorf("newest operation is %s, want done", ops[0].Phase)
	}
	if _, left := ts.files[templates.CloudflaredUnitPath]; left {
		t.Error("the disable reported done with the cloudflared unit still on the node")
	}
}

// retireAsStaticNode makes the node what a node dropped from the configuration file is: retired, of a static
// provider.
func (ts *tunnelSetting) retireAsStaticNode() {
	ts.t.Helper()
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		node, err := database.GetNode(ctx, tx, ts.node.ID)
		if err != nil {
			return err
		}
		node.ManagementState = domain.ManagementRetired
		if _, err := database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE providers SET origin = 'static' WHERE id = ?`, node.ProviderID)
		return err
	})
}

func TestARetiredNodeOfTheConfigurationFileCanBeRemovedAgainToTakeItsTunnelDown(t *testing.T) {
	ts := newRemovableTunnel(t)
	before := ts.instanceObjects()
	ts.retireAsStaticNode()

	ts.requestRemoval()
	mustf(t, ts.attempt(), "cleanup of the retired node")

	ts.wantRemovedWithItsTunnel(before)
	if got := len(ts.events("node.remove")); got != 0 {
		t.Errorf("%d node.remove events, want none: the node was retired already", got)
	}
}

func TestANodeOfTheConfigurationFileWithoutATunnelCannotBeRemovedThroughTheAPI(t *testing.T) {
	ts := newTunnelSettingWith(t, destructiveAdmins)
	ts.retireAsStaticNode()

	_, err := ts.inv.RemoveNode(context.Background(), ts.caller(ts.admin), ts.node.ID, ts.currentNode().SpecRevision)

	wantError(t, err, smerr.CodeConflict, "")
	if !strings.Contains(err.Error(), "configuration file") {
		t.Errorf("error %q does not say the node is defined in the file", err)
	}
}

func TestANodeThatLeftTheConfigurationFileWithATunnelIsRetiredWithAWarningThatPointsAtItsRemoval(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	ctx := context.Background()
	providers := []config.Provider{fileNode("edge-1", "10.1.0.1"), fileNode("edge-2", "10.1.0.2")}
	mustf(t, r.Reconcile(ctx, fileEnvs(), providers), "first")
	for _, name := range []string{"edge-1", "edge-2"} {
		node, _ := f.nodeNamed(name)
		f.inTx(func(ctx context.Context, tx *database.Tx) error {
			_, err := database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
				ID: f.ids.NewID(), NodeID: node.ID, AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, InstanceID: "instance",
				Hostname: "ssh-" + name + "." + cffake.DefaultZone, CreatedAt: f.clock.Now(),
				Objects: database.TunnelObjects{TunnelID: "t-" + name, DNSRecordID: "d-" + name, AccessAppID: "a-" + name},
			})
			return err
		})
	}

	mustf(t, r.Reconcile(ctx, fileEnvs(), providers[:1]), "second")

	gone, _ := f.nodeNamed("edge-2")
	warnings := f.events("node.tunnel.left_in_cloudflare")
	if gone.ManagementState != domain.ManagementRetired || len(warnings) != 1 {
		t.Fatalf("node %s with %d warnings, want it retired with one", gone.ManagementState, len(warnings))
	}
	text := string(mustJSON(t, warnings[0].Data))
	if !strings.Contains(text, "sm nodes remove "+gone.ID.String()) || warnings[0].ResourceID != gone.ID {
		t.Errorf("warning %s does not point at `sm nodes remove %s`", text, gone.ID)
	}
}

func TestANodeThatLeftTheConfigurationFileWithoutATunnelIsRetiredWithoutAWarning(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	providers := []config.Provider{fileNode("edge-1", "10.1.0.1")}
	mustf(t, r.Reconcile(context.Background(), fileEnvs(), providers), "first")

	mustf(t, r.Reconcile(context.Background(), fileEnvs(), nil), "second")

	if got := len(f.events("node.tunnel.left_in_cloudflare")); got != 0 {
		t.Errorf("%d warnings for a node with no tunnel, want none", got)
	}
}

func TestOnlyANodeThatRecordsObjectsOrAnUnfinishedOperationHasATunnelToTakeDown(t *testing.T) {
	obj := database.TunnelObjects{TunnelID: "t"}
	tests := []struct {
		name string
		ops  []database.TunnelOperation // newest first
		want bool
	}{
		{"no operation", nil, false},
		{"a committed enable with objects", []database.TunnelOperation{{Kind: database.TunnelEnable, Phase: database.PhaseCommitted, Objects: obj}}, true},
		{"a committed enable that recorded nothing", []database.TunnelOperation{{Kind: database.TunnelEnable, Phase: database.PhaseCommitted}}, false},
		{"an unfinished enable", []database.TunnelOperation{{Kind: database.TunnelEnable, Phase: database.PhaseTokenReady}}, true},
		{"a halted enable", []database.TunnelOperation{{Kind: database.TunnelEnable, Phase: database.PhaseConflict}}, true},
		{"an unfinished disable", []database.TunnelOperation{
			{Kind: database.TunnelDisable, Phase: database.PhaseRouteClosed},
			{Kind: database.TunnelEnable, Phase: database.PhaseCommitted, Objects: obj},
		}, true},
		{"a finished disable took the objects down", []database.TunnelOperation{
			{Kind: database.TunnelDisable, Phase: database.PhaseDone},
			{Kind: database.TunnelEnable, Phase: database.PhaseCommitted, Objects: obj},
		}, false},
		{"an enable after a finished disable", []database.TunnelOperation{
			{Kind: database.TunnelEnable, Phase: database.PhaseCommitted, Objects: obj},
			{Kind: database.TunnelDisable, Phase: database.PhaseDone},
			{Kind: database.TunnelEnable, Phase: database.PhaseCommitted, Objects: obj},
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := recordsTunnel(tc.ops); got != tc.want {
				t.Errorf("recordsTunnel = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTheServiceWiresTheTunnelEngineIntoTheRemovalOfATunnelNode(t *testing.T) {
	ts := newRemovableTunnel(t)
	before := ts.instanceObjects()
	opts := ts.handler.tunnel.opts
	h, err := NewHandlers(ts.fixture.cfg, HandlersOptions{
		Store: ts.store, Connector: ts.conn, Inventory: ts.inv, Prober: ts.handler.prober, Tunnel: &opts,
		Identity: func(context.Context) (secrets.Identity, error) { return secrets.Identity{}, nil },
	})
	mustf(t, err, "NewHandlers")
	ts.requestRemoval()
	ts.current = h.Map()[JobControlPlaneApply]

	mustf(t, ts.attempt(), "removal through the handler table")

	ts.wantRemovedWithItsTunnel(before)
}
