package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// refusedByHold plans an action; the refusal may come from Create or Submit.
func (ts *tunnelSetting) refusedByHold(action string, target domain.ResourceRef, params map[string]any) error {
	ts.t.Helper()
	ctx, by := context.Background(), ts.caller(ts.admin)
	created, err := ts.plans.Create(ctx, by, PlanRequest{Action: action, Target: target, Parameters: params})
	if err != nil {
		return err
	}
	_, err = ts.plans.Submit(ctx, by, created.Record.ID, created.Record.PlanHash)
	return err
}

// holdRefusal sees through the step names the jobs add to an error.
func holdRefusal(err error) bool {
	return errors.Is(err, smerr.FromReason(smerr.ReasonRestoreHold, ""))
}

func (ts *tunnelSetting) reconciler() *TunnelReconciler {
	return &TunnelReconciler{engine: ts.handler.tunnel}
}

func (ts *tunnelSetting) reconcile() TunnelReconcileReport {
	ts.t.Helper()
	report, err := ts.reconciler().Run(context.Background())
	mustf(ts.t, err, "reconcile")
	return report
}

// api is a client for the test to change Cloudflare behind the instance's back.
func (ts *tunnelSetting) api() CloudflareAPI {
	ts.t.Helper()
	r, err := ts.handler.tunnel.newInstanceRun(context.Background(), ts.lease, ts.queued)
	mustf(ts.t, err, "newInstanceRun")
	return r.api
}

func TestTunnelActionsAreRefusedAtSubmissionDuringTheRestoreHold(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.setHold(true)

	params := defaultSetup()
	params["tunnel"] = "true"
	for name, refused := range map[string]error{
		"node.setup tunnel=true":         ts.refusedByHold("node.setup", ts.nodeRef(), params),
		"node.tunnel.disable":            ts.refusedByHold("node.tunnel.disable", ts.nodeRef(), nil),
		"cloudflare.access_token.rotate": ts.refusedByHold("cloudflare.access_token.rotate", ts.instanceRef(), nil),
	} {
		if !isRestoreHold(refused) {
			t.Errorf("%s during the hold = %v; want CONFLICT/RESTORE_HOLD", name, refused)
		}
	}
}

func TestQueuedTunnelJobsAreNotClaimedDuringTheRestoreHold(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.plan()
	ts.store.SetRestoreHold(true)

	if _, ok := ts.claim(); ok {
		t.Fatal("a tunnel job was claimed during the restore hold")
	}
	ts.store.SetRestoreHold(false)
	if _, ok := ts.claim(); !ok {
		t.Fatal("the job is not claimable after the hold ended")
	}
}

func TestTunnelJobsThatRunDuringTheHoldMutateNothingInCloudflare(t *testing.T) {
	setups := func() *tunnelSetting {
		ts := newTunnelSetting(t)
		ts.plan()
		return ts
	}
	disables := func() *tunnelSetting {
		ts := newEnabledTunnel(t)
		ts.planDisable()
		return ts
	}
	rotations := func() *tunnelSetting {
		ts := newEnabledTunnel(t)
		ts.planRotation()
		return ts
	}
	for name, build := range map[string]func() *tunnelSetting{"setup": setups, "disable": disables, "rotate": rotations} {
		t.Run(name, func(t *testing.T) {
			ts := build()
			before := len(ts.cf.Mutations())
			ts.setHold(true) // the persisted value is what the gate reads, not the claim flag

			err := ts.attempt()

			if !holdRefusal(err) {
				t.Errorf("job under the hold = %v; want RESTORE_HOLD", err)
			}
			if after := len(ts.cf.Mutations()); after != before {
				t.Errorf("%d Cloudflare mutations during the hold", after-before)
			}
		})
	}
}

// Every mutating method of the Cloudflare client the jobs use is gated; a
// method added later with a mutating name is covered without editing this test.
func TestEveryMutatingCloudflareCallIsGatedByTheHold(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.setHold(true)
	gated := gateOnRestoreHold(nil, ts.db.Reader())
	methods := reflect.TypeOf((*CloudflareAPI)(nil)).Elem()
	checked := 0
	for i := range methods.NumMethod() {
		m := methods.Method(i)
		if !strings.HasPrefix(m.Name, "Create") && !strings.HasPrefix(m.Name, "Put") && !strings.HasPrefix(m.Name, "Update") &&
			!strings.HasPrefix(m.Name, "Delete") && !strings.HasPrefix(m.Name, "Cleanup") && m.Name != "TunnelToken" {
			continue
		}
		checked++
		args := []reflect.Value{reflect.ValueOf(context.Background())}
		for j := 1; j < m.Type.NumIn(); j++ {
			args = append(args, reflect.Zero(m.Type.In(j)))
		}
		func() {
			defer func() {
				if recover() != nil {
					t.Errorf("%s reached the Cloudflare client during the hold", m.Name)
				}
			}()
			out := reflect.ValueOf(gated).MethodByName(m.Name).Call(args)
			err, _ := out[len(out)-1].Interface().(error)
			if !isRestoreHold(err) {
				t.Errorf("%s during the hold = %v; want RESTORE_HOLD", m.Name, err)
			}
		}()
	}
	if checked < 10 {
		t.Fatalf("only %d mutating methods found; the name filter is stale", checked)
	}
}

func TestReconciliationRefusesToRunDuringTheHold(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.setHold(true)

	_, err := ts.reconciler().Run(context.Background())

	if !isRestoreHold(err) {
		t.Errorf("reconcile during the hold = %v; want RESTORE_HOLD", err)
	}
}

func TestReconciliationOfAnUnchangedAccountFindsNothingAndChangesNothing(t *testing.T) {
	ts := newEnabledTunnel(t)
	before, snap := len(ts.cf.Mutations()), ts.cf.Snapshot()

	report := ts.reconcile()

	if len(report.Findings) != 0 || report.Checked != 6 { // tunnel, app, dns, two policies, service token
		t.Errorf("report = %+v; want 6 objects checked and no findings", report)
	}
	if len(ts.cf.Mutations()) != before || !reflect.DeepEqual(ts.cf.Snapshot(), snap) {
		t.Error("the reconciliation changed Cloudflare")
	}
}

func TestReconciliationSeparatesVanishedFromRecreatedObjects(t *testing.T) {
	ts := newEnabledTunnel(t)
	ctx, api := context.Background(), ts.api()
	snap := ts.cf.Snapshot()
	_, zoneID := ts.cf.Zone()
	tunnel, app, dns := snap.Tunnels[0], snap.Apps[0], snap.DNSRecords[0]

	// The Access application vanished; the tunnel and the DNS record were
	// deleted and recreated by someone else; the service token is untouched.
	mustf(t, api.DeleteAccessApp(ctx, app.ID), "delete app")
	mustf(t, api.CleanupTunnelConnections(ctx, tunnel.ID), "cleanup tunnel")
	mustf(t, api.DeleteTunnel(ctx, tunnel.ID), "delete tunnel")
	mustf(t, api.DeleteDNSRecord(ctx, zoneID, dns.ID), "delete dns")
	newTunnel := ts.cf.SeedTunnel(tunnel.Name)
	newDNS := ts.cf.SeedDNSRecord(dns.Name, dns.Content, "someone else")
	mutations, records := len(ts.cf.Mutations()), ts.operations()

	report := ts.reconcile()

	want := map[string]TunnelFinding{
		"tunnel":             {Kind: "tunnel", RecordedID: tunnel.ID, FoundID: newTunnel.ID, State: ObjectRecreated},
		"DNS record":         {Kind: "DNS record", RecordedID: dns.ID, FoundID: newDNS.ID, State: ObjectRecreated},
		"Access application": {Kind: "Access application", RecordedID: app.ID, State: ObjectMissing},
	}
	if len(report.Findings) != len(want) || report.Checked != 6 {
		t.Fatalf("report = %+v; want 3 findings among 6 objects", report)
	}
	for _, got := range report.Findings {
		w, ok := want[got.Kind]
		if !ok || got.NodeID != ts.node.ID || got.RecordedID != w.RecordedID || got.FoundID != w.FoundID || got.State != w.State {
			t.Errorf("finding %+v; want %+v for node %s", got, w, ts.node.ID)
		}
	}
	// It reads and audits: nothing deleted, adopted, created or rewritten.
	if len(ts.cf.Mutations()) != mutations {
		t.Error("the reconciliation mutated Cloudflare")
	}
	if !reflect.DeepEqual(ts.operations(), records) {
		t.Error("the reconciliation rewrote the operation records")
	}
	if got := ts.cf.Snapshot(); len(got.Tunnels) != 1 || got.Tunnels[0].ID != newTunnel.ID {
		t.Errorf("tunnels after the pass = %+v; the foreign tunnel must be left alone", got.Tunnels)
	}
	ts.wantEvents(eventReconcileMissing, 1)
	ts.wantEvents(eventReconcileRecreated, 2)
	ts.wantEvents(eventReconcileDone, 1)
}

func TestReconciledMissingObjectIsRepairedByTheNextEnableRun(t *testing.T) {
	ts := newEnabledTunnel(t)
	ctx, api := context.Background(), ts.api()
	app := ts.cf.Snapshot().Apps[0]
	mustf(t, api.DeleteAccessApp(ctx, app.ID), "delete app")
	if report := ts.reconcile(); len(report.Findings) != 1 || report.Findings[0].State != ObjectMissing {
		t.Fatalf("report = %+v", report)
	}

	ts.current = nil
	ts.plan()
	mustf(t, ts.attempt(), "setup after the reconciliation")

	if apps := ts.cf.Snapshot().Apps; len(apps) != 1 || apps[0].ID == app.ID {
		t.Errorf("apps = %+v; want the vanished one created again", apps)
	}
	if report := ts.reconcile(); len(report.Findings) != 0 {
		t.Errorf("findings after the repair = %+v", report.Findings)
	}
}

func TestReconciledRecreatedObjectIsNotAdoptedByTheNextEnableRun(t *testing.T) {
	ts := newEnabledTunnel(t)
	ctx, api := context.Background(), ts.api()
	tunnel := ts.cf.Snapshot().Tunnels[0]
	mustf(t, api.CleanupTunnelConnections(ctx, tunnel.ID), "cleanup tunnel")
	mustf(t, api.DeleteTunnel(ctx, tunnel.ID), "delete tunnel")
	foreign := ts.cf.SeedTunnel(tunnel.Name)
	ts.clock.Advance(10 * time.Minute) // the foreign object predates the next run's phase start
	if report := ts.reconcile(); len(report.Findings) != 1 || report.Findings[0].State != ObjectRecreated {
		t.Fatalf("report = %+v", report)
	}

	ts.current = nil
	ts.plan()
	err := ts.attempt()

	if err == nil {
		t.Fatal("setup adopted a tunnel it did not create")
	}
	if got := ts.cf.Snapshot().Tunnels; len(got) != 1 || got[0].ID != foreign.ID {
		t.Errorf("tunnels = %+v; the foreign tunnel must be left in place", got)
	}
}

func TestReconciliationOfInstanceObjects(t *testing.T) {
	ts := newEnabledTunnel(t)
	ctx, api := context.Background(), ts.api()
	token := ts.cf.Snapshot().ServiceTokens[0]
	mustf(t, api.DeleteServiceToken(ctx, token.ID), "delete token")

	report := ts.reconcile()

	if len(report.Findings) != 1 || report.Findings[0].Kind != "service token" || report.Findings[0].NodeID != "" ||
		report.Findings[0].State != ObjectMissing || report.Findings[0].RecordedID != token.ID {
		t.Errorf("report = %+v; want the service token missing", report)
	}
	seeded := ts.cf.SeedServiceToken(token.Name)
	if report := ts.reconcile(); len(report.Findings) != 1 || report.Findings[0].State != ObjectRecreated || report.Findings[0].FoundID != seeded.ID {
		t.Errorf("report = %+v; want the service token recreated", report)
	}
}

func (ts *tunnelSetting) wantEvents(action string, n int) {
	ts.t.Helper()
	var got int
	err := ts.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM events WHERE action = ?`, action).Scan(&got)
	mustf(ts.t, err, "count events")
	if got != n {
		ts.t.Errorf("%d %s events; want %d", got, action, n)
	}
}
