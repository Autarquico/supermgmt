package app

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// ---- the read surface -------------------------------------------------------------------------------------------

func TestList_ShowsEachRouteOfARoutedMoveWithItsHostnameAccessAndState(t *testing.T) {
	rw := newRoutedWorld(t)
	active := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	waiting := rw.route(rw.main(), "later.example.com", "public", database.AppRouteWaiting)
	res := rw.mustRoutedMove()

	views, err := rw.svc.List(context.Background(), rw.caller(rw.admin), rw.target.ID)

	mustf(t, err, "List")
	if len(views) != 1 || views[0].Move.ID != res.Move.ID || len(views[0].Routes) != 2 {
		t.Fatalf("views = %+v, want the one move with its two routes", views)
	}
	want := map[domain.ID]struct{ hostname, access string }{
		active.ID: {"shop.example.com", "public"}, waiting.ID: {"later.example.com", "public"},
	}
	for _, r := range views[0].Routes {
		w, ok := want[r.RouteID]
		if !ok || r.Hostname != w.hostname || r.Access != w.access || r.State != database.AppMoveRoutePending {
			t.Errorf("route view = %+v, want %+v pending", r, w)
		}
		delete(want, r.RouteID)
	}
	if len(want) != 0 {
		t.Errorf("routes missing from the view: %v", want)
	}

	rw.exec(`UPDATE app_moves SET phase = 'failed', halted_phase = 'routes_switched' WHERE id = ?`, res.Move.ID)
	rw.exec(`UPDATE app_move_routes SET state = 'dns_switched' WHERE route_id = ?`, active.ID)
	views, err = rw.svc.List(context.Background(), rw.caller(rw.admin), rw.target.ID)
	mustf(t, err, "List after the state moved")
	for _, r := range views[0].Routes {
		if r.RouteID == active.ID && r.State != database.AppMoveRouteDNSSwitched {
			t.Errorf("state = %s, want dns_switched as the row has it", r.State)
		}
	}
}

func TestList_ShowsNoRoutesForAnUnroutedMove(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.mustRoutedMove()

	views, err := rw.svc.List(context.Background(), rw.caller(rw.admin), rw.target.ID)

	mustf(t, err, "List")
	if len(views) != 1 || len(views[0].Routes) != 0 {
		t.Errorf("views = %+v, want one move without routes", views)
	}
}

// ---- a halted routed move keeps waiting ---------------------------------------------------------------------------

// haltedRoutedMove is a routed move that stopped in a phase that is still open, with the rows as that phase leaves them.
func (rw *routedWorld) haltedRoutedMove() database.AppMove {
	rw.t.Helper()
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove()
	rw.exec(`UPDATE app_moves SET phase = 'failed', halted_phase = 'routes_switched' WHERE id = ?`, res.Move.ID)
	rw.exec(`UPDATE app_move_routes SET state = 'dns_switched' WHERE move_id = ?`, res.Move.ID)
	return res.Move
}

func TestHaltedRoutedMove_RefusesExposeUnexposeAndTunnelOperationsAtRequestTime(t *testing.T) {
	rw := newRoutedWorld(t)
	m := rw.haltedRoutedMove()
	ctx := context.Background()
	jobsBefore := rw.rowCount("jobs")

	_, err := rw.routes.Expose(ctx, rw.caller(rw.admin), rw.target.ID, ExposeRouteRequest{Hostname: "new.example.com", Service: "web", Port: 8080})
	wantRefusal(t, err, smerr.CodeConflict, m.ID.String())

	_, err = rw.routes.Unexpose(ctx, rw.caller(rw.admin), rw.target.ID, "shop.example.com")
	wantRefusal(t, err, smerr.CodeConflict, m.ID.String())

	for name, req := range map[string]PlanRequest{
		"disable of A": {Action: policy.ActionNodeTunnelDisable, Target: nodeRef(rw.node.ID)},
		"disable of B": {Action: policy.ActionNodeTunnelDisable, Target: nodeRef(rw.dest.ID)},
		"setup of A":   {Action: policy.ActionNodeSetup, Target: nodeRef(rw.node.ID), Parameters: map[string]any{policy.ParamTunnel: "true"}},
		"setup of B":   {Action: policy.ActionNodeSetup, Target: nodeRef(rw.dest.ID), Parameters: map[string]any{policy.ParamTunnel: "true"}},
		"rotation":     {Action: policy.ActionCloudflareRotate, Target: domain.ResourceRef{Type: domain.ResourceInstance, ID: "instance"}},
	} {
		err := rw.plans.requireTunnelAvailable(ctx, rw.db.Reader(), req)
		if smerr.CodeOf(err) != smerr.CodeConflict || !strings.Contains(err.Error(), m.ID.String()) {
			t.Errorf("%s: %v, want a refusal naming the move %s", name, err, m.ID)
		}
	}
	if rw.rowCount("jobs") != jobsBefore {
		t.Error("a refused request queued a job")
	}
}

func TestHaltedRoutedMove_RefusesJobsQueuedBeforeItAtClaim(t *testing.T) {
	rw := newRoutedWorld(t)
	ctx := context.Background()
	queued, err := rw.routes.Expose(ctx, rw.caller(rw.admin), rw.target.ID, ExposeRouteRequest{Hostname: "queued.example.com", Service: "web", Port: 8080})
	mustf(t, err, "Expose")
	m := rw.haltedRoutedMove()
	planner := LockPlanner{}

	_, err = planner.PlanLocks(ctx, rw.db.Reader(), queued.Submission.Job)
	wantRefusal(t, err, smerr.CodeConflict, m.ID.String())

	unexpose := rw.lockPlanFor(JobControlPlaneApply, appRouteUnexposeAction, appTargetRef(rw.target.ID), map[string]any{"hostname": "shop.example.com", "route_id": "r"})
	_, err = planner.PlanLocks(ctx, rw.db.Reader(), unexpose)
	wantRefusal(t, err, smerr.CodeConflict, m.ID.String())

	for name, job := range map[string]jobs.Job{
		"setup of A": rw.lockPlanFor(policy.ActionNodeSetup, policy.ActionNodeSetup, nodeRef(rw.node.ID), map[string]any{policy.ParamTunnel: "true"}),
		"setup of B": rw.lockPlanFor(policy.ActionNodeSetup, policy.ActionNodeSetup, nodeRef(rw.dest.ID), map[string]any{policy.ParamTunnel: "true"}),
		"disable":    rw.lockPlanFor(policy.ActionNodeTunnelDisable, policy.ActionNodeTunnelDisable, nodeRef(rw.dest.ID), map[string]any{}),
		"rotation":   rw.lockPlanFor(policy.ActionCloudflareRotate, policy.ActionCloudflareRotate, domain.ResourceRef{Type: domain.ResourceInstance, ID: "instance"}, map[string]any{}),
	} {
		_, err := planner.PlanLocks(ctx, rw.db.Reader(), job)
		if smerr.CodeOf(err) != smerr.CodeConflict || !strings.Contains(err.Error(), m.ID.String()) {
			t.Errorf("%s: PlanLocks = %v, want a refusal naming the move %s", name, err, m.ID)
		}
	}
}

// ---- stateful rollback report ---------------------------------------------------------------------------------------

func TestMoveRoutesRun_AStatefulRollbackReportsTheVolumesItKeepsOnB(t *testing.T) {
	rr := newRoutedRun(t, runOptions{stateful: true, compose: moveStatefulCompose})
	rr.expose(rr.main(), "admin.example.test", "public")
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(2, cffake.Forbidden)

	if err := rr.run(); err == nil {
		t.Fatal("Run succeeded although the second repoint was refused")
	}

	events := rr.events(eventAppMoveRolledBack)
	if len(events) != 1 {
		t.Fatalf("%d rolled_back events, want 1", len(events))
	}
	if kept := rr.keptVolumes(events[0]); len(kept) == 0 {
		t.Errorf("event data = %v, want the volumes kept on B listed", events[0].Data)
	}
	if rr.a.state != "running" {
		t.Errorf("A is %s, want it serving after its health check", rr.a.state)
	}
}
