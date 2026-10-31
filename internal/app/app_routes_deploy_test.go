package app

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// routeWorld is a deployment world whose handler can activate routes.
type routeWorld struct {
	*deployWorld
	system domain.ID
}

func newRouteWorld(t *testing.T) *routeWorld {
	t.Helper()
	w := &routeWorld{deployWorld: newDeployWorld(t)}
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		w.system = w.identity(ctx, tx, "system", domain.ActorSystem, "")
		return nil
	})
	w.handler.systemID = w.system
	return w
}

// addRoute inserts a route of the world's target for service web, in phase. The deployment fixture publishes
// web on 127.0.0.1:8080.
func (w *routeWorld) addRoute(hostname string, port int, phase database.AppRoutePhase) database.AppRoute {
	w.t.Helper()
	var route database.AppRoute
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		route, err = database.InsertAppRoute(ctx, tx, database.AppRoute{
			ID: w.ids.NewID(), AppTargetID: w.target.ID, NodeID: w.node.ID, Hostname: hostname, Service: "web", Port: port,
			Access: "public", AccountID: "acct", Zone: "example.test", InstanceID: "inst", TunnelID: "tunnel", TunnelGeneration: 1,
			CreatedBy: w.deployer, CreatedAt: w.clock.Now(),
		})
		if err != nil || phase == database.AppRouteWaiting {
			return err
		}
		route, err = database.AdvanceAppRoutePhase(ctx, tx, route.ID, database.AppRouteWaiting, phase, database.AppRouteObjects{}, w.clock.Now())
		return err
	})
	return route
}

func (w *routeWorld) routeRow(id domain.ID) database.AppRoute {
	w.t.Helper()
	r, err := database.GetAppRoute(context.Background(), w.db.Reader(), id)
	mustf(w.t, err, "GetAppRoute")
	return r
}

// routeJobs lists the plans of app route jobs, by action.
func (w *routeWorld) routeJobs() []string {
	w.t.Helper()
	rows, err := w.db.Reader().QueryContext(context.Background(),
		`SELECT p.action, j.actor_id FROM jobs j JOIN plans p ON p.id = j.plan_id WHERE p.action LIKE 'app_route.%' ORDER BY j.created_at`)
	mustf(w.t, err, "query")
	defer rows.Close()
	var out []string
	for rows.Next() {
		var action, actor string
		mustf(w.t, rows.Scan(&action, &actor), "scan")
		if actor != w.system.String() {
			w.t.Errorf("the %s job was submitted by %s, not the system identity", action, actor)
		}
		out = append(out, action)
	}
	return out
}

func TestASucceededDeploymentActivatesTheWaitingRoutesItPublishes(t *testing.T) {
	w := newRouteWorld(t)
	route := w.addRoute("shop.example.test", 8080, database.AppRouteWaiting)
	dep := w.queued()

	mustf(t, w.run(), "Run")

	w.want(dep.ID, deployments.StateSucceeded)
	if got := w.routeRow(route.ID); got.Phase != database.AppRouteWaiting {
		t.Errorf("phase = %s, want waiting: only the route's own job moves it on", got.Phase)
	}
	if jobs := w.routeJobs(); !slices.Equal(jobs, []string{appRouteExposeAction}) {
		t.Errorf("route jobs = %v, want one expose", jobs)
	}
}

func TestActivationSubmitsNoSecondJobWhenOneIsOpen(t *testing.T) {
	w := newRouteWorld(t)
	route := w.addRoute("shop.example.test", 8080, database.AppRouteWaiting)
	dep := w.queued()
	w.clock.Advance(time.Second)
	w.inTx(func(ctx context.Context, tx *database.Tx) error { return w.handler.submitExpose(ctx, tx, route) }) // the request's own job

	mustf(t, w.run(), "Run") // claims the deployment: the route job waits behind the target's lock

	w.want(dep.ID, deployments.StateSucceeded)
	if got := w.routeRow(route.ID); got.Phase != database.AppRouteWaiting {
		t.Errorf("phase = %s, want waiting for the job that is already open", got.Phase)
	}
	if jobs := w.routeJobs(); len(jobs) != 1 {
		t.Errorf("route jobs = %v, want only the open one", jobs)
	}
}

func TestAFailedDeploymentLeavesTheRouteWaiting(t *testing.T) {
	w := newRouteWorld(t)
	route := w.addRoute("shop.example.test", 8080, database.AppRouteWaiting)
	dep := w.queued()
	w.remote.reply("health.http", "503")

	if err := w.run(); err == nil {
		t.Fatal("an unhealthy deployment succeeded")
	}

	w.want(dep.ID, deployments.StateFailed)
	if got := w.routeRow(route.ID); got.Phase != database.AppRouteWaiting {
		t.Errorf("phase = %s, want waiting", got.Phase)
	}
	if jobs := w.routeJobs(); len(jobs) != 0 {
		t.Errorf("route jobs = %v, want none", jobs)
	}
}

func TestActivationOnlyMovesTheRoutesTheVersionPublishes(t *testing.T) {
	w := newRouteWorld(t)
	served := w.addRoute("shop.example.test", 8080, database.AppRouteWaiting)
	other := w.addRoute("admin.example.test", 9090, database.AppRouteWaiting)
	ports := []compose.HostPort{{Service: "web", Addr: netip.MustParseAddr("127.0.0.1"), Port: 8080, Proto: "tcp"}}

	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		return w.handler.activateRoutes(ctx, tx, w.target.ID, ports)
	})

	if jobs := w.routeJobs(); len(jobs) != 1 {
		t.Errorf("route jobs = %v, want one, for the published route", jobs)
	}
	for name, route := range map[string]database.AppRoute{"published": served, "unpublished": other} {
		if got := w.routeRow(route.ID); got.Phase != database.AppRouteWaiting {
			t.Errorf("%s route: phase = %s, want waiting", name, got.Phase)
		}
	}
}

// ---- the port guard ------------------------------------------------------------------------------

func TestADeploymentFinalizedBeforeTheRouteIsRefusedWhenItRuns(t *testing.T) {
	w := newRouteWorld(t)
	dep := w.queued() // publishes web on 8080 only
	w.addRoute("admin.example.test", 9090, database.AppRouteActive)

	err := w.run()

	if err == nil || !strings.Contains(err.Error(), "admin.example.test") || !strings.Contains(err.Error(), "sm apps unexpose") {
		t.Fatalf("Run = %v, want a refusal naming the route and sm apps unexpose", err)
	}
	w.want(dep.ID, deployments.StateFailed)
	if calls := w.calls(); len(calls) != 0 {
		t.Errorf("the node was touched: %v", w.templatesRun())
	}
}

func TestADeploymentFinalizedAfterTheRouteIsRefusedAtFinalization(t *testing.T) {
	w := newRouteWorld(t)
	w.addRoute("admin.example.test", 9090, database.AppRouteActive)
	created := w.create()

	mustf(t, w.finalize(created.ID), "Finalize")

	row := w.row(created.ID)
	if row.State != deployments.StateFailed || row.PlanID != nil || row.Failure.Code != string(smerr.CodeInvalidArgument) {
		t.Errorf("deployment = %s %+v, want failed at finalization with INVALID_ARGUMENT", row.State, row.Failure)
	}
}

func TestARemovedRouteDoesNotGuardDeployments(t *testing.T) {
	w := newRouteWorld(t)
	route := w.addRoute("admin.example.test", 9090, database.AppRouteActive)
	w.exec(`UPDATE app_routes SET phase = 'removed' WHERE id = ?`, route.ID)
	dep := w.queued()

	mustf(t, w.run(), "Run")

	w.want(dep.ID, deployments.StateSucceeded)
}

func TestARollbackThatDropsARoutesPortIsRefusedAtRequest(t *testing.T) {
	w := newRouteWorld(t)
	next, _ := w.afterKnownGood()
	by := w.caller(w.deployer)
	before := w.count()
	w.addRoute("admin.example.test", 9090, database.AppRouteActive)

	_, err := w.final.Rollback(context.Background(), by, next.ID, wire.RollbackRequest{})

	if err == nil || !strings.Contains(err.Error(), "admin.example.test") {
		t.Fatalf("Rollback = %v, want a refusal naming the route", err)
	}
	if w.count() != before {
		t.Error("a refused rollback wrote a deployment")
	}
}

func TestARollbackThatKeepsTheRoutesPortIsAccepted(t *testing.T) {
	w := newRouteWorld(t)
	next, _ := w.afterKnownGood()
	w.addRoute("shop.example.test", 8080, database.AppRouteActive)

	_, err := w.final.Rollback(context.Background(), w.caller(w.deployer), next.ID, wire.RollbackRequest{})

	mustf(t, err, "Rollback")
}

func TestTheAutomaticRollbackModelIsHeldToTheRoutesToo(t *testing.T) {
	w := newRouteWorld(t)
	next, good := w.afterKnownGood()
	target := w.planOf(next.ID).Content.RollbackTarget
	if target == nil || target.DeploymentID != good.ID.String() {
		t.Fatalf("rollback target = %+v, want %s", target, good.ID)
	}
	route := w.addRoute("admin.example.test", 9090, database.AppRouteActive)
	q := w.db.Reader()

	err := requireRollbackTargetServes(context.Background(), q, w.target.ID, target)

	if err == nil || !strings.Contains(err.Error(), route.Hostname) || !strings.Contains(err.Error(), "automatic rollback") {
		t.Errorf("requireRollbackTargetServes = %v, want a refusal naming the route and the rollback", err)
	}
	if err := requireRollbackTargetServes(context.Background(), q, w.target.ID, (*plan.RollbackTarget)(nil)); err != nil {
		t.Errorf("no rollback target: %v", err)
	}
}
