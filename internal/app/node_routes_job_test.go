package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// Run lets a test register the route handler on its own, without the apply step before it.
func (h nodeRouteHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	action, err := jobAction(ctx, h.cfg.DB.Reader(), job)
	if err != nil {
		return err
	}
	return h.run(ctx, lease, job, action)
}

// routeSetting is a node with an enabled tunnel.
type routeSetting struct {
	*tunnelSetting
	routes nodeRouteHandler
}

func newRouteSetting(t *testing.T) *routeSetting {
	t.Helper()
	return newRouteSettingOn(newEnabledTunnel(t))
}

// newRouteSettingOn wraps the node of ts, with or without a tunnel.
func newRouteSettingOn(ts *tunnelSetting) *routeSetting {
	rs := &routeSetting{tunnelSetting: ts}
	rs.routes = nodeRouteHandler{core: ts.handler.core, store: ts.store, tunnel: ts.handler.tunnel}
	rs.current = rs.routes
	return rs
}

// addRoute admits a route the way the service does: frozen identity from the node's tunnel, in admitted,
// then moved on to phase.
func (rs *routeSetting) addRoute(hostname string, port int, access string, phase database.NodeRoutePhase) database.NodeRoute {
	rs.t.Helper()
	var route database.NodeRoute
	rs.inTx(func(ctx context.Context, tx *database.Tx) error {
		tunnelID, generation, err := nodeTunnelIdentity(ctx, tx, rs.node)
		if err != nil {
			return err
		}
		instance, err := database.GetInstance(ctx, tx)
		if err != nil {
			return err
		}
		route, err = database.InsertNodeRoute(ctx, tx, database.NodeRoute{
			ID: rs.ids.NewID(), NodeID: rs.node.ID, Hostname: hostname, Port: port,
			Access: access, AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, InstanceID: instance.ID.String(),
			TunnelID: tunnelID, TunnelGeneration: generation, CreatedBy: rs.admin, CreatedAt: rs.clock.Now(),
		})
		for _, next := range []database.NodeRoutePhase{database.NodeRouteProvisioning, phase} {
			if err != nil || route.Phase == phase {
				break
			}
			rs.clock.Advance(1)
			route, err = database.AdvanceNodeRoutePhase(ctx, tx, route.ID, route.Phase, next, database.NodeRouteObjects{}, rs.clock.Now())
		}
		return err
	})
	return route
}

func (rs *routeSetting) route(id domain.ID) database.NodeRoute {
	rs.t.Helper()
	r, err := database.GetNodeRoute(context.Background(), rs.db.Reader(), id)
	mustf(rs.t, err, "GetNodeRoute")
	return r
}

// enqueue plans, submits and approves the action for route as the admin, the way the request path does, and
// makes attempt run its job. The plan is what the claim revalidates.
func (rs *routeSetting) enqueue(action string, route database.NodeRoute) jobs.Job {
	rs.t.Helper()
	params := nodeRouteParams{Hostname: route.Hostname, RouteID: route.ID.String()}
	if action == nodeRouteExposeAction {
		params = nodeRouteParams{Hostname: route.Hostname, Port: fmt.Sprint(route.Port), Access: route.Access}
	}
	raw, err := toParams(params)
	mustf(rs.t, err, "toParams")
	by := rs.caller(rs.admin)
	var sub Submission
	rs.inTx(func(ctx context.Context, tx *database.Tx) error {
		actor, err := loadCaller(ctx, tx, by)
		if err != nil {
			return err
		}
		b, err := build(ctx, tx, action, rs.admin, nodeRef(rs.node.ID), raw)
		if err != nil {
			return err
		}
		res, err := rs.plans.evaluate(ctx, tx, actor, b)
		if err != nil {
			return err
		}
		sub, err = rs.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		if err != nil || action != nodeRouteExposeAction {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE node_routes SET plan_id = ? WHERE id = ?`, sub.Job.PlanID, route.ID) // as admission does
		return err
	})
	job := sub.Job
	for _, approver := range []domain.ID{rs.bob, rs.carol} { // as many as the policy asks for
		if job.State != domain.JobAwaitingApproval {
			break
		}
		job, err = rs.approve(approver, job)
		mustf(rs.t, err, "approve")
	}
	rs.queued, rs.current = job, rs.routes
	return job
}

// dropQueued cancels the requeued job of a worker that died, so the next job is the one the test enqueues.
func (rs *routeSetting) dropQueued(job jobs.Job) {
	rs.t.Helper()
	interruptAndRequeue(rs.t, rs.fixture, job.ID)
	rs.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := rs.store.Cancel(ctx, tx, job.ID, domain.Actor{ID: rs.admin, Type: domain.ActorHuman})
		return err
	})
}

func (rs *routeSetting) ingress() []cffake.Ingress {
	tunnels := rs.cf.Tunnels()
	if len(tunnels) != 1 {
		rs.t.Fatalf("%d tunnels, want 1", len(tunnels))
	}
	return tunnels[0].Ingress
}

func (rs *routeSetting) wantIngress(hostnames ...string) {
	rs.t.Helper()
	want := []cffake.Ingress{{Hostname: rs.hostname(), Service: cloudflare.ServiceSSH}}
	for _, h := range hostnames {
		port := 8080
		if route, err := rs.liveRoute(h); err == nil {
			port = route.Port
		}
		want = append(want, cffake.Ingress{Hostname: h, Service: fmt.Sprintf("http://127.0.0.1:%d", port)})
	}
	want = append(want, cffake.Ingress{Service: cloudflare.ServiceNotFound})
	if got := rs.ingress(); !slices.Equal(got, want) {
		rs.t.Errorf("ingress = %+v, want %+v", got, want)
	}
}

// routeObjects counts what Cloudflare holds for the route beyond the node's own objects.
func (rs *routeSetting) routeObjects(hostname string) (rules, apps, records int) {
	for _, r := range rs.ingress() {
		if r.Hostname == hostname {
			rules++
		}
	}
	for _, a := range rs.cf.Apps() {
		if a.Domain == hostname {
			apps++
		}
	}
	for _, d := range rs.cf.DNSRecords() {
		if d.Name == hostname {
			records++
		}
	}
	return rules, apps, records
}

const shop = "shop.example.test"

func TestExposeAPublicRouteWritesTheRuleAndTheMarkedCNAME(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)

	mustf(t, rs.attempt(), "expose")

	rs.wantIngress(shop)
	if rules, apps, records := rs.routeObjects(shop); rules != 1 || apps != 0 || records != 1 {
		t.Errorf("rules, apps, records = %d, %d, %d; want 1, 0, 1", rules, apps, records)
	}
	record := rs.cf.DNSRecords()[len(rs.cf.DNSRecords())-1]
	instance, _ := database.GetInstance(context.Background(), rs.db.Reader())
	if !record.Proxied || record.Comment != cloudflare.RouteDNSComment(instance.ID.String(), route.ID.String()) ||
		record.Content != cloudflare.TunnelTarget(route.TunnelID) {
		t.Errorf("record = %+v", record)
	}
	got := rs.route(route.ID)
	if got.Phase != database.NodeRouteActive || got.Objects.DNSRecordID != record.ID || got.Objects.AccessAppID != "" {
		t.Errorf("route = %+v", got)
	}
	if events := rs.events("node_route.exposed"); len(events) != 1 || events[0].Data["hostname"] != shop || events[0].Data["access"] != "public" {
		t.Errorf("node_route.exposed events = %+v", events)
	}
}

func TestExposeAnOwnersRouteGuardsItBeforeItHasDNS(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)

	mustf(t, rs.attempt(), "expose")

	state, err := database.GetCloudflareState(context.Background(), rs.db.Reader())
	mustf(t, err, "GetCloudflareState")
	var app *cffake.App
	for _, a := range rs.cf.Apps() {
		if a.Domain == shop {
			app = &a
		}
	}
	if app == nil || !slices.Equal(app.PolicyIDs, []string{state.OwnersPolicyID}) {
		t.Fatalf("Access application = %+v, want only the owners policy %s", app, state.OwnersPolicyID)
	}
	instance, _ := database.GetInstance(context.Background(), rs.db.Reader())
	if app.Name != cloudflare.RouteAccessAppName(instance.ID.String(), route.ID.String()) {
		t.Errorf("name = %q", app.Name)
	}
	if routable := rs.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		t.Errorf("routable without Access: %v", routable)
	}
	if got := rs.route(route.ID); got.Phase != database.NodeRouteActive || got.Objects.AccessAppID != app.ID {
		t.Errorf("route = %+v", got)
	}
}

func TestExposeLeavesNoDNSRecordWhenItDiesAfterTheIngressStep(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	rs.arm("crash", 1) // the ingress write

	if err := rs.attempt(); err == nil {
		t.Fatal("the crash changed nothing")
	}

	if rules, apps, records := rs.routeObjects(shop); rules != 1 || apps != 0 || records != 0 {
		t.Errorf("rules, apps, records = %d, %d, %d; want 1, 0, 0", rules, apps, records)
	}
	if got := rs.route(route.ID).Phase; got != database.NodeRouteProvisioning {
		t.Errorf("phase = %s: the write was not recorded", got)
	}
}

func TestExposeResumesAfterEveryFaultAfterEveryMutationWithEachObjectOnce(t *testing.T) {
	for _, access := range []string{"public", "owners"} {
		mutations := 3 // ingress, Access application, DNS record
		if access == "public" {
			mutations = 2
		}
		for _, mode := range []string{"lost response", "refused before", "crash", "lease loss"} {
			for k := 1; k <= mutations; k++ {
				t.Run(fmt.Sprintf("%s %s at mutation %d", access, mode, k), func(t *testing.T) {
					rs := newRouteSetting(t)
					route := rs.addRoute(shop, 8080, access, database.NodeRouteProvisioning)
					rs.enqueue(nodeRouteExposeAction, route)
					rs.arm(mode, k)

					rs.converge(4)

					rs.wantIngress(shop)
					wantApps := 0
					if access == "owners" {
						wantApps = 1
					}
					if rules, apps, records := rs.routeObjects(shop); rules != 1 || apps != wantApps || records != 1 {
						t.Errorf("rules, apps, records = %d, %d, %d; want 1, %d, 1", rules, apps, records, wantApps)
					}
					if got := rs.route(route.ID).Phase; got != database.NodeRouteActive {
						t.Errorf("phase = %s", got)
					}
					if routable := rs.cf.EverRoutableWithoutAccess(); access == "owners" && len(routable) != 0 {
						t.Errorf("routable without Access: %v", routable)
					}
				})
			}
		}
	}
}

func TestAForeignDNSRecordHaltsTheRouteBeforeAnyMutationAndIsLeftAlone(t *testing.T) {
	rs := newRouteSetting(t)
	foreign := rs.cf.SeedDNSRecord(shop, "elsewhere.example.net", "")
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteAdmitted)
	rs.enqueue(nodeRouteExposeAction, route)
	before := len(rs.cf.Mutations())

	err := rs.attempt()

	if err == nil || !strings.Contains(err.Error(), foreign.ID) {
		t.Fatalf("error = %v, want it to name the record %s", err, foreign.ID)
	}
	if got := len(rs.cf.Mutations()); got != before {
		t.Errorf("%d Cloudflare mutations after the preflight", got-before)
	}
	rs.wantIngress()
	halted := rs.route(route.ID)
	if halted.Phase != database.NodeRouteConflict || halted.HaltedPhase != database.NodeRouteAdmitted {
		t.Errorf("route = %s (halted in %s)", halted.Phase, halted.HaltedPhase)
	}
	if kept := rs.cf.DNSRecords(); !slices.ContainsFunc(kept, func(d cffake.DNSRecord) bool { return d.ID == foreign.ID && d.Content == foreign.Content }) {
		t.Error("the foreign record was changed or deleted")
	}
	if len(rs.events("node_route.halted")) != 1 {
		t.Error("no app_route.halted event")
	}
}

func TestASiblingRecordThatAppearsBeforeTheCreateHaltsTheRouteAndWithdrawsTheRule(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	seeded := false
	rs.chaos.afterMutation = func() {
		if !seeded && len(rs.cf.Apps()) > 1 { // after the route's Access application
			seeded = true
			rs.cf.SeedDNSRecord(shop, cloudflare.TunnelTarget(route.TunnelID), "someone else")
		}
	}

	err := rs.attempt()

	var halt *routeHalt
	if !errors.As(err, &halt) || halt.halt != database.NodeRouteConflict {
		t.Fatalf("error = %v, want a conflict halt", err)
	}
	rs.wantIngress()
	if _, _, records := rs.routeObjects(shop); records != 1 {
		t.Errorf("%d records, want only the foreign one", records)
	}
}

func TestASetupRerunKeepsTheRouteRules(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")

	rs.current = nil
	rs.plan()
	mustf(t, rs.attempt(), "setup rerun")

	rs.wantIngress(shop)
	if got := rs.route(route.ID).Phase; got != database.NodeRouteActive {
		t.Errorf("phase = %s: a rerun must not invalidate the route", got)
	}
	// the route survives the rerun's new generation: the identity check still holds
	rs.enqueue(nodeRouteUnexposeAction, route)
	mustf(t, rs.attempt(), "unexpose after the rerun")
}

func TestUnexposeRemovesDNSThenTheRuleThenAccessAndReleasesTheHostname(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")
	other := rs.addRoute("blog.example.test", 8081, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, other)
	mustf(t, rs.attempt(), "expose the second route")
	skip := len(rs.cf.Mutations())

	rs.enqueue(nodeRouteUnexposeAction, rs.route(route.ID))
	mustf(t, rs.attempt(), "unexpose")

	ops := rs.committedOps(skip)
	want := []cffake.Op{cffake.OpDNSDelete, cffake.OpTunnelConfigPut, cffake.OpAppDelete}
	if !slices.Equal(ops, want) {
		t.Errorf("mutations = %v, want %v", ops, want)
	}
	rs.wantIngress("blog.example.test")
	if rules, apps, records := rs.routeObjects(shop); rules+apps+records != 0 {
		t.Errorf("rules, apps, records = %d, %d, %d; want none", rules, apps, records)
	}
	if got := rs.route(route.ID).Phase; got != database.NodeRouteRemoved {
		t.Errorf("phase = %s", got)
	}
	if events := rs.events("node_route.removed"); len(events) != 1 {
		t.Errorf("node_route.removed events = %d", len(events))
	}
	rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning) // the hostname is free again
}

func TestUnexposeResumesAfterEveryFaultAfterEveryMutation(t *testing.T) {
	for _, mode := range []string{"lost response", "refused before", "crash", "lease loss"} {
		for k := 1; k <= 3; k++ {
			t.Run(fmt.Sprintf("%s at mutation %d", mode, k), func(t *testing.T) {
				rs := newRouteSetting(t)
				route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
				rs.enqueue(nodeRouteExposeAction, route)
				mustf(t, rs.attempt(), "expose")
				rs.enqueue(nodeRouteUnexposeAction, rs.route(route.ID))
				rs.arm(mode, k)

				rs.converge(4)

				rs.wantIngress()
				if rules, apps, records := rs.routeObjects(shop); rules+apps+records != 0 {
					t.Errorf("rules, apps, records = %d, %d, %d; want none", rules, apps, records)
				}
				if got := rs.route(route.ID).Phase; got != database.NodeRouteRemoved {
					t.Errorf("phase = %s", got)
				}
				if routable := rs.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
					t.Errorf("routable without Access: %v", routable)
				}
			})
		}
	}
}

func TestACrashAfterTheIngressWriteIsCleanedUpByUnexposeAndSurvivesAnotherWriter(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	rs.arm("crash", 1)
	if err := rs.attempt(); err == nil {
		t.Fatal("the crash changed nothing")
	}

	want, err := desiredIngress(context.Background(), rs.db.Reader(), rs.node.ID, rs.hostname(), "")
	mustf(t, err, "desiredIngress")
	if !slices.ContainsFunc(want, func(r cloudflare.IngressRule) bool { return r.Hostname == shop }) {
		t.Fatalf("another writer would drop the unrecorded rule: %+v", want)
	}
	rs.dropQueued(rs.queued)
	rs.enqueue(nodeRouteUnexposeAction, rs.route(route.ID))
	mustf(t, rs.attempt(), "unexpose")

	rs.wantIngress()
	if got := rs.route(route.ID).Phase; got != database.NodeRouteRemoved {
		t.Errorf("phase = %s", got)
	}
}

func TestUnexposeFindsAnAccessApplicationCreatedButNeverRecorded(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	rs.arm("crash", 2) // the Access application
	if err := rs.attempt(); err == nil {
		t.Fatal("the crash changed nothing")
	}
	if got := rs.route(route.ID); got.Phase != database.NodeRouteIngressReady || got.Objects.AccessAppID != "" {
		t.Fatalf("route = %+v", got)
	}
	rs.dropQueued(rs.queued)

	rs.enqueue(nodeRouteUnexposeAction, rs.route(route.ID))
	mustf(t, rs.attempt(), "unexpose")

	if rules, apps, records := rs.routeObjects(shop); rules+apps+records != 0 {
		t.Errorf("rules, apps, records = %d, %d, %d; want none", rules, apps, records)
	}
}

func TestUnexposeOfARouteThatNeverReachedCloudflareChangesNothingThere(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteUnexposeAction, route)
	mutations := len(rs.cf.Mutations())

	mustf(t, rs.attempt(), "unexpose")

	if got := len(rs.cf.Mutations()); got != mutations {
		t.Errorf("%d Cloudflare mutations, want none", got-mutations)
	}
	if got := rs.route(route.ID).Phase; got != database.NodeRouteRemoved {
		t.Errorf("phase = %s", got)
	}
}

func TestAChangedTunnelHaltsTheRouteBeforeAnyMutation(t *testing.T) {
	for name, change := range map[string]func(rs *routeSetting, route database.NodeRoute){
		"another zone": func(rs *routeSetting, route database.NodeRoute) {
			rs.exec("DROP TRIGGER node_routes_ids_once")
			rs.exec("UPDATE node_routes SET zone = 'other.example' WHERE id = ?", route.ID)
		},
		"another tunnel": func(rs *routeSetting, route database.NodeRoute) {
			rs.exec("DROP TRIGGER node_routes_ids_once")
			rs.exec("UPDATE node_routes SET tunnel_id = 'recreated' WHERE id = ?", route.ID)
		},
		"a generation that is gone": func(rs *routeSetting, route database.NodeRoute) {
			rs.exec("DROP TRIGGER node_routes_ids_once")
			rs.exec("UPDATE node_routes SET tunnel_generation = 99 WHERE id = ?", route.ID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			rs := newRouteSetting(t)
			route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
			change(rs, route)
			rs.enqueue(nodeRouteExposeAction, route)
			before := len(rs.cf.Mutations())

			err := rs.attempt()

			if err == nil || !strings.Contains(err.Error(), "unexpose and expose again") {
				t.Fatalf("error = %v", err)
			}
			if got := len(rs.cf.Mutations()); got != before {
				t.Errorf("%d Cloudflare mutations before the halt", got-before)
			}
			if got := rs.route(route.ID); got.Phase != database.NodeRouteFailed || got.HaltedPhase != database.NodeRouteProvisioning {
				t.Errorf("route = %s (halted in %s)", got.Phase, got.HaltedPhase)
			}
		})
	}
}

func (rs *routeSetting) exec(query string, args ...any) {
	rs.t.Helper()
	rs.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	})
}

func TestADisableIsRefusedWhileTheNodeHasRoutesAndNamesThem(t *testing.T) {
	rs := newRouteSetting(t)
	rs.planDisable() // asked before the routes were admitted: the job refuses them itself
	rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	rs.addRoute("blog.example.test", 8081, "public", database.NodeRouteProvisioning)
	before := len(rs.cf.Mutations())

	err := rs.attempt()

	if smerr.CodeOf(err) != smerr.CodeConflict || !strings.Contains(err.Error(), "blog.example.test, "+shop) {
		t.Fatalf("error = %v, want a conflict naming both routes", err)
	}
	if got := len(rs.cf.Mutations()); got != before {
		t.Errorf("%d Cloudflare mutations", got-before)
	}
	if got := rs.currentNode().Endpoint.Transport; got != domain.TransportCloudflare {
		t.Errorf("transport = %q: the node left the tunnel", got)
	}
}

func TestADisableProceedsOnceTheRoutesAreRemoved(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteUnexposeAction, route)
	mustf(t, rs.attempt(), "unexpose")
	before := rs.instanceObjects()

	rs.planDisable()
	mustf(t, rs.attempt(), "disable")

	rs.wantDisabled(before)
}

func TestRouteJobsAndDisableHoldTheIngressLock(t *testing.T) {
	rs := newRouteSetting(t)
	disable := rs.planDisable()
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	held := func(job jobs.Job) []domain.LockSpec {
		specs, err := LockPlanner{}.PlanLocks(context.Background(), rs.db.Reader(), job)
		mustf(t, err, "PlanLocks")
		return specs
	}
	for _, action := range []string{nodeRouteExposeAction, nodeRouteUnexposeAction} {
		specs := held(rs.enqueue(action, route))
		if !slices.Contains(specs, cloudflareInstanceLock) {
			t.Errorf("%s locks = %+v, want the instance lock", action, specs)
		}
		if !slices.Contains(specs, nodeRouteLock(shop)) {
			t.Errorf("%s locks = %+v, want the lock of the route", action, specs)
		}
		for _, spec := range specs {
			if spec.Key == domain.ResourceLock(nodeRef(rs.node.ID), domain.LockShared).Key {
				t.Errorf("%s locks = %+v: a route job must not lock its node", action, specs)
			}
		}
	}
	if specs := held(disable); !slices.Contains(specs, cloudflareInstanceLock) {
		t.Errorf("node.tunnel.disable locks = %+v, want the instance lock", specs)
	}
}

func TestARouteJobDoesNotBlockTheActionsOfItsNode(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	expose := rs.enqueue(nodeRouteExposeAction, route)
	routing, ok := rs.claim()
	if !ok || routing.Job.ID != expose.ID {
		t.Fatalf("claimed %v (found %v), want the expose job %s", routing.Job.ID, ok, expose.ID)
	}

	for _, action := range []string{"node.probe", "node.reboot"} {
		queued := rs.actionPlan(action, rs.nodeRef())
		claimed, ok := rs.claim()
		if !ok || claimed.Job.ID != queued.ID {
			t.Fatalf("%s was not claimable while a route job runs (claimed %v, found %v)", action, claimed.Job.ID, ok)
		}
		mustf(t, rs.store.Succeed(context.Background(), claimed.Lease), "Succeed")
	}

	rs.enqueue(nodeRouteUnexposeAction, route) // the same route is serialised by design
	if claimed, ok := rs.claim(); ok {
		t.Errorf("a second job of the same route was claimed: %s", claimed.Job.ID)
	}
}

func TestDesiredIngressListsTheRoutesThatServe(t *testing.T) {
	rs := newRouteSetting(t)
	phases := map[string]database.NodeRoutePhase{
		"b-prov.example.test":   database.NodeRouteProvisioning,
		"c-active.example.test": database.NodeRouteActive, "d-removing.example.test": database.NodeRouteRemoving,
	}
	port := 8080
	for _, host := range slices.Sorted(maps.Keys(phases)) {
		rs.addRoute(host, port, "public", phases[host])
		port++
	}
	halted := rs.addRoute("e-halted-expose.example.test", 8090, "public", database.NodeRouteAccessReady)
	rs.exec("UPDATE node_routes SET phase = 'conflict', halted_phase = 'access_ready' WHERE id = ?", halted.ID)
	haltedRemoval := rs.addRoute("f-halted-removal.example.test", 8091, "public", database.NodeRouteDNSRemoved)
	rs.exec("UPDATE node_routes SET phase = 'failed', halted_phase = 'dns_removed' WHERE id = ?", haltedRemoval.ID)

	got, err := desiredIngress(context.Background(), rs.db.Reader(), rs.node.ID, rs.hostname(), "")
	mustf(t, err, "desiredIngress")

	var hosts []string
	for _, r := range got {
		hosts = append(hosts, r.Hostname)
	}
	want := []string{rs.hostname(), "b-prov.example.test", "c-active.example.test", "d-removing.example.test", ""}
	if !slices.Equal(hosts, want) {
		t.Errorf("hostnames = %v, want %v", hosts, want)
	}
	if none, err := desiredIngress(context.Background(), rs.db.Reader(), "", rs.hostname(), ""); err != nil || len(none) != 2 {
		t.Errorf("a run with no node row: %+v, %v; want the SSH rule and the catch-all", none, err)
	}
}

func TestExposeCatalogRiskFollowsTheAccessMode(t *testing.T) {
	for access, want := range map[string]domain.RiskClass{"public": domain.RiskHigh, "owners": domain.RiskOperational} {
		got, err := policy.RiskFor(policy.ActionNodeRouteExpose, map[string]any{
			"hostname": shop, "port": "8080", "access": access,
		})
		if err != nil || got != want {
			t.Errorf("access %s: risk = %q, %v; want %q", access, got, err, want)
		}
	}
	if got, err := policy.RiskFor(policy.ActionNodeRouteUnexpose, map[string]any{"hostname": shop}); err != nil || got != domain.RiskOperational {
		t.Errorf("unexpose risk = %q, %v", got, err)
	}
}

// ---- a route halts before its job publishes it ------------------------------------------------------------

func TestAnAdmittedRouteWithAForeignRecordHaltsBeforeItsJobPublishesIt(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteAdmitted)
	foreign := rs.cf.SeedDNSRecord(shop, "elsewhere.example.net", "")
	rs.enqueue(nodeRouteExposeAction, route)
	before := len(rs.cf.Mutations())

	err := rs.attempt()

	if err == nil || !strings.Contains(err.Error(), foreign.ID) {
		t.Fatalf("error = %v, want it to name the record %s", err, foreign.ID)
	}
	got := rs.route(route.ID)
	if got.Phase != database.NodeRouteConflict || got.HaltedPhase != database.NodeRouteAdmitted {
		t.Errorf("route = %s (halted in %s), want a conflict held in admitted", got.Phase, got.HaltedPhase)
	}
	if len(rs.cf.Mutations()) != before {
		t.Error("the halt was preceded by a Cloudflare mutation")
	}
	rs.wantIngress()
}

func TestAnotherWritersIngressLeavesOutAnAdmittedRouteWhoseDNSWasNeverChecked(t *testing.T) {
	rs := newRouteSetting(t)
	admitted := rs.addRoute(shop, 8080, "owners", database.NodeRouteAdmitted)
	rs.cf.SeedDNSRecord(shop, cloudflare.TunnelTarget(admitted.TunnelID), "left behind")
	other := rs.addRoute(apiHost, 8081, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, other)

	mustf(t, rs.attempt(), "expose of the other route")

	rs.wantIngress(apiHost)
	if got := rs.route(admitted.ID).Phase; got != database.NodeRouteAdmitted {
		t.Errorf("admitted route = %s, want it untouched by another route's job", got)
	}
}

func TestAnOwnersRouteIsNeverReachableWithoutAccessWhateverWritesTheIngressFirst(t *testing.T) {
	rs := newRouteSetting(t)
	owners := rs.addRoute(shop, 8080, "owners", database.NodeRouteAdmitted)
	other := rs.addRoute(apiHost, 8081, "public", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, other)
	mustf(t, rs.attempt(), "expose of the other route")
	rs.wantIngress(apiHost)

	rs.enqueue(nodeRouteExposeAction, owners)
	mustf(t, rs.attempt(), "expose of the owners route")

	if got := rs.route(owners.ID).Phase; got != database.NodeRouteActive {
		t.Fatalf("owners route = %s (%s), want active", got, rs.route(owners.ID).LastError)
	}
	if routable := rs.cf.EverRoutableWithoutAccess(); slices.Contains(routable, shop) {
		t.Errorf("the owners route was routable without Access: %v", routable)
	}
}

// ---- the Access application is checked again before the record exists ----------------------------------

// atAccessReady puts an owners route in access_ready with the Access application app recorded, as an earlier
// attempt that stopped before the DNS record would have left it.
func (rs *routeSetting) atAccessReady(route database.NodeRoute, appID string) {
	rs.exec(`UPDATE node_routes SET phase = 'access_ready', access_app_id = ? WHERE id = ?`, appID, route.ID)
}

func TestAnOwnersRouteResumedAtAccessReadyHaltsWhenItsAccessApplicationIsGone(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.atAccessReady(route, "deleted-in-the-dashboard")
	rs.enqueue(nodeRouteExposeAction, route)

	err := rs.attempt()

	var halt *routeHalt
	if !errors.As(err, &halt) || halt.halt != database.NodeRouteFailed {
		t.Fatalf("error = %v, want a failed halt", err)
	}
	if _, _, records := rs.routeObjects(shop); records != 0 {
		t.Errorf("%d DNS records created for a hostname without its Access application", records)
	}
}

func TestAnOwnersRouteResumedAtAccessReadyRepairsADriftedAccessApplicationBeforeTheRecord(t *testing.T) {
	for name, drift := range map[string]func(rs *routeSetting, route database.NodeRoute) cffake.App{
		"policies": func(rs *routeSetting, route database.NodeRoute) cffake.App {
			return rs.cf.SeedApp(cloudflare.RouteAccessAppName(rs.instanceID(), route.ID.String()), shop, rs.cf.SeedPolicy("everyone", "anyone@example.test").ID)
		},
		"domain": func(rs *routeSetting, route database.NodeRoute) cffake.App {
			return rs.cf.SeedApp(cloudflare.RouteAccessAppName(rs.instanceID(), route.ID.String()), "elsewhere.example.test", rs.ownersPolicy())
		},
	} {
		t.Run(name, func(t *testing.T) {
			rs := newRouteSetting(t)
			route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
			app := drift(rs, route)
			rs.atAccessReady(route, app.ID)
			rs.enqueue(nodeRouteExposeAction, route)

			mustf(t, rs.attempt(), "expose")

			for _, got := range rs.cf.Apps() {
				if got.ID == app.ID && (got.Domain != shop || !slices.Equal(got.PolicyIDs, []string{rs.ownersPolicy()})) {
					t.Errorf("app = %+v, want %s behind the owners policy only", got, shop)
				}
			}
			if got := rs.route(route.ID).Phase; got != database.NodeRouteActive {
				t.Errorf("phase = %s", got)
			}
		})
	}
}

func (rs *routeSetting) instanceID() string {
	rs.t.Helper()
	instance, err := database.GetInstance(context.Background(), rs.db.Reader())
	mustf(rs.t, err, "GetInstance")
	return instance.ID.String()
}

func (rs *routeSetting) ownersPolicy() string {
	rs.t.Helper()
	state, err := database.GetCloudflareState(context.Background(), rs.db.Reader())
	mustf(rs.t, err, "GetCloudflareState")
	return state.OwnersPolicyID
}

func TestAHaltedRouteNeverServesTheIngressWhateverPhaseItHaltedIn(t *testing.T) {
	phases := []database.NodeRoutePhase{
		database.NodeRouteProvisioning, database.NodeRouteProvisioning, database.NodeRouteIngressReady, database.NodeRouteAccessReady,
		database.NodeRouteActive, database.NodeRouteRemoving, database.NodeRouteDNSRemoved,
	}
	for _, halted := range []database.NodeRoutePhase{database.NodeRouteFailed, database.NodeRouteConflict} {
		for _, in := range phases {
			if servesIngress(database.NodeRoute{Phase: halted, HaltedPhase: in}) {
				t.Errorf("a route %s while %s serves the ingress", halted, in)
			}
		}
	}
}

func TestAnExhaustedJobThatFailsBeforeItsRunExistsStillHaltsTheRoute(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteIngressReady) // an earlier attempt wrote the rule
	job := rs.enqueue(nodeRouteExposeAction, route)
	rs.exec(`UPDATE jobs SET attempts = max_attempts - 1 WHERE id = ?`, job.ID) // the claim makes this the last attempt
	rs.cf.Inject(cffake.OpZoneList, cffake.FailBefore, -1)                      // the zone lookup of the run fails

	if err := rs.attempt(); err == nil {
		t.Fatal("the zone lookup did not fail")
	}

	got := rs.route(route.ID)
	if got.Phase != database.NodeRouteFailed || got.HaltedPhase != database.NodeRouteIngressReady {
		t.Errorf("route = %s (halted in %s), want failed in ingress_ready", got.Phase, got.HaltedPhase)
	}
}
