package app

import (
	"context"
	"errors"
	"fmt"
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
func (h appRouteHandler) Run(ctx context.Context, lease jobs.Lease) error {
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

// routeSetting is a node with an enabled tunnel and an app target on it.
type routeSetting struct {
	*tunnelSetting
	target database.AppTarget
	routes appRouteHandler
}

func newRouteSetting(t *testing.T) *routeSetting {
	t.Helper()
	return newRouteSettingOn(newEnabledTunnel(t))
}

// newRouteSettingOn puts an app target on the node of ts, with or without a tunnel.
func newRouteSettingOn(ts *tunnelSetting) *routeSetting {
	rs := &routeSetting{tunnelSetting: ts}
	rs.routes = appRouteHandler{core: ts.handler.core, store: ts.store, tunnel: ts.handler.tunnel}
	rs.current = rs.routes
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := ts.clock.Now()
		app, err := database.CreateApp(ctx, tx, database.App{
			ID: ts.ids.NewID(), Name: "shop", DeployedService: "web", ImagePolicyJSON: []byte(`{}`),
			ComposeSource: "control-plane", CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		rs.target, err = database.CreateAppTarget(ctx, tx, database.AppTarget{
			ID: ts.ids.NewID(), AppID: app.ID, EnvironmentID: ts.env.ID, NodeID: ts.node.ID, ComposeProject: "sm-shop-prod",
			DeploymentPolicyJSON: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		})
		return err
	})
	return rs
}

// addRoute admits a route the way the service does: frozen identity from the node's tunnel, then waiting,
// or provisioning when the target already has a version that publishes the port.
func (rs *routeSetting) addRoute(hostname string, port int, access string, phase database.AppRoutePhase) database.AppRoute {
	rs.t.Helper()
	var route database.AppRoute
	rs.inTx(func(ctx context.Context, tx *database.Tx) error {
		tunnelID, generation, err := nodeTunnelIdentity(ctx, tx, rs.node.ID)
		if err != nil {
			return err
		}
		instance, err := database.GetInstance(ctx, tx)
		if err != nil {
			return err
		}
		route, err = database.InsertAppRoute(ctx, tx, database.AppRoute{
			ID: rs.ids.NewID(), AppTargetID: rs.target.ID, NodeID: rs.node.ID, Hostname: hostname, Service: "web", Port: port,
			Access: access, AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, InstanceID: instance.ID.String(),
			TunnelID: tunnelID, TunnelGeneration: generation, CreatedBy: rs.admin, CreatedAt: rs.clock.Now(),
		})
		if err != nil || phase == database.AppRouteWaiting {
			return err
		}
		rs.clock.Advance(1)
		route, err = database.AdvanceAppRoutePhase(ctx, tx, route.ID, database.AppRouteWaiting, phase, database.AppRouteObjects{}, rs.clock.Now())
		return err
	})
	return route
}

func (rs *routeSetting) route(id domain.ID) database.AppRoute {
	rs.t.Helper()
	r, err := database.GetAppRoute(context.Background(), rs.db.Reader(), id)
	mustf(rs.t, err, "GetAppRoute")
	return r
}

// enqueue plans, submits and approves the action for route as the admin, the way the request path does, and
// makes attempt run its job. The plan is what the claim revalidates.
func (rs *routeSetting) enqueue(action string, route database.AppRoute) jobs.Job {
	rs.t.Helper()
	params := appRouteParams{Hostname: route.Hostname, RouteID: route.ID.String()}
	if action == appRouteExposeAction {
		params = appRouteParams{Hostname: route.Hostname, Service: route.Service, Port: fmt.Sprint(route.Port), Access: route.Access}
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
		b, err := build(ctx, tx, action, rs.admin, appTargetRef(rs.target.ID), raw)
		if err != nil {
			return err
		}
		res, err := rs.plans.evaluate(ctx, tx, actor, b)
		if err != nil {
			return err
		}
		sub, err = rs.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		if err != nil || action != appRouteExposeAction {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE app_routes SET plan_id = ? WHERE id = ?`, sub.Job.PlanID, route.ID) // as admission does
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
		want = append(want, cffake.Ingress{Hostname: h, Service: "http://127.0.0.1:8080"})
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
	route := rs.addRoute(shop, 8080, "public", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)

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
	if got.Phase != database.AppRouteActive || got.Objects.DNSRecordID != record.ID || got.Objects.AccessAppID != "" {
		t.Errorf("route = %+v", got)
	}
	if events := rs.events("app_route.exposed"); len(events) != 1 || events[0].Data["hostname"] != shop || events[0].Data["access"] != "public" {
		t.Errorf("app_route.exposed events = %+v", events)
	}
}

func TestExposeAnOwnersRouteGuardsItBeforeItHasDNS(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)

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
	if got := rs.route(route.ID); got.Phase != database.AppRouteActive || got.Objects.AccessAppID != app.ID {
		t.Errorf("route = %+v", got)
	}
}

func TestExposeLeavesNoDNSRecordWhenItDiesAfterTheIngressStep(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
	rs.arm("crash", 1) // the ingress write

	if err := rs.attempt(); err == nil {
		t.Fatal("the crash changed nothing")
	}

	if rules, apps, records := rs.routeObjects(shop); rules != 1 || apps != 0 || records != 0 {
		t.Errorf("rules, apps, records = %d, %d, %d; want 1, 0, 0", rules, apps, records)
	}
	if got := rs.route(route.ID).Phase; got != database.AppRouteProvisioning {
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
					route := rs.addRoute(shop, 8080, access, database.AppRouteProvisioning)
					rs.enqueue(appRouteExposeAction, route)
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
					if got := rs.route(route.ID).Phase; got != database.AppRouteActive {
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
	route := rs.addRoute(shop, 8080, "public", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
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
	if halted.Phase != database.AppRouteConflict || halted.HaltedPhase != database.AppRouteProvisioning {
		t.Errorf("route = %s (halted in %s)", halted.Phase, halted.HaltedPhase)
	}
	if kept := rs.cf.DNSRecords(); !slices.ContainsFunc(kept, func(d cffake.DNSRecord) bool { return d.ID == foreign.ID && d.Content == foreign.Content }) {
		t.Error("the foreign record was changed or deleted")
	}
	if len(rs.events("app_route.halted")) != 1 {
		t.Error("no app_route.halted event")
	}
}

func TestASiblingRecordThatAppearsBeforeTheCreateHaltsTheRouteAndWithdrawsTheRule(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
	seeded := false
	rs.chaos.afterMutation = func() {
		if !seeded && len(rs.cf.Apps()) > 1 { // after the route's Access application
			seeded = true
			rs.cf.SeedDNSRecord(shop, cloudflare.TunnelTarget(route.TunnelID), "someone else")
		}
	}

	err := rs.attempt()

	var halt *routeHalt
	if !errors.As(err, &halt) || halt.halt != database.AppRouteConflict {
		t.Fatalf("error = %v, want a conflict halt", err)
	}
	rs.wantIngress()
	if _, _, records := rs.routeObjects(shop); records != 1 {
		t.Errorf("%d records, want only the foreign one", records)
	}
}

func TestASetupRerunKeepsTheRouteRules(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")

	rs.current = nil
	rs.plan()
	mustf(t, rs.attempt(), "setup rerun")

	rs.wantIngress(shop)
	if got := rs.route(route.ID).Phase; got != database.AppRouteActive {
		t.Errorf("phase = %s: a rerun must not invalidate the route", got)
	}
	// the route survives the rerun's new generation: the identity check still holds
	rs.enqueue(appRouteUnexposeAction, route)
	mustf(t, rs.attempt(), "unexpose after the rerun")
}

func TestUnexposeRemovesDNSThenTheRuleThenAccessAndReleasesTheHostname(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")
	other := rs.addRoute("blog.example.test", 8080, "public", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, other)
	mustf(t, rs.attempt(), "expose the second route")
	skip := len(rs.cf.Mutations())

	rs.enqueue(appRouteUnexposeAction, rs.route(route.ID))
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
	if got := rs.route(route.ID).Phase; got != database.AppRouteRemoved {
		t.Errorf("phase = %s", got)
	}
	if events := rs.events("app_route.removed"); len(events) != 1 {
		t.Errorf("app_route.removed events = %d", len(events))
	}
	rs.addRoute(shop, 8080, "public", database.AppRouteWaiting) // the hostname is free again
}

func TestUnexposeResumesAfterEveryFaultAfterEveryMutation(t *testing.T) {
	for _, mode := range []string{"lost response", "refused before", "crash", "lease loss"} {
		for k := 1; k <= 3; k++ {
			t.Run(fmt.Sprintf("%s at mutation %d", mode, k), func(t *testing.T) {
				rs := newRouteSetting(t)
				route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
				rs.enqueue(appRouteExposeAction, route)
				mustf(t, rs.attempt(), "expose")
				rs.enqueue(appRouteUnexposeAction, rs.route(route.ID))
				rs.arm(mode, k)

				rs.converge(4)

				rs.wantIngress()
				if rules, apps, records := rs.routeObjects(shop); rules+apps+records != 0 {
					t.Errorf("rules, apps, records = %d, %d, %d; want none", rules, apps, records)
				}
				if got := rs.route(route.ID).Phase; got != database.AppRouteRemoved {
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
	route := rs.addRoute(shop, 8080, "public", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
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
	rs.enqueue(appRouteUnexposeAction, rs.route(route.ID))
	mustf(t, rs.attempt(), "unexpose")

	rs.wantIngress()
	if got := rs.route(route.ID).Phase; got != database.AppRouteRemoved {
		t.Errorf("phase = %s", got)
	}
}

func TestUnexposeFindsAnAccessApplicationCreatedButNeverRecorded(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
	rs.arm("crash", 2) // the Access application
	if err := rs.attempt(); err == nil {
		t.Fatal("the crash changed nothing")
	}
	if got := rs.route(route.ID); got.Phase != database.AppRouteIngressReady || got.Objects.AccessAppID != "" {
		t.Fatalf("route = %+v", got)
	}
	rs.dropQueued(rs.queued)

	rs.enqueue(appRouteUnexposeAction, rs.route(route.ID))
	mustf(t, rs.attempt(), "unexpose")

	if rules, apps, records := rs.routeObjects(shop); rules+apps+records != 0 {
		t.Errorf("rules, apps, records = %d, %d, %d; want none", rules, apps, records)
	}
}

func TestUnexposeOfAWaitingRouteCallsNothingInCloudflare(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.AppRouteWaiting)
	rs.enqueue(appRouteUnexposeAction, route)
	requests := len(rs.cf.Requests())

	mustf(t, rs.attempt(), "unexpose")

	if got := len(rs.cf.Requests()); got != requests {
		t.Errorf("%d Cloudflare requests, want none", got-requests)
	}
	if got := rs.route(route.ID).Phase; got != database.AppRouteRemoved {
		t.Errorf("phase = %s", got)
	}
}

func TestAChangedTunnelHaltsTheRouteBeforeAnyMutation(t *testing.T) {
	for name, change := range map[string]func(rs *routeSetting, route database.AppRoute){
		"another zone": func(rs *routeSetting, route database.AppRoute) {
			rs.exec("DROP TRIGGER app_routes_ids_once")
			rs.exec("UPDATE app_routes SET zone = 'other.example' WHERE id = ?", route.ID)
		},
		"another tunnel": func(rs *routeSetting, route database.AppRoute) {
			rs.exec("DROP TRIGGER app_routes_ids_once")
			rs.exec("UPDATE app_routes SET tunnel_id = 'recreated' WHERE id = ?", route.ID)
		},
		"a generation that is gone": func(rs *routeSetting, route database.AppRoute) {
			rs.exec("DROP TRIGGER app_routes_ids_once")
			rs.exec("UPDATE app_routes SET tunnel_generation = 99 WHERE id = ?", route.ID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			rs := newRouteSetting(t)
			route := rs.addRoute(shop, 8080, "public", database.AppRouteProvisioning)
			change(rs, route)
			rs.enqueue(appRouteExposeAction, route)
			before := len(rs.cf.Mutations())

			err := rs.attempt()

			if err == nil || !strings.Contains(err.Error(), "unexpose and expose again") {
				t.Fatalf("error = %v", err)
			}
			if got := len(rs.cf.Mutations()); got != before {
				t.Errorf("%d Cloudflare mutations before the halt", got-before)
			}
			if got := rs.route(route.ID); got.Phase != database.AppRouteFailed || got.HaltedPhase != database.AppRouteProvisioning {
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
	rs.addRoute(shop, 8080, "public", database.AppRouteWaiting)
	rs.addRoute("blog.example.test", 8080, "public", database.AppRouteWaiting)
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
	route := rs.addRoute(shop, 8080, "public", database.AppRouteWaiting)
	rs.enqueue(appRouteUnexposeAction, route)
	mustf(t, rs.attempt(), "unexpose")
	before := rs.instanceObjects()

	rs.planDisable()
	mustf(t, rs.attempt(), "disable")

	rs.wantDisabled(before)
}

func TestRouteJobsAndDisableHoldTheIngressLock(t *testing.T) {
	rs := newRouteSetting(t)
	disable := rs.planDisable()
	route := rs.addRoute(shop, 8080, "public", database.AppRouteProvisioning)
	held := func(job jobs.Job) []domain.LockSpec {
		specs, err := LockPlanner{}.PlanLocks(context.Background(), rs.db.Reader(), job)
		mustf(t, err, "PlanLocks")
		return specs
	}
	for _, action := range []string{appRouteExposeAction, appRouteUnexposeAction} {
		specs := held(rs.enqueue(action, route))
		if !slices.Contains(specs, cloudflareInstanceLock) {
			t.Errorf("%s locks = %+v, want the instance lock", action, specs)
		}
		if !slices.Contains(specs, domain.ResourceLock(appTargetRef(rs.target.ID), domain.LockExclusive)) {
			t.Errorf("%s locks = %+v, want the app target", action, specs)
		}
	}
	if specs := held(disable); !slices.Contains(specs, cloudflareInstanceLock) {
		t.Errorf("node.tunnel.disable locks = %+v, want the instance lock", specs)
	}
}

func TestDesiredIngressListsTheRoutesThatServe(t *testing.T) {
	rs := newRouteSetting(t)
	phases := map[string]database.AppRoutePhase{
		"a-waiting.example.test": database.AppRouteWaiting, "b-prov.example.test": database.AppRouteProvisioning,
		"c-active.example.test": database.AppRouteActive, "d-removing.example.test": database.AppRouteRemoving,
	}
	for host, phase := range phases {
		rs.addRoute(host, 8080, "public", phase)
	}
	halted := rs.addRoute("e-halted-expose.example.test", 8080, "public", database.AppRouteAccessReady)
	rs.exec("UPDATE app_routes SET phase = 'conflict', halted_phase = 'access_ready' WHERE id = ?", halted.ID)
	haltedRemoval := rs.addRoute("f-halted-removal.example.test", 8080, "public", database.AppRouteDNSRemoved)
	rs.exec("UPDATE app_routes SET phase = 'failed', halted_phase = 'dns_removed' WHERE id = ?", haltedRemoval.ID)

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
		got, err := policy.RiskFor(policy.ActionAppRouteExpose, map[string]any{
			"hostname": shop, "service": "web", "port": "8080", "access": access,
		})
		if err != nil || got != want {
			t.Errorf("access %s: risk = %q, %v; want %q", access, got, err, want)
		}
	}
	if got, err := policy.RiskFor(policy.ActionAppRouteUnexpose, map[string]any{"hostname": shop}); err != nil || got != domain.RiskOperational {
		t.Errorf("unexpose risk = %q, %v", got, err)
	}
}

// ---- a route is published only by its own job ------------------------------------------------------------

func TestAnotherWritersIngressLeavesOutAWaitingRouteWhoseDNSWasNeverChecked(t *testing.T) {
	rs := newRouteSetting(t)
	rs.cf.SeedDNSRecord(shop, cloudflare.TunnelTarget(rs.addRoute(shop, 8080, "owners", database.AppRouteWaiting).TunnelID), "left behind")
	other := rs.addRoute(apiHost, 8080, "public", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, other)

	mustf(t, rs.attempt(), "expose of the other route")

	rs.wantIngress(apiHost)
}

func TestAWaitingRouteWithAForeignRecordHaltsBeforeItIsEverPublished(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteWaiting)
	foreign := rs.cf.SeedDNSRecord(shop, "elsewhere.example.net", "")
	rs.enqueue(appRouteExposeAction, route)
	before := len(rs.cf.Mutations())

	err := rs.attempt()

	if err == nil || !strings.Contains(err.Error(), foreign.ID) {
		t.Fatalf("error = %v, want it to name the record %s", err, foreign.ID)
	}
	got := rs.route(route.ID)
	if got.Phase != database.AppRouteConflict || got.HaltedPhase != database.AppRouteWaiting {
		t.Errorf("route = %s (halted in %s), want a conflict held in waiting", got.Phase, got.HaltedPhase)
	}
	if len(rs.cf.Mutations()) != before {
		t.Error("the halt was preceded by a Cloudflare mutation")
	}
	rs.wantIngress()
}

// ---- the Access application is checked again before the record exists ----------------------------------

// atAccessReady puts an owners route in access_ready with the Access application app recorded, as an earlier
// attempt that stopped before the DNS record would have left it.
func (rs *routeSetting) atAccessReady(route database.AppRoute, appID string) {
	rs.exec(`UPDATE app_routes SET phase = 'access_ready', access_app_id = ? WHERE id = ?`, appID, route.ID)
}

func TestAnOwnersRouteResumedAtAccessReadyHaltsWhenItsAccessApplicationIsGone(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.atAccessReady(route, "deleted-in-the-dashboard")
	rs.enqueue(appRouteExposeAction, route)

	err := rs.attempt()

	var halt *routeHalt
	if !errors.As(err, &halt) || halt.halt != database.AppRouteFailed {
		t.Fatalf("error = %v, want a failed halt", err)
	}
	if _, _, records := rs.routeObjects(shop); records != 0 {
		t.Errorf("%d DNS records created for a hostname without its Access application", records)
	}
}

func TestAnOwnersRouteResumedAtAccessReadyRepairsADriftedAccessApplicationBeforeTheRecord(t *testing.T) {
	for name, drift := range map[string]func(rs *routeSetting, route database.AppRoute) cffake.App{
		"policies": func(rs *routeSetting, route database.AppRoute) cffake.App {
			return rs.cf.SeedApp(cloudflare.RouteAccessAppName(rs.instanceID(), route.ID.String()), shop, rs.cf.SeedPolicy("everyone", "anyone@example.test").ID)
		},
		"domain": func(rs *routeSetting, route database.AppRoute) cffake.App {
			return rs.cf.SeedApp(cloudflare.RouteAccessAppName(rs.instanceID(), route.ID.String()), "elsewhere.example.test", rs.ownersPolicy())
		},
	} {
		t.Run(name, func(t *testing.T) {
			rs := newRouteSetting(t)
			route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
			app := drift(rs, route)
			rs.atAccessReady(route, app.ID)
			rs.enqueue(appRouteExposeAction, route)

			mustf(t, rs.attempt(), "expose")

			for _, got := range rs.cf.Apps() {
				if got.ID == app.ID && (got.Domain != shop || !slices.Equal(got.PolicyIDs, []string{rs.ownersPolicy()})) {
					t.Errorf("app = %+v, want %s behind the owners policy only", got, shop)
				}
			}
			if got := rs.route(route.ID).Phase; got != database.AppRouteActive {
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
	phases := []database.AppRoutePhase{
		database.AppRouteWaiting, database.AppRouteProvisioning, database.AppRouteIngressReady, database.AppRouteAccessReady,
		database.AppRouteActive, database.AppRouteRemoving, database.AppRouteDNSRemoved,
	}
	for _, halted := range []database.AppRoutePhase{database.AppRouteFailed, database.AppRouteConflict} {
		for _, in := range phases {
			if servesIngress(database.AppRoute{Phase: halted, HaltedPhase: in}) {
				t.Errorf("a route %s while %s serves the ingress", halted, in)
			}
		}
	}
}

func TestAnExhaustedJobThatFailsBeforeItsRunExistsStillHaltsTheRoute(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteIngressReady) // an earlier attempt wrote the rule
	job := rs.enqueue(appRouteExposeAction, route)
	rs.exec(`UPDATE jobs SET attempts = max_attempts - 1 WHERE id = ?`, job.ID) // the claim makes this the last attempt
	rs.cf.Inject(cffake.OpZoneList, cffake.FailBefore, -1)                      // the zone lookup of the run fails

	if err := rs.attempt(); err == nil {
		t.Fatal("the zone lookup did not fail")
	}

	got := rs.route(route.ID)
	if got.Phase != database.AppRouteFailed || got.HaltedPhase != database.AppRouteIngressReady {
		t.Errorf("route = %s (halted in %s), want failed in ingress_ready", got.Phase, got.HaltedPhase)
	}
}
