package app

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

func (rs *routeSetting) service() *NodeRoutes {
	return &NodeRoutes{core: rs.handler.core, plans: rs.plans}
}

// applyHandler is the control_plane.apply handler of the instance: the apply step admits the route, then the
// route handler moves it.
func (rs *routeSetting) applyHandler() applyHandler {
	return applyHandler{inv: rs.inv, routes: &rs.routes}
}

func (rs *routeSetting) liveRoute(hostname string) (database.NodeRoute, error) {
	return database.GetLiveNodeRouteByHostname(context.Background(), rs.db.Reader(), hostname)
}

func (rs *routeSetting) expose(r ExposeRouteRequest) (NodeRouteResult, error) {
	return rs.service().Expose(context.Background(), rs.caller(rs.admin), rs.node.ID, r)
}

// approved approves the job of an expose or unexpose result while it waits, and returns it queued.
func (rs *routeSetting) approved(res NodeRouteResult) jobs.Job {
	rs.t.Helper()
	job := res.Submission.Job
	for _, approver := range []domain.ID{rs.bob, rs.carol} {
		if job.State != domain.JobAwaitingApproval {
			break
		}
		var err error
		job, err = rs.approve(approver, job)
		mustf(rs.t, err, "approve")
	}
	return job
}

// runApproved claims the job of a result, approving it first when it waits, and runs it through the
// control_plane.apply handler.
func (rs *routeSetting) runApproved(res NodeRouteResult) error {
	rs.t.Helper()
	rs.queued, rs.current = rs.approved(res), rs.applyHandler()
	return rs.attempt()
}

// runJob claims the next job, which must be job, and runs it through the control_plane.apply handler as the
// engine does: a failure goes back to the store, which requeues the job or ends it.
func (rs *routeSetting) runJob(job jobs.Job) error {
	rs.t.Helper()
	claimed, ok := rs.claim()
	if !ok || claimed.Job.ID != job.ID {
		rs.t.Fatalf("claimed %v (found %v), want job %s", claimed.Job.ID, ok, job.ID)
	}
	err := rs.applyHandler().Run(context.Background(), claimed.Lease)
	if err == nil {
		mustf(rs.t, rs.store.Succeed(context.Background(), claimed.Lease), "Succeed")
		return nil
	}
	mustf(rs.t, rs.store.Fail(context.Background(), claimed.Lease, err), "Fail")
	return err
}

func webRequest(hostname string) ExposeRouteRequest {
	return ExposeRouteRequest{Hostname: hostname, Port: 8080, Access: "owners"}
}

func TestExposeAdmitsTheRouteAndTheJobRunsItThroughControlPlaneApply(t *testing.T) {
	rs := newRouteSetting(t)
	rs.exec(`UPDATE environments SET risk_level = 'development'`) // an owners expose needs no approval there

	res, err := rs.expose(webRequest("Shop.Example.Test."))

	mustf(t, err, "Expose")
	if res.Submission.Job.Type != JobControlPlaneApply {
		t.Errorf("job type = %s, want %s", res.Submission.Job.Type, JobControlPlaneApply)
	}
	if res.Route == nil {
		t.Fatal("an expose that needs no approval admitted no route")
	}
	if res.Route.Hostname != shop || res.Route.Phase != database.NodeRouteAdmitted {
		t.Errorf("route = %+v, want %s admitted", res.Route, shop)
	}

	mustf(t, rs.runApproved(res), "run")

	route, err := rs.liveRoute(shop)
	mustf(t, err, "route")
	if route.Phase != database.NodeRouteActive {
		t.Fatalf("route phase = %s (%s), want active", route.Phase, route.LastError)
	}
	if rules, apps, records := rs.routeObjects(shop); rules != 1 || apps != 1 || records != 1 {
		t.Errorf("rules, apps, records = %d, %d, %d; want 1, 1, 1", rules, apps, records)
	}
}

func TestAPublicExposeIsHighRiskAndWritesNothingUntilApproved(t *testing.T) {
	rs := newRouteSetting(t)
	before := len(rs.cf.Mutations())

	res, err := rs.expose(ExposeRouteRequest{Hostname: shop, Port: 8080}) // access omitted

	mustf(t, err, "Expose")
	if !res.Submission.Policy.ApprovalRequired || res.Submission.Job.State != domain.JobAwaitingApproval {
		t.Fatalf("job state %s, approval required %v; want a public route to wait for approval", res.Submission.Job.State, res.Submission.Policy.ApprovalRequired)
	}
	if res.Route != nil {
		t.Errorf("route written before approval: %+v", res.Route)
	}
	if _, err := rs.liveRoute(shop); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("a row exists before approval: %v", err)
	}
	if len(rs.cf.Mutations()) != before {
		t.Error("Cloudflare was called before approval")
	}
	planned, err := database.GetPlan(context.Background(), rs.db.Reader(), *res.Submission.Job.PlanID)
	mustf(t, err, "GetPlan")
	stored, err := plan.Parse(planned.PlanJSON)
	mustf(t, err, "Parse")
	if stored.Risk != domain.RiskHigh || stored.Parameters["access"] != "public" {
		t.Errorf("plan risk %s access %v, want high / public", stored.Risk, stored.Parameters["access"])
	}

	mustf(t, rs.runApproved(res), "run")

	if route, err := rs.liveRoute(shop); err != nil || route.Phase != database.NodeRouteActive || route.Access != "public" {
		t.Errorf("route = %+v, %v; want active and public", route, err)
	}
}

func TestExposeRefusesBeforeCloudflareAndWritesNoRoute(t *testing.T) {
	cases := []struct {
		name  string
		req   ExposeRouteRequest
		setup func(*routeSetting)
		want  string
	}{
		{"suffix spoof", ExposeRouteRequest{Hostname: "shop.evil-example.test", Port: 8080}, nil, "not under the zone"},
		{"another zone", ExposeRouteRequest{Hostname: "shop.example.com", Port: 8080}, nil, "not under the zone"},
		{"the apex", ExposeRouteRequest{Hostname: "example.test", Port: 8080}, nil, "not under the zone"},
		{"ssh namespace", ExposeRouteRequest{Hostname: "ssh-node.example.test", Port: 8080}, nil, "reserved"},
		{"wildcard", ExposeRouteRequest{Hostname: "*.example.test", Port: 8080}, nil, "valid DNS name"},
		{"port zero", ExposeRouteRequest{Hostname: shop, Port: 0}, nil, "port"},
		{"bad access", ExposeRouteRequest{Hostname: shop, Port: 8080, Access: "everyone"}, nil, "access"},
		{
			"hostname in use under another case",
			ExposeRouteRequest{Hostname: "SHOP.example.test", Port: 8080},
			func(rs *routeSetting) { rs.addRoute(shop, 9090, "public", database.NodeRouteProvisioning) }, "already routed",
		},
		{"port above the range", ExposeRouteRequest{Hostname: shop, Port: 65536}, nil, "port"},
		{"the endpoint SSH port", ExposeRouteRequest{Hostname: shop, Port: 2222, Access: "owners"}, func(rs *routeSetting) {
			rs.exec(`UPDATE nodes SET endpoint_json = json_set(endpoint_json, '$.Port', 2222)`)
		}, "SSH port"},
		{"the SSH port of the node", ExposeRouteRequest{Hostname: shop, Port: 22, Access: "owners"}, nil, "SSH port"},
		{"a tunnel whose enable is not committed", webRequest(shop), func(rs *routeSetting) {
			rs.exec(`UPDATE tunnel_operations SET phase = 'verified'`)
		}, "no Cloudflare connector"},
		{"a tunnel disabled after its enable", webRequest(shop), func(rs *routeSetting) {
			rs.exec(`INSERT INTO tunnel_operations (id, node_id, generation, operation, phase, phase_started_at, account_id, zone,
					instance_id, created_at, updated_at)
				SELECT 'disable-1', node_id, generation + 1, 'disable', 'started', phase_started_at, account_id, zone,
					instance_id, created_at, updated_at FROM tunnel_operations`)
		}, "no Cloudflare connector"},
		{"a port routed by another hostname", webRequest(shop), func(rs *routeSetting) {
			rs.addRoute("other.example.test", 8080, "public", database.NodeRouteActive)
		}, "already routed as other.example.test"},
		{"a port routed by a halted route", webRequest(shop), func(rs *routeSetting) {
			route := rs.addRoute("other.example.test", 8080, "public", database.NodeRouteProvisioning)
			rs.exec(`UPDATE node_routes SET phase = 'failed', halted_phase = 'provisioning' WHERE id = ?`, route.ID)
		}, "already routed as other.example.test"},
		{"a node that is not managed", webRequest(shop), func(rs *routeSetting) {
			rs.exec(`UPDATE nodes SET management_state = 'retired'`)
		}, "not managed"},
		{"a node at its limit", webRequest(shop), func(rs *routeSetting) {
			for i := range maxRoutesPerNode {
				rs.addRoute(fmt.Sprintf("r%d.example.test", i), 10000+i, "public", database.NodeRouteProvisioning)
			}
		}, "limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRouteSetting(t)
			if tc.setup != nil {
				tc.setup(rs)
			}
			routes, before := rs.countRoutes(), len(rs.cf.Mutations())

			_, err := rs.expose(tc.req)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Expose = %v, want an error containing %q", err, tc.want)
			}
			if rs.countRoutes() != routes || len(rs.cf.Mutations()) != before {
				t.Error("a refused request wrote a route or reached Cloudflare")
			}
		})
	}
}

func (rs *routeSetting) countRoutes() int {
	rows, err := database.ListNodeRoutes(context.Background(), rs.db.Reader(), database.NodeRouteFilter{IncludeRemoved: true})
	mustf(rs.t, err, "ListNodeRoutes")
	return len(rows)
}

func TestExposeRefusesANodeWithoutAConnector(t *testing.T) {
	rs := newRouteSettingOn(newTunnelSetting(t)) // set up with no tunnel: the node's transport is direct

	_, err := rs.expose(webRequest(shop))

	if err == nil || !strings.Contains(err.Error(), "--tunnel") || smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("Expose = %v, want CAPABILITY_UNAVAILABLE suggesting setup --tunnel", err)
	}
	if rs.countRoutes() != 0 {
		t.Error("a route was written")
	}
}

func TestExposeRefusesPort22EvenWhenTheNodesDirectSSHPortIsAnother(t *testing.T) {
	rs := newRouteSetting(t)
	rs.exec(`UPDATE nodes SET endpoint_json = json_set(endpoint_json, '$.Port', 2222)`)

	_, err := rs.expose(ExposeRouteRequest{Hostname: shop, Port: 22, Access: "owners"})

	if err == nil || !strings.Contains(err.Error(), "SSH port") {
		t.Fatalf("Expose of the port the tunnel's SSH rule serves = %v, want a refusal naming the SSH port", err)
	}
}

func TestExposeConflictsNameWhatHoldsTheHostnameOrPortAndHowToFreeIt(t *testing.T) {
	rs := newRouteSetting(t)
	rs.addRoute(shop, 8080, "public", database.NodeRouteActive)

	_, sameHost := rs.expose(ExposeRouteRequest{Hostname: shop, Port: 9090, Access: "owners"})
	_, samePort := rs.expose(ExposeRouteRequest{Hostname: apiHost, Port: 8080, Access: "owners"})

	for name, err := range map[string]error{"hostname": sameHost, "port": samePort} {
		want := "`sm nodes unexpose " + rs.node.Name + " --hostname " + shop + "`"
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), rs.node.Name) {
			t.Errorf("%s conflict = %v, want the node and %s", name, err, want)
		}
	}
}

func TestListShowsRemovedRoutesWithTheirNoteOnlyWhenAsked(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "public", database.NodeRouteActive)
	rs.exec(`UPDATE node_routes SET phase = 'removed', last_error = 'waited for a deployment' WHERE id = ?`, route.ID)

	live, err := rs.service().List(context.Background(), rs.caller(rs.admin), "", false)
	mustf(t, err, "List")
	all, err := rs.service().List(context.Background(), rs.caller(rs.admin), "", true)
	mustf(t, err, "List all")

	if len(live) != 0 || len(all) != 1 || all[0].LastError != "waited for a deployment" {
		t.Errorf("live = %+v, all = %+v; want the removed route and its note only with includeRemoved", live, all)
	}
}

func TestExposeRefusesWithoutACloudflareBlock(t *testing.T) {
	rs := newRouteSetting(t)
	service := rs.service()
	service.cfg.Cloudflare = nil

	_, err := service.Expose(context.Background(), rs.caller(rs.admin), rs.node.ID, webRequest(shop))

	if err == nil || !strings.Contains(err.Error(), "cloudflare") {
		t.Errorf("Expose = %v, want a refusal naming the missing cloudflare: block", err)
	}
}

func TestExposeAgainOfAHaltedRouteResumesItAndRefusesALiveOne(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)

	_, err := rs.expose(webRequest(shop))
	if err == nil || !strings.Contains(err.Error(), "already routed") {
		t.Fatalf("Expose of a live route = %v, want a conflict", err)
	}

	rs.exec(`UPDATE node_routes SET phase = 'conflict', halted_phase = 'provisioning' WHERE id = ?`, route.ID)
	res, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose of a halted route")
	mustf(t, rs.runApproved(res), "run")

	if rs.countRoutes() != 1 {
		t.Errorf("%d rows, want the halted route and no second one", rs.countRoutes())
	}
	if got := rs.route(route.ID); got.Phase != database.NodeRouteActive {
		t.Errorf("phase = %s (%s), want the new job to resume the route to active", got.Phase, got.LastError)
	}
}

func TestApplyApprovedAdmissionIsIdempotentAndNeverAdmitsAgainAfterTheRemoval(t *testing.T) {
	rs := newRouteSetting(t)
	res, err := rs.expose(ExposeRouteRequest{Hostname: shop, Port: 8080, Access: "public"}) // waits for approval
	mustf(t, err, "Expose")
	job := rs.approved(res)

	stored := rs.job(job.ID)
	apply := func() {
		rs.inTx(func(ctx context.Context, tx *database.Tx) error {
			return rs.service().applyApproved(ctx, tx, domain.Actor{ID: rs.admin, Type: domain.ActorHuman}, nodeRouteExposeAction, stored)
		})
	}
	apply()
	apply()
	if rs.countRoutes() != 1 {
		t.Fatalf("%d routes after two applies, want 1", rs.countRoutes())
	}

	rs.exec(`UPDATE node_routes SET phase = 'removed'`) // the route was unexposed while a retry waited
	apply()

	if rs.countRoutes() != 1 {
		t.Errorf("%d routes after a retry that followed the removal, want the removed one only", rs.countRoutes())
	}
}

func TestAnExposeJobThatRunsAfterTheUnexposeDoesNotAdmitTheRouteAgain(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteAdmitted) // admitted by the request transaction
	exposeJob := rs.enqueue(nodeRouteExposeAction, route)
	rs.exec(`UPDATE jobs SET scheduled_at = scheduled_at + 600000 WHERE id = ?`, exposeJob.ID) // still queued when the unexpose comes
	unexpose, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, shop)
	mustf(t, err, "Unexpose")
	mustf(t, rs.runJob(rs.approved(unexpose)), "unexpose")
	rs.clock.Advance(11 * time.Minute) // within the approval's lifetime

	mustf(t, rs.runJob(exposeJob), "expose")

	if rs.countRoutes() != 1 {
		t.Errorf("%d routes, want only the removed one", rs.countRoutes())
	}
	if _, err := rs.liveRoute(shop); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("the late job brought the route back: %v", err)
	}
	rs.wantIngress()
}

func TestAnExhaustedExposeHaltsTheRouteWithdrawsItsRuleAndExposeAgainResumesIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		refuse int // the mutation that fails: 2 is the Access application, 3 the DNS record
		halted database.NodeRoutePhase
	}{
		{"ingress_ready", 2, database.NodeRouteIngressReady},
		{"access_ready", 3, database.NodeRouteAccessReady},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRouteSetting(t)
			res, err := rs.expose(webRequest(shop))
			mustf(t, err, "Expose")
			job := rs.approved(res)
			rs.exec(`UPDATE jobs SET attempts = max_attempts - 1 WHERE id = ?`, job.ID) // the claim makes this the last attempt
			rs.arm("refused before", tc.refuse)

			if err := rs.runJob(job); err == nil {
				t.Fatal("the transient failure changed nothing")
			}

			route, err := rs.liveRoute(shop)
			mustf(t, err, "route")
			if route.Phase != database.NodeRouteFailed || route.HaltedPhase != tc.halted {
				t.Fatalf("route = %s (halted in %s), want failed in %s", route.Phase, route.HaltedPhase, tc.halted)
			}
			rs.wantIngress() // a halt while exposing withdraws the rule

			again, err := rs.expose(webRequest(shop))
			mustf(t, err, "Expose of the halted route")
			mustf(t, rs.runApproved(again), "run")

			if got := rs.route(route.ID); got.Phase != database.NodeRouteActive || rs.countRoutes() != 1 {
				t.Errorf("route = %s (%s), %d rows; want the same route active", got.Phase, got.LastError, rs.countRoutes())
			}
			rs.wantIngress(shop)
		})
	}
}

func TestExposeAgainChecksTheAccessApplicationBeforeAnOwnersRouteServesAgain(t *testing.T) {
	rs := newRouteSetting(t)
	res, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose")
	job := rs.approved(res)
	rs.exec(`UPDATE jobs SET attempts = max_attempts - 1 WHERE id = ?`, job.ID)
	rs.arm("refused before", 3) // halts in access_ready
	if err := rs.runJob(job); err == nil {
		t.Fatal("the transient failure changed nothing")
	}
	route, err := rs.liveRoute(shop)
	mustf(t, err, "route")
	if !rs.cf.RemoveApp(route.Objects.AccessAppID) {
		t.Fatal("no Access application to remove")
	}

	again, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose of the halted route")
	before := len(rs.cf.Mutations())
	if err := rs.runApproved(again); err == nil {
		t.Fatal("a missing Access application did not stop the resume")
	}

	if got := rs.route(route.ID).Phase; !got.Halted() {
		t.Errorf("phase = %s, want halted", got)
	}
	if got := rs.cf.Mutations()[before:]; len(got) != 0 {
		t.Errorf("mutations = %v, want none: the rule is not published without its Access application", got)
	}
	rs.wantIngress()
}

func TestExposeAgainChecksTheDNSBeforeAHaltedRouteServesAgain(t *testing.T) {
	rs := newRouteSetting(t)
	res, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose")
	job := rs.approved(res)
	rs.exec(`UPDATE jobs SET attempts = max_attempts - 1 WHERE id = ?`, job.ID)
	rs.arm("refused before", 2)
	if err := rs.runJob(job); err == nil {
		t.Fatal("the transient failure changed nothing")
	}
	route, err := rs.liveRoute(shop)
	mustf(t, err, "route")
	rs.cf.SeedDNSRecord(shop, "elsewhere.example.net", "")

	again, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose of the halted route")
	if err := rs.runApproved(again); err == nil {
		t.Fatal("a foreign record did not stop the resume")
	}

	if got := rs.route(route.ID).Phase; got != database.NodeRouteFailed {
		t.Errorf("phase = %s, want failed: the route must not serve before its preflight passes", got)
	}
	rs.wantIngress()
}

// ---- unexpose --------------------------------------------------------------------------------------

func TestUnexposeRemovesTheRouteAndAnotherNodesHostnameIsNotFound(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")

	_, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), domain.ID("other-node"), shop)
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("Unexpose of a hostname of another node = %v, want NOT_FOUND", err)
	}

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, strings.ToUpper(shop))
	mustf(t, err, "Unexpose")
	mustf(t, rs.runApproved(res), "run")

	if got := rs.route(route.ID); got.Phase != database.NodeRouteRemoved {
		t.Errorf("phase = %s, want removed", got.Phase)
	}
	if rules, apps, records := rs.routeObjects(shop); rules+apps+records != 0 {
		t.Errorf("rules, apps, records = %d, %d, %d; want none", rules, apps, records)
	}
}

// exposedOnARecreatedTunnel exposes an owners route, then records another tunnel as the node's.
func exposedOnARecreatedTunnel(t *testing.T) (*routeSetting, database.NodeRoute) {
	t.Helper()
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")
	rs.inTx(func(ctx context.Context, tx *database.Tx) error { // the node's tunnel was recreated
		instance, err := database.GetInstance(ctx, tx)
		if err != nil {
			return err
		}
		_, err = database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: rs.ids.NewID(), NodeID: rs.node.ID, AccountID: route.AccountID, Zone: route.Zone, InstanceID: instance.ID.String(),
			Hostname: rs.hostname(), Objects: database.TunnelObjects{TunnelID: "recreated"}, CreatedAt: rs.clock.Now(),
		})
		return err
	})
	return rs, route
}

func TestUnexposeAfterTheNodesTunnelChangedStillRemovesWhatItOwns(t *testing.T) {
	rs, route := exposedOnARecreatedTunnel(t)

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, shop)
	mustf(t, err, "Unexpose")
	mustf(t, rs.runApproved(res), "run")

	if got := rs.route(route.ID); got.Phase != database.NodeRouteRemoved {
		t.Fatalf("phase = %s (%s), want removed", got.Phase, got.LastError)
	}
	rules, apps, records := rs.routeObjects(shop)
	if apps != 0 || records != 0 {
		t.Errorf("apps, records = %d, %d; want the Access app and the DNS record deleted", apps, records)
	}
	if rules != 0 {
		t.Errorf("rules = %d, want the rule taken out of the frozen tunnel", rules)
	}
	rs.wantIngress()
}

func TestUnexposeAfterTheFrozenTunnelWasDeletedSkipsItsIngress(t *testing.T) {
	rs, route := exposedOnARecreatedTunnel(t)
	mustf(t, rs.chaos.CloudflareAPI.DeleteTunnel(context.Background(), route.TunnelID), "delete the frozen tunnel")

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, shop)
	mustf(t, err, "Unexpose")
	mustf(t, rs.runApproved(res), "run")

	if got := rs.route(route.ID); got.Phase != database.NodeRouteRemoved {
		t.Fatalf("phase = %s (%s), want removed", got.Phase, got.LastError)
	}
	apps, records := 0, 0
	for _, a := range rs.cf.Apps() {
		if a.Domain == shop {
			apps++
		}
	}
	for _, d := range rs.cf.DNSRecords() {
		if d.Name == shop {
			records++
		}
	}
	if apps != 0 || records != 0 {
		t.Errorf("apps, records = %d, %d; want none", apps, records)
	}
}

func TestUnexposeKeepsTheAccessApplicationWhenTheFrozenTunnelCannotBeRead(t *testing.T) {
	rs, route := exposedOnARecreatedTunnel(t)
	rs.cf.Inject(cffake.OpTunnelConfigGet, cffake.FailBefore, -1)

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, shop)
	mustf(t, err, "Unexpose")
	if err := rs.runApproved(res); err == nil {
		t.Fatal("an unexpose that could not read the frozen tunnel succeeded")
	}

	if got := rs.route(route.ID); got.Phase == database.NodeRouteRemoved || got.Phase == database.NodeRouteIngressRemoved {
		t.Errorf("phase = %s, want the removal stopped before the ingress step completed", got.Phase)
	}
	if _, apps, _ := rs.routeObjects(shop); apps != 1 {
		t.Errorf("Access apps = %d, want the application kept while the rule may still serve", apps)
	}
}

func TestAnUnexposeApprovedAfterTheHostnameWasExposedAgainLeavesTheNewRoute(t *testing.T) {
	rs := newRouteSetting(t)
	old := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	first, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, shop)
	mustf(t, err, "first Unexpose")
	second, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, shop)
	mustf(t, err, "second Unexpose")
	mustf(t, rs.runApproved(first), "run the first")
	if got := rs.route(old.ID).Phase; got != database.NodeRouteRemoved {
		t.Fatalf("phase = %s, want removed", got)
	}
	reused := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)

	mustf(t, rs.runApproved(second), "run the second")

	if got := rs.route(reused.ID).Phase; got != database.NodeRouteProvisioning {
		t.Errorf("the route that reused the hostname is %s, want it untouched by an unexpose requested for the old one", got)
	}
}

func TestUnexposeAfterTheZoneChangedMarksTheRouteRemovedWithoutCloudflare(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.NodeRouteProvisioning)
	rs.enqueue(nodeRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")
	exposed := rs.route(route.ID)
	rs.routes.tunnel.opts.Config.Zone = "new.example.test" // the instance now serves another zone
	before := len(rs.cf.Mutations())

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.node.ID, shop)
	mustf(t, err, "Unexpose")
	mustf(t, rs.runApproved(res), "run")

	if got := rs.route(route.ID); got.Phase != database.NodeRouteRemoved {
		t.Fatalf("phase = %s (%s), want removed", got.Phase, got.LastError)
	}
	if len(rs.cf.Mutations()) != before {
		t.Error("an unexpose across a changed zone called Cloudflare")
	}
	events := rs.events("node_route.removed")
	last := events[len(events)-1]
	if last.Data["abandoned"] != true || last.Data["dns_record_id"] != exposed.Objects.DNSRecordID || last.Data["access_app_id"] != exposed.Objects.AccessAppID {
		t.Errorf("event data = %+v, want the abandoned objects listed", last.Data)
	}
}

// ---- revalidation -----------------------------------------------------------------

func TestARouteJobIsRevalidatedAgainstItsPlan(t *testing.T) {
	rs := newRouteSetting(t)
	res, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose")
	rs.exec(`UPDATE environments SET spec_revision = spec_revision + 1 WHERE id = ?`, rs.env.ID)

	job := res.Submission.Job
	for _, approver := range []domain.ID{rs.bob, rs.carol} {
		if job.State != domain.JobAwaitingApproval {
			break
		}
		job, err = rs.approve(approver, job)
		mustf(t, err, "approve")
	}
	if _, ok := rs.claim(); ok {
		t.Fatal("a job whose plan inputs changed was claimed")
	}
	got, err := rs.store.Get(context.Background(), rs.db.Reader(), job.ID)
	mustf(t, err, "Get")
	if got.State != domain.JobFailed {
		t.Errorf("job state = %s, want failed with a stale plan", got.State)
	}
}
