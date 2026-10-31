package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

func (rs *routeSetting) service() *AppRoutes {
	return &AppRoutes{core: rs.handler.core, plans: rs.plans}
}

func (rs *routeSetting) apps() *Apps {
	return &Apps{core: rs.handler.core, plans: rs.plans}
}

// applyHandler is the control_plane.apply handler of the instance: the apply step admits the route, then the
// route handler moves it.
func (rs *routeSetting) applyHandler() applyHandler {
	return applyHandler{inv: rs.inv, apps: rs.apps(), routes: &rs.routes}
}

func tcpPort(service, addr string, port uint16) snapshotPort {
	return snapshotPort{Service: service, Addr: addr, Port: port, Proto: "tcp"}
}

// seedKnownGood records a succeeded known-good deployment of the target whose frozen model publishes ports.
func (rs *routeSetting) seedKnownGood(ports ...snapshotPort) database.Deployment {
	rs.t.Helper()
	var dep database.Deployment
	rs.inTx(func(ctx context.Context, tx *database.Tx) error {
		content, err := json.Marshal(composeSnapshot{
			Public: "services: {}", Effective: json.RawMessage(`{}`), HostPorts: append([]snapshotPort{}, ports...),
			Images: []snapshotImage{}, Secrets: []snapshotSecret{},
		})
		if err != nil {
			return err
		}
		hash := database.ExecutionSnapshotHash(content)
		now := rs.clock.Now()
		if err := database.PutExecutionSnapshot(ctx, tx, database.ExecutionSnapshot{
			Hash: hash, Kind: database.SnapshotComposeModel, Content: content, CreatedAt: now,
		}); err != nil {
			return err
		}
		raw, err := plan.Canonical(&plan.Plan{
			Version: plan.Version, Action: deploymentCreateAction, Actor: "identity/" + rs.admin.String(),
			Targets: []plan.Target{{Type: string(domain.ResourceAppTarget), ID: rs.target.ID.String()}},
			Content: plan.Content{ComposeHash: &hash}, Risk: domain.RiskOperational,
		})
		if err != nil {
			return err
		}
		rec := database.PlanRecord{
			ID: rs.ids.NewID(), Action: deploymentCreateAction, ActorID: rs.admin, Credential: rs.caller(rs.admin).Credential, PlanJSON: raw, PlanHash: "hash-" + hash,
			FinalizedAt: now, CreatedAt: now, ExpiresAt: now.Add(24 * 3600e9),
		}
		if err := database.InsertPlan(ctx, tx, rec); err != nil {
			return err
		}
		dep = database.Deployment{
			ID: rs.ids.NewID(), Kind: deployments.KindDeploy, AppID: rs.target.AppID, AppTargetID: rs.target.ID,
			EnvironmentID: rs.target.EnvironmentID, NodeID: rs.node.ID, State: deployments.StateCreated, RequestedBy: rs.admin,
			Credential: rs.caller(rs.admin).Credential,
			CommitSha:  "abc", RequestedRaw: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
		}
		if err := database.InsertDeployment(ctx, tx, dep); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE deployments SET plan_id = ?, state = 'succeeded', known_good = 1, finished_at = ? WHERE id = ?`,
			rec.ID, domain.UnixMillis(now), dep.ID)
		return err
	})
	return dep
}

func (rs *routeSetting) liveRoute(hostname string) (database.AppRoute, error) {
	return database.GetLiveAppRouteByHostname(context.Background(), rs.db.Reader(), hostname)
}

func (rs *routeSetting) expose(r ExposeRouteRequest) (AppRouteResult, error) {
	return rs.service().Expose(context.Background(), rs.caller(rs.admin), rs.target.ID, r)
}

// approved approves the job of an expose or unexpose result while it waits, and returns it queued.
func (rs *routeSetting) approved(res AppRouteResult) jobs.Job {
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
func (rs *routeSetting) runApproved(res AppRouteResult) error {
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
	return ExposeRouteRequest{Hostname: hostname, Service: "web", Port: 8080, Access: "owners"}
}

func TestExposeAdmitsTheRouteAndTheJobRunsItThroughControlPlaneApply(t *testing.T) {
	rs := newRouteSetting(t)
	rs.exec(`UPDATE environments SET risk_level = 'development'`) // an owners expose needs no approval there
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))

	res, err := rs.expose(webRequest("Shop.Example.Test."))

	mustf(t, err, "Expose")
	if res.Submission.Job.Type != JobControlPlaneApply {
		t.Errorf("job type = %s, want %s", res.Submission.Job.Type, JobControlPlaneApply)
	}
	if res.Route == nil {
		t.Fatal("an expose that needs no approval admitted no route")
	}
	if res.Route.Hostname != shop || res.Route.Phase != database.AppRouteWaiting {
		t.Errorf("route = %+v, want %s in waiting", res.Route, shop)
	}

	mustf(t, rs.runApproved(res), "run")

	route, err := rs.liveRoute(shop)
	mustf(t, err, "route")
	if route.Phase != database.AppRouteActive {
		t.Fatalf("route phase = %s (%s), want active", route.Phase, route.LastError)
	}
	if rules, apps, records := rs.routeObjects(shop); rules != 1 || apps != 1 || records != 1 {
		t.Errorf("rules, apps, records = %d, %d, %d; want 1, 1, 1", rules, apps, records)
	}
}

func TestAPublicExposeIsHighRiskAndWritesNothingUntilApproved(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "0.0.0.0", 8080))
	before := len(rs.cf.Mutations())

	res, err := rs.expose(ExposeRouteRequest{Hostname: shop, Service: "web", Port: 8080}) // access omitted

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

	if route, err := rs.liveRoute(shop); err != nil || route.Phase != database.AppRouteActive || route.Access != "public" {
		t.Errorf("route = %+v, %v; want active and public", route, err)
	}
}

func TestExposeOfATargetWithoutAKnownGoodWaitsAndDoesNotCallCloudflare(t *testing.T) {
	rs := newRouteSetting(t)
	before := len(rs.cf.Mutations())

	res, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose")
	mustf(t, rs.runApproved(res), "run")

	route, err := rs.liveRoute(shop)
	mustf(t, err, "route")
	if route.Phase != database.AppRouteWaiting {
		t.Errorf("phase = %s, want waiting", route.Phase)
	}
	if len(rs.cf.Mutations()) != before {
		t.Error("a waiting route reached Cloudflare")
	}
}

func TestExposeRefusesBeforeCloudflareAndWritesNoRoute(t *testing.T) {
	cases := []struct {
		name  string
		req   ExposeRouteRequest
		ports []snapshotPort
		setup func(*routeSetting)
		want  string
	}{
		{"suffix spoof", ExposeRouteRequest{Hostname: "shop.evil-example.test", Service: "web", Port: 8080}, nil, nil, "not under the zone"},
		{"another zone", ExposeRouteRequest{Hostname: "shop.example.com", Service: "web", Port: 8080}, nil, nil, "not under the zone"},
		{"the apex", ExposeRouteRequest{Hostname: "example.test", Service: "web", Port: 8080}, nil, nil, "not under the zone"},
		{"ssh namespace", ExposeRouteRequest{Hostname: "ssh-node.example.test", Service: "web", Port: 8080}, nil, nil, "reserved"},
		{"wildcard", ExposeRouteRequest{Hostname: "*.example.test", Service: "web", Port: 8080}, nil, nil, "valid DNS name"},
		{"port zero", ExposeRouteRequest{Hostname: shop, Service: "web", Port: 0}, nil, nil, "port"},
		{"bad access", ExposeRouteRequest{Hostname: shop, Service: "web", Port: 8080, Access: "everyone"}, nil, nil, "access"},
		{
			"hostname in use under another case",
			ExposeRouteRequest{Hostname: "SHOP.example.test", Service: "web", Port: 8080},
			nil,
			func(rs *routeSetting) { rs.addRoute(shop, 9090, "public", database.AppRouteWaiting) }, "already routed",
		},
		{"ipv6 only", webRequest(shop), []snapshotPort{tcpPort("web", "::", 8080)}, nil, "does not publish"},
		{"another interface", webRequest(shop), []snapshotPort{tcpPort("web", "192.168.1.5", 8080)}, nil, "does not publish"},
		{"udp", webRequest(shop), []snapshotPort{{Service: "web", Addr: "127.0.0.1", Port: 8080, Proto: "udp"}}, nil, "does not publish"},
		{"another service", webRequest(shop), []snapshotPort{tcpPort("db", "127.0.0.1", 8080)}, nil, "does not publish"},
		{"a node at its limit", webRequest(shop), []snapshotPort{tcpPort("web", "127.0.0.1", 8080)}, func(rs *routeSetting) {
			for i := range maxRoutesPerNode {
				rs.addRoute(fmt.Sprintf("r%d.example.test", i), 8080, "public", database.AppRouteWaiting)
			}
		}, "limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRouteSetting(t)
			if len(tc.ports) > 0 {
				rs.seedKnownGood(tc.ports...)
			}
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
	rows, err := database.ListAppRoutes(context.Background(), rs.db.Reader(), database.AppRouteFilter{IncludeRemoved: true})
	mustf(rs.t, err, "ListAppRoutes")
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

func TestExposeRefusesWithoutACloudflareBlock(t *testing.T) {
	rs := newRouteSetting(t)
	service := rs.service()
	service.cfg.Cloudflare = nil

	_, err := service.Expose(context.Background(), rs.caller(rs.admin), rs.target.ID, webRequest(shop))

	if err == nil || !strings.Contains(err.Error(), "cloudflare") {
		t.Errorf("Expose = %v, want a refusal naming the missing cloudflare: block", err)
	}
}

func TestExposeAgainOfAHaltedRouteResumesItAndRefusesALiveOne(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)

	_, err := rs.expose(webRequest(shop))
	if err == nil || !strings.Contains(err.Error(), "already routed") {
		t.Fatalf("Expose of a live route = %v, want a conflict", err)
	}

	rs.exec(`UPDATE app_routes SET phase = 'conflict', halted_phase = 'provisioning' WHERE id = ?`, route.ID)
	res, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose of a halted route")
	mustf(t, rs.runApproved(res), "run")

	if rs.countRoutes() != 1 {
		t.Errorf("%d rows, want the halted route and no second one", rs.countRoutes())
	}
	if got := rs.route(route.ID); got.Phase != database.AppRouteActive {
		t.Errorf("phase = %s (%s), want the new job to resume the route to active", got.Phase, got.LastError)
	}
}

func TestApplyApprovedAdmissionIsIdempotentAndNeverAdmitsAgainAfterTheRemoval(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
	res, err := rs.expose(ExposeRouteRequest{Hostname: shop, Service: "web", Port: 8080, Access: "public"}) // waits for approval
	mustf(t, err, "Expose")
	job := rs.approved(res)

	stored := rs.job(job.ID)
	apply := func() {
		rs.inTx(func(ctx context.Context, tx *database.Tx) error {
			return rs.apps().applyApprovedAppRoute(ctx, tx, domain.Actor{ID: rs.admin, Type: domain.ActorHuman}, appRouteExposeAction, stored)
		})
	}
	apply()
	apply()
	if rs.countRoutes() != 1 {
		t.Fatalf("%d routes after two applies, want 1", rs.countRoutes())
	}

	rs.exec(`UPDATE app_routes SET phase = 'removed'`) // the route was unexposed while a retry waited
	apply()

	if rs.countRoutes() != 1 {
		t.Errorf("%d routes after a retry that followed the removal, want the removed one only", rs.countRoutes())
	}
}

func TestExposeAdmitsInWaitingEvenWhenTheVersionPublishesThePort(t *testing.T) {
	rs := newRouteSetting(t)
	rs.exec(`UPDATE environments SET risk_level = 'development'`) // an owners expose needs no approval there
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))

	res, err := rs.expose(webRequest(shop))

	mustf(t, err, "Expose")
	job := res.Submission.Job
	if res.Route == nil || job.State == domain.JobAwaitingApproval {
		t.Fatalf("route = %v, job %s: the request must admit the route itself", res.Route, job.State)
	}
	if res.Route.Phase != database.AppRouteWaiting || res.Route.PlanID == nil || *res.Route.PlanID != *job.PlanID {
		t.Errorf("route = %+v, want waiting with the plan of the job", res.Route)
	}
	rs.wantIngress()

	mustf(t, rs.runApproved(res), "run") // the apply step must not admit it again

	if got := rs.route(res.Route.ID); got.Phase != database.AppRouteActive || rs.countRoutes() != 1 {
		t.Errorf("route = %s (%s), %d rows; want the same route active", got.Phase, got.LastError, rs.countRoutes())
	}
}

func TestAnExposeJobThatRunsAfterTheUnexposeDoesNotAdmitTheRouteAgain(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteWaiting) // admitted by the request transaction
	exposeJob := rs.enqueue(appRouteExposeAction, route)
	rs.exec(`UPDATE jobs SET scheduled_at = scheduled_at + 600000 WHERE id = ?`, exposeJob.ID) // still queued when the unexpose comes
	unexpose, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.target.ID, shop)
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
		halted database.AppRoutePhase
	}{
		{"ingress_ready", 2, database.AppRouteIngressReady},
		{"access_ready", 3, database.AppRouteAccessReady},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRouteSetting(t)
			rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
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
			if route.Phase != database.AppRouteFailed || route.HaltedPhase != tc.halted {
				t.Fatalf("route = %s (halted in %s), want failed in %s", route.Phase, route.HaltedPhase, tc.halted)
			}
			rs.wantIngress() // a halt while exposing withdraws the rule

			again, err := rs.expose(webRequest(shop))
			mustf(t, err, "Expose of the halted route")
			mustf(t, rs.runApproved(again), "run")

			if got := rs.route(route.ID); got.Phase != database.AppRouteActive || rs.countRoutes() != 1 {
				t.Errorf("route = %s (%s), %d rows; want the same route active", got.Phase, got.LastError, rs.countRoutes())
			}
			rs.wantIngress(shop)
		})
	}
}

func TestExposeAgainChecksTheAccessApplicationBeforeAnOwnersRouteServesAgain(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
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
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
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

	if got := rs.route(route.ID).Phase; got != database.AppRouteFailed {
		t.Errorf("phase = %s, want failed: the route must not serve before its preflight passes", got)
	}
	rs.wantIngress()
}

func TestAWaitingRouteStaysWaitingWhenTheNewestVersionNoLongerPublishesItsPort(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteWaiting) // admitted while the old version still publishes 8080
	rs.enqueue(appRouteExposeAction, route)
	rs.clock.Advance(time.Minute)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 9090)) // the deployment that passed its guard earlier succeeds without 8080
	before := len(rs.cf.Mutations())

	mustf(t, rs.attempt(), "run")

	if got := rs.route(route.ID).Phase; got != database.AppRouteWaiting {
		t.Errorf("phase = %s, want waiting", got)
	}
	if len(rs.cf.Mutations()) != before {
		t.Error("a route whose port is not published reached Cloudflare")
	}
}

// ---- unexpose --------------------------------------------------------------------------------------

func TestUnexposeRemovesTheRouteAndAnotherTargetsHostnameIsNotFound(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")

	_, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), domain.ID("other-target"), shop)
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("Unexpose of a hostname of another target = %v, want NOT_FOUND", err)
	}

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.target.ID, strings.ToUpper(shop))
	mustf(t, err, "Unexpose")
	mustf(t, rs.runApproved(res), "run")

	if got := rs.route(route.ID); got.Phase != database.AppRouteRemoved {
		t.Errorf("phase = %s, want removed", got.Phase)
	}
	if rules, apps, records := rs.routeObjects(shop); rules+apps+records != 0 {
		t.Errorf("rules, apps, records = %d, %d, %d; want none", rules, apps, records)
	}
}

func TestUnexposeAfterTheNodesTunnelChangedStillRemovesWhatItOwns(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
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

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.target.ID, shop)
	mustf(t, err, "Unexpose")
	mustf(t, rs.runApproved(res), "run")

	if got := rs.route(route.ID); got.Phase != database.AppRouteRemoved {
		t.Fatalf("phase = %s (%s), want removed", got.Phase, got.LastError)
	}
	rules, apps, records := rs.routeObjects(shop)
	if apps != 0 || records != 0 {
		t.Errorf("apps, records = %d, %d; want the Access app and the DNS record deleted", apps, records)
	}
	if rules != 1 {
		t.Errorf("rules = %d, want the ingress step skipped for a tunnel that is not the node's", rules)
	}
}

func TestUnexposeAfterTheZoneChangedMarksTheRouteRemovedWithoutCloudflare(t *testing.T) {
	rs := newRouteSetting(t)
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	rs.enqueue(appRouteExposeAction, route)
	mustf(t, rs.attempt(), "expose")
	exposed := rs.route(route.ID)
	rs.routes.tunnel.opts.Config.Zone = "new.example.test" // the instance now serves another zone
	before := len(rs.cf.Mutations())

	res, err := rs.service().Unexpose(context.Background(), rs.caller(rs.admin), rs.target.ID, shop)
	mustf(t, err, "Unexpose")
	mustf(t, rs.runApproved(res), "run")

	if got := rs.route(route.ID); got.Phase != database.AppRouteRemoved {
		t.Fatalf("phase = %s (%s), want removed", got.Phase, got.LastError)
	}
	if len(rs.cf.Mutations()) != before {
		t.Error("an unexpose across a changed zone called Cloudflare")
	}
	events := rs.events("app_route.removed")
	last := events[len(events)-1]
	if last.Data["abandoned"] != true || last.Data["dns_record_id"] != exposed.Objects.DNSRecordID || last.Data["access_app_id"] != exposed.Objects.AccessAppID {
		t.Errorf("event data = %+v, want the abandoned objects listed", last.Data)
	}
}

// ---- revalidation and the system's plan -----------------------------------------------------------------

func TestARouteJobIsRevalidatedAgainstItsPlan(t *testing.T) {
	rs := newRouteSetting(t)
	rs.seedKnownGood(tcpPort("web", "127.0.0.1", 8080))
	res, err := rs.expose(webRequest(shop))
	mustf(t, err, "Expose")
	rs.exec(`UPDATE environments SET spec_revision = spec_revision + 1 WHERE id = ?`, rs.target.EnvironmentID)

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

func TestTheSystemsActivationPlanRevalidatesAndRunsTheRoute(t *testing.T) {
	rs := newRouteSetting(t)
	var system domain.ID
	rs.inTx(func(ctx context.Context, tx *database.Tx) error {
		system = rs.fixture.identity(ctx, tx, "system", domain.ActorSystem, "")
		return nil
	})
	route := rs.addRoute(shop, 8080, "owners", database.AppRouteProvisioning)
	h := deployHandler{core: rs.handler.core, store: rs.store, systemID: system}

	rs.inTx(func(ctx context.Context, tx *database.Tx) error { return h.submitExpose(ctx, tx, route) })

	rs.current = rs.applyHandler()
	mustf(t, rs.attempt(), "run")
	got := rs.route(route.ID)
	if got.Phase != database.AppRouteActive {
		t.Fatalf("phase = %s (%s), want active", got.Phase, got.LastError)
	}
	open, err := h.hasOpenExposeJob(context.Background(), rs.db.Reader(), got)
	mustf(t, err, "hasOpenExposeJob")
	if open {
		t.Error("the finished job still counts as open")
	}
	if !slices.Contains(eventActions(rs.events()), "plan.submit") {
		t.Error("the activation was not planned")
	}
}

func eventActions(events []domain.Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Action
	}
	return out
}

func TestRouteServedAcceptsOnlyWhatTheConnectorDials(t *testing.T) {
	port := func(addr, proto string) []compose.HostPort {
		return []compose.HostPort{{Service: "web", Addr: netip.MustParseAddr(addr), Port: 8080, Proto: proto}}
	}
	for _, tc := range []struct {
		name  string
		ports []compose.HostPort
		want  bool
	}{
		{"loopback", port("127.0.0.1", "tcp"), true},
		{"every IPv4 interface", port("0.0.0.0", "tcp"), true},
		{"every interface in the mapped form", port("::ffff:0.0.0.0", "tcp"), true},
		{"IPv6 wildcard", port("::", "tcp"), false},
		{"IPv6 loopback", port("::1", "tcp"), false},
		{"another interface", port("10.0.0.5", "tcp"), false},
		{"UDP", port("127.0.0.1", "udp"), false},
	} {
		if got := routeServed(tc.ports, "web", 8080); got != tc.want {
			t.Errorf("%s: routeServed = %v, want %v", tc.name, got, tc.want)
		}
	}
}
