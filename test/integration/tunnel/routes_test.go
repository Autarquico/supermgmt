package tunnel

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// Scenarios "a node port is published without a deployment", "owners-only routes get Access before DNS",
// "admission refuses what cannot work" and "unexpose removes in reverse order" (docs/specs/node-routes.md) on
// the real stack: a node enrolled through the carrier, the job engine running the control_plane.apply job of
// the route plan, and cffake as Cloudflare. No app or deployment exists. The setup rerun that keeps the rules
// needs a node that runs setup, which is the fixtures suite; the unit test TestASetupRerunKeepsTheRouteRules
// holds it.

const routeHost = "shop." + cffake.DefaultZone

// finish approves the job of a route request when policy asks, and waits for it.
func (r *enrollRig) finish(res app.NodeRouteResult) jobs.Job {
	r.t.Helper()
	job := res.Submission.Job
	if job.State == domain.JobAwaitingApproval {
		var err error
		job, err = r.appr.Approve(context.Background(), r.admin, app.DecisionRequest{JobID: job.ID, PlanHash: job.PlanHash, Reason: "route suite"})
		must(r.t, err)
	}
	return r.wait(job.ID, time.Minute)
}

func (r *enrollRig) routeObjects() (ingress []cffake.Ingress, apps, records []string) {
	r.t.Helper()
	tunnels := r.cf.Tunnels()
	if len(tunnels) != 1 {
		r.t.Fatalf("%d tunnels, want 1", len(tunnels))
	}
	for _, a := range r.cf.Apps() {
		if a.Domain == routeHost {
			apps = append(apps, a.ID)
		}
	}
	for _, d := range r.cf.DNSRecords() {
		if d.Name == routeHost {
			records = append(records, d.ID)
		}
	}
	return tunnels[0].Ingress, apps, records
}

func TestAnOwnersRouteOfANodePortIsExposedThroughTheEngineAndUnexposedInReverse(t *testing.T) {
	r := newEnrollRig(t, stackOptions{})
	_, node := r.enrollToCommit("vps1")
	ctx := context.Background()

	res, err := r.routes.Expose(ctx, r.admin, node.ID, app.ExposeRouteRequest{Hostname: "Shop." + cffake.DefaultZone, Port: 8080, Access: "owners"})
	must(t, err)
	if job := r.finish(res); job.State != domain.JobSucceeded {
		t.Fatalf("expose job = %s (%s)", job.State, r.logs.bytes())
	}

	ingress, apps, records := r.routeObjects()
	if len(ingress) != 3 || ingress[0].Service != cloudflare.ServiceSSH || ingress[1] != (cffake.Ingress{Hostname: routeHost, Service: "http://127.0.0.1:8080"}) ||
		ingress[2].Service != cloudflare.ServiceNotFound {
		t.Errorf("ingress = %+v, want the SSH rule, the route and the 404", ingress)
	}
	if len(apps) != 1 || len(records) != 1 {
		t.Errorf("Access applications %v, DNS records %v; want one each", apps, records)
	}
	if routable := r.cf.EverRoutableWithoutAccess(); slices.ContainsFunc(routable, func(h string) bool { return strings.EqualFold(h, routeHost) }) {
		t.Errorf("%s was routable without Access: %v", routeHost, routable)
	}
	route, err := database.GetLiveNodeRouteByHostname(ctx, r.db.Reader(), routeHost)
	must(t, err)
	if route.Phase != database.NodeRouteActive {
		t.Fatalf("route = %s (%s), want active", route.Phase, route.LastError)
	}

	res, err = r.routes.Unexpose(ctx, r.admin, node.ID, routeHost)
	must(t, err)
	if job := r.finish(res); job.State != domain.JobSucceeded {
		t.Fatalf("unexpose job = %s (%s)", job.State, r.logs.bytes())
	}

	ingress, apps, records = r.routeObjects()
	if len(ingress) != 2 || ingress[0].Service != cloudflare.ServiceSSH || ingress[1].Service != cloudflare.ServiceNotFound || len(apps) != 0 || len(records) != 0 {
		t.Errorf("after unexpose: ingress %+v, Access applications %v, DNS records %v", ingress, apps, records)
	}
	if _, err := database.GetLiveNodeRouteByHostname(ctx, r.db.Reader(), routeHost); err == nil {
		t.Error("the hostname is still held by a live route")
	}
	res, err = r.routes.Expose(ctx, r.admin, node.ID, app.ExposeRouteRequest{Hostname: routeHost, Port: 8080})
	must(t, err)
	if res.Submission.Job.State != domain.JobAwaitingApproval {
		t.Fatalf("a public expose is %s, want awaiting_approval", res.Submission.Job.State)
	}
	if res.Route != nil {
		t.Errorf("a public expose waiting for approval wrote %+v", res.Route)
	}
	if _, err := database.GetLiveNodeRouteByHostname(ctx, r.db.Reader(), routeHost); err == nil {
		t.Error("a route row exists before the approval")
	}
	if _, _, records := r.routeObjects(); len(records) != 0 {
		t.Errorf("DNS records %v exist before the approval", records)
	}
	if job := r.finish(res); job.State != domain.JobSucceeded {
		t.Fatalf("expose again = %s (%s)", job.State, r.logs.bytes())
	}
	listed, err := r.routes.List(ctx, r.admin, node.ID, false)
	must(t, err)
	if len(listed) != 1 || listed[0].Hostname != routeHost || listed[0].Access != "public" || listed[0].Phase != database.NodeRouteActive {
		t.Errorf("routes = %+v, want %s public and active", listed, routeHost)
	}
}

func TestAPublicRouteIsInTheIngressBeforeTheCatchAllAndGetsDNSWithoutAnyDeployment(t *testing.T) {
	r := newEnrollRig(t, stackOptions{})
	_, node := r.enrollToCommit("vps1")
	ctx := context.Background()

	res, err := r.routes.Expose(ctx, r.admin, node.ID, app.ExposeRouteRequest{Hostname: routeHost, Port: 8080})
	must(t, err)
	if job := r.finish(res); job.State != domain.JobSucceeded {
		t.Fatalf("expose job = %s (%s)", job.State, r.logs.bytes())
	}

	ingress, apps, records := r.routeObjects()
	if len(ingress) != 3 || ingress[1] != (cffake.Ingress{Hostname: routeHost, Service: "http://127.0.0.1:8080"}) || ingress[2].Service != cloudflare.ServiceNotFound {
		t.Errorf("ingress = %+v, want the SSH rule, the route and the 404 last", ingress)
	}
	if len(apps) != 0 || len(records) != 1 {
		t.Errorf("Access applications %v, DNS records %v; want no Access application and one record for a public route", apps, records)
	}
	route, err := database.GetLiveNodeRouteByHostname(ctx, r.db.Reader(), routeHost)
	must(t, err)
	if route.Phase != database.NodeRouteActive || route.Port != 8080 || route.NodeID != node.ID {
		t.Errorf("route = %+v, want active on port 8080 of the node", route)
	}
}

func TestAdmissionRefusesTheSSHPortAPortAlreadyRoutedAndAHostnameOutsideTheZone(t *testing.T) {
	r := newEnrollRig(t, stackOptions{})
	_, node := r.enrollToCommit("vps1")
	ctx := context.Background()
	res, err := r.routes.Expose(ctx, r.admin, node.ID, app.ExposeRouteRequest{Hostname: routeHost, Port: 8080, Access: "owners"})
	must(t, err)
	if job := r.finish(res); job.State != domain.JobSucceeded {
		t.Fatalf("expose job = %s (%s)", job.State, r.logs.bytes())
	}
	mutations := len(r.cf.Mutations())

	for name, c := range map[string]struct {
		req  app.ExposeRouteRequest
		want string
	}{
		"the SSH port":              {app.ExposeRouteRequest{Hostname: "admin." + cffake.DefaultZone, Port: 22, Access: "owners"}, "SSH port"},
		"a port already routed":     {app.ExposeRouteRequest{Hostname: "again." + cffake.DefaultZone, Port: 8080, Access: "owners"}, "already routed"},
		"a hostname outside a zone": {app.ExposeRouteRequest{Hostname: "shop.other.invalid", Port: 9090, Access: "owners"}, "not under the zone"},
		"a hostname already live":   {app.ExposeRouteRequest{Hostname: routeHost, Port: 9090, Access: "owners"}, "already routed"},
	} {
		if _, err := r.routes.Expose(ctx, r.admin, node.ID, c.req); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Expose = %v, want an error containing %q", name, err, c.want)
		}
	}
	if got := len(r.cf.Mutations()); got != mutations {
		t.Errorf("refused requests wrote %d Cloudflare objects", got-mutations)
	}
	listed, err := r.routes.List(ctx, r.admin, node.ID, false)
	must(t, err)
	if len(listed) != 1 {
		t.Errorf("routes = %+v, want only the first", listed)
	}
}
