package tunnel

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// Scenarios "an app on a tunnel node is exposed with one command", "an owners route is guarded before it has
// DNS" and "unexpose removes in reverse order" (docs/specs/app-expose-tunnel.md) on the real stack: a node
// enrolled through the carrier, the job engine running the control_plane.apply job of the route plan, and
// cffake as Cloudflare. The setup rerun that keeps the rules needs a node that runs setup, which is the
// fixtures suite; the unit test TestASetupRerunKeepsTheRouteRules holds it.

// noGitHub stands for the GitHub clients an instance with no repositories never asks.
type noGitHub struct{ app.GitHubClients }

const routeHost = "shop." + cffake.DefaultZone

// seedExposableTarget gives the node an app target whose newest known-good deployment publishes web on
// 127.0.0.1:8080.
func seedExposableTarget(r *enrollRig, node domain.Node) database.AppTarget {
	r.t.Helper()
	var target database.AppTarget
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		now := r.clock.Now()
		env, err := database.CreateEnvironment(ctx, tx, domain.Environment{ID: r.ids.NewID(), Name: "prod", RiskLevel: domain.EnvironmentProduction})
		if err != nil {
			return err
		}
		a, err := database.CreateApp(ctx, tx, database.App{
			ID: r.ids.NewID(), Name: "shop", DeployedService: "web", ImagePolicyJSON: []byte(`{}`),
			ComposeSource: "control-plane", CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		target, err = database.CreateAppTarget(ctx, tx, database.AppTarget{
			ID: r.ids.NewID(), AppID: a.ID, EnvironmentID: env.ID, NodeID: node.ID, ComposeProject: "sm-shop-prod",
			DeploymentPolicyJSON: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		content, err := json.Marshal(map[string]any{
			"public": "services: {}", "effective": json.RawMessage(`{}`), "images": []any{}, "secrets": []any{},
			"host_ports": []map[string]any{{"service": "web", "addr": "127.0.0.1", "port": 8080, "proto": "tcp"}},
		})
		if err != nil {
			return err
		}
		hash := database.ExecutionSnapshotHash(content)
		if err := database.PutExecutionSnapshot(ctx, tx, database.ExecutionSnapshot{
			Hash: hash, Kind: database.SnapshotComposeModel, Content: content, CreatedAt: now,
		}); err != nil {
			return err
		}
		raw, err := plan.Canonical(&plan.Plan{
			Version: plan.Version, Action: "deployment.create", Actor: "identity/" + r.admin.ID.String(),
			Targets: []plan.Target{{Type: string(domain.ResourceAppTarget), ID: target.ID.String()}},
			Content: plan.Content{ComposeHash: &hash}, Risk: domain.RiskOperational,
		})
		if err != nil {
			return err
		}
		rec := database.PlanRecord{
			ID: r.ids.NewID(), Action: "deployment.create", ActorID: r.admin.ID, Credential: r.admin.Credential, PlanJSON: raw,
			PlanHash: "hash-" + hash, FinalizedAt: now, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		}
		if err := database.InsertPlan(ctx, tx, rec); err != nil {
			return err
		}
		dep := database.Deployment{
			ID: r.ids.NewID(), Kind: deployments.KindDeploy, AppID: a.ID, AppTargetID: target.ID, EnvironmentID: env.ID,
			NodeID: node.ID, State: deployments.StateCreated, RequestedBy: r.admin.ID, Credential: r.admin.Credential,
			CommitSha: "abc", RequestedRaw: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
		}
		if err := database.InsertDeployment(ctx, tx, dep); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE deployments SET plan_id = ?, state = 'succeeded', known_good = 1, finished_at = ? WHERE id = ?`,
			rec.ID, domain.UnixMillis(now), dep.ID)
		return err
	}))
	return target
}

// finish approves the job of a route request when policy asks, and waits for it.
func (r *enrollRig) finish(res app.AppRouteResult) jobs.Job {
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

func TestAnOwnersRouteIsExposedThroughTheEngineAndUnexposedInReverse(t *testing.T) {
	r := newEnrollRig(t, stackOptions{withApps: true})
	_, node := r.enrollToCommit("vps1")
	target := seedExposableTarget(r, node)
	ctx := context.Background()

	res, err := r.apps.Routes().Expose(ctx, r.admin, target.ID, app.ExposeRouteRequest{Hostname: "Shop." + cffake.DefaultZone, Service: "web", Port: 8080, Access: "owners"})
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
	route, err := database.GetLiveAppRouteByHostname(ctx, r.db.Reader(), routeHost)
	must(t, err)
	if route.Phase != database.AppRouteActive {
		t.Fatalf("route = %s (%s), want active", route.Phase, route.LastError)
	}

	res, err = r.apps.Routes().Unexpose(ctx, r.admin, target.ID, routeHost)
	must(t, err)
	if job := r.finish(res); job.State != domain.JobSucceeded {
		t.Fatalf("unexpose job = %s (%s)", job.State, r.logs.bytes())
	}

	ingress, apps, records = r.routeObjects()
	if len(ingress) != 2 || ingress[0].Service != cloudflare.ServiceSSH || ingress[1].Service != cloudflare.ServiceNotFound || len(apps) != 0 || len(records) != 0 {
		t.Errorf("after unexpose: ingress %+v, Access applications %v, DNS records %v", ingress, apps, records)
	}
	if _, err := database.GetLiveAppRouteByHostname(ctx, r.db.Reader(), routeHost); err == nil {
		t.Error("the hostname is still held by a live route")
	}
	res, err = r.apps.Routes().Expose(ctx, r.admin, target.ID, app.ExposeRouteRequest{Hostname: routeHost, Service: "web", Port: 8080})
	must(t, err)
	if res.Submission.Job.State != domain.JobAwaitingApproval {
		t.Fatalf("a public expose is %s, want awaiting_approval", res.Submission.Job.State)
	}
	if res.Route != nil {
		t.Errorf("a public expose waiting for approval wrote %+v", res.Route)
	}
	if _, err := database.GetLiveAppRouteByHostname(ctx, r.db.Reader(), routeHost); err == nil {
		t.Error("a route row exists before the approval")
	}
	if _, _, records := r.routeObjects(); len(records) != 0 {
		t.Errorf("DNS records %v exist before the approval", records)
	}
	if job := r.finish(res); job.State != domain.JobSucceeded {
		t.Fatalf("expose again = %s (%s)", job.State, r.logs.bytes())
	}
	listed, err := r.apps.Routes().List(ctx, r.admin, target.ID)
	must(t, err)
	if len(listed) != 1 || listed[0].Hostname != routeHost || listed[0].Access != "public" || listed[0].Phase != database.AppRouteActive {
		t.Errorf("routes = %+v, want %s public and active", listed, routeHost)
	}
}
