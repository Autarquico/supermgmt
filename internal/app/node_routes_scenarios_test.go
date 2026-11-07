package app

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const apiHost = "api.example.test"

// Two route jobs and a node setup are all ingress writers: the lock planner lets one run at a time, and the
// last one still sees the rules of the others.
func TestTwoExposesRacingASetupLeaveTheSSHRuleAndBothRoutes(t *testing.T) {
	rs := newRouteSetting(t)
	first := rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	second := rs.addRoute(apiHost, 8081, "public", database.NodeRouteProvisioning)
	exposeFirst := rs.enqueue(nodeRouteExposeAction, first)
	exposeSecond := rs.enqueue(nodeRouteExposeAction, second)
	setup := rs.plan()
	handlers := map[string]jobs.Handler{exposeFirst.ID.String(): rs.routes, exposeSecond.ID.String(): rs.routes, setup.ID.String(): rs.handler}

	for range 3 {
		claimed, ok := rs.claim()
		if !ok {
			t.Fatalf("no job to claim (states: %s %s %s)", rs.job(exposeFirst.ID).State, rs.job(exposeSecond.ID).State, rs.job(setup.ID).State)
		}
		if _, concurrent := rs.claim(); concurrent {
			t.Fatalf("a second ingress writer was claimed while %s runs", claimed.Job.ID)
		}
		mustf(t, handlers[claimed.Job.ID.String()].Run(context.Background(), claimed.Lease), "run")
		mustf(t, rs.store.Succeed(context.Background(), claimed.Lease), "Succeed")
		rs.clock.Advance(time.Minute) // the blocked claims were deferred
	}

	rs.wantIngress(apiHost, shop) // sorted by hostname
	for _, route := range []database.NodeRoute{first, second} {
		if got := rs.route(route.ID).Phase; got != database.NodeRouteActive {
			t.Errorf("%s = %s, want active", route.Hostname, got)
		}
	}
}

func FuzzRouteHostname(f *testing.F) {
	for _, seed := range []string{
		"shop.example.test", "SHOP.Example.Test.", " shop.example.test ", "evil-example.test", "shop.evil-example.test",
		"example.test", ".example.test", "ssh-web-1.example.test", "a..example.test", "-a.example.test", "*.example.test",
		"bücher.example.test", "shop.example.test\x00", strings.Repeat("a", 64) + ".example.test",
		strings.Repeat("a.", 130) + "example.test",
	} {
		f.Add(seed, "example.test")
	}
	f.Add("shop.example.test", "Example.Test.")
	f.Fuzz(func(t *testing.T, hostname, zone string) {
		host, err := routeHostname(hostname, zone)
		if err != nil {
			return
		}
		if host != canonicalHostname(host) {
			t.Errorf("%q is not canonical", host)
		}
		if !strings.HasSuffix(host, "."+canonicalHostname(zone)) || len(host) > 253 || strings.HasPrefix(host, reservedSSHLabelPrefix) {
			t.Errorf("accepted %q for zone %q", host, zone)
		}
		for _, label := range strings.Split(host, ".") {
			if !validDNSLabel(label) {
				t.Errorf("accepted %q with the label %q", host, label)
			}
		}
		if !utf8.ValidString(host) || strings.ContainsAny(host, "*/ \x00") {
			t.Errorf("accepted %q", host)
		}
	})
}

// addActiveRoute puts an active route of the fixture's node on port, which the fixture's model does not publish.
func (f *finFixture) addActiveRoute(port int) database.NodeRoute {
	f.t.Helper()
	var route database.NodeRoute
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		inserted, err := database.InsertNodeRoute(ctx, tx, database.NodeRoute{
			ID: f.ids.NewID(), NodeID: f.node.ID, Hostname: shop, Port: port, Access: "public",
			AccountID: "acct", Zone: "example.test", InstanceID: "inst", TunnelID: "tunnel", TunnelGeneration: 1,
			CreatedBy: f.deployer, CreatedAt: f.clock.Now(),
		})
		if err != nil {
			return err
		}
		for _, step := range [][2]database.NodeRoutePhase{
			{database.NodeRouteAdmitted, database.NodeRouteProvisioning},
			{database.NodeRouteProvisioning, database.NodeRouteIngressReady},
			{database.NodeRouteIngressReady, database.NodeRouteActive},
		} {
			if inserted, err = database.AdvanceNodeRoutePhase(ctx, tx, inserted.ID, step[0], step[1], database.NodeRouteObjects{}, f.clock.Now()); err != nil {
				return err
			}
		}
		route = inserted
		return nil
	})
	return route
}

// A deployment is not held to the ports the node routes: the route answers whatever listens there.
func TestADeploymentThatDoesNotPublishARoutedPortIsAcceptedAndTheRouteStaysActive(t *testing.T) {
	w := newDeployWorld(t) // its model publishes web on 127.0.0.1:8080 only
	route := w.addActiveRoute(9090)

	dep := w.queued()
	mustf(t, w.run(), "Run")

	w.want(dep.ID, deployments.StateSucceeded)
	got, err := database.GetNodeRoute(context.Background(), w.db.Reader(), route.ID)
	mustf(t, err, "GetNodeRoute")
	if got.Phase != database.NodeRouteActive {
		t.Errorf("route = %s, want active", got.Phase)
	}
}

func TestFinalizingADeploymentAndItsAutomaticRollbackIgnoreTheRoutedPorts(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.goodDeployment(depCommit) // the automatic rollback target
	f.addActiveRoute(9090)
	created := f.create(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })

	got := f.mustFinalize(created.ID)

	if got.State != deployments.StateQueued || f.planOf(created.ID).Content.RollbackTarget == nil {
		t.Errorf("deployment = %s with rollback target %v, want it queued with a plan that can roll back", got.State, f.planOf(created.ID).Content.RollbackTarget)
	}
}

func TestARollbackToAVersionThatDoesNotPublishTheRoutedPortIsAccepted(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	good := f.goodDeployment(depCommit)
	newer := f.goodDeployment(depOtherCommit)
	f.addActiveRoute(9090)

	view := f.mustRollback(newer.ID, wire.RollbackRequest{ToDeploymentID: &good.ID})

	if view.State != string(deployments.StateQueued) {
		t.Errorf("rollback = %s, want queued", view.State)
	}
}
