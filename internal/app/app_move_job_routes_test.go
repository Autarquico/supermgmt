package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// ---- a routed move running against cffake -----------------------------------------------------------------------

// routedRun is a run world whose nodes both have a Cloudflare tunnel in cffake and whose target has routes there. The
// assertions read Cloudflare, the nodes and the database, not only the phase names.
type routedRun struct {
	*runWorld
	cf         *cffake.Fake
	api        CloudflareAPI
	instance   domain.ID
	opts       *TunnelOptions
	tunA, tunB cffake.Tunnel
	zoneID     string
}

const (
	sshOfA = "ssh-web-1." + cffake.DefaultZone
	sshOfB = "ssh-web-2." + cffake.DefaultZone
)

func newRoutedRun(t *testing.T, o runOptions) *routedRun {
	t.Helper()
	w := newRunWorld(t, o)
	cfg := config.Cloudflare{
		AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, APITokenRef: testAPIToken, AccessTokenRef: testAccessToken,
		OwnerEmails: []string{"owner@example.test"}, AccessIdentityProviders: []string{"11111111-1111-4111-8111-111111111111"},
	}
	rr := &routedRun{runWorld: w, cf: cffake.New(t, cffake.WithClock(w.clock.Now))}
	store := newMemSecrets()
	_, err := store.Put(context.Background(), "cloudflare/api-token", audit.Secret(rr.cf.Token()), nil)
	mustf(t, err, "Put the API token")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rr.cf.CAPEM())
	rr.opts = &TunnelOptions{
		Config: cfg, Secrets: store, Sleep: func(context.Context, time.Duration) {},
		NewAPI: func(account string, token audit.Secret) (CloudflareAPI, error) {
			return cloudflare.New(rr.cf.Endpoint(), account, token,
				cloudflare.WithNetguardOptions(netguard.WithRootCAs(pool), netguard.WithTestDialer(rr.cf.Dial)))
		},
	}
	w.cfg.Cloudflare, w.svc.cfg.Cloudflare, w.plans.cfg.Cloudflare, w.handler.cfg.Cloudflare = &cfg, &cfg, &cfg, &cfg
	mustf(t, w.svc.UseTunnel(rr.opts), "UseTunnel")
	w.handler.tunnel, err = newTunnelEngine(w.handler.core, rr.opts)
	mustf(t, err, "newTunnelEngine")

	rr.tunA, rr.tunB = rr.cf.SeedTunnel("a"), rr.cf.SeedTunnel("b")
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		instance := database.Instance{ID: w.ids.NewID(), Name: "sm", CreatedAt: w.clock.Now()}
		if err := database.CreateInstance(ctx, tx, instance); err != nil {
			return err
		}
		rr.instance = instance.ID
		for node, tunnel := range map[domain.ID]string{w.node.ID: rr.tunA.ID, w.dest.ID: rr.tunB.ID} {
			_, err := database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
				ID: w.ids.NewID(), NodeID: node, AccountID: cfg.AccountID, Zone: cfg.Zone, InstanceID: instance.ID.String(),
				Hostname: "ssh.example.test", Objects: database.TunnelObjects{TunnelID: tunnel}, CreatedAt: w.clock.Now(),
			})
			if err != nil {
				return err
			}
		}
		for node, host := range map[domain.ID]string{w.node.ID: sshOfA, w.dest.ID: sshOfB} {
			n, err := database.GetNode(ctx, tx, node)
			if err != nil {
				return err
			}
			n.Endpoint.Transport, n.Endpoint.TunnelHostname = domain.TransportCloudflare, host
			if _, err := database.UpdateNodeSpec(ctx, tx, n, n.SpecRevision); err != nil {
				return err
			}
		}
		return nil
	})
	run, err := w.handler.tunnel.newInstanceRun(context.Background(), jobs.Lease{}, jobs.Job{})
	mustf(t, err, "newInstanceRun")
	rr.api = run.api
	zone, err := rr.api.ZoneByName(context.Background(), cfg.Zone)
	mustf(t, err, "ZoneByName")
	rr.zoneID = zone.ID
	policy := rr.cf.SeedPolicy(cloudflare.OwnersPolicyName(rr.instance.String()), "owner@example.test")
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.SaveCloudflareState(ctx, tx, database.CloudflareState{AccountID: cfg.AccountID, OwnersPolicyID: policy.ID}, 0, w.clock.Now())
		return err
	})
	rr.syncNode(w.node.ID)
	rr.syncNode(w.dest.ID)
	return rr
}

// main is the world's own app target, on A.
func (rr *routedRun) main() database.AppTarget {
	rr.t.Helper()
	target, err := database.GetAppTarget(context.Background(), rr.db.Reader(), rr.target.ID)
	mustf(rr.t, err, "GetAppTarget")
	return target
}

// syncNode writes the node's desired ingress to its tunnel, as any writer of the shared builder does.
func (rr *routedRun) syncNode(node domain.ID) {
	rr.t.Helper()
	tunnel, ssh := rr.tunA.ID, sshOfA
	if node == rr.dest.ID {
		tunnel, ssh = rr.tunB.ID, sshOfB
	}
	want, err := desiredIngress(context.Background(), rr.db.Reader(), node, ssh, "")
	mustf(rr.t, err, "desiredIngress")
	_, err = rr.api.PutTunnelIngress(context.Background(), tunnel, want)
	mustf(rr.t, err, "PutTunnelIngress")
}

// addTarget adds an app target of its own on node.
func (rr *routedRun) addTarget(name string, node domain.ID) database.AppTarget {
	rr.t.Helper()
	var target database.AppTarget
	rr.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := rr.clock.Now()
		app, err := database.CreateApp(ctx, tx, database.App{
			ID: rr.ids.NewID(), Name: name, DeployedService: "web", ImagePolicyJSON: []byte(`{}`), ComposeSource: "control-plane",
			CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		target, err = database.CreateAppTarget(ctx, tx, database.AppTarget{
			ID: rr.ids.NewID(), AppID: app.ID, EnvironmentID: rr.env.ID, NodeID: node, ComposeProject: "sm-" + name,
			DeploymentPolicyJSON: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		})
		return err
	})
	return target
}

// expose gives the target an active route with the objects Cloudflare holds for it: the Access application of an
// owners route, the marked CNAME to the tunnel of the target's node and the rule in that node's ingress.
func (rr *routedRun) expose(target database.AppTarget, hostname, access string) database.AppRoute {
	rr.t.Helper()
	ctx := context.Background()
	tunnel := rr.tunA.ID
	if target.NodeID == rr.dest.ID {
		tunnel = rr.tunB.ID
	}
	var route database.AppRoute
	rr.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		route, err = database.InsertAppRoute(ctx, tx, database.AppRoute{
			ID: rr.ids.NewID(), AppTargetID: target.ID, NodeID: target.NodeID, Hostname: hostname, Service: "web", Port: 8080,
			Access: access, AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, InstanceID: rr.instance.String(),
			TunnelID: tunnel, TunnelGeneration: 1, CreatedBy: rr.admin, CreatedAt: rr.clock.Now(),
		})
		return err
	})
	var appID string
	if access == "owners" {
		state, err := database.GetCloudflareState(ctx, rr.db.Reader())
		mustf(rr.t, err, "GetCloudflareState")
		app, err := rr.api.CreateAccessApp(ctx, cloudflare.AppSpec{
			Name: cloudflare.RouteAccessAppName(rr.instance.String(), route.ID.String()), Domain: hostname,
			PolicyIDs: []string{state.OwnersPolicyID}, AllowedIdPs: rr.opts.Config.AccessIdentityProviders,
		})
		mustf(rr.t, err, "CreateAccessApp")
		appID = app.ID
	}
	record, err := rr.api.CreateTunnelCNAME(ctx, rr.zoneID, hostname, tunnel, cloudflare.RouteDNSComment(rr.instance.String(), route.ID.String()))
	mustf(rr.t, err, "CreateTunnelCNAME")
	rr.exec(`UPDATE app_routes SET phase = 'active', dns_record_id = ?, access_app_id = ? WHERE id = ?`, record.ID, appID, route.ID)
	rr.syncNode(target.NodeID)
	return rr.route(route.ID)
}

func (rr *routedRun) route(id domain.ID) database.AppRoute {
	rr.t.Helper()
	r, err := database.GetAppRoute(context.Background(), rr.db.Reader(), id)
	mustf(rr.t, err, "GetAppRoute")
	return r
}

// waiting adds a route of the target that has no Cloudflare objects yet.
func (rr *routedRun) waiting(target database.AppTarget, hostname string) database.AppRoute {
	rr.t.Helper()
	var route database.AppRoute
	rr.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		route, err = database.InsertAppRoute(ctx, tx, database.AppRoute{
			ID: rr.ids.NewID(), AppTargetID: target.ID, NodeID: target.NodeID, Hostname: hostname, Service: "web", Port: 8080,
			Access: "public", AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, InstanceID: rr.instance.String(),
			TunnelID: rr.tunA.ID, TunnelGeneration: 1, CreatedBy: rr.admin, CreatedAt: rr.clock.Now(),
		})
		return err
	})
	return route
}

// ---- reading Cloudflare and the database -----------------------------------------------------------------------------

// content is where the hostname's record points: "a", "b" or the raw content when it is neither.
func (rr *routedRun) content(hostname string) string {
	rr.t.Helper()
	for _, d := range rr.cf.DNSRecords() {
		if d.Name != hostname {
			continue
		}
		switch d.Content {
		case cloudflare.TunnelTarget(rr.tunA.ID):
			return "a"
		case cloudflare.TunnelTarget(rr.tunB.ID):
			return "b"
		}
		return d.Content
	}
	return "none"
}

// served lists the hostnames a tunnel's ingress has rules for, besides the node's own.
func (rr *routedRun) served(tunnel cffake.Tunnel) []string {
	rr.t.Helper()
	var out []string
	for _, t := range rr.cf.Tunnels() {
		if t.ID != tunnel.ID {
			continue
		}
		for _, rule := range t.Ingress {
			if rule.Hostname != "" && rule.Service != cloudflare.ServiceSSH {
				out = append(out, rule.Hostname)
			}
		}
	}
	slices.Sort(out)
	return out
}

func (rr *routedRun) wantServed(tunnel cffake.Tunnel, which string, hostnames ...string) {
	rr.t.Helper()
	slices.Sort(hostnames)
	if got := rr.served(tunnel); !slices.Equal(got, hostnames) {
		rr.t.Errorf("ingress of %s serves %v, want %v", which, got, hostnames)
	}
}

func (rr *routedRun) wantContent(hostname, want string) {
	rr.t.Helper()
	if got := rr.content(hostname); got != want {
		rr.t.Errorf("the record of %s points at %s, want %s", hostname, got, want)
	}
}

func (rr *routedRun) rows() []database.AppMoveRoute {
	rr.t.Helper()
	rows, err := database.ListAppMoveRoutes(context.Background(), rr.db.Reader(), rr.moveRow().ID)
	mustf(rr.t, err, "ListAppMoveRoutes")
	return rows
}

func (rr *routedRun) wantRows(state database.AppMoveRouteState) {
	rr.t.Helper()
	for _, row := range rr.rows() {
		if row.State != state {
			rr.t.Errorf("the row of route %s is %s, want %s", row.RouteID, row.State, state)
		}
	}
}

func (rr *routedRun) reserved() int {
	rr.t.Helper()
	n, err := database.IncomingReservations(context.Background(), rr.db.Reader(), rr.dest.ID)
	mustf(rr.t, err, "IncomingReservations")
	return n
}

// updates are the PATCHes of DNS records the fake received, in order, with whether each changed state.
func (rr *routedRun) updates() []cffake.Applied {
	var out []cffake.Applied
	for _, m := range rr.cf.Mutations() {
		if m.Op == cffake.OpDNSUpdate {
			out = append(out, m)
		}
	}
	return out
}

// wantOwnersNeverUnprotected checks, over the whole run, that no owners hostname was ever routable without its
// Access application. A public hostname has none by design.
func (rr *routedRun) wantOwnersNeverUnprotected(owners ...string) {
	rr.t.Helper()
	for _, host := range rr.cf.EverRoutableWithoutAccess() {
		if slices.Contains(owners, host) {
			rr.t.Errorf("the owners hostname %s was routable without an Access application", host)
		}
	}
}

// onCheckpoint runs f after every durable write of the move, before the world's own crash injection.
func (rr *routedRun) onCheckpoint(f func()) {
	rr.handler.checkpoint = func() error {
		f()
		return rr.tickError("checkpoint")
	}
}

// stateOfRow is the state of the i-th row of the move, in the order the move repoints them.
func (rr *routedRun) stateOfRow(i int) database.AppMoveRouteState {
	return rr.rows()[i].State
}

// failNthUpdate makes the n-th PATCH of a DNS record (1-based) suffer fault.
func (rr *routedRun) failNthUpdate(n int, fault cffake.Fault) {
	rr.failUpdates(map[int]cffake.Fault{n: fault})
}

// failUpdates makes the PATCHes of DNS records, counted from 1, suffer the faults by their ordinal.
func (rr *routedRun) failUpdates(faults map[int]cffake.Fault) {
	var mu sync.Mutex
	seen := 0
	rr.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Op != cffake.OpDNSUpdate {
			return cffake.NoFault
		}
		mu.Lock()
		defer mu.Unlock()
		seen++
		return faults[seen]
	})
}

// loaded is a run of the move as a new job attempt would load it.
func (rr *routedRun) loaded() *moveRun {
	rr.t.Helper()
	job, err := rr.store.Get(context.Background(), rr.db.Reader(), rr.lease.JobID)
	mustf(rr.t, err, "Get the job")
	r, err := rr.handler.load(context.Background(), rr.lease, job)
	mustf(rr.t, err, "load")
	return r
}

// ---- the happy paths ---------------------------------------------------------------------------------------------------

func TestMoveRoutesRun_APublicRouteFollowsTheAppWithItsRecordMarkerAndComment(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	route := rr.expose(rr.main(), "shop.example.test", "public")
	before := rr.cf.DNSRecords()[0]
	rr.started()
	rr.wantServed(rr.tunA, "A", "shop.example.test")
	base := len(rr.cf.Mutations())

	mustf(t, rr.run(), "Run")

	if m := rr.moveRow(); m.Phase != database.AppMoveDone {
		t.Fatalf("move = %+v, want done", m)
	}
	records := rr.cf.DNSRecords()
	if len(records) != 1 {
		t.Fatalf("records = %+v, want the one record kept", records)
	}
	after := records[0]
	if after.ID != before.ID || after.Comment != before.Comment || after.Type != "CNAME" || !after.Proxied {
		t.Errorf("record = %+v, want the same ID, marker, type and proxying as %+v", after, before)
	}
	rr.wantContent("shop.example.test", "b")
	rr.wantServed(rr.tunB, "B", "shop.example.test")
	rr.wantServed(rr.tunA, "A")
	got := rr.route(route.ID)
	if got.NodeID != rr.dest.ID || got.TunnelID != rr.tunB.ID || got.TunnelGeneration != 1 || got.Phase != database.AppRouteActive {
		t.Errorf("route = %+v, want it active on B's tunnel", got)
	}
	rr.wantRows(database.AppMoveRouteSourceCleaned)
	if rr.a.state != "exited" || rr.b.state != "running" || rr.reserved() != 0 {
		t.Errorf("A %s, B %s, %d reserved: want A parked, B running and nothing reserved", rr.a.state, rr.b.state, rr.reserved())
	}
	if n := len(rr.events(eventAppMoveRouteSwitched)); n != 1 {
		t.Errorf("%d route_switched events, want 1", n)
	}
	// B serves the rule before the record points there.
	putB, patch := -1, -1
	for i, m := range rr.cf.Mutations()[base:] {
		switch {
		case m.Op == cffake.OpTunnelConfigPut && strings.Contains(m.Path, rr.tunB.ID) && putB < 0:
			putB = i
		case m.Op == cffake.OpDNSUpdate && patch < 0:
			patch = i
		}
	}
	if putB < 0 || patch < 0 || putB > patch {
		t.Errorf("B's ingress was written at %d and the record repointed at %d: the rule must come first", putB, patch)
	}
}

func TestMoveRoutesRun_AnOwnersRouteKeepsItsAccessApplicationAndIsNeverRoutableWithoutIt(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	route := rr.expose(rr.main(), "admin.example.test", "owners")
	rr.expose(rr.main(), "shop.example.test", "public")
	app := rr.cf.Apps()[0]
	rr.started()

	mustf(t, rr.run(), "Run")

	if apps := rr.cf.Apps(); len(apps) != 1 || apps[0].ID != app.ID || apps[0].Domain != "admin.example.test" || len(apps[0].PolicyIDs) != 1 {
		t.Errorf("apps = %+v, want the same application %+v, untouched", apps, app)
	}
	if got := rr.route(route.ID); got.Objects.AccessAppID != app.ID || got.NodeID != rr.dest.ID {
		t.Errorf("route = %+v, want the same application recorded and the route on B", got)
	}
	rr.wantContent("admin.example.test", "b")
	rr.wantContent("shop.example.test", "b")
	rr.wantServed(rr.tunB, "B", "admin.example.test", "shop.example.test")
	rr.wantOwnersNeverUnprotected("admin.example.test")
}

func TestMoveRoutesRun_AWaitingRouteMakesNoCloudflareCallAndIsActivatedOnBWhenTheMoveIsDone(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.inTx(func(ctx context.Context, tx *database.Tx) error {
		rr.handler.dep.systemID = rr.identity(ctx, tx, "system", domain.ActorSystem, "")
		return nil
	})
	rr.expose(rr.main(), "shop.example.test", "public")
	waiting := rr.waiting(rr.main(), "later.example.test")
	rr.started()
	calls := 0
	rr.onCheckpoint(func() {
		if m := rr.moveRow(); m.Phase != database.AppMoveDone && len(rr.exposeJobs()) > 0 {
			t.Errorf("an expose job was scheduled in phase %s, before the move was done", m.Phase)
		}
		calls++
	})

	mustf(t, rr.run(), "Run")

	if rr.content("later.example.test") != "none" {
		t.Error("the waiting route has a DNS record")
	}
	for _, m := range rr.cf.Mutations() {
		if m.Op == cffake.OpDNSCreate && strings.Contains(m.Path, "later") {
			t.Errorf("mutation %+v created a record for the waiting route", m)
		}
	}
	if n := len(rr.updates()); n != 1 {
		t.Errorf("%d record updates, want the one of the active route", n)
	}
	got := rr.route(waiting.ID)
	if got.NodeID != rr.dest.ID || got.TunnelID != rr.tunB.ID || got.Phase != database.AppRouteWaiting {
		t.Errorf("route = %+v, want it waiting and naming B", got)
	}
	if jobs := rr.exposeJobs(); len(jobs) != 1 || jobs[0] != "later.example.test" {
		t.Errorf("expose jobs = %v, want one for later.example.test", jobs)
	}
	rr.wantServed(rr.tunB, "B", "shop.example.test")
	if calls == 0 {
		t.Error("the checkpoint hook never ran")
	}
}

// exposeJobs are the hostnames of the expose jobs the system submitted.
func (rr *routedRun) exposeJobs() []string {
	rr.t.Helper()
	rows, err := rr.db.Reader().QueryContext(context.Background(),
		`SELECT json_extract(j.payload_json, '$.hostname') FROM jobs j JOIN plans p ON p.id = j.plan_id WHERE p.action = 'app_route.expose'`)
	mustf(rr.t, err, "query")
	defer rows.Close()
	var out []string
	for rows.Next() {
		var host string
		mustf(rr.t, rows.Scan(&host), "scan")
		out = append(out, host)
	}
	mustf(rr.t, rows.Err(), "rows")
	return out
}

// ---- Access ---------------------------------------------------------------------------------------------------------

func TestMoveRoutesRun_AnOwnersRouteWhoseAccessApplicationIsGoneAtPublishHaltsAndNoIngressServesIt(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	route := rr.expose(rr.main(), "admin.example.test", "owners")
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	appID := rr.cf.Apps()[0].ID
	removed := false
	rr.onCheckpoint(func() {
		if !removed && rr.moveRow().Phase == database.AppMoveVerified {
			removed = true
			rr.cf.RemoveApp(appID)
		}
	})

	err := rr.run()

	if err == nil {
		t.Fatal("Run succeeded without the Access application")
	}
	got := rr.route(route.ID)
	if got.Phase != database.AppRouteFailed || got.HaltedPhase != database.AppRouteActive {
		t.Errorf("route = %+v, want it halted as failed while active", got)
	}
	rr.wantServed(rr.tunA, "A", "shop.example.test")
	rr.wantServed(rr.tunB, "B")
	if n := len(rr.updates()); n != 0 {
		t.Errorf("%d record updates, want none: the Access check comes first", n)
	}
	rr.wantContent("admin.example.test", "a")
	rr.wantContent("shop.example.test", "a")
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Errorf("move = %+v, want rolled back", m)
	}
	if rr.a.state != "running" || rr.b.state != "exited" || rr.reserved() != 0 {
		t.Errorf("A %s, B %s, %d reserved: want A serving, B stopped and the reservation released", rr.a.state, rr.b.state, rr.reserved())
	}
	if len(rr.events(eventAppMoveRouteHalted)) != 1 {
		t.Errorf("%d route_halted events, want 1", len(rr.events(eventAppMoveRouteHalted)))
	}
}

func TestMoveRoutesRun_AnAccessApplicationLostBetweenTwoSwitchesHaltsThatRouteAndRestoresTheFirst(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "admin.example.test", "owners")
	rr.expose(rr.main(), "shop.example.test", "owners")
	rr.started()
	rows := rr.rows()
	second := rr.route(rows[1].RouteID)
	first := rr.route(rows[0].RouteID)
	removed := false
	rr.onCheckpoint(func() {
		if !removed && rr.stateOfRow(0) == database.AppMoveRouteDNSSwitched {
			removed = true
			rr.cf.RemoveApp(second.Objects.AccessAppID)
		}
	})

	err := rr.run()

	if err == nil || !removed {
		t.Fatalf("Run = %v (removed %v), want a failure after the first switch", err, removed)
	}
	if got := rr.route(second.ID); got.Phase != database.AppRouteFailed {
		t.Errorf("second route = %+v, want it halted", got)
	}
	if got := rr.route(first.ID); got.Phase != database.AppRouteActive || got.NodeID != rr.node.ID {
		t.Errorf("first route = %+v, want it active on A", got)
	}
	rr.wantContent(first.Hostname, "a")
	rr.wantContent(second.Hostname, "a")
	rr.wantServed(rr.tunA, "A", first.Hostname)
	rr.wantServed(rr.tunB, "B")
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Errorf("move = %+v, want rolled back", m)
	}
	if len(rr.updates()) != 2 {
		t.Errorf("%d record updates, want the first forward and its restore", len(rr.updates()))
	}
}

// ---- partial switch and compensation ----------------------------------------------------------------------------------

// snapshot is what Cloudflare and the nodes looked like at one moment of the compensation.
type snapshot struct {
	records        string // where the records point, as "host=a " per hostname
	servedB        []string
	aState, bState string
}

func (rr *routedRun) snap(hosts ...string) snapshot {
	var s snapshot
	for _, h := range hosts {
		s.records += fmt.Sprintf("%s=%s ", h, rr.content(h))
	}
	s.servedB = rr.served(rr.tunB)
	s.aState, s.bState = rr.a.state, rr.b.state
	return s
}

func TestMoveRoutesRun_APartialSwitchIsUndoneBeforeBStops(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "admin.example.test", "owners")
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(2, cffake.Forbidden)
	var atStop *snapshot
	rr.before = func(label string, c templates.Command) {
		if label == "B" && c.Template == "compose.stop" && atStop == nil {
			s := rr.snap("admin.example.test", "shop.example.test")
			atStop = &s
		}
	}

	err := rr.run()

	if err == nil {
		t.Fatal("Run succeeded although the second repoint was refused")
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if atStop == nil {
		t.Fatal("B was never stopped")
	}
	if want := "admin.example.test=a shop.example.test=a "; atStop.records != want || len(atStop.servedB) != 0 {
		t.Errorf("when B stopped the records were %q and B served %v: DNS goes back and B's rules leave first", atStop.records, atStop.servedB)
	}
	rr.wantContent("admin.example.test", "a")
	rr.wantContent("shop.example.test", "a")
	rr.wantServed(rr.tunB, "B")
	rr.wantServed(rr.tunA, "A", "admin.example.test", "shop.example.test")
	rr.wantOwnersNeverUnprotected("admin.example.test")
	for _, route := range []string{"admin.example.test", "shop.example.test"} {
		r, err := database.GetLiveAppRouteByHostname(context.Background(), rr.db.Reader(), route)
		mustf(t, err, "GetLiveAppRouteByHostname")
		if r.NodeID != rr.node.ID || r.TunnelID != rr.tunA.ID {
			t.Errorf("route %s = %+v, want it still on A", route, r)
		}
	}
	if rr.targetRow().NodeID != rr.node.ID || rr.a.state != "running" || rr.b.state != "exited" || rr.reserved() != 0 {
		t.Errorf("target on %s, A %s, B %s, %d reserved: want A serving, B stopped, no reservation", rr.targetRow().NodeID, rr.a.state, rr.b.state, rr.reserved())
	}
	wantRows := []database.AppMoveRouteState{database.AppMoveRouteDestWithdrawn, database.AppMoveRouteDestWithdrawn}
	var got []database.AppMoveRouteState
	for _, row := range rr.rows() {
		got = append(got, row.State)
	}
	if !slices.Equal(got, wantRows) {
		t.Errorf("rows = %v, want %v", got, wantRows)
	}
	if n := len(rr.events(eventAppMoveRouteRestored)); n != 1 {
		t.Errorf("%d route_restored events, want 1", n)
	}
	rr.wantOwnersNeverUnprotected("admin.example.test")
}

func TestMoveRoutesRun_ACommitThatLosesItsCompareAndSetRestoresTheRecordsBeforeRollingBack(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	bumped := false
	rr.onCheckpoint(func() {
		if !bumped && rr.moveRow().Phase == database.AppMoveRoutesSwitched {
			bumped = true
			rr.exec(`UPDATE app_targets SET spec_revision = spec_revision + 1 WHERE id = ?`, rr.target.ID)
		}
	})

	err := rr.run()

	if err == nil || !bumped {
		t.Fatalf("Run = %v (bumped %v), want the commit to lose its compare-and-set", err, bumped)
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack || m.CommittedRevision != 0 {
		t.Fatalf("move = %+v, want rolled back and uncommitted", m)
	}
	rr.wantContent("shop.example.test", "a")
	rr.wantServed(rr.tunB, "B")
	rr.wantServed(rr.tunA, "A", "shop.example.test")
	if rr.targetRow().NodeID != rr.node.ID || rr.a.state != "running" || rr.b.state != "exited" {
		t.Errorf("target on %s, A %s, B %s: want it on A", rr.targetRow().NodeID, rr.a.state, rr.b.state)
	}
}

func TestMoveRoutesRun_AStatefulRollbackPointsDNSBackThenStopsBThenStartsA(t *testing.T) {
	rr := newRoutedRun(t, runOptions{stateful: true, compose: moveStatefulCompose})
	rr.expose(rr.main(), "admin.example.test", "public")
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(2, cffake.Forbidden)
	var order []string
	var dnsAtStop snapshot
	rr.before = func(label string, c templates.Command) {
		switch {
		case label == "B" && c.Template == "compose.stop":
			dnsAtStop = rr.snap("admin.example.test", "shop.example.test")
			order = append(order, "B stop")
		case label == "A" && c.Template == "compose.start":
			order = append(order, fmt.Sprintf("A start (B %s)", rr.b.state))
		}
	}

	err := rr.run()

	if err == nil {
		t.Fatal("Run succeeded although the second repoint was refused")
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if want := "admin.example.test=a shop.example.test=a "; dnsAtStop.records != want || len(dnsAtStop.servedB) != 0 {
		t.Errorf("when B stopped: records %q, B serving %v; want DNS back at A and B's rules withdrawn", dnsAtStop.records, dnsAtStop.servedB)
	}
	if want := []string{"B stop", "A start (B exited)"}; !slices.Equal(order, want) {
		t.Errorf("order = %v, want B stopped before A started", order)
	}
	if rr.a.state != "running" || rr.b.state != "exited" {
		t.Errorf("A %s, B %s, want A serving after its health check and B stopped with its volumes kept", rr.a.state, rr.b.state)
	}
	if len(rr.b.volumes) == 0 {
		t.Error("B's volumes were deleted: they are kept after B's first start")
	}
	rr.wantContent("admin.example.test", "a")
	rr.wantContent("shop.example.test", "a")
}

// ---- unknown outcomes ---------------------------------------------------------------------------------------------------

func TestMoveRoutesRun_AForwardAnswerLostIsReconciledAtBAfterTheNotBeforeTime(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(1, cffake.LostResponse)
	rr.stuck = true

	err := rr.run()

	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome before the not-before time", err)
	}
	rr.wantRows(database.AppMoveRouteDNSSwitching)
	rr.wantContent("shop.example.test", "b")
	if len(rr.updates()) != 1 {
		t.Errorf("%d updates, want only the one in doubt", len(rr.updates()))
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRoutesDestIncluded || rr.b.state != "running" {
		t.Errorf("move %s, B %s: want it open with B running", m.Phase, rr.b.state)
	}

	rr.stuck = false
	mustf(t, rr.resume(), "Run after the not-before time")

	if m := rr.moveRow(); m.Phase != database.AppMoveDone {
		t.Fatalf("move = %+v, want done", m)
	}
	rr.wantContent("shop.example.test", "b")
	if len(rr.updates()) != 1 {
		t.Errorf("%d updates, want the one that applied and no repeat", len(rr.updates()))
	}
	intents := rr.intentsOf(operationDNSUpdate)
	if len(intents) != 1 || intents[0].Outcome != jobs.OutcomeSucceeded {
		t.Errorf("intents = %+v, want one, settled as succeeded by the read", intents)
	}
}

func TestMoveRoutesRun_AForwardAnswerLostWithTheRecordStillAtARetriesTheRepoint(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(1, cffake.FailBefore)

	mustf(t, rr.run(), "Run")

	if m := rr.moveRow(); m.Phase != database.AppMoveDone {
		t.Fatalf("move = %+v, want done", m)
	}
	rr.wantContent("shop.example.test", "b")
	updates := rr.updates()
	if len(updates) != 2 || updates[0].Committed || !updates[1].Committed {
		t.Errorf("updates = %+v, want a failed attempt and an applied one", updates)
	}
	intents := rr.intentsOf(operationDNSUpdate)
	if len(intents) != 2 || intents[0].Outcome != jobs.OutcomeFailed || intents[1].Outcome != jobs.OutcomeSucceeded {
		t.Errorf("intents = %+v, want the first settled as failed by the read and the second as succeeded", intents)
	}
}

func TestMoveRoutesRun_AReconciliationThatFindsASiblingOrOtherContentHaltsTheMoveWithBRunning(t *testing.T) {
	tampers := map[string]func(rr *routedRun, host string){
		"a sibling record": func(rr *routedRun, host string) { rr.cf.SeedDNSRecord(host, "elsewhere.example.test", "someone else") },
		"other content": func(rr *routedRun, host string) {
			_, err := rr.api.UpdateDNSRecord(context.Background(), rr.zoneID, rr.cf.DNSRecords()[0].ID, "elsewhere.example.test")
			mustf(rr.t, err, "UpdateDNSRecord")
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			rr := newRoutedRun(t, runOptions{})
			rr.expose(rr.main(), "shop.example.test", "public")
			rr.started()
			rr.failNthUpdate(1, cffake.LostResponse)
			tampered := 0
			rr.handler.dep.sleep = func(ctx context.Context, d time.Duration) {
				rr.sleep(ctx, d)
				tamper(rr, "shop.example.test")
				tampered = len(rr.updates())
			}

			err := rr.run()

			if err == nil {
				t.Fatal("Run succeeded although the record cannot be validated")
			}
			m := rr.moveRow()
			if m.Phase != database.AppMoveFailed || m.LastError == "" || !strings.Contains(m.LastError, "shop.example.test") {
				t.Errorf("move = %+v, want it halted and naming the hostname", m)
			}
			if rr.b.state != "running" {
				t.Errorf("B is %s: a halted move leaves B running", rr.b.state)
			}
			rr.wantServed(rr.tunB, "B", "shop.example.test")
			if rr.reserved() == 0 {
				t.Error("a halted move releases its reservation")
			}
			if got := len(rr.updates()); got != tampered {
				t.Errorf("%d updates, want none after the record was tampered with (%d)", got, tampered)
			}
		})
	}
}

// recovered is the way a job with an unknown outcome really comes back: the worker interrupts it, the jobs reconciler
// proves its open intents past their not-before time and closes them (a record update only as partial_stable, hence
// failed), and the next claim takes the requeued job. The result is the lease of that claim.
func (rr *routedRun) recovered() {
	rr.t.Helper()
	ctx := context.Background()
	mustf(rr.t, rr.store.Interrupt(ctx, rr.lease, jobs.ErrOutcomeUnknown), "Interrupt")
	store, err := jobs.NewStore(jobs.Config{
		DB: rr.db, Clock: rr.clock, IDs: rr.ids, Revalidator: rr.reval, LockPlanner: LockPlanner{},
		TypePolicies: MovePolicy{}.TypePolicies(),
	})
	mustf(rr.t, err, "NewStore")
	evidence := &MoveEvidence{core: rr.handler.core, next: &passedOn{}}
	rr.clock.Advance(dnsQuiescence + time.Minute)
	for range 2 {
		_, err := store.Reconcile(ctx, evidence)
		mustf(rr.t, err, "Reconcile")
		rr.clock.Advance(31 * time.Second)
	}
	rr.store, rr.handler.dep.store = store, store
	claimed, found, err := store.Claim(ctx, "worker-2")
	mustf(rr.t, err, "Claim")
	if !found {
		rr.t.Fatal("the reconciled job was not requeued")
	}
	rr.lease = claimed.Lease
	for _, in := range rr.intentsOf(operationDNSUpdate) {
		if in.Outcome != jobs.OutcomeFailed {
			rr.t.Fatalf("intent %s closed as %q, want the reconciler's failed", in.ID, in.Outcome)
		}
	}
}

func TestMoveRoutesRun_AForwardAnswerLostAndClosedByTheReconcilerIsStillSettledByReadingTheRecord(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(1, cffake.LostResponse)
	rr.stuck = true
	if err := rr.run(); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}

	rr.recovered()
	rr.stuck = false
	mustf(t, rr.run(), "Run after the recovery")

	if m := rr.moveRow(); m.Phase != database.AppMoveDone {
		t.Fatalf("move = %+v, want done", m)
	}
	rr.wantContent("shop.example.test", "b")
	if len(rr.updates()) != 1 {
		t.Errorf("%d updates, want the one that applied and no repeat", len(rr.updates()))
	}
}

func TestMoveRoutesRun_ACompensationAfterAReconcilerClosedUpdateRestoresTheRecordBeforeWithdrawingAndStoppingB(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(1, cffake.LostResponse)
	rr.stuck = true
	if err := rr.run(); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	rr.recovered()
	rr.stuck = false
	var atStop snapshot
	rr.before = func(label string, c templates.Command) {
		if label == "B" && c.Template == "compose.stop" {
			atStop = rr.snap("shop.example.test")
		}
	}

	wantAppsCode(t, rr.handler.compensate(context.Background(), rr.loaded(), errCompensationResumed), smerr.CodeDeploymentFailed)

	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if atStop.records != "shop.example.test=a " || len(atStop.servedB) != 0 {
		t.Errorf("when B stopped: %q, B serving %v; want the record restored and the rule withdrawn first", atStop.records, atStop.servedB)
	}
	rr.wantContent("shop.example.test", "a")
}

// resolvedSucceeded is the operator's way out of an interrupted job: job.resolve with outcome succeeded and
// assume_quiescent closes every dispatched intent as succeeded, with no evidence. The job is then put back under a
// live lease, as the next job of the move would hold one.
func (rr *routedRun) resolvedSucceeded() {
	rr.t.Helper()
	ctx := context.Background()
	mustf(rr.t, rr.store.Interrupt(ctx, rr.lease, jobs.ErrOutcomeUnknown), "Interrupt")
	job, err := rr.store.Get(ctx, rr.db.Reader(), rr.lease.JobID)
	mustf(rr.t, err, "Get the job")
	rr.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := rr.store.Resolve(ctx, tx, jobs.ResolveRequest{
			JobID: job.ID, PlanHash: job.PlanHash, Outcome: jobs.ResolveSucceeded, AssumeQuiescent: true,
			By: domain.Actor{ID: rr.admin, Type: domain.ActorHuman},
		})
		return err
	})
	rr.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'running', lease_until = ? WHERE id = ?`,
			domain.UnixMillis(rr.clock.Now().Add(time.Hour)), job.ID)
		return err
	})
	rr.lease.Generation = job.LeaseGeneration
	for _, in := range rr.intentsOf(operationDNSUpdate) {
		if in.Outcome != jobs.OutcomeSucceeded {
			rr.t.Fatalf("intent %s closed as %q, want the operator's succeeded", in.ID, in.Outcome)
		}
	}
}

func TestMoveRoutesRun_AnOperatorResolvedUpdateThatDidNotApplyIsStillSettledByReadingTheRecord(t *testing.T) {
	for _, tc := range []string{"forward", "compensation"} {
		t.Run(tc, func(t *testing.T) {
			rr := newRoutedRun(t, runOptions{})
			rr.expose(rr.main(), "shop.example.test", "public")
			rr.started()
			rr.holdFirstUpdate()
			rr.resolvedSucceeded()
			var atStop snapshot
			rr.before = func(label string, c templates.Command) {
				if label == "B" && c.Template == "compose.stop" {
					atStop = rr.snap("shop.example.test")
				}
			}

			if tc == "forward" {
				mustf(t, rr.run(), "Run after the resolve")
				if m := rr.moveRow(); m.Phase != database.AppMoveDone {
					t.Fatalf("move = %+v, want done", m)
				}
				rr.wantContent("shop.example.test", "b")
				return
			}
			wantAppsCode(t, rr.handler.compensate(context.Background(), rr.loaded(), errCompensationResumed), smerr.CodeDeploymentFailed)
			if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
				t.Fatalf("move = %+v, want rolled back", m)
			}
			if atStop.records != "shop.example.test=a " || len(atStop.servedB) != 0 {
				t.Errorf("when B stopped: %q, B serving %v; want the record at A and the rule withdrawn first", atStop.records, atStop.servedB)
			}
			rr.wantContent("shop.example.test", "a")
		})
	}
}

func TestMoveRoutesRun_ACompensationDoesNothingBeforeAnUnknownUpdateIsReconciledThenRestoresIt(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failNthUpdate(1, cffake.LostResponse)
	rr.stuck = true
	if err := rr.run(); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	cause := errors.New("the move is ended")
	bBefore := slices.Clone(rr.mutations(rr.b))

	err := rr.handler.compensate(context.Background(), rr.loaded(), cause)

	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("compensate = %v, want the outcome to stay unknown before the not-before time", err)
	}
	rr.wantContent("shop.example.test", "b")
	rr.wantServed(rr.tunB, "B", "shop.example.test")
	if got := rr.mutations(rr.b); !slices.Equal(got, bBefore) || rr.b.state != "running" {
		t.Errorf("B mutations went from %v to %v, B %s: nothing is stopped while the outcome is unknown", bBefore, got, rr.b.state)
	}
	if len(rr.updates()) != 1 {
		t.Errorf("%d updates, want no reverse PATCH yet", len(rr.updates()))
	}
	var atStop snapshot
	rr.before = func(label string, c templates.Command) {
		if label == "B" && c.Template == "compose.stop" {
			atStop = rr.snap("shop.example.test")
		}
	}

	rr.stuck = false
	wantAppsCode(t, rr.handler.compensate(context.Background(), rr.loaded(), errCompensationResumed), smerr.CodeDeploymentFailed)

	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if atStop.records != "shop.example.test=a " || len(atStop.servedB) != 0 {
		t.Errorf("when B stopped: %q, B serving %v; want the record restored and the rule withdrawn first", atStop.records, atStop.servedB)
	}
	rr.wantContent("shop.example.test", "a")
	if updates := rr.updates(); len(updates) != 2 {
		t.Errorf("%d updates, want the forward one and its restore", len(updates))
	}
}

// holdFirstUpdate sends the first record update of the run to Cloudflare, which keeps it open until the worker is
// cancelled and applies it only at ReleaseDeferred: the late write of a request the worker gave up on.
func (rr *routedRun) holdFirstUpdate() {
	rr.t.Helper()
	rr.cf.Inject(cffake.OpDNSUpdate, cffake.HangApplyLater, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rr.handler.Run(ctx, rr.lease) }()
	for waited := 0; !slices.ContainsFunc(rr.cf.Requests(), func(r cffake.Request) bool { return r.Method == "PATCH" }); waited++ {
		if waited > 2000 {
			rr.t.Fatal("the update never reached Cloudflare")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		rr.t.Fatal("Run succeeded although it was cancelled")
	}
	rr.wantRows(database.AppMoveRouteDNSSwitching)
	rr.wantContent("shop.example.test", "a")
}

func TestMoveRoutesRun_ALateForwardRequestThatLandsWhileTheRunWaitsIsFoundAtB(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.holdFirstUpdate()
	released := false
	rr.handler.dep.sleep = func(ctx context.Context, d time.Duration) {
		rr.sleep(ctx, d)
		released = rr.cf.ReleaseDeferred() == 1
	}

	mustf(t, rr.handler.Run(context.Background(), rr.lease), "the resumed run")

	if !released {
		t.Fatal("the late request was never released while the run waited")
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveDone {
		t.Fatalf("move = %+v, want done after the late request applied", m)
	}
	rr.wantContent("shop.example.test", "b")
	if len(rr.updates()) != 1 {
		t.Errorf("%d updates, want only the late one: no second attempt", len(rr.updates()))
	}
}

func TestMoveRoutesRun_ACompensationSendsNoReversePATCHBeforeALateForwardRequestCouldLand(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.holdFirstUpdate()

	released := false
	rr.handler.dep.sleep = func(ctx context.Context, d time.Duration) {
		rr.sleep(ctx, d)
		released = released || rr.cf.ReleaseDeferred() == 1
	}
	var reverseSawRelease []bool
	rr.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Op == cffake.OpDNSUpdate {
			reverseSawRelease = append(reverseSawRelease, released)
		}
		return cffake.NoFault
	})

	err := rr.handler.compensate(context.Background(), rr.loaded(), errors.New("the move is ended"))

	if err == nil || !released {
		t.Fatalf("compensate = %v (released %v)", err, released)
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if !slices.Equal(reverseSawRelease, []bool{true}) {
		t.Errorf("the reverse PATCH was sent with the late request released = %v, want exactly one, after it", reverseSawRelease)
	}
	rr.wantContent("shop.example.test", "a")
	rr.wantServed(rr.tunB, "B")
}

func TestMoveRoutesRun_ARestoreThatFailsHaltsTheMoveWithBRunningAndNamesTheHostnamesAtB(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "admin.example.test", "public")
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failUpdates(map[int]cffake.Fault{2: cffake.Forbidden, 3: cffake.Forbidden})

	err := rr.run()

	if err == nil {
		t.Fatal("Run succeeded although the second repoint and the restore were refused")
	}
	m := rr.moveRow()
	if m.Phase != database.AppMoveFailed || !strings.Contains(m.LastError, "admin.example.test") || strings.Contains(m.LastError, "shop.example.test") {
		t.Errorf("move = %+v, want it halted and naming only the hostname that points at B", m)
	}
	if rr.b.state != "running" || rr.a.state != "running" {
		t.Errorf("A %s, B %s: a halted move leaves B running", rr.a.state, rr.b.state)
	}
	rr.wantContent("admin.example.test", "b")
	rr.wantContent("shop.example.test", "a")
	rr.wantServed(rr.tunB, "B", "admin.example.test", "shop.example.test")
	if rr.reserved() == 0 {
		t.Error("a halted move releases its reservation")
	}
	if got := len(rr.events(eventAppMoveRouteRestored)); got != 0 {
		t.Errorf("%d route_restored events, want none", got)
	}
}

func TestMoveRoutesRun_AReverseAnswerLostIsReconciledAtAAfterTheNotBeforeTimeBeforeBStops(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "admin.example.test", "public")
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.failUpdates(map[int]cffake.Fault{2: cffake.Forbidden, 3: cffake.LostResponse})
	var atStop snapshot
	rr.before = func(label string, c templates.Command) {
		if label == "B" && c.Template == "compose.stop" {
			atStop = rr.snap("admin.example.test", "shop.example.test")
		}
	}
	started := rr.clock.Now()

	err := rr.run()

	if err == nil {
		t.Fatal("Run succeeded although the second repoint was refused")
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if atStop.records != "admin.example.test=a shop.example.test=a " || len(atStop.servedB) != 0 {
		t.Errorf("when B stopped: %q, B serving %v; want both records back at A and B's rules withdrawn", atStop.records, atStop.servedB)
	}
	if rr.clock.Now().Sub(started) < dnsQuiescence {
		t.Error("the run did not wait for the not-before time of the reverse update")
	}
	if len(rr.updates()) != 3 {
		t.Errorf("%d updates, want forward, refused forward and one reverse that applied", len(rr.updates()))
	}
}

// ---- ingress ----------------------------------------------------------------------------------------------------------

func TestMoveRoutesRun_AnIngressWriteWhoseAnswerIsLostIsProvenByReadingTheConfiguration(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.cf.Inject(cffake.OpTunnelConfigPut, cffake.LostResponse, 1)

	mustf(t, rr.run(), "Run")

	if m := rr.moveRow(); m.Phase != database.AppMoveDone {
		t.Fatalf("move = %+v, want done", m)
	}
	rr.wantServed(rr.tunB, "B", "shop.example.test")
	rr.wantContent("shop.example.test", "b")
}

func TestMoveRoutesRun_AnIngressWriteThatDidNotApplyEndsTheMoveBeforeAnyRecordMoves(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	rr.cf.Inject(cffake.OpTunnelConfigPut, cffake.FailBefore, 1)

	err := rr.run()

	if err == nil {
		t.Fatal("Run succeeded although B's ingress was not written")
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if n := len(rr.updates()); n != 0 {
		t.Errorf("%d record updates, want none before the rule was published", n)
	}
	rr.wantServed(rr.tunB, "B")
	rr.wantServed(rr.tunA, "A", "shop.example.test")
	rr.wantContent("shop.example.test", "a")
	rr.wantRows(database.AppMoveRouteDestWithdrawn)
}

func TestMoveRoutesRun_AnotherTargetsExposeOnBKeepsTheIncomingRulesAndTheWithdrawalRemovesOnlyThose(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	other := rr.addTarget("other", rr.dest.ID)
	rr.started()
	rr.failNthUpdate(1, cffake.Forbidden)
	exposed := false
	var during []string
	rr.onCheckpoint(func() {
		rows := rr.rows()
		if exposed || len(rows) == 0 || rows[0].State != database.AppMoveRouteDestPublished {
			return
		}
		exposed = true
		rr.expose(other, "blog.example.test", "public") // the writer takes the same builder and writes B's ingress
		during = rr.served(rr.tunB)
	})

	err := rr.run()

	if err == nil || !exposed {
		t.Fatalf("Run = %v (exposed %v), want a refused repoint after the other expose", err, exposed)
	}
	if want := []string{"blog.example.test", "shop.example.test"}; !slices.Equal(during, want) {
		t.Errorf("B served %v after the other expose, want the incoming rule and the new one %v", during, want)
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	rr.wantServed(rr.tunB, "B", "blog.example.test")
	rr.wantServed(rr.tunA, "A", "shop.example.test")
}

// ---- crashes and takeover ------------------------------------------------------------------------------------------------

func TestMoveRoutesRun_ACrashAtAnyCheckpointOrDispatchResumesToTheSameEnd(t *testing.T) {
	dry := newRoutedRun(t, runOptions{})
	dry.expose(dry.main(), "admin.example.test", "owners")
	dry.expose(dry.main(), "shop.example.test", "public")
	dry.started()
	mustf(t, dry.run(), "uninterrupted Run")
	total := map[string]int{"dispatch": dry.ticks["dispatch"], "checkpoint": dry.ticks["checkpoint"]}
	if total["checkpoint"] < 15 {
		t.Fatalf("ticks = %v: the run has too few checkpoints to test", total)
	}

	for _, kind := range []string{"dispatch", "checkpoint"} {
		for n := 1; n <= total[kind]; n++ {
			t.Run(fmt.Sprintf("%s %d", kind, n), func(t *testing.T) {
				rr := newRoutedRun(t, runOptions{})
				rr.expose(rr.main(), "admin.example.test", "owners")
				rr.expose(rr.main(), "shop.example.test", "public")
				rr.started()
				rr.crash[kind] = n

				if err := rr.run(); err == nil {
					t.Fatal("the crash did not stop the run")
				}
				rr.crash[kind] = 0

				mustf(t, rr.resume(), "resumed Run")

				if m := rr.moveRow(); m.Phase != database.AppMoveDone {
					t.Fatalf("move = %+v, want done", m)
				}
				rr.wantContent("admin.example.test", "b")
				rr.wantContent("shop.example.test", "b")
				rr.wantServed(rr.tunB, "B", "admin.example.test", "shop.example.test")
				rr.wantServed(rr.tunA, "A")
				rr.wantRows(database.AppMoveRouteSourceCleaned)
				if rr.targetRow().NodeID != rr.dest.ID || rr.b.state != "running" || rr.reserved() != 0 {
					t.Errorf("target on %s, B %s, %d reserved", rr.targetRow().NodeID, rr.b.state, rr.reserved())
				}
				rr.wantOwnersNeverUnprotected("admin.example.test")
			})
		}
	}
}

func TestMoveRoutesRun_ARunThatLostItsLeaseMidSwitchChangesNothingMore(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "admin.example.test", "public")
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	taken := false
	rr.onCheckpoint(func() {
		if !taken && rr.stateOfRow(0) == database.AppMoveRouteDNSSwitched {
			taken = true
			rr.exec(`UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id = ?`, rr.lease.JobID)
		}
	})

	err := rr.run()

	if !errors.Is(err, jobs.ErrLeaseLost) || !taken {
		t.Fatalf("Run = %v (taken %v), want the lost lease", err, taken)
	}
	if n := len(rr.updates()); n != 1 {
		t.Errorf("%d record updates, want only the one before the takeover", n)
	}
	if m := rr.moveRow(); m.Phase != database.AppMoveRoutesDestIncluded {
		t.Errorf("move = %+v, want it left where the takeover found it", m)
	}
}

// ---- after the commit ----------------------------------------------------------------------------------------------------

func TestMoveRoutesRun_APostCommitHaltOnAIngressWriteOnlyGoesForward(t *testing.T) {
	rr := newRoutedRun(t, runOptions{})
	rr.expose(rr.main(), "shop.example.test", "public")
	rr.started()
	puts := 0
	rr.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Op != cffake.OpTunnelConfigPut {
			return cffake.NoFault
		}
		if puts++; puts == 2 { // the first is B's publication, the second A's clean after the commit
			return cffake.FailBefore
		}
		return cffake.NoFault
	})
	rr.exec(`UPDATE jobs SET attempts = max_attempts WHERE id = ?`, rr.lease.JobID)

	err := rr.run()

	if err == nil {
		t.Fatal("Run succeeded although A's ingress was not written")
	}
	m := rr.moveRow()
	if m.Phase != database.AppMoveFailed || m.HaltedPhase != database.AppMoveCommitted {
		t.Fatalf("move = %+v, want halted after the commit", m)
	}
	if rr.targetRow().NodeID != rr.dest.ID || rr.b.state != "running" {
		t.Errorf("target on %s, B %s: a committed move is never undone", rr.targetRow().NodeID, rr.b.state)
	}
	rr.wantContent("shop.example.test", "b")
	rr.wantServed(rr.tunB, "B", "shop.example.test")
	rr.wantRows(database.AppMoveRouteCommitted)
	if len(rr.updates()) != 1 {
		t.Errorf("%d record updates, want the forward one only: no restore after the commit", len(rr.updates()))
	}

	rr.exec(`UPDATE jobs SET attempts = 1 WHERE id = ?`, rr.lease.JobID)
	mustf(t, rr.resume(), "resumed Run")

	if m := rr.moveRow(); m.Phase != database.AppMoveDone {
		t.Fatalf("move = %+v, want done", m)
	}
	rr.wantServed(rr.tunA, "A")
	rr.wantRows(database.AppMoveRouteSourceCleaned)
	if len(rr.updates()) != 1 || rr.reserved() != 0 {
		t.Errorf("%d updates, %d reserved: want no further record update and no reservation", len(rr.updates()), rr.reserved())
	}
}
