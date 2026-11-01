package app

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// ---- the phase contract ----------------------------------------------------------------------------------------

func TestMovePhases_EveryPhaseOfTheSchemaIsClassified(t *testing.T) {
	w := newMoveWorld(t)
	var ddl string
	err := w.db.Reader().QueryRowContext(context.Background(), `SELECT sql FROM sqlite_master WHERE name = 'app_moves'`).Scan(&ddl)
	mustf(t, err, "read the schema of app_moves")
	m := regexp.MustCompile(`(?s)phase\s+TEXT NOT NULL CHECK \(phase IN \((.*?)\)\)`).FindStringSubmatch(ddl)
	if m == nil {
		t.Fatal("the phase CHECK of app_moves was not found")
	}
	var schema []string
	for _, q := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(m[1], -1) {
		schema = append(schema, q[1])
	}
	var table []string
	for _, p := range movePhases {
		table = append(table, string(p.phase))
	}
	slices.Sort(schema)
	slices.Sort(table)
	if !slices.Equal(schema, table) {
		t.Errorf("the phase table lists %v, the schema allows %v", table, schema)
	}
}

func TestMovePhases_ClassOfEveryPhase(t *testing.T) {
	want := map[database.AppMovePhase]phaseClass{
		database.AppMovePreflight: classPreCommit, database.AppMoveStaged: classPreCommit, database.AppMoveSourceStop: classPreCommit,
		database.AppMoveDataCopied: classPreCommit, database.AppMoveStarted: classPreCommit, database.AppMoveVerified: classPreCommit,
		database.AppMoveRoutesDestIncluded: classPreCommit, database.AppMoveRoutesSwitched: classPreCommit,
		database.AppMoveCommitted: classPostCommit, database.AppMoveRoutesSourceCleaned: classPostCommit,
		database.AppMoveSourceParked: classPostCommit, database.AppMoveDone: classPostCommit,
		database.AppMoveCompensatingRoutesRestored: classCompensation, database.AppMoveCompensatingRoutesWithdrawn: classCompensation,
		database.AppMoveCompensatingBStopped: classCompensation, database.AppMoveCompensatingSourceStarted: classCompensation,
		database.AppMoveCompensatingSourceVerified: classCompensation, database.AppMoveCompensatingBRemoved: classCompensation,
		database.AppMoveRolledBack: classCompensation,
		database.AppMoveFailed:     classHalted, database.AppMoveConflict: classHalted,
	}
	if len(want) != len(movePhases) {
		t.Fatalf("%d phases expected, the table has %d", len(want), len(movePhases))
	}
	for phase, class := range want {
		rule, ok := ruleOf(phase)
		if !ok || rule.class != class {
			t.Errorf("%s: rule = %+v, want class %d", phase, rule, class)
		}
	}
}

func TestMovePhases_AHaltedMoveIsClassifiedByThePhaseItHeld(t *testing.T) {
	for _, p := range movePhases {
		if p.class == classHalted || p.phase == database.AppMoveRolledBack {
			continue
		}
		for _, halted := range []database.AppMovePhase{database.AppMoveFailed, database.AppMoveConflict} {
			m := database.AppMove{Phase: halted, HaltedPhase: p.phase}
			if got, want := pastCommit(m), p.class == classPostCommit; got != want {
				t.Errorf("%s halted in %s: pastCommit = %v, want %v", halted, p.phase, got, want)
			}
			if got, want := compensating(m), p.class == classCompensation; got != want {
				t.Errorf("%s halted in %s: compensating = %v, want %v", halted, p.phase, got, want)
			}
		}
		m := database.AppMove{Phase: p.phase}
		if pastCommit(m) != (p.class == classPostCommit) || compensating(m) != (p.class == classCompensation) {
			t.Errorf("%s: pastCommit/compensating disagree with the class", p.phase)
		}
	}
}

func TestMovePhases_TheSuccessorDependsOnTheShapeOfTheMove(t *testing.T) {
	tests := []struct {
		from             database.AppMovePhase
		routed, stateful bool
		want             database.AppMovePhase
		ok               bool
	}{
		{database.AppMoveVerified, false, false, database.AppMoveCommitted, true},
		{database.AppMoveVerified, true, false, database.AppMoveRoutesDestIncluded, true},
		{database.AppMoveRoutesDestIncluded, true, false, database.AppMoveRoutesSwitched, true},
		{database.AppMoveRoutesSwitched, true, false, database.AppMoveCommitted, true},
		{database.AppMoveCommitted, false, false, database.AppMoveSourceParked, true},
		{database.AppMoveCommitted, true, false, database.AppMoveRoutesSourceCleaned, true},
		{database.AppMoveRoutesSourceCleaned, true, false, database.AppMoveSourceParked, true},
		{database.AppMoveStaged, false, false, database.AppMoveStarted, true},
		{database.AppMoveStaged, false, true, database.AppMoveSourceStop, true},
		{database.AppMoveRoutesSwitched, false, false, "", false}, // not on the unrouted path
		{database.AppMoveDone, true, true, "", false},
		{database.AppMoveCompensatingBStopped, false, false, "", false},
	}
	for _, tc := range tests {
		got, ok := successorOf(tc.from, tc.routed, tc.stateful)
		if got != tc.want || ok != tc.ok {
			t.Errorf("successor of %s (routed %v, stateful %v) = %q %v, want %q %v", tc.from, tc.routed, tc.stateful, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMovePhases_TheStepsOfARoutedPlanHaveTheRoutesPhasesInOrder(t *testing.T) {
	want := []string{
		"preflight", "staged", "started", "verified", "routes_dest_included", "routes_switched", "committed",
		"routes_source_cleaned", "source_parked",
	}
	if got := moveSteps(false, true); !slices.Equal(got, want) {
		t.Errorf("routed steps = %v, want %v", got, want)
	}
	if got := moveSteps(true, false); slices.Contains(got, "routes_switched") || !slices.Contains(got, "data_copied") {
		t.Errorf("unrouted stateful steps = %v", got)
	}
}

// ---- a world with routes ---------------------------------------------------------------------------------------

const (
	tunnelOfA = "tun-a"
	tunnelOfB = "tun-b"
)

// routedWorld is a move world whose nodes both have a committed Cloudflare tunnel and whose service is configured
// for Cloudflare.
type routedWorld struct {
	*moveWorld
	instance domain.ID
	routes   *AppRoutes
}

func newRoutedWorld(t *testing.T) *routedWorld {
	t.Helper()
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	cf := &config.Cloudflare{AccountID: "acct", Zone: "example.com"}
	w.svc.cfg.Cloudflare, w.plans.cfg.Cloudflare = cf, cf
	rw := &routedWorld{moveWorld: w}
	rw.routes = &AppRoutes{core: w.svc.core, plans: w.plans}
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		instance := database.Instance{ID: w.ids.NewID(), Name: "sm", CreatedAt: w.clock.Now()}
		if err := database.CreateInstance(ctx, tx, instance); err != nil {
			return err
		}
		rw.instance = instance.ID
		return nil
	})
	rw.setTransport(w.node.ID, domain.TransportCloudflare, "ssh-web-1.example.com")
	rw.setTransport(w.dest.ID, domain.TransportCloudflare, "ssh-web-2.example.com")
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		for node, tunnel := range map[domain.ID]string{w.node.ID: tunnelOfA, w.dest.ID: tunnelOfB} {
			_, err := database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
				ID: w.ids.NewID(), NodeID: node, AccountID: "acct", Zone: "example.com", InstanceID: rw.instance.String(),
				Hostname: "ssh.example.com", Objects: database.TunnelObjects{TunnelID: tunnel}, CreatedAt: w.clock.Now(),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return rw
}

// setTransport changes how the control plane reaches the node.
func (rw *routedWorld) setTransport(node domain.ID, transport domain.Transport, hostname string) {
	rw.t.Helper()
	rw.inTx(func(ctx context.Context, tx *database.Tx) error {
		n, err := database.GetNode(ctx, tx, node)
		if err != nil {
			return err
		}
		n.Endpoint.Transport, n.Endpoint.TunnelHostname = transport, hostname
		_, err = database.UpdateNodeSpec(ctx, tx, n, n.SpecRevision)
		return err
	})
}

// freshNodes are the nodes as the database has them now, as a job loads them.
func (rw *routedWorld) freshNodes() (a, b domain.Node) {
	rw.t.Helper()
	var err error
	a, err = database.GetNode(context.Background(), rw.db.Reader(), rw.node.ID)
	mustf(rw.t, err, "GetNode A")
	b, err = database.GetNode(context.Background(), rw.db.Reader(), rw.dest.ID)
	mustf(rw.t, err, "GetNode B")
	return a, b
}

// addTarget adds an app target of its own on node.
func (rw *routedWorld) addTarget(name string, node domain.ID) database.AppTarget {
	rw.t.Helper()
	var target database.AppTarget
	rw.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := rw.clock.Now()
		app, err := database.CreateApp(ctx, tx, database.App{
			ID: rw.ids.NewID(), Name: name, DeployedService: "web", ImagePolicyJSON: []byte(`{}`), ComposeSource: "control-plane",
			CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		target, err = database.CreateAppTarget(ctx, tx, database.AppTarget{
			ID: rw.ids.NewID(), AppID: app.ID, EnvironmentID: rw.env.ID, NodeID: node, ComposeProject: "sm-" + name,
			DeploymentPolicyJSON: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		})
		return err
	})
	return target
}

// route adds a route of the target on its node, in the phase: an active one has its record and, with owners access,
// its Access application.
func (rw *routedWorld) route(target database.AppTarget, hostname, access string, phase database.AppRoutePhase) database.AppRoute {
	rw.t.Helper()
	tunnel := tunnelOfA
	if target.NodeID == rw.dest.ID {
		tunnel = tunnelOfB
	}
	var route database.AppRoute
	rw.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		route, err = database.InsertAppRoute(ctx, tx, database.AppRoute{
			ID: rw.ids.NewID(), AppTargetID: target.ID, NodeID: target.NodeID, Hostname: hostname, Service: "web", Port: 8080,
			Access: access, AccountID: "acct", Zone: "example.com", InstanceID: rw.instance.String(),
			TunnelID: tunnel, TunnelGeneration: 1, CreatedBy: rw.admin, CreatedAt: rw.clock.Now(),
		})
		return err
	})
	if phase != database.AppRouteWaiting {
		rw.exec(`UPDATE app_routes SET phase = ? WHERE id = ?`, phase, route.ID)
	}
	if phase == database.AppRouteActive {
		rw.exec(`UPDATE app_routes SET dns_record_id = ? WHERE id = ?`, "dns-"+hostname, route.ID)
		if access == "owners" {
			rw.exec(`UPDATE app_routes SET access_app_id = ? WHERE id = ?`, "app-"+hostname, route.ID)
		}
	}
	return rw.liveRoute(route.ID)
}

// main is the world's own app target, on A.
func (rw *routedWorld) main() database.AppTarget {
	rw.t.Helper()
	target, err := database.GetAppTarget(context.Background(), rw.db.Reader(), rw.target.ID)
	mustf(rw.t, err, "GetAppTarget")
	return target
}

func (rw *routedWorld) liveRoute(id domain.ID) database.AppRoute {
	rw.t.Helper()
	r, err := database.GetAppRoute(context.Background(), rw.db.Reader(), id)
	mustf(rw.t, err, "GetAppRoute")
	return r
}

func (rw *routedWorld) fillerRoutes(target database.AppTarget, n int) {
	rw.t.Helper()
	for i := range n {
		rw.route(target, fmt.Sprintf("filler-%d.example.com", i), "public", database.AppRouteActive)
	}
}

func (rw *routedWorld) moveRows(m database.AppMove) []database.AppMoveRoute {
	rw.t.Helper()
	rows, err := database.ListAppMoveRoutes(context.Background(), rw.db.Reader(), m.ID)
	mustf(rw.t, err, "ListAppMoveRoutes")
	return rows
}

// incomingMove writes an open move of another target into B with a pending row per route, the way a request would,
// borrowing the plan and job of the main move.
func (rw *routedWorld) incomingMove(target database.AppTarget, like database.AppMove, routes ...database.AppRoute) database.AppMove {
	rw.t.Helper()
	var m database.AppMove
	rw.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		m, err = database.InsertAppMove(ctx, tx, database.AppMove{
			ID: rw.ids.NewID(), AppTargetID: target.ID, SourceNodeID: rw.node.ID, DestNodeID: rw.dest.ID, PlanID: like.PlanID,
			JobID: like.JobID, KnownGoodDeploymentID: like.KnownGoodDeploymentID, CreatedBy: rw.admin, CreatedAt: rw.clock.Now(),
		}, nil)
		if err != nil {
			return err
		}
		rows := make([]database.AppMoveRoute, len(routes))
		for i, r := range routes {
			rows[i] = database.AppMoveRoute{
				RouteID: r.ID, FrozenPhase: r.Phase, FromNodeID: rw.node.ID, FromTunnelID: tunnelOfA, FromGeneration: 1,
				ToNodeID: rw.dest.ID, ToTunnelID: tunnelOfB, ToGeneration: 1,
			}
		}
		_, err = database.InsertAppMoveRoutes(ctx, tx, m.ID, rows, rw.clock.Now())
		return err
	})
	return m
}

func (rw *routedWorld) mustRoutedMove() AppMoveResult {
	rw.t.Helper()
	res, err := rw.move()
	mustf(rw.t, err, "Move")
	return res
}

// ---- admission --------------------------------------------------------------------------------------------------

func TestMoveRoutes_APlanFreezesEveryRouteAndTheTunnelsOfBothNodes(t *testing.T) {
	rw := newRoutedWorld(t)
	active := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	waiting := rw.route(rw.main(), "later.example.com", "public", database.AppRouteWaiting)

	res := rw.mustRoutedMove()

	rows := rw.moveRows(res.Move)
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	for _, row := range rows {
		want := database.AppMoveRoute{
			MoveID: res.Move.ID, RouteID: row.RouteID, FromNodeID: rw.node.ID, FromTunnelID: tunnelOfA, FromGeneration: 1,
			ToNodeID: rw.dest.ID, ToTunnelID: tunnelOfB, ToGeneration: 1, State: database.AppMoveRoutePending,
		}
		switch row.RouteID {
		case active.ID:
			want.FrozenPhase, want.DNSRecordID = database.AppRouteActive, "dns-shop.example.com"
		case waiting.ID:
			want.FrozenPhase = database.AppRouteWaiting
		default:
			t.Fatalf("row for an unknown route %s", row.RouteID)
		}
		row.CreatedAt, row.UpdatedAt = time.Time{}, time.Time{}
		if row != want {
			t.Errorf("row = %+v, want %+v", row, want)
		}
	}
	p := rw.planOfJob(res.Submission.Job)
	if !slices.Contains(p.Steps, "routes_switched") {
		t.Errorf("steps = %v, want the routes phases", p.Steps)
	}
	var named []string
	for _, in := range p.Inputs {
		if in.Type == moveRouteInputType {
			named = append(named, in.ID)
		}
	}
	slices.Sort(named)
	if want := []string{active.ID.String(), waiting.ID.String()}; !slices.Equal(named, sortedStrings(want)) {
		t.Errorf("route inputs = %v, want %v", named, want)
	}
}

func sortedStrings(s []string) []string {
	slices.Sort(s)
	return s
}

func TestMoveRoutes_AnUnroutedTargetKeepsItsPlan(t *testing.T) {
	rw := newRoutedWorld(t)

	res := rw.mustRoutedMove()

	if rows := rw.moveRows(res.Move); len(rows) != 0 {
		t.Errorf("rows = %+v, want none", rows)
	}
	p := rw.planOfJob(res.Submission.Job)
	if slices.Contains(p.Steps, "routes_switched") || slices.ContainsFunc(p.Inputs, func(in plan.Input) bool { return in.Type == moveRouteInputType }) {
		t.Errorf("plan = %+v, want no routes", p)
	}
}

func TestMoveRoutes_RefusalsAtRequestTime(t *testing.T) {
	tests := []struct {
		name     string
		code     smerr.Code
		contains string
		setup    func(rw *routedWorld)
	}{
		{"a provisioning route", smerr.CodeConflict, "shop.example.com is provisioning", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteProvisioning)
		}},
		{"an ingress_ready route", smerr.CodeConflict, "ingress_ready", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteIngressReady)
		}},
		{"an access_ready route", smerr.CodeConflict, "access_ready", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteAccessReady)
		}},
		{"a route being removed", smerr.CodeConflict, "removing", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteRemoving)
		}},
		{"a route whose DNS record is removed", smerr.CodeConflict, "dns_removed", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteDNSRemoved)
		}},
		{"a failed route", smerr.CodeConflict, "failed", func(rw *routedWorld) {
			r := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			rw.exec(`UPDATE app_routes SET phase = 'failed', halted_phase = 'active' WHERE id = ?`, r.ID)
		}},
		{"a conflicting route", smerr.CodeConflict, "conflict", func(rw *routedWorld) {
			r := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			rw.exec(`UPDATE app_routes SET phase = 'conflict', halted_phase = 'active' WHERE id = ?`, r.ID)
		}},
		{"a route with an open job", smerr.CodeConflict, "has a job that has not ended", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			_, err := rw.routes.Unexpose(context.Background(), rw.caller(rw.admin), rw.target.ID, "shop.example.com")
			mustf(rw.t, err, "Unexpose")
		}},
		{"a destination without a connector", smerr.CodeCapabilityUnavailable, "no Cloudflare connector", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			rw.setTransport(rw.dest.ID, domain.TransportDirect, "")
		}},
		{"a destination whose tunnel was disabled", smerr.CodeCapabilityUnavailable, "no Cloudflare connector", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			rw.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := tx.ExecContext(ctx, `DELETE FROM tunnel_operations WHERE node_id = ?`, rw.dest.ID)
				return err
			})
		}},
		{"a route of another zone", smerr.CodeConflict, "another Cloudflare account, zone or instance", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			rw.svc.cfg.Cloudflare = &config.Cloudflare{AccountID: "acct", Zone: "other.example"}
		}},
		{"no Cloudflare configuration", smerr.CodeInvalidArgument, "cloudflare", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			rw.svc.cfg.Cloudflare = nil
		}},
		{"an owners route and no Cloudflare access", smerr.CodeInvalidArgument, "cloudflare", func(rw *routedWorld) {
			rw.route(rw.main(), "shop.example.com", "owners", database.AppRouteActive)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rw := newRoutedWorld(t)
			tc.setup(rw)
			moves, plans := rw.rowCount("app_moves"), rw.rowCount("plans")

			_, err := rw.move()

			wantRefusal(t, err, tc.code, tc.contains)
			if rw.rowCount("app_moves") != moves || rw.rowCount("plans") != plans {
				t.Error("a refused request wrote a move or a plan")
			}
		})
	}
}

func TestMoveRoutes_ARemovedRouteAndAWaitingRouteDoNotBlock(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "gone.example.com", "public", database.AppRouteRemoved)
	rw.route(rw.main(), "later.example.com", "public", database.AppRouteWaiting)

	res := rw.mustRoutedMove()

	if rows := rw.moveRows(res.Move); len(rows) != 1 || rows[0].FrozenPhase != database.AppRouteWaiting {
		t.Errorf("rows = %+v, want the waiting route only", rows)
	}
}

// ---- capacity --------------------------------------------------------------------------------------------------

func TestMoveRoutes_CapacityOfTheDestinationIsHeldAt98(t *testing.T) {
	rw := newRoutedWorld(t)
	filler := rw.addTarget("filler", rw.dest.ID)
	rw.fillerRoutes(filler, 97)
	rw.route(rw.main(), "a.example.com", "public", database.AppRouteActive)
	rw.route(rw.main(), "b.example.com", "public", database.AppRouteWaiting)

	_, err := rw.move()
	wantRefusal(t, err, smerr.CodeConflict, "limit of 98")

	rw.exec(`UPDATE app_routes SET phase = 'removed' WHERE hostname = 'filler-0.example.com'`) // 96 live: 98 with the two
	res, err := rw.move()
	mustf(t, err, "Move at the boundary")
	if len(rw.moveRows(res.Move)) != 2 {
		t.Errorf("rows = %+v, want 2", rw.moveRows(res.Move))
	}
}

func TestMoveRoutes_TwoIncomingMovesAndAnOrdinaryExposeShareTheCapacity(t *testing.T) {
	rw := newRoutedWorld(t)
	filler := rw.addTarget("filler", rw.dest.ID)
	rw.fillerRoutes(filler, 94)
	rw.route(rw.main(), "a.example.com", "public", database.AppRouteActive)
	rw.route(rw.main(), "b.example.com", "public", database.AppRouteActive)
	first := rw.mustRoutedMove() // 94 live + 2 reserved
	other := rw.addTarget("other", rw.node.ID)
	second := rw.incomingMove(other, first.Move,
		rw.route(other, "c.example.com", "public", database.AppRouteActive),
		rw.route(other, "d.example.com", "public", database.AppRouteActive)) // 94 + 4 reserved: the last slot is gone
	expose := func() error {
		ctx := context.Background()
		_, _, err := rw.routes.assess(ctx, rw.db.Reader(), filler.ID, appRouteParams{Hostname: "new.example.com", Service: "web", Port: "8080", Access: "public"}, true)
		return err
	}

	wantRefusal(t, expose(), smerr.CodeConflict, "4 reserved by moves")

	rw.exec(`UPDATE app_moves SET phase = 'rolled_back' WHERE id = ?`, second.ID)
	mustf(t, expose(), "an ordinary expose after one move rolled back") // 94 + 2 + 1
	rw.route(filler, "new.example.com", "public", database.AppRouteActive)
	rw.exec(`UPDATE app_moves SET phase = 'rolled_back' WHERE id = ?`, first.Move.ID)
	mustf(t, expose2(rw, filler.ID), "an ordinary expose after both rolled back")
}

func expose2(rw *routedWorld, targetID domain.ID) error {
	_, _, err := rw.routes.assess(context.Background(), rw.db.Reader(), targetID,
		appRouteParams{Hostname: "newer.example.com", Service: "web", Port: "8080", Access: "public"}, true)
	return err
}

func TestMoveRoutes_TheMoveItselfIsNotCountedTwice(t *testing.T) {
	rw := newRoutedWorld(t)
	filler := rw.addTarget("filler", rw.dest.ID)
	rw.fillerRoutes(filler, 96)
	rw.route(rw.main(), "a.example.com", "public", database.AppRouteActive)
	rw.route(rw.main(), "b.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove() // 96 + 2 = 98
	ctx := context.Background()
	dest, err := database.GetNode(ctx, rw.db.Reader(), rw.dest.ID)
	mustf(t, err, "GetNode")

	wantRefusal(t, requireRouteCapacity(ctx, rw.db.Reader(), dest, 2, ""), smerr.CodeConflict, "98")
	mustf(t, requireRouteCapacity(ctx, rw.db.Reader(), dest, 2, res.Move.ID), "capacity checked as the move itself")
}

// ---- the Access applications -----------------------------------------------------------------------------------

// accessStub answers the two Access reads of the check; every other call panics through the nil interface.
type accessStub struct {
	CloudflareAPI
	apps []cloudflare.AccessApp
}

func (a accessStub) ResolveAllowedIdPs(context.Context, []string) ([]string, error) {
	return []string{"idp-1"}, nil
}

func (a accessStub) FindAccessApps(_ context.Context, name string) ([]cloudflare.AccessApp, error) {
	var out []cloudflare.AccessApp
	for _, app := range a.apps {
		if app.Name == name {
			out = append(out, app)
		}
	}
	return out, nil
}

// accessEngine is a tunnel engine whose Cloudflare client is the stub, over the world's database.
func (rw *routedWorld) accessEngine(apps ...cloudflare.AccessApp) *tunnelEngine {
	rw.t.Helper()
	store := newMemSecrets()
	_, err := store.Put(context.Background(), "cf-api", audit.Secret("api-token"), nil)
	mustf(rw.t, err, "Put")
	rw.inTx(func(ctx context.Context, tx *database.Tx) error {
		if _, err := database.GetCloudflareState(ctx, tx); err == nil {
			return nil
		}
		_, err := database.SaveCloudflareState(ctx, tx, database.CloudflareState{AccountID: "acct", OwnersPolicyID: "owners-1"}, 0, rw.clock.Now())
		return err
	})
	engine, err := newTunnelEngine(rw.svc.core, &TunnelOptions{
		Config:  config.Cloudflare{AccountID: "acct", Zone: "example.com", APITokenRef: "secret://cf-api", AccessTokenRef: "secret://cf-access"},
		Secrets: store,
		NewAPI:  func(string, audit.Secret) (CloudflareAPI, error) { return accessStub{apps: apps}, nil },
	})
	mustf(rw.t, err, "newTunnelEngine")
	return engine
}

func (rw *routedWorld) accessAppOf(route database.AppRoute) cloudflare.AccessApp {
	return cloudflare.AccessApp{
		ID: route.Objects.AccessAppID, Name: cloudflare.RouteAccessAppName(rw.instance.String(), route.ID.String()),
		Domain: route.Hostname, Type: accessAppType, PolicyIDs: []string{"owners-1"}, AllowedIdPs: []string{"idp-1"},
	}
}

func TestMoveRoutes_TheAccessCheckRefusesAMissingOrDriftedApplication(t *testing.T) {
	rw := newRoutedWorld(t)
	route := rw.route(rw.main(), "admin.example.com", "owners", database.AppRouteActive)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	rw.route(rw.main(), "later.example.com", "owners", database.AppRouteWaiting)
	good := rw.accessAppOf(route)
	drift := func(mutate func(*cloudflare.AccessApp)) cloudflare.AccessApp {
		app := good
		mutate(&app)
		return app
	}
	tests := []struct {
		name string
		apps []cloudflare.AccessApp
		ok   bool
	}{
		{"the application is as required", []cloudflare.AccessApp{good}, true},
		{"the application is missing", nil, false},
		{"another application has the recorded name but a different ID", []cloudflare.AccessApp{drift(func(a *cloudflare.AccessApp) { a.ID = "other" })}, false},
		{"it guards another domain", []cloudflare.AccessApp{drift(func(a *cloudflare.AccessApp) { a.Domain = "elsewhere.example.com" })}, false},
		{"it carries another policy", []cloudflare.AccessApp{drift(func(a *cloudflare.AccessApp) { a.PolicyIDs = []string{"allow-all"} })}, false},
		{"it carries the owners policy and another", []cloudflare.AccessApp{drift(func(a *cloudflare.AccessApp) { a.PolicyIDs = []string{"owners-1", "allow-all"} })}, false},
		{"it allows other identity providers", []cloudflare.AccessApp{drift(func(a *cloudflare.AccessApp) { a.AllowedIdPs = []string{"idp-2"} })}, false},
		{"it is not a self-hosted application", []cloudflare.AccessApp{drift(func(a *cloudflare.AccessApp) { a.Type = "bookmark" })}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := rw.accessEngine(tc.apps...)
			rows := []database.AppMoveRoute{}
			for _, r := range []database.AppRoute{route} {
				rows = append(rows, database.AppMoveRoute{RouteID: r.ID, FrozenPhase: database.AppRouteActive})
			}

			err := checkMoveAccessApps(context.Background(), rw.db.Reader(), engine, rows)

			if tc.ok {
				mustf(t, err, "checkMoveAccessApps")
				return
			}
			wantRefusal(t, err, smerr.CodeConflict, "admin.example.com")
		})
	}
}

func TestMoveRoutes_TheAccessCheckSkipsPublicAndWaitingRoutesAndNeedsTheEngineForOwners(t *testing.T) {
	rw := newRoutedWorld(t)
	public := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	waiting := rw.route(rw.main(), "later.example.com", "owners", database.AppRouteWaiting)
	rows := []database.AppMoveRoute{
		{RouteID: public.ID, FrozenPhase: database.AppRouteActive}, {RouteID: waiting.ID, FrozenPhase: database.AppRouteWaiting},
	}

	mustf(t, checkMoveAccessApps(context.Background(), rw.db.Reader(), nil, rows), "no owners route needs no Cloudflare")

	owners := rw.route(rw.main(), "admin.example.com", "owners", database.AppRouteActive)
	rows = append(rows, database.AppMoveRoute{RouteID: owners.ID, FrozenPhase: database.AppRouteActive})
	wantAppsCode(t, checkMoveAccessApps(context.Background(), rw.db.Reader(), nil, rows), smerr.CodeInvalidArgument)
}

func TestMoveRoutes_AMoveIsRefusedWhenItsOwnersRouteHasNoApplication(t *testing.T) {
	rw := newRoutedWorld(t)
	route := rw.route(rw.main(), "admin.example.com", "owners", database.AppRouteActive)

	mustf(t, rw.svc.UseTunnel(&TunnelOptions{
		Config:  config.Cloudflare{AccountID: "acct", Zone: "example.com", APITokenRef: "secret://cf-api", AccessTokenRef: "secret://cf-access"},
		Secrets: rw.accessEngine().opts.Secrets,
		NewAPI:  func(string, audit.Secret) (CloudflareAPI, error) { return accessStub{}, nil },
	}), "UseTunnel")
	moves := rw.rowCount("app_moves")

	_, err := rw.move()

	wantRefusal(t, err, smerr.CodeConflict, "admin.example.com")
	if rw.rowCount("app_moves") != moves {
		t.Error("a refused request wrote a move")
	}

	mustf(t, rw.svc.UseTunnel(&TunnelOptions{
		Config:  config.Cloudflare{AccountID: "acct", Zone: "example.com", APITokenRef: "secret://cf-api", AccessTokenRef: "secret://cf-access"},
		Secrets: rw.accessEngine().opts.Secrets,
		NewAPI: func(string, audit.Secret) (CloudflareAPI, error) {
			return accessStub{apps: []cloudflare.AccessApp{rw.accessAppOf(route)}}, nil
		},
	}), "UseTunnel")
	if _, err := rw.move(); err != nil {
		t.Fatalf("Move with the application in place: %v", err)
	}
}

// ---- freeze and revalidation -----------------------------------------------------------------------------------

func TestMoveRoutes_RevalidationFailsOnAnyDifferenceFromWhatTheMoveFroze(t *testing.T) {
	changes := map[string]func(rw *routedWorld, route database.AppRoute){
		"a route was added": func(rw *routedWorld, _ database.AppRoute) {
			rw.route(rw.main(), "new.example.com", "public", database.AppRouteWaiting)
		},
		"a route was removed": func(rw *routedWorld, route database.AppRoute) {
			rw.exec(`UPDATE app_routes SET phase = 'removed' WHERE id = ?`, route.ID)
		},
		"a route changed phase": func(rw *routedWorld, route database.AppRoute) {
			rw.exec(`UPDATE app_routes SET phase = 'removing' WHERE id = ?`, route.ID)
		},
		"B's tunnel changed": func(rw *routedWorld, _ database.AppRoute) {
			rw.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
					ID: rw.ids.NewID(), NodeID: rw.dest.ID, AccountID: "acct", Zone: "example.com", InstanceID: rw.instance.String(),
					Objects: database.TunnelObjects{TunnelID: "tun-b2"}, CreatedAt: rw.clock.Now(),
				})
				return err
			})
		},
		"B's tunnel generation changed": func(rw *routedWorld, _ database.AppRoute) {
			rw.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
					ID: rw.ids.NewID(), NodeID: rw.dest.ID, AccountID: "acct", Zone: "example.com", InstanceID: rw.instance.String(),
					Objects: database.TunnelObjects{TunnelID: tunnelOfB}, CreatedAt: rw.clock.Now(),
				})
				return err
			})
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			rw := newRoutedWorld(t)
			route := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			job := rw.approved(rw.mustRoutedMove())
			mustf(t, rw.revalidate(job), "Revalidate before the change")

			change(rw, route)

			wantError(t, rw.revalidate(job), smerr.CodeConflict, smerr.ReasonPlanStale)
		})
	}
}

func TestMoveRoutes_AHaltedRouteKeepsTheFrozenPhaseForRevalidation(t *testing.T) {
	rw := newRoutedWorld(t)
	route := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	job := rw.approved(rw.mustRoutedMove())

	rw.exec(`UPDATE app_routes SET phase = 'failed', halted_phase = 'active' WHERE id = ?`, route.ID)

	mustf(t, rw.revalidate(job), "Revalidate with the route halted in the frozen phase")
}

func TestMoveRoutes_AfterTheCommitAndInCompensationRevalidationReadsTheMoveRecord(t *testing.T) {
	rw := newRoutedWorld(t)
	route := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	rw.mustRoutedMove()
	m := rw.openMove()

	rw.exec(`UPDATE app_moves SET phase = 'compensating_routes_restored' WHERE id = ?`, m.ID)
	rw.exec(`UPDATE app_routes SET phase = 'removing' WHERE id = ?`, route.ID)
	mustf(t, requireFrozenRoutes(context.Background(), rw.db.Reader(), rw.openMove()), "compensation does not depend on the forward check")

	rw.exec(`UPDATE app_moves SET phase = 'routes_source_cleaned' WHERE id = ?`, m.ID)
	mustf(t, requireFrozenRoutes(context.Background(), rw.db.Reader(), rw.openMove()), "a committed move does not either")
}

func TestMoveRoutes_ARecheckUnderTheClaimLocksComparesWithTheFrozenRoutes(t *testing.T) {
	rw := newRoutedWorld(t)
	filler := rw.addTarget("filler", rw.dest.ID)
	rw.fillerRoutes(filler, 95)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove() // 95 + 1
	a, b := rw.freshNodes()
	run := &moveRun{
		h: appMoveHandler{core: rw.svc.core}, move: res.Move, target: rw.main(),
		a: moveNode{node: a}, b: moveNode{node: b},
	}
	ctx := context.Background()
	mustf(t, run.recheckRoutes(ctx), "recheck of the frozen routes")

	other := rw.addTarget("other", rw.node.ID)
	rw.incomingMove(other, res.Move, rw.route(other, "x.example.com", "public", database.AppRouteActive),
		rw.route(other, "y.example.com", "public", database.AppRouteActive),
		rw.route(other, "z.example.com", "public", database.AppRouteActive)) // 95 + 3 others + the move's own: one too many
	wantRefusal(t, run.recheckRoutes(ctx), smerr.CodeConflict, "limit of 98")
}

func TestMoveRoutes_ARecheckRefusesRoutesTheMoveDidNotFreeze(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove()
	a, b := rw.freshNodes()
	run := &moveRun{
		h: appMoveHandler{core: rw.svc.core}, move: res.Move, target: rw.main(),
		a: moveNode{node: a}, b: moveNode{node: b},
	}

	rw.route(rw.main(), "new.example.com", "public", database.AppRouteWaiting)

	wantRefusal(t, run.recheckRoutes(context.Background()), smerr.CodeConflict, "differ from what the plan froze")
}

// ---- refusals while a routed move is open ----------------------------------------------------------------------

// openRoutedMove puts the target in a routed move, written directly so that jobs queued before it exist.
func (rw *routedWorld) openRoutedMove(like database.AppMove) database.AppMove {
	rw.t.Helper()
	route := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	return rw.incomingMove(rw.main(), like, route)
}

func TestOpenRoutedMove_RefusesExposeAndUnexposeOfTheTargetAtRequestTime(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove()
	ctx := context.Background()
	jobs := rw.rowCount("jobs")

	_, err := rw.routes.Expose(ctx, rw.caller(rw.admin), rw.target.ID, ExposeRouteRequest{Hostname: "new.example.com", Service: "web", Port: 8080})
	wantRefusal(t, err, smerr.CodeConflict, res.Move.ID.String())

	_, err = rw.routes.Unexpose(ctx, rw.caller(rw.admin), rw.target.ID, "shop.example.com")
	wantRefusal(t, err, smerr.CodeConflict, "an unexpose is refused")

	// the existing-route path of assess: the same parameters as the live route
	_, _, err = rw.routes.assess(ctx, rw.db.Reader(), rw.target.ID,
		appRouteParams{Hostname: "shop.example.com", Service: "web", Port: "8080", Access: "public"}, false)
	wantRefusal(t, err, smerr.CodeConflict, "an expose is refused")
	if rw.rowCount("jobs") != jobs {
		t.Error("a refused request queued a job")
	}
}

func TestOpenRoutedMove_StillRefusesWhenItIsHalted(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	rw.mustRoutedMove()
	rw.exec(`UPDATE app_moves SET phase = 'conflict', halted_phase = 'routes_switched'`)

	_, err := rw.routes.Unexpose(context.Background(), rw.caller(rw.admin), rw.target.ID, "shop.example.com")

	wantRefusal(t, err, smerr.CodeConflict, "routes_switched")
}

func TestOpenRoutedMove_OnlyAnOpenMoveWithRoutesRefuses(t *testing.T) {
	for _, phase := range []string{"preflight", "routes_switched", "committed", "compensating_b_stopped", "done", "rolled_back"} {
		t.Run(phase, func(t *testing.T) {
			rw := newRoutedWorld(t)
			rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			res := rw.mustRoutedMove()
			rw.exec(`UPDATE app_moves SET phase = ? WHERE id = ?`, phase, res.Move.ID)
			ctx := context.Background()

			err := requireNoRoutedMove(ctx, rw.db.Reader(), rw.target.ID, "an expose")
			onNode := requireNoRoutedMoveOnNode(ctx, rw.db.Reader(), rw.dest.ID, "a tunnel setup")

			if finished := phase == "done" || phase == "rolled_back"; finished == (err != nil) || finished == (onNode != nil) {
				t.Errorf("phase %s: refusals = %v, %v", phase, err, onNode)
			}
		})
	}
}

func TestOpenRoutedMove_AMoveWithoutRoutesDoesNotRefuse(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.mustRoutedMove()
	ctx := context.Background()

	mustf(t, requireNoRoutedMove(ctx, rw.db.Reader(), rw.target.ID, "an expose"), "an unrouted move")
	mustf(t, requireNoRoutedMoveOnNode(ctx, rw.db.Reader(), rw.dest.ID, "a tunnel setup"), "an unrouted move, tunnel operation")
}

func TestOpenRoutedMove_RefusesTunnelOperationsOnEitherNode(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove()
	ctx := context.Background()
	third := rw.insertNode("web-3")
	for name, req := range map[string]PlanRequest{
		"disable of A": {Action: policy.ActionNodeTunnelDisable, Target: nodeRef(rw.node.ID)},
		"disable of B": {Action: policy.ActionNodeTunnelDisable, Target: nodeRef(rw.dest.ID)},
		"setup of A":   {Action: policy.ActionNodeSetup, Target: nodeRef(rw.node.ID), Parameters: map[string]any{policy.ParamTunnel: "true"}},
		"setup of B":   {Action: policy.ActionNodeSetup, Target: nodeRef(rw.dest.ID), Parameters: map[string]any{policy.ParamTunnel: "true"}},
		"rotation":     {Action: policy.ActionCloudflareRotate, Target: domain.ResourceRef{Type: domain.ResourceInstance, ID: "instance"}},
	} {
		err := rw.plans.requireTunnelAvailable(ctx, rw.db.Reader(), req)
		wantRefusal(t, err, smerr.CodeConflict, res.Move.ID.String())
		if !strings.Contains(err.Error(), "refused while move") {
			t.Errorf("%s: %v", name, err)
		}
	}
	err := requireNoRoutedMoveOnNode(ctx, rw.db.Reader(), third, "a tunnel setup")
	mustf(t, err, "a node outside the move")
}

func (rw *routedWorld) insertNode(name string) domain.ID {
	rw.t.Helper()
	var id domain.ID
	rw.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := rw.clock.Now()
		n, err := database.CreateNode(ctx, tx, domain.Node{
			ID: rw.ids.NewID(), ProviderID: rw.provider.ID, NativeID: name, Name: name, Kind: "ssh", EnvironmentID: &rw.env.ID,
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			Endpoint:      domain.NodeEndpoint{Host: "10.0.0.9", Port: 22, User: "supermgmt", AdminUser: "admin", AdminCredentialRef: "ssh-agent://default", HostPublicKey: testHostKey},
			CredentialRef: "secret://ssh/default", CreatedAt: now, UpdatedAt: now,
		})
		id = n.ID
		return err
	})
	return id
}

// lockPlanFor stores a plan of action and returns a job of jobType on resource that carries it.
func (rw *routedWorld) lockPlanFor(jobType, action string, resource domain.ResourceRef, params map[string]any) jobs.Job {
	rw.t.Helper()
	raw, err := plan.Canonical(&plan.Plan{
		Version: plan.Version, Action: action, Actor: "identity/" + rw.admin.String(),
		Targets: []plan.Target{{Type: string(resource.Type), ID: resource.ID.String()}}, Parameters: params, Risk: domain.RiskOperational,
	})
	mustf(rw.t, err, "plan.Canonical")
	now := rw.clock.Now()
	rec := database.PlanRecord{
		ID: rw.ids.NewID(), Action: action, ActorID: rw.admin, Credential: rw.caller(rw.admin).Credential, PlanJSON: raw,
		PlanHash: "hash-" + rw.ids.NewID().String(), FinalizedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	rw.inTx(func(ctx context.Context, tx *database.Tx) error { return database.InsertPlan(ctx, tx, rec) })
	return jobs.Job{ID: rw.ids.NewID(), Type: jobType, Resource: resource, PlanID: &rec.ID}
}

func TestOpenRoutedMove_RefusesJobsQueuedBeforeItAtClaim(t *testing.T) {
	rw := newRoutedWorld(t)
	// a real expose request, queued while no move was open: it admits a route of a new hostname when approved
	queued, err := rw.routes.Expose(context.Background(), rw.caller(rw.admin), rw.target.ID,
		ExposeRouteRequest{Hostname: "queued.example.com", Service: "web", Port: 8080})
	mustf(t, err, "Expose")
	expose := queued.Submission.Job
	like := rw.mustRoutedMoveLike()
	rw.openRoutedMove(like)
	ctx := context.Background()
	planner := LockPlanner{}

	_, err = planner.PlanLocks(ctx, rw.db.Reader(), expose)
	wantRefusal(t, err, smerr.CodeConflict, "an expose is refused")

	unexpose := rw.lockPlanFor(JobControlPlaneApply, appRouteUnexposeAction, appTargetRef(rw.target.ID), map[string]any{"hostname": "shop.example.com", "route_id": "r"})
	_, err = planner.PlanLocks(ctx, rw.db.Reader(), unexpose)
	wantRefusal(t, err, smerr.CodeConflict, "an unexpose is refused")

	for name, job := range map[string]jobs.Job{
		"setup of A": rw.lockPlanFor(policy.ActionNodeSetup, policy.ActionNodeSetup, nodeRef(rw.node.ID), map[string]any{policy.ParamTunnel: "true"}),
		"setup of B": rw.lockPlanFor(policy.ActionNodeSetup, policy.ActionNodeSetup, nodeRef(rw.dest.ID), map[string]any{policy.ParamTunnel: "true"}),
		"disable":    rw.lockPlanFor(policy.ActionNodeTunnelDisable, policy.ActionNodeTunnelDisable, nodeRef(rw.dest.ID), map[string]any{}),
		"rotation":   rw.lockPlanFor(policy.ActionCloudflareRotate, policy.ActionCloudflareRotate, domain.ResourceRef{Type: domain.ResourceInstance, ID: "instance"}, map[string]any{}),
	} {
		_, err = planner.PlanLocks(ctx, rw.db.Reader(), job)
		if smerr.CodeOf(err) != smerr.CodeConflict || !strings.Contains(err.Error(), "refused while move") {
			t.Errorf("%s: PlanLocks = %v, want a refusal naming the move", name, err)
		}
	}

	plain := rw.lockPlanFor(policy.ActionNodeSetup, policy.ActionNodeSetup, nodeRef(rw.dest.ID), map[string]any{})
	if _, err := planner.PlanLocks(ctx, rw.db.Reader(), plain); err != nil {
		t.Errorf("a setup without a tunnel: PlanLocks = %v, want none", err)
	}
}

// mustRoutedMoveLike runs a plain move request on a throwaway second world's worth of rows: it returns a move whose
// plan and job the hand-written moves borrow, and settles it so that it blocks nothing.
func (rw *routedWorld) mustRoutedMoveLike() database.AppMove {
	rw.t.Helper()
	res := rw.mustRoutedMove()
	rw.exec(`UPDATE app_moves SET phase = 'rolled_back' WHERE id = ?`, res.Move.ID)
	return res.Move
}

func TestOpenRoutedMove_SystemActivationLeavesTheRoutesWaiting(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "later.example.com", "public", database.AppRouteWaiting)
	rw.mustRoutedMove()
	jobsBefore := rw.rowCount("jobs")

	rw.inTx(func(ctx context.Context, tx *database.Tx) error {
		return deployHandler{}.activateRoutes(ctx, tx, rw.target.ID, []compose.HostPort{{Service: "web", Port: 8080, Proto: "tcp", Addr: loopback}})
	})

	if rw.rowCount("jobs") != jobsBefore {
		t.Error("the activation of a waiting route queued a job during the move")
	}
}

// ---- locks -----------------------------------------------------------------------------------------------------

func TestMoveLocks_ARoutedMoveHoldsTheInstanceCloudflareLock(t *testing.T) {
	rw := newRoutedWorld(t)
	plain := rw.mustRoutedMove()
	plainLocks, err := LockPlanner{}.PlanLocks(context.Background(), rw.db.Reader(), rw.job(plain.Submission.Job.ID))
	mustf(t, err, "PlanLocks of an unrouted move")
	if slices.Contains(plainLocks, cloudflareInstanceLock) {
		t.Errorf("an unrouted move holds %v", cloudflareInstanceLock)
	}
	rw.exec(`UPDATE app_moves SET phase = 'rolled_back' WHERE id = ?`, plain.Move.ID)

	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	routed := rw.mustRoutedMove()

	locks, err := LockPlanner{}.PlanLocks(context.Background(), rw.db.Reader(), rw.job(routed.Submission.Job.ID))
	mustf(t, err, "PlanLocks of a routed move")
	if !slices.Contains(locks, cloudflareInstanceLock) {
		t.Errorf("locks = %v, want the instance Cloudflare lock", locks)
	}
}

// ---- abandon ---------------------------------------------------------------------------------------------------

func TestAbandon_ARoutedMoveWithARouteThatMayPointAtBIsRefused(t *testing.T) {
	blocking := []database.AppMoveRouteState{
		database.AppMoveRouteDNSSwitching, database.AppMoveRouteDNSSwitched, database.AppMoveRouteDNSRestoring,
		database.AppMoveRouteDestIncluded, database.AppMoveRouteDestPublished, database.AppMoveRouteDestExcluded,
	}
	allowed := []database.AppMoveRouteState{
		database.AppMoveRoutePending, database.AppMoveRouteDNSRestored, database.AppMoveRouteDestWithdrawn,
	}
	for _, state := range append(slices.Clone(blocking), allowed...) {
		t.Run(string(state), func(t *testing.T) {
			rw := newRoutedWorld(t)
			route := rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
			res := rw.mustRoutedMove()
			rw.exec(`UPDATE app_moves SET phase = 'failed', halted_phase = 'compensating_b_stopped' WHERE id = ?`, res.Move.ID)
			rw.exec(`UPDATE app_move_routes SET state = ? WHERE move_id = ?`, state, res.Move.ID)

			_, err := rw.svc.Abandon(context.Background(), rw.caller(rw.admin), rw.target.ID)

			if slices.Contains(blocking, state) {
				wantRefusal(t, err, smerr.CodeConflict, route.ID.String()+" ("+string(state)+")")
				return
			}
			mustf(t, err, "Abandon")
		})
	}
}

func TestAbandon_ARoutedMoveHaltedAfterTheCommitCannotBeAbandoned(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove()
	rw.exec(`UPDATE app_moves SET phase = 'failed', halted_phase = 'routes_source_cleaned' WHERE id = ?`, res.Move.ID)

	_, err := rw.svc.Abandon(context.Background(), rw.caller(rw.admin), rw.target.ID)

	wantRefusal(t, err, smerr.CodeConflict, "only a move halted in compensation")
}

func TestAbandon_TheClaimRefusesARoutedMoveWhoseRowsChanged(t *testing.T) {
	rw := newRoutedWorld(t)
	rw.route(rw.main(), "shop.example.com", "public", database.AppRouteActive)
	res := rw.mustRoutedMove()
	rw.exec(`UPDATE app_moves SET phase = 'failed', halted_phase = 'compensating_b_stopped' WHERE id = ?`, res.Move.ID)
	sub, err := rw.svc.Abandon(context.Background(), rw.caller(rw.admin), rw.target.ID)
	mustf(t, err, "Abandon")
	job := rw.approved(AppMoveResult{Submission: sub})
	mustf(t, rw.revalidate(job), "Revalidate")

	rw.exec(`UPDATE app_move_routes SET state = 'dns_restoring' WHERE move_id = ?`, res.Move.ID)

	wantRefusal(t, rw.revalidate(job), smerr.CodeConflict, "may point at the destination")
}
