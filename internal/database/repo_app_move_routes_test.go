package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// routedWorld is a stateless move from a to b that has reached routes_switched with two frozen routes: an active one
// whose record was repointed (dns_switched) and a waiting one (pending). B's deployment is verifying, ready to settle.
type routedWorld struct {
	moveWorld
	move            AppMove
	deployment      domain.ID
	active, waiting AppRoute
}

func (mw moveWorld) activeRoute(ctx context.Context, f *fixture, q Querier, target AppTarget, hostname string) AppRoute {
	r := must(InsertAppRoute(ctx, q, appRouteOf(f, target, mw.by, hostname)))
	for _, step := range [][2]AppRoutePhase{
		{AppRouteWaiting, AppRouteProvisioning},
		{AppRouteProvisioning, AppRouteIngressReady},
		{AppRouteIngressReady, AppRouteAccessReady},
		{AppRouteAccessReady, AppRouteActive},
	} {
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, step[0], step[1], AppRouteObjects{DNSRecordID: "dns-" + hostname}, testEpoch))
	}
	return r
}

func frozen(r AppRoute, to domain.ID, toTunnel string, toGeneration int64) AppMoveRoute {
	return AppMoveRoute{
		RouteID: r.ID, FrozenPhase: r.Phase, FromNodeID: r.NodeID, FromTunnelID: r.TunnelID, FromGeneration: r.TunnelGeneration,
		ToNodeID: to, ToTunnelID: toTunnel, ToGeneration: toGeneration, DNSRecordID: r.Objects.DNSRecordID,
	}
}

func newRoutedWorld(ctx context.Context, f *fixture, q Querier, toGeneration int64) routedWorld {
	mw := newMoveWorld(ctx, f, q)
	rw := routedWorld{moveWorld: mw}
	rw.active = mw.activeRoute(ctx, f, q, mw.target, "shop.example.com")
	rw.waiting = must(InsertAppRoute(ctx, q, appRouteOf(f, mw.target, mw.by, "later.example.com")))
	rw.move = mw.move(ctx, f, q, false)
	rw.deployment = mw.deployment(ctx, f, q, "move", mw.b.ID)
	walkDeployment(f, ctx, q, rw.deployment, "queued", "preparing", "staging", "deploying", "verifying")
	must(BindAppMoveDestDeployment(ctx, q, rw.move.ID, rw.deployment, testEpoch))
	must(InsertAppMoveRoutes(ctx, q, rw.move.ID, []AppMoveRoute{
		frozen(rw.active, mw.b.ID, "tun-b", toGeneration), frozen(rw.waiting, mw.b.ID, "tun-b", toGeneration),
	}, testEpoch))
	for _, step := range [][2]AppMovePhase{
		{AppMovePreflight, AppMoveStaged},
		{AppMoveStaged, AppMoveStarted},
		{AppMoveStarted, AppMoveVerified},
		{AppMoveVerified, AppMoveRoutesDestIncluded},
		{AppMoveRoutesDestIncluded, AppMoveRoutesSwitched},
	} {
		rw.move = must(AdvanceAppMovePhase(ctx, q, rw.move.ID, step[0], step[1], testEpoch))
	}
	rw.routeTo(ctx, q, rw.active.ID, AppMoveRoutePending, AppMoveRouteDestIncluded, AppMoveRouteDestPublished,
		AppMoveRouteDNSSwitching, AppMoveRouteDNSSwitched)
	return rw
}

// routeTo walks one row through the states, each fenced on the previous one.
func (rw routedWorld) routeTo(ctx context.Context, q Querier, route domain.ID, from AppMoveRouteState, states ...AppMoveRouteState) {
	for _, s := range states {
		must(AdvanceAppMoveRoute(ctx, q, rw.move.ID, route, from, s, testEpoch))
		from = s
	}
}

func (rw routedWorld) commit(ctx context.Context, q Querier, now time.Time) (AppMove, error) {
	return CommitAppMove(ctx, q, rw.move.ID, rw.target.ID, rw.target.SpecRevision, rw.a.ID, rw.b.ID, rw.deployment, now)
}

func (rw routedWorld) routeOf(ctx context.Context, q Querier, id domain.ID) AppRoute {
	return must(GetAppRoute(ctx, q, id))
}

func TestCommitAppMoveWritesTheRoutesAsOneTuple(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		rw := newRoutedWorld(ctx, f, q, 2)
		later := testEpoch.Add(time.Minute)
		m, err := rw.commit(ctx, q, later)
		noErr(t, err)
		if m.Phase != AppMoveCommitted {
			t.Fatalf("committed = %+v", m)
		}
		for _, id := range []domain.ID{rw.active.ID, rw.waiting.ID} {
			r := rw.routeOf(ctx, q, id)
			if r.NodeID != rw.b.ID || r.TunnelID != "tun-b" || r.TunnelGeneration != 2 || !r.UpdatedAt.Equal(later) {
				t.Errorf("route %s = node %s tunnel %s generation %d updated %v", r.Hostname, r.NodeID, r.TunnelID, r.TunnelGeneration, r.UpdatedAt)
			}
			if r.Phase != rw.routeOf(ctx, q, id).Phase || r.Objects.DNSRecordID != rw.active.Objects.DNSRecordID && id == rw.active.ID {
				t.Errorf("route %s lost its phase or objects: %+v", r.Hostname, r)
			}
		}
		if got := rw.routeOf(ctx, q, rw.active.ID); got.Phase != AppRouteActive || got.Objects.DNSRecordID != "dns-shop.example.com" {
			t.Errorf("active route = %+v", got)
		}
		if got := rw.routeOf(ctx, q, rw.waiting.ID); got.Phase != AppRouteWaiting {
			t.Errorf("waiting route = %+v", got)
		}
		for _, r := range must(ListAppMoveRoutes(ctx, q, rw.move.ID)) {
			if r.State != AppMoveRouteCommitted || !r.UpdatedAt.Equal(later) {
				t.Errorf("row %s = %s updated %v", r.RouteID, r.State, r.UpdatedAt)
			}
		}
		// the node and revision moved in the same commit
		if tgt := must(GetAppTarget(ctx, q, rw.target.ID)); tgt.NodeID != rw.b.ID || tgt.SpecRevision != rw.target.SpecRevision+1 {
			t.Errorf("target = %+v", tgt)
		}
	})
}

// With equal generations on both nodes the tuple still moves, node and tunnel changing and the generation staying.
func TestCommitAppMoveAcceptsEqualGenerations(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		rw := newRoutedWorld(ctx, f, q, 1)
		_, err := rw.commit(ctx, q, testEpoch)
		noErr(t, err)
		if r := rw.routeOf(ctx, q, rw.active.ID); r.NodeID != rw.b.ID || r.TunnelID != "tun-b" || r.TunnelGeneration != 1 {
			t.Errorf("route = %+v", r)
		}
	})
}

func TestAppRoutesTriggerAcceptsOnlyTheExactTuple(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		rw := newRoutedWorld(ctx, f, q, 2)
		tuple := `node_id = '` + rw.b.ID.String() + `', tunnel_id = 'tun-b', tunnel_generation = 2`
		refused := func(what, set string, args ...any) {
			t.Helper()
			_, err := q.ExecContext(ctx, `UPDATE app_routes SET `+set+` WHERE id = ?`, append(args, rw.active.ID)...)
			if err == nil || !strings.Contains(err.Error(), "keeps its identity") {
				t.Errorf("%s: err = %v, want the trigger to refuse", what, err)
			}
		}

		// every other identity column changed together with the exact tuple
		for _, col := range []string{
			"hostname = 'x.example.com'", "service = 'x'", "port = 9", "access = 'owners'", "account_id = 'x'", "zone = 'x'",
			"instance_id = 'x'", "dns_record_id = 'other'", "created_by = 'x'", "created_at = 99", "app_target_id = 'x'", "id = 'x'",
		} {
			refused("tuple with "+col, tuple+", "+col)
		}
		// the columns the old trigger never listed, changed together with the exact tuple
		for _, col := range []string{
			"phase = 'removing'", "phase = 'failed', halted_phase = 'active'", "last_error = 'x'", "access_app_id = 'x'", "plan_id = 'x'",
		} {
			refused("tuple with "+col, tuple+", "+col)
		}
		// other to-values, partial tuples, a third node
		for what, set := range map[string]string{
			"other tunnel":      `node_id = '` + rw.b.ID.String() + `', tunnel_id = 'tun-x', tunnel_generation = 2`,
			"other generation":  `node_id = '` + rw.b.ID.String() + `', tunnel_id = 'tun-b', tunnel_generation = 3`,
			"node only":         `node_id = '` + rw.b.ID.String() + `'`,
			"tunnel only":       `tunnel_id = 'tun-b'`,
			"generation only":   `tunnel_generation = 2`,
			"source node as to": `node_id = '` + rw.a.ID.String() + `', tunnel_id = 'tun-b', tunnel_generation = 2`,
			"empty tunnel":      `node_id = '` + rw.b.ID.String() + `', tunnel_id = '', tunnel_generation = 2`,
		} {
			refused(what, set)
		}

		// a route of another target, though its row sits in this move
		other := must(CreateApp(ctx, q, appsAppOf(f, "api")))
		otherTarget := must(CreateAppTarget(ctx, q, appsTargetOf(f, other, rw.appsWorld, "sm-api-prod")))
		foreign := rw.activeRoute(ctx, f, q, otherTarget, "api.example.com")
		must(InsertAppMoveRoutes(ctx, q, rw.move.ID, []AppMoveRoute{frozen(foreign, rw.b.ID, "tun-b", 2)}, testEpoch))
		rw.routeTo(ctx, q, foreign.ID, AppMoveRoutePending, AppMoveRouteDNSSwitched)
		if _, err := q.ExecContext(ctx, `UPDATE app_routes SET `+tuple+` WHERE id = ?`, foreign.ID); err == nil {
			t.Error("a route of another target moved on this move's evidence")
		}

		// the pair of row state, frozen phase and route phase
		mismatched := []struct {
			name   string
			frozen AppRoutePhase
			state  AppMoveRouteState
		}{
			{"active route, row frozen waiting and pending", AppRouteWaiting, AppMoveRoutePending},
			{"active route, row frozen active but pending", AppRouteActive, AppMoveRoutePending},
			{"active route, row frozen waiting but dns_switched", AppRouteWaiting, AppMoveRouteDNSSwitched},
		}
		for i, c := range mismatched {
			r := rw.activeRoute(ctx, f, q, rw.target, "m"+string(rune('a'+i))+".example.com")
			row := frozen(r, rw.b.ID, "tun-b", 2)
			row.FrozenPhase = c.frozen
			// a second move would clash with the open one, so the rows join this move
			must(InsertAppMoveRoutes(ctx, q, rw.move.ID, []AppMoveRoute{row}, testEpoch))
			if c.state != AppMoveRoutePending {
				rw.routeTo(ctx, q, r.ID, AppMoveRoutePending, c.state)
			}
			if _, err := q.ExecContext(ctx, `UPDATE app_routes SET `+tuple+` WHERE id = ?`, r.ID); err == nil {
				t.Errorf("%s: the route moved", c.name)
			}
		}

		// every row state but dns_switched refuses (committed is only written by the commit)
		cur := AppMoveRouteDNSSwitched
		for _, s := range []AppMoveRouteState{
			AppMoveRoutePending, AppMoveRouteDestIncluded, AppMoveRouteDestPublished, AppMoveRouteDNSSwitching,
			AppMoveRouteSourceCleaned, AppMoveRouteDNSRestoring, AppMoveRouteDNSRestored, AppMoveRouteDestExcluded, AppMoveRouteDestWithdrawn,
		} {
			must(AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.active.ID, cur, s, testEpoch))
			cur = s
			refused("row "+string(s), tuple)
		}
		must(AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.active.ID, cur, AppMoveRouteDNSSwitched, testEpoch))

		setPhase := func(p AppMovePhase) { // plain SQL: the repo reserves committed for the commit
			if _, err := q.ExecContext(ctx, `UPDATE app_moves SET phase = ? WHERE id = ?`, p, rw.move.ID); err != nil {
				t.Fatal(err)
			}
		}
		// the move must be in routes_switched, not halted, compensating or earlier
		for _, phase := range []AppMovePhase{
			AppMoveVerified, AppMoveRoutesDestIncluded, AppMoveCompensatingRoutesRestored,
			AppMoveCompensatingRoutesWithdrawn, AppMoveCompensatingBStopped, AppMoveCommitted, AppMoveRoutesSourceCleaned,
		} {
			setPhase(phase)
			refused("move "+string(phase), tuple)
		}
		setPhase(AppMoveRoutesSwitched)
		for _, halt := range []AppMovePhase{AppMoveFailed, AppMoveConflict} {
			must(HaltAppMove(ctx, q, rw.move.ID, AppMoveRoutesSwitched, halt, "x", testEpoch))
			refused("move "+string(halt), tuple)
			must(ResumeHaltedAppMove(ctx, q, rw.move.ID, halt, testEpoch))
		}

		// the route's phase must be the frozen one
		must(MarkAppRouteRemoving(ctx, q, rw.active.ID, AppRouteActive, testEpoch))
		refused("route removing", tuple)

		// nothing above moved the route
		if r := rw.routeOf(ctx, q, rw.active.ID); r.NodeID != rw.a.ID || r.TunnelID != "tun" || r.TunnelGeneration != 1 {
			t.Errorf("route = %+v", r)
		}
	})
}

func TestAppMoveRouteIdentityIsImmutable(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		rw := newRoutedWorld(ctx, f, q, 2)
		for _, set := range []string{
			"move_id = 'x'", "route_id = 'x'", "frozen_phase = 'waiting'", "from_node_id = 'x'", "from_tunnel_id = 'x'", "from_generation = 9",
			"to_node_id = 'x'", "to_tunnel_id = 'x'", "to_generation = 9", "dns_record_id = 'x'", "created_at = 99",
		} {
			_, err := q.ExecContext(ctx, `UPDATE app_move_routes SET `+set+` WHERE route_id = ?`, rw.active.ID)
			if err == nil || !strings.Contains(err.Error(), "frozen identity") {
				t.Errorf("UPDATE %s: err = %v", set, err)
			}
		}
		// the state and its timestamp are the only columns that move
		_, err := q.ExecContext(ctx, `UPDATE app_move_routes SET state = 'dns_restoring', updated_at = updated_at + 1 WHERE route_id = ?`, rw.active.ID)
		noErr(t, err)
	})
}

func TestAdvanceAppMoveRouteIsFenced(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		rw := newRoutedWorld(ctx, f, q, 2)
		_, err := AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.waiting.ID, AppMoveRouteDestIncluded, AppMoveRouteDestPublished, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		var e *smerr.Error
		if !errors.As(err, &e) || e.Details["current_state"] != "pending" || e.Details["expected_state"] != "dest_included" {
			t.Fatalf("conflict details = %v", err)
		}
		_, err = AdvanceAppMoveRoute(ctx, q, rw.move.ID, "missing", AppMoveRoutePending, AppMoveRouteDestIncluded, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.waiting.ID, AppMoveRoutePending, AppMoveRouteCommitted, testEpoch)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		got := must(AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.waiting.ID, AppMoveRoutePending, AppMoveRouteDestIncluded, testEpoch.Add(time.Minute)))
		if got.State != AppMoveRouteDestIncluded || !got.UpdatedAt.Equal(testEpoch.Add(time.Minute)) {
			t.Fatalf("advanced = %+v", got)
		}
	})
}

func TestInsertAppMoveRoutesFreezesTheRoutes(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		r := mw.activeRoute(ctx, f, q, mw.target, "shop.example.com")
		m := mw.move(ctx, f, q, false)
		rows := must(InsertAppMoveRoutes(ctx, q, m.ID, []AppMoveRoute{frozen(r, mw.b.ID, "tun-b", 4)}, testEpoch))
		if len(rows) != 1 {
			t.Fatalf("rows = %+v", rows)
		}
		want := AppMoveRoute{
			MoveID: m.ID, RouteID: r.ID, FrozenPhase: AppRouteActive, FromNodeID: mw.a.ID, FromTunnelID: "tun", FromGeneration: 1,
			ToNodeID: mw.b.ID, ToTunnelID: "tun-b", ToGeneration: 4, DNSRecordID: "dns-shop.example.com",
			State: AppMoveRoutePending, CreatedAt: testEpoch, UpdatedAt: testEpoch,
		}
		if rows[0] != want {
			t.Fatalf("row = %+v, want %+v", rows[0], want)
		}
		_, err := InsertAppMoveRoutes(ctx, q, m.ID, []AppMoveRoute{frozen(r, mw.b.ID, "tun-b", 4)}, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		for name, bad := range map[string]func(*AppMoveRoute){
			"same node":        func(r *AppMoveRoute) { r.ToNodeID = r.FromNodeID },
			"generation zero":  func(r *AppMoveRoute) { r.ToGeneration = 0 },
			"empty tunnel":     func(r *AppMoveRoute) { r.ToTunnelID = "" },
			"removed route":    func(r *AppMoveRoute) { r.FrozenPhase = AppRouteRemoved },
			"unknown route":    func(r *AppMoveRoute) { r.RouteID = "missing" },
			"unknown dest":     func(r *AppMoveRoute) { r.ToNodeID = "missing" },
			"provisioning row": func(r *AppMoveRoute) { r.FrozenPhase = AppRouteProvisioning },
		} {
			other := mw.activeRoute(ctx, f, q, mw.target, name[:2]+strings.ReplaceAll(name, " ", "")+".example.com")
			row := frozen(other, mw.b.ID, "tun-b", 4)
			bad(&row)
			if _, err := InsertAppMoveRoutes(ctx, q, m.ID, []AppMoveRoute{row}, testEpoch); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

func TestIncomingMoveRoutesAndReservations(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		rw := newRoutedWorld(ctx, f, q, 2)
		hostnames := func(node domain.ID) []string {
			var out []string
			for _, r := range must(IncomingMoveRoutes(ctx, q, node)) {
				out = append(out, r.Hostname)
			}
			return out
		}
		reservations := func(node domain.ID) int { return must(IncomingReservations(ctx, q, node)) }

		// dns_switched counts for B's ingress; the pending waiting route does not, but it reserves a slot
		if got := hostnames(rw.b.ID); len(got) != 1 || got[0] != "shop.example.com" {
			t.Fatalf("incoming = %v", got)
		}
		if got := hostnames(rw.a.ID); len(got) != 0 {
			t.Fatalf("incoming at the source = %v", got)
		}
		if got := reservations(rw.b.ID); got != 2 {
			t.Fatalf("reservations at B = %d, want 2", got)
		}
		if got := reservations(rw.a.ID); got != 0 {
			t.Fatalf("reservations at A = %d, want 0", got)
		}

		// every state that puts the rule in B's ingress, and only those
		in := map[AppMoveRouteState]bool{
			AppMoveRouteDestIncluded: true, AppMoveRouteDestPublished: true, AppMoveRouteDNSSwitching: true,
			AppMoveRouteDNSSwitched: true, AppMoveRouteDNSRestoring: true,
		}
		cur := AppMoveRouteDNSSwitched
		for _, s := range []AppMoveRouteState{
			AppMoveRoutePending, AppMoveRouteDestIncluded, AppMoveRouteDestPublished, AppMoveRouteDNSSwitching,
			AppMoveRouteDNSRestoring, AppMoveRouteDNSRestored, AppMoveRouteDestExcluded, AppMoveRouteDestWithdrawn, AppMoveRouteDNSSwitched,
		} {
			must(AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.active.ID, cur, s, testEpoch))
			cur = s
			if got := len(hostnames(rw.b.ID)); (got == 1) != in[s] {
				t.Errorf("state %s: %d incoming routes", s, got)
			}
			if got := reservations(rw.b.ID); got != 2 {
				t.Errorf("state %s: %d reservations, want 2 (excluded and withdrawn rows still hold the slot)", s, got)
			}
		}

		// a halted move keeps both
		must(HaltAppMove(ctx, q, rw.move.ID, AppMoveRoutesSwitched, AppMoveConflict, "x", testEpoch))
		if len(hostnames(rw.b.ID)) != 1 || reservations(rw.b.ID) != 2 {
			t.Error("a halted move dropped its incoming routes or reservations")
		}
		must(ResumeHaltedAppMove(ctx, q, rw.move.ID, AppMoveConflict, testEpoch))

		// after the commit the routes name B: no row is incoming and nothing is counted twice
		_, err := rw.commit(ctx, q, testEpoch)
		noErr(t, err)
		if len(hostnames(rw.b.ID)) != 0 || reservations(rw.b.ID) != 0 {
			t.Errorf("after the commit: %v incoming, %d reservations", hostnames(rw.b.ID), reservations(rw.b.ID))
		}
	})
}

func TestIncomingReservationsEndWithTheMove(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		rw := newRoutedWorld(ctx, f, q, 2)
		if got := must(IncomingReservations(ctx, q, rw.b.ID)); got != 2 {
			t.Fatalf("reservations = %d, want 2", got)
		}
		must(AdvanceAppMovePhase(ctx, q, rw.move.ID, AppMoveRoutesSwitched, AppMoveRolledBack, testEpoch))
		if got := must(IncomingReservations(ctx, q, rw.b.ID)); got != 0 {
			t.Fatalf("reservations after rollback = %d, want 0", got)
		}
		if got := must(IncomingMoveRoutes(ctx, q, rw.b.ID)); len(got) != 0 {
			t.Fatalf("incoming after rollback = %+v", got)
		}
	})
}

func TestIncomingReservationsIgnoreAMoveThatNeverRan(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		r := mw.activeRoute(ctx, f, q, mw.target, "shop.example.com")
		m := mw.move(ctx, f, q, false)
		must(InsertAppMoveRoutes(ctx, q, m.ID, []AppMoveRoute{frozen(r, mw.b.ID, "tun-b", 1)}, testEpoch))
		if got := must(IncomingReservations(ctx, q, mw.b.ID)); got != 1 {
			t.Fatalf("reservations = %d, want 1", got)
		}
		if _, err := q.ExecContext(ctx, `UPDATE jobs SET state = 'cancelled' WHERE id = ?`, m.JobID); err != nil {
			t.Fatal(err)
		}
		if got := must(IncomingReservations(ctx, q, mw.b.ID)); got != 0 {
			t.Fatalf("reservations of a move that never ran = %d, want 0", got)
		}
	})
}

// A commit that finds anything different rolls everything back: the node, the revision, the deployment, the routes
// and their rows stay as they were.
func TestCommitAppMoveRollsBackOnARouteMismatch(t *testing.T) {
	cases := map[string]func(ctx context.Context, q Querier, rw routedWorld){
		"route phase changed": func(ctx context.Context, q Querier, rw routedWorld) {
			must(MarkAppRouteRemoving(ctx, q, rw.active.ID, AppRouteActive, testEpoch))
		},
		"active row not switched": func(ctx context.Context, q Querier, rw routedWorld) {
			must(AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.active.ID, AppMoveRouteDNSSwitched, AppMoveRouteDNSSwitching, testEpoch))
		},
		"waiting row advanced": func(ctx context.Context, q Querier, rw routedWorld) {
			must(AdvanceAppMoveRoute(ctx, q, rw.move.ID, rw.waiting.ID, AppMoveRoutePending, AppMoveRouteDestIncluded, testEpoch))
		},
		"route not on the frozen tunnel": func(ctx context.Context, q Querier, rw routedWorld) {
			if _, err := q.ExecContext(ctx, `DELETE FROM app_move_routes WHERE route_id = ?`, rw.waiting.ID); err != nil {
				panic(err)
			}
			must(InsertAppMoveRoutes(ctx, q, rw.move.ID, []AppMoveRoute{{
				RouteID: rw.waiting.ID, FrozenPhase: AppRouteWaiting, FromNodeID: rw.a.ID, FromTunnelID: "tun-old", FromGeneration: 1,
				ToNodeID: rw.b.ID, ToTunnelID: "tun-b", ToGeneration: 2,
			}}, testEpoch))
		},
		"move not at routes_switched": func(ctx context.Context, q Querier, rw routedWorld) {
			must(AdvanceAppMovePhase(ctx, q, rw.move.ID, AppMoveRoutesSwitched, AppMoveVerified, testEpoch))
		},
		"move halted": func(ctx context.Context, q Querier, rw routedWorld) {
			must(HaltAppMove(ctx, q, rw.move.ID, AppMoveRoutesSwitched, AppMoveFailed, "x", testEpoch))
		},
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.tx(func(ctx context.Context, q Querier) {
				rw := newRoutedWorld(ctx, f, q, 2)
				break_(ctx, q, rw)
				rowsBefore, routesBefore := dumpTable(ctx, t, q, "app_move_routes", "route_id"), dumpTable(ctx, t, q, "app_routes", "id")
				moveBefore, depBefore := dumpTable(ctx, t, q, "app_moves", "id"), dumpTable(ctx, t, q, "deployments", "id")
				_, err := rw.commit(ctx, q, testEpoch.Add(time.Hour))
				wantError(t, err, smerr.CodeConflict, "")
				if tgt := must(GetAppTarget(ctx, q, rw.target.ID)); tgt.NodeID != rw.a.ID || tgt.SpecRevision != rw.target.SpecRevision {
					t.Errorf("target = %+v", tgt)
				}
				for table, before := range map[string][]string{
					"app_move_routes": rowsBefore, "app_routes": routesBefore, "app_moves": moveBefore, "deployments": depBefore,
				} {
					order := map[string]string{"app_move_routes": "route_id"}[table]
					if order == "" {
						order = "id"
					}
					if got := dumpTable(ctx, t, q, table, order); strings.Join(got, "\n") != strings.Join(before, "\n") {
						t.Errorf("%s changed by the failed commit", table)
					}
				}
			})
		})
	}
}

// A move with rows commits only from routes_switched, one without only from verified.
func TestCommitAppMovePhaseFollowsTheRoutes(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m, dep := mw.verifiedMove(ctx, f, q)
		must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveVerified, AppMoveRoutesSwitched, testEpoch))
		_, err := CommitAppMove(ctx, q, m.ID, mw.target.ID, mw.target.SpecRevision, mw.a.ID, mw.b.ID, dep, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		if got := must(GetAppMove(ctx, q, m.ID)); got.Phase != AppMoveRoutesSwitched {
			t.Fatalf("phase = %s", got.Phase)
		}
		must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveRoutesSwitched, AppMoveVerified, testEpoch))
		_, err = CommitAppMove(ctx, q, m.ID, mw.target.ID, mw.target.SpecRevision, mw.a.ID, mw.b.ID, dep, testEpoch)
		noErr(t, err)
	})
}
