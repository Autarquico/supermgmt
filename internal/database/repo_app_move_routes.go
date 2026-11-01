package database

import (
	"context"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// AppMoveRouteState is where one route of a move stands (ADR-0042). The *ing and dest_included/dest_excluded states
// are intents recorded before the matching Cloudflare call; their successors are reached once the outcome is known.
type AppMoveRouteState string

const (
	AppMoveRoutePending       AppMoveRouteState = "pending"
	AppMoveRouteDestIncluded  AppMoveRouteState = "dest_included"
	AppMoveRouteDestPublished AppMoveRouteState = "dest_published"
	AppMoveRouteDNSSwitching  AppMoveRouteState = "dns_switching"
	AppMoveRouteDNSSwitched   AppMoveRouteState = "dns_switched"
	AppMoveRouteCommitted     AppMoveRouteState = "committed"
	AppMoveRouteSourceCleaned AppMoveRouteState = "source_cleaned"
	AppMoveRouteDNSRestoring  AppMoveRouteState = "dns_restoring"
	AppMoveRouteDNSRestored   AppMoveRouteState = "dns_restored"
	AppMoveRouteDestExcluded  AppMoveRouteState = "dest_excluded"
	AppMoveRouteDestWithdrawn AppMoveRouteState = "dest_withdrawn"
)

// AppMoveRoute is one route frozen into a move: the route's phase and identity at A, and the identity it takes on B.
type AppMoveRoute struct {
	MoveID         domain.ID
	RouteID        domain.ID
	FrozenPhase    AppRoutePhase // active or waiting
	FromNodeID     domain.ID
	FromTunnelID   string
	FromGeneration int64
	ToNodeID       domain.ID
	ToTunnelID     string
	ToGeneration   int64
	DNSRecordID    string // the route's record when frozen; empty for a waiting route
	State          AppMoveRouteState
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const appMoveRouteColumns = `move_id, route_id, frozen_phase, from_node_id, from_tunnel_id, from_generation, to_node_id,
	to_tunnel_id, to_generation, dns_record_id, state, created_at, updated_at`

func scanAppMoveRoute(s scanner) (AppMoveRoute, error) {
	var (
		r                  AppMoveRoute
		createdMs, updated int64
	)
	err := s.Scan(&r.MoveID, &r.RouteID, &r.FrozenPhase, &r.FromNodeID, &r.FromTunnelID, &r.FromGeneration, &r.ToNodeID,
		&r.ToTunnelID, &r.ToGeneration, &r.DNSRecordID, &r.State, &createdMs, &updated)
	if err != nil {
		return AppMoveRoute{}, err
	}
	r.CreatedAt, r.UpdatedAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(updated)
	return r, nil
}

// InsertAppMoveRoutes freezes the routes into the move, all pending, in the caller's transaction (the one that
// inserted the move). Every field of a route but State, CreatedAt and UpdatedAt is used; MoveID is the move's.
func InsertAppMoveRoutes(ctx context.Context, q Querier, moveID domain.ID, routes []AppMoveRoute, now time.Time) ([]AppMoveRoute, error) {
	for _, r := range routes {
		_, err := q.ExecContext(ctx, `
			INSERT INTO app_move_routes (move_id, route_id, frozen_phase, from_node_id, from_tunnel_id, from_generation,
				to_node_id, to_tunnel_id, to_generation, dns_record_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			moveID, r.RouteID, r.FrozenPhase, r.FromNodeID, r.FromTunnelID, r.FromGeneration,
			r.ToNodeID, r.ToTunnelID, r.ToGeneration, r.DNSRecordID, millis(now), millis(now))
		if err != nil {
			return nil, conflictIfDuplicate(err, "app move route")
		}
	}
	return ListAppMoveRoutes(ctx, q, moveID)
}

// ListAppMoveRoutes returns the routes frozen into the move, in route ID order.
func ListAppMoveRoutes(ctx context.Context, q Querier, moveID domain.ID) ([]AppMoveRoute, error) {
	return list(ctx, q, "app move routes",
		`SELECT `+appMoveRouteColumns+` FROM app_move_routes WHERE move_id = ? ORDER BY route_id`, scanAppMoveRoute, moveID)
}

// AdvanceAppMoveRoute moves one route of the move from one state to another, but only while the stored state still
// equals from. Otherwise CONFLICT (or NOT_FOUND) with the stored state, and nothing changes. The commit writes the
// state committed itself, together with the route, so it cannot be the target here.
func AdvanceAppMoveRoute(ctx context.Context, q Querier, moveID, routeID domain.ID, from, to AppMoveRouteState, now time.Time) (AppMoveRoute, error) {
	if to == AppMoveRouteCommitted {
		return AppMoveRoute{}, smerr.New(smerr.CodeInvalidArgument, "", "committing a move route belongs to the commit of the move")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE app_move_routes SET state = ?, updated_at = ? WHERE move_id = ? AND route_id = ? AND state = ?`,
		to, millis(now), moveID, routeID, from)
	if err != nil {
		return AppMoveRoute{}, fmt.Errorf("advance app move route: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return AppMoveRoute{}, fmt.Errorf("app move route: %w", err)
	}
	current, scanErr := scanAppMoveRoute(q.QueryRowContext(ctx,
		`SELECT `+appMoveRouteColumns+` FROM app_move_routes WHERE move_id = ? AND route_id = ?`, moveID, routeID))
	if scanErr != nil {
		return AppMoveRoute{}, getErr(scanErr, "app move route")
	}
	if n > 0 {
		return current, nil
	}
	e := smerr.New(smerr.CodeConflict, "", "app move route changed concurrently")
	e.Details = map[string]any{"current_state": string(current.State), "expected_state": string(from)}
	return AppMoveRoute{}, e
}

// incomingRouteStates are the states in which a row makes B's ingress carry the route: from the intent to include it
// until the withdrawal intent. After the commit the route names B itself and the row is no longer needed for that.
const incomingRouteStates = `'dest_included', 'dest_published', 'dns_switching', 'dns_switched', 'dns_restoring'`

// IncomingMoveRoutes returns the routes of open moves into the node whose rows are in a state that puts the rule in
// the node's ingress. Halted moves count: their rows are as durable as the ingress they describe.
func IncomingMoveRoutes(ctx context.Context, q Querier, nodeID domain.ID) ([]AppRoute, error) {
	return list(ctx, q, "incoming move routes", `
		SELECT `+appRouteColumns+` FROM app_routes WHERE id IN (
			SELECT r.route_id FROM app_move_routes r JOIN app_moves m ON m.id = r.move_id
			WHERE m.dest_node_id = ? AND m.phase NOT IN ('done', 'rolled_back') AND r.state IN (`+incomingRouteStates+`))
		ORDER BY hostname, id`, scanAppRoute, nodeID)
}

// IncomingReservations counts the routes that open moves into the node hold on its route capacity: rows not yet
// committed, in any state, halted moves included, a move that never ran excepted. A committed row is a live route of
// the node already and is counted with the node's routes.
func IncomingReservations(ctx context.Context, q Querier, nodeID domain.ID) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `
		SELECT count(*) FROM app_move_routes r JOIN app_moves m ON m.id = r.move_id
		WHERE m.dest_node_id = ? AND m.phase NOT IN ('done', 'rolled_back') AND NOT `+neverRanMove+`
		  AND r.state NOT IN ('committed', 'source_cleaned')`, nodeID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count incoming route reservations: %w", err)
	}
	return n, nil
}

// commitAppMoveRoutes writes the routes of the move to B as the commit's part (inside its savepoint): each route's
// node, tunnel and generation change together, fenced on the frozen values, and its row becomes committed. The state
// the row must be in follows the frozen phase. It returns how many routes the move carries.
func commitAppMoveRoutes(ctx context.Context, q Querier, moveID, targetID domain.ID, now time.Time) (int, error) {
	routes, err := ListAppMoveRoutes(ctx, q, moveID)
	if err != nil {
		return 0, err
	}
	for _, r := range routes {
		wantState := AppMoveRouteDNSSwitched
		if r.FrozenPhase == AppRouteWaiting {
			wantState = AppMoveRoutePending
		}
		if err := requireOneRow(ctx, q, "the route or its move is not as the plan froze it", `
			UPDATE app_routes SET node_id = ?, tunnel_id = ?, tunnel_generation = ?, updated_at = ?
			WHERE id = ? AND app_target_id = ? AND node_id = ? AND tunnel_id = ? AND tunnel_generation = ? AND phase = ?
			  AND EXISTS (SELECT 1 FROM app_move_routes r JOIN app_moves m ON m.id = r.move_id
			              WHERE r.move_id = ? AND r.route_id = app_routes.id AND r.state = ? AND m.phase = 'routes_switched')`,
			r.ToNodeID, r.ToTunnelID, r.ToGeneration, millis(now),
			r.RouteID, targetID, r.FromNodeID, r.FromTunnelID, r.FromGeneration, r.FrozenPhase, moveID, wantState); err != nil {
			return 0, err
		}
		if err := requireOneRow(ctx, q, "the route of the move is not in the state the commit needs", `
			UPDATE app_move_routes SET state = 'committed', updated_at = ? WHERE move_id = ? AND route_id = ? AND state = ?`,
			millis(now), moveID, r.RouteID, wantState); err != nil {
			return 0, err
		}
	}
	return len(routes), nil
}
