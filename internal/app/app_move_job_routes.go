package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// The Cloudflare work of a routed move (ADR-0042, spec §6 to §10): B's ingress gains the rules, each record is
// repointed in place, the commit moves the routes, and A's ingress loses the rules. The record updates and their
// reconciliation are app_move_job_routes_dns.go, the undo app_move_job_routes_compensate.go. The whole job holds the
// instance Cloudflare lock (moveLocks), so every ingress it builds is the state at that moment.

const (
	eventAppMoveRouteSwitched = "app_move.route_switched"
	eventAppMoveRouteRestored = "app_move.route_restored"
	eventAppMoveRouteHalted   = "app_move.route_halted"
)

// moveRoute is a route of the move with its row.
type moveRoute struct {
	row   database.AppMoveRoute
	route database.AppRoute
}

// active reports whether the route has Cloudflare objects to move; a waiting route has none and skips every step
// until the commit.
func (m moveRoute) active() bool { return m.row.FrozenPhase == database.AppRouteActive }

func (m moveRoute) data(state database.AppMoveRouteState) map[string]any {
	return map[string]any{"route_id": m.row.RouteID.String(), "hostname": m.route.Hostname, "state": string(state)}
}

func (r *moveRun) moveRoutes(ctx context.Context) ([]moveRoute, error) {
	q := r.h.cfg.DB.Reader()
	rows, err := database.ListAppMoveRoutes(ctx, q, r.move.ID)
	if err != nil {
		return nil, err
	}
	out := make([]moveRoute, len(rows))
	for i, row := range rows {
		route, err := database.GetAppRoute(ctx, q, row.RouteID)
		if err != nil {
			return nil, err
		}
		out[i] = moveRoute{row: row, route: route}
	}
	return out, nil
}

// activeMoveRoutes are the routes of the move that have a record to repoint.
func (r *moveRun) activeMoveRoutes(ctx context.Context) ([]moveRoute, error) {
	all, err := r.moveRoutes(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(m moveRoute) bool { return !m.active() }), nil
}

// cloudflare is the move's client of the instance, with the zone looked up, built once per run.
func (r *moveRun) cloudflare(ctx context.Context) (*tunnelRun, error) {
	if r.cf != nil {
		return r.cf, nil
	}
	if r.h.tunnel == nil {
		return nil, requireTunnelAllowed(false, domain.Node{})
	}
	run, err := r.h.tunnel.newInstanceRun(ctx, r.lease, r.job)
	if err != nil {
		return nil, err
	}
	zone, err := run.api.ZoneByName(ctx, r.h.tunnel.opts.Config.Zone)
	if err != nil {
		return nil, run.step("zone lookup", err)
	}
	run.zoneID = zone.ID
	r.cf = run
	return run, nil
}

// advanceRoute moves the row of m from its state to to in a fenced transaction, with an audit event when event is not
// empty.
func (r *moveRun) advanceRoute(ctx context.Context, m moveRoute, to database.AppMoveRouteState, event string) (moveRoute, error) {
	next := m
	err := r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		row, err := database.AdvanceAppMoveRoute(ctx, tx, r.move.ID, m.row.RouteID, m.row.State, to, r.h.cfg.Clock.Now())
		if err != nil {
			return err
		}
		next.row = row
		if event == "" {
			return nil
		}
		return r.emitMove(ctx, tx, event, domain.ResultSucceeded, m.data(to))
	})
	if err != nil {
		return m, err
	}
	return next, nil
}

// advanceRoutes moves every route in state from to state to, and returns the routes as they are afterwards.
func (r *moveRun) advanceRoutes(ctx context.Context, routes []moveRoute, from, to database.AppMoveRouteState) ([]moveRoute, error) {
	for i, m := range routes {
		if m.row.State != from {
			continue
		}
		next, err := r.advanceRoute(ctx, m, to, "")
		if err != nil {
			return routes, err
		}
		routes[i] = next
	}
	return routes, nil
}

// ---- ingress ---------------------------------------------------------------------------------------------------

// putIngress makes the ingress of node n's tunnel the node's desired list, which counts the rules of the rows of the
// move (desiredIngress), and reconciles the answer by reading the tunnel configuration: a PUT whose answer was lost
// is proven by the configuration, a configuration that differs is a failure.
func (r *moveRun) putIngress(ctx context.Context, n moveNode, tunnelID string) error {
	cf, err := r.cloudflare(ctx)
	if err != nil {
		return err
	}
	ssh, err := sshHostnameOf(n.node, r.h.tunnel.opts.Config.Zone)
	if err != nil {
		return err
	}
	want, err := desiredIngress(ctx, r.h.cfg.DB.Reader(), n.node.ID, ssh, "")
	if err != nil {
		return err
	}
	current, err := cf.api.GetTunnelConfig(ctx, tunnelID)
	if err != nil {
		return ingressReadError(n, err)
	}
	if slices.Equal(current.Ingress, want) {
		return nil
	}
	if err := cf.mayMutate(ctx); err != nil {
		return err
	}
	_, putErr := cf.api.PutTunnelIngress(ctx, tunnelID, want)
	if putErr != nil && !cloudflare.IsAmbiguous(putErr) {
		return fmt.Errorf("writing the ingress of node %s: %w", n.node.Name, putErr)
	}
	got, err := cf.api.GetTunnelConfig(ctx, tunnelID)
	if err != nil {
		return ingressReadError(n, errors.Join(putErr, err))
	}
	if !slices.Equal(got.Ingress, want) {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the ingress of node %s is not what the move wrote; another writer changed it or the write did not apply", n.node.Name))
	}
	return nil
}

func ingressReadError(n moveNode, err error) error {
	if cloudflare.IsNotFound(err) {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the tunnel of node %s no longer exists in Cloudflare", n.node.Name))
	}
	return fmt.Errorf("reading the ingress of node %s: %w", n.node.Name, err)
}

// syncIngresses writes the desired ingress of both nodes: after a route halted, neither serves it.
func (r *moveRun) syncIngresses(ctx context.Context, routes []moveRoute) error {
	if len(routes) == 0 {
		return nil
	}
	return errors.Join(
		r.putIngress(ctx, r.a, routes[0].row.FromTunnelID),
		r.putIngress(ctx, r.b, routes[0].row.ToTunnelID))
}

// ---- publish (spec §6, §7.1) ---------------------------------------------------------------------------------------

// publishRoutes puts the rules of the active routes in B's ingress, before any record points there: the rows say so
// first, then B's ingress is built and written, then the rows say it is published. Access applications are checked
// first, so a rule is never served without one.
func (r *moveRun) publishRoutes(ctx context.Context) error {
	active, err := r.activeMoveRoutes(ctx)
	if err != nil {
		return err
	}
	if err := r.recheck(ctx); err != nil {
		return err
	}
	if len(active) > 0 {
		if active, err = r.advanceRoutes(ctx, active, database.AppMoveRoutePending, database.AppMoveRouteDestIncluded); err != nil {
			return err
		}
		if err := r.putIngress(ctx, r.b, active[0].row.ToTunnelID); err != nil {
			return err
		}
		if _, err := r.advanceRoutes(ctx, active, database.AppMoveRouteDestIncluded, database.AppMoveRouteDestPublished); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppMoveRoutesDestIncluded, "")
}

// accessFirst revalidates, and repairs, the Access application of an owners route. One that is missing or cannot be
// repaired halts the route itself, which no ingress serves, and ends the move: it is never served without it. all are
// the active routes of the move, for the ingress writes that follow the halt.
func (r *moveRun) accessFirst(ctx context.Context, m moveRoute, all []moveRoute) error {
	if !m.active() || m.route.Access != "owners" {
		return nil
	}
	cf, err := r.cloudflare(ctx)
	if err != nil {
		return err
	}
	rr := &routeRun{routeRecord: routeRecord{core: r.h.core, lease: r.lease, job: r.job, route: m.route}, tun: cf}
	err = rr.requireAccessApp(ctx)
	var halt *routeHalt
	if !errors.As(err, &halt) {
		if !repairRefused(ctx, err) {
			return err
		}
		halt = failedHalt(fmt.Sprintf("the Access application of %s drifted and Cloudflare refused to repair it; resolve it in Cloudflare and expose the route again", m.route.Hostname))
	}
	if err := rr.halt(ctx, halt.halt, halt); err != nil {
		return err
	}
	cause := fmt.Errorf("the route %s halted: %w", m.route.Hostname, halt)
	data := m.data(m.row.State)
	data["cause"] = recordedError(halt)
	if err := r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		return r.emitMove(ctx, tx, eventAppMoveRouteHalted, domain.ResultFailed, data)
	}); err != nil {
		return errors.Join(cause, err)
	}
	// The route is halted now, so the shared builder leaves its rule out of both ingresses.
	return errors.Join(cause, r.syncIngresses(ctx, all))
}

// repairRefused reports that Cloudflare definitively refused to repair a drifted Access application: a refusal that
// retrying does not change, not a cancelled run, a lost lease, or an answer that may have been lost.
func repairRefused(ctx context.Context, err error) bool {
	var repair *accessRepairError
	var api *cloudflare.APIError
	return errors.As(err, &repair) && errors.As(err, &api) && ctx.Err() == nil &&
		!api.Retryable() && !cloudflare.IsAmbiguous(err) &&
		!errors.Is(err, jobs.ErrLeaseLost) && !errors.Is(err, jobs.ErrOutcomeUnknown)
}

// ---- switch (spec §7.3) ----------------------------------------------------------------------------------------------

// switchRoutes repoints the record of every active route to B, one by one. A waiting route has no record and skips.
func (r *moveRun) switchRoutes(ctx context.Context) error {
	active, err := r.activeMoveRoutes(ctx)
	if err != nil {
		return err
	}
	for _, m := range active {
		if _, err := r.driveLeg(ctx, forwardLeg, m, active); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppMoveRoutesSwitched, "")
}

// ---- source clean and done (spec §10) -------------------------------------------------------------------------------------

// cleanSource takes the rules of the moved routes out of A's ingress: the routes name B since the commit, so A's
// builder no longer counts them. It only goes forward.
func (r *moveRun) cleanSource(ctx context.Context) error {
	routes, err := r.moveRoutes(ctx)
	if err != nil {
		return err
	}
	if err := r.putIngress(ctx, r.a, routes[0].row.FromTunnelID); err != nil {
		return err
	}
	if _, err := r.advanceRoutes(ctx, routes, database.AppMoveRouteCommitted, database.AppMoveRouteSourceCleaned); err != nil {
		return err
	}
	return r.advance(ctx, database.AppMoveRoutesSourceCleaned, "")
}

// finish closes the move. A routed move also schedules, in the same transaction, the activation of its waiting routes
// on B, through the activation a deployment uses, with its deduplication.
func (r *moveRun) finish(ctx context.Context) error {
	if !r.routed {
		return r.advance(ctx, database.AppMoveDone, "")
	}
	fz, err := r.freeze(ctx)
	if err != nil {
		return err
	}
	return r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		done, err := database.AdvanceAppMovePhase(ctx, tx, r.move.ID, r.move.Phase, database.AppMoveDone, r.h.cfg.Clock.Now())
		if err != nil {
			return done, err
		}
		return done, r.h.dep.activateRoutes(ctx, tx, r.target.ID, fz.frozen.HostPorts)
	})
}

// hostnamesOf lists the hostnames of the routes, sorted.
func hostnamesOf(routes []moveRoute) string {
	names := make([]string, len(routes))
	for i, m := range routes {
		names[i] = m.route.Hostname
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}
