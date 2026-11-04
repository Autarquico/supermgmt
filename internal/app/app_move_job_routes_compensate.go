package app

import (
	"context"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
)

// Compensation of the routes (ADR-0042, spec §11) comes before ADR-0041's steps. It runs on a move that has not
// committed, from verified, routes_dest_included or routes_switched:
//
//  1. every update of unknown outcome is reconciled (only after its not-before time);
//  2. every record that was repointed is pointed back at A, after the validator;
//     compensating_routes_restored
//  3. B's rules are withdrawn from its ingress, and A's ingress drops a route that halted;
//     compensating_routes_withdrawn
//
// then B is stopped and A started. Nothing is withdrawn or stopped while a record may still point at B.

// routedCompensation reports whether the phase is one from which the routes have to be undone first.
func (r *moveRun) routedCompensation() bool {
	if !r.routed {
		return false
	}
	switch r.move.Phase {
	case database.AppMoveVerified, database.AppMoveRoutesDestIncluded, database.AppMoveRoutesSwitched:
		return true
	case database.AppMovePreflight, database.AppMoveStaged, database.AppMoveSourceStop, database.AppMoveDataCopied,
		database.AppMoveStarted, database.AppMoveCommitted, database.AppMoveRoutesSourceCleaned, database.AppMoveSourceParked,
		database.AppMoveDone, database.AppMoveCompensatingRoutesRestored, database.AppMoveCompensatingRoutesWithdrawn,
		database.AppMoveCompensatingBStopped, database.AppMoveCompensatingSourceStarted, database.AppMoveCompensatingSourceVerified,
		database.AppMoveCompensatingBRemoved, database.AppMoveRolledBack, database.AppMoveFailed, database.AppMoveConflict:
	}
	return false
}

// routesCompensating reports whether a move that is not in a compensation phase has begun undoing its routes: a run
// that halted between its first restore and the phase change resumes the compensation, not the switch.
func (r *moveRun) routesCompensating(ctx context.Context) (bool, error) {
	if !r.routed || pastCommit(r.move) {
		return false, nil
	}
	routes, err := r.moveRoutes(ctx)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(routes, func(m moveRoute) bool {
		switch m.row.State {
		case database.AppMoveRouteDNSRestoring, database.AppMoveRouteDNSRestored,
			database.AppMoveRouteDestExcluded, database.AppMoveRouteDestWithdrawn:
			return true
		case database.AppMoveRoutePending, database.AppMoveRouteDestIncluded, database.AppMoveRouteDestPublished,
			database.AppMoveRouteDNSSwitching, database.AppMoveRouteDNSSwitched, database.AppMoveRouteCommitted,
			database.AppMoveRouteSourceCleaned:
		}
		return false
	}), nil
}

// restoreRoutes settles every update of unknown outcome, then points every record that applied its forward update back
// at A. A record that cannot be restored, or an outcome that cannot be settled, ends the compensation with B running;
// the error names the hostnames that point at B.
func (r *moveRun) restoreRoutes(ctx context.Context) error {
	active, err := r.activeMoveRoutes(ctx)
	if err != nil {
		return err
	}
	for i, m := range active {
		for _, l := range []dnsLeg{forwardLeg, reverseLeg} {
			if m.row.State != l.pending {
				continue
			}
			if active[i], err = r.settlePending(ctx, l, m); err != nil {
				return r.stillAtB(ctx, err)
			}
			m = active[i]
		}
	}
	for i, m := range active {
		if m.row.State != reverseLeg.idle && m.row.State != reverseLeg.pending {
			continue
		}
		if active[i], err = r.driveLeg(ctx, reverseLeg, m, active); err != nil {
			return r.stillAtB(ctx, err)
		}
	}
	return r.advance(ctx, database.AppMoveCompensatingRoutesRestored, "")
}

// stillAtB adds to err the hostnames whose record points at B, or may.
func (r *moveRun) stillAtB(ctx context.Context, err error) error {
	routes, lerr := r.moveRoutes(ctx)
	if lerr != nil {
		return err
	}
	var at []moveRoute
	for _, m := range routes {
		switch m.row.State {
		case database.AppMoveRouteDNSSwitching, database.AppMoveRouteDNSSwitched, database.AppMoveRouteDNSRestoring:
			at = append(at, m)
		case database.AppMoveRoutePending, database.AppMoveRouteDestIncluded, database.AppMoveRouteDestPublished,
			database.AppMoveRouteCommitted, database.AppMoveRouteSourceCleaned, database.AppMoveRouteDNSRestored,
			database.AppMoveRouteDestExcluded, database.AppMoveRouteDestWithdrawn:
		}
	}
	if len(at) == 0 {
		return err
	}
	return fmt.Errorf("the destination was left running; these hostnames may still point at it: %s: %w", hostnamesOf(at), err)
}

// withdrawRoutes takes B's rules out of its ingress: the rows say so first, then B's ingress is built and written,
// then the rows say it is done. A route that halted is taken out of A's ingress as well.
func (r *moveRun) withdrawRoutes(ctx context.Context) error {
	routes, err := r.moveRoutes(ctx)
	if err != nil {
		return err
	}
	for _, m := range routes {
		switch m.row.State {
		case database.AppMoveRouteDNSSwitching, database.AppMoveRouteDNSSwitched, database.AppMoveRouteDNSRestoring:
			return r.stillAtB(ctx, fmt.Errorf("the rules of B stay while the record of %s may point at it", m.route.Hostname))
		case database.AppMoveRoutePending, database.AppMoveRouteDestIncluded, database.AppMoveRouteDestPublished,
			database.AppMoveRouteCommitted, database.AppMoveRouteSourceCleaned, database.AppMoveRouteDNSRestored,
			database.AppMoveRouteDestExcluded, database.AppMoveRouteDestWithdrawn:
		}
	}
	for _, from := range []database.AppMoveRouteState{
		database.AppMoveRouteDestIncluded, database.AppMoveRouteDestPublished, database.AppMoveRouteDNSRestored,
	} {
		if routes, err = r.advanceRoutes(ctx, routes, from, database.AppMoveRouteDestExcluded); err != nil {
			return err
		}
	}
	if slices.ContainsFunc(routes, func(m moveRoute) bool { return m.row.State == database.AppMoveRouteDestExcluded }) {
		if err := r.putIngress(ctx, r.b, routes[0].row.ToTunnelID); err != nil {
			return err
		}
	}
	if slices.ContainsFunc(routes, func(m moveRoute) bool { return m.route.Phase.Halted() }) {
		if err := r.putIngress(ctx, r.a, routes[0].row.FromTunnelID); err != nil {
			return err
		}
	}
	if _, err := r.advanceRoutes(ctx, routes, database.AppMoveRouteDestExcluded, database.AppMoveRouteDestWithdrawn); err != nil {
		return err
	}
	return r.advance(ctx, database.AppMoveCompensatingRoutesWithdrawn, "")
}
