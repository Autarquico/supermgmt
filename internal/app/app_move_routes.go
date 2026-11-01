package app

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// The routes of a move (ADR-0042): what admission asks of a target that has routes, what the plan freezes of them,
// and what every other path that would change them or the tunnels under them refuses while the move is open. The
// Cloudflare work of the move itself is not here.

// moveRouteInputType is the plan input that names a route the move carries, so the approved plan binds the set.
const moveRouteInputType = "app_route"

func moveRouteInputs(routes []database.AppMoveRoute) []plan.Input {
	inputs := make([]plan.Input, len(routes))
	for i, r := range routes {
		inputs[i] = plan.Input{Type: moveRouteInputType, ID: r.RouteID.String()}
	}
	return inputs
}

// ---- admission -------------------------------------------------------------------------------------------------

// admitMoveRoutes is the request-time admission of the target's routes (spec §1) and, run again under the claim
// locks with own set to the move, its re-check. It reads the database only. It refuses a route that is neither
// active nor waiting, one with an open job, a B without a committed tunnel and a B that cannot hold the routes, and
// returns what the plan freezes: per route its phase, DNS record and the tunnel identity at A and at B.
func admitMoveRoutes(ctx context.Context, q database.Querier, c core, target database.AppTarget, source, dest domain.Node, own *domain.ID) ([]database.AppMoveRoute, error) {
	routes, err := database.ListAppRoutes(ctx, q, database.AppRouteFilter{TargetID: target.ID})
	if err != nil || len(routes) == 0 {
		return nil, err
	}
	for _, r := range routes {
		if err := requireSettledRoute(r); err != nil {
			return nil, err
		}
	}
	if c.cfg.Cloudflare == nil {
		return nil, requireTunnelAllowed(false, domain.Node{})
	}
	instance, err := database.GetInstance(ctx, q)
	if err != nil {
		return nil, err
	}
	toTunnel, toGeneration, err := destTunnelIdentity(ctx, q, dest)
	if err != nil {
		return nil, err
	}
	ops, err := database.ListTunnelOperations(ctx, q, source.ID)
	if err != nil {
		return nil, err
	}
	frozen := make([]database.AppMoveRoute, 0, len(routes))
	for _, r := range routes {
		if err := requireRouteMovable(ctx, q, c, instance.ID.String(), source, ops, r); err != nil {
			return nil, err
		}
		frozen = append(frozen, database.AppMoveRoute{
			RouteID: r.ID, FrozenPhase: r.Phase, FromNodeID: source.ID, FromTunnelID: r.TunnelID, FromGeneration: r.TunnelGeneration,
			ToNodeID: dest.ID, ToTunnelID: toTunnel, ToGeneration: toGeneration, DNSRecordID: r.Objects.DNSRecordID,
		})
	}
	slices.SortFunc(frozen, func(a, b database.AppMoveRoute) int { return cmp.Compare(a.RouteID, b.RouteID) })
	var except domain.ID
	if own != nil {
		except = *own
	}
	if err := requireRouteCapacity(ctx, q, dest, len(frozen), except); err != nil {
		return nil, err
	}
	return frozen, nil
}

// destTunnelIdentity is B's committed tunnel: B must reach the control plane through Cloudflare, with a tunnel
// whose setup committed.
func destTunnelIdentity(ctx context.Context, q database.Querier, dest domain.Node) (string, int64, error) {
	if dest.Endpoint.Transport.Effective() != domain.TransportCloudflare {
		return "", 0, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf(
			"the destination %s has no Cloudflare connector; run `sm nodes setup %s --tunnel` before moving a target with routes", dest.Name, dest.Name))
	}
	return nodeTunnelIdentity(ctx, q, dest.ID)
}

// requireSettledRoute refuses a route that is in the middle of an operation or halted.
func requireSettledRoute(r database.AppRoute) error {
	if r.Phase == database.AppRouteActive || r.Phase == database.AppRouteWaiting {
		return nil
	}
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"the route %s is %s: finish it, remove it or resume it before moving the target", r.Hostname, r.Phase))
}

func requireRouteMovable(ctx context.Context, q database.Querier, c core, instanceID string, source domain.Node, sourceOps []database.TunnelOperation, r database.AppRoute) error {
	switch {
	case r.NodeID != source.ID:
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the route %s is not on the node the target moves from", r.Hostname))
	case r.AccountID != c.cfg.Cloudflare.AccountID || r.Zone != c.cfg.Cloudflare.Zone || r.InstanceID != instanceID:
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the route %s belongs to another Cloudflare account, zone or instance than the configured one", r.Hostname))
	case !routeTunnelCarries(sourceOps, r):
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the tunnel of %s is no longer the one the route %s froze", source.Name, r.Hostname))
	case r.Phase == database.AppRouteActive && r.Objects.DNSRecordID == "",
		r.Phase == database.AppRouteActive && r.Access == "owners" && r.Objects.AccessAppID == "":
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the route %s records no DNS record or Access application to move", r.Hostname))
	}
	open, err := openRouteJobs(ctx, q, r)
	if err != nil {
		return err
	}
	if open > 0 {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the route %s has a job that has not ended: let it finish or cancel it before moving the target", r.Hostname))
	}
	return nil
}

// openRouteJobs counts the expose and unexpose jobs of the route's hostname on its target that have not ended.
func openRouteJobs(ctx context.Context, q database.Querier, r database.AppRoute) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM jobs
		WHERE type = ? AND resource_type = ? AND resource_id = ? AND json_extract(payload_json, '$.hostname') = ?
		  AND state IN (?, ?, ?, ?)`,
		JobControlPlaneApply, domain.ResourceAppTarget, r.AppTargetID, r.Hostname,
		domain.JobQueued, domain.JobRunning, domain.JobInterrupted, domain.JobAwaitingApproval).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count the open jobs of route %s: %w", r.Hostname, err)
	}
	return n, nil
}

// checkMoveAccessApps reads, and changes nothing, the Access application of each active owners route: it must
// exist, guard the hostname and carry only the owners policy, as requireAccessApp holds an expose to. A route that
// drifted is not repaired at request time; the move is refused. A public or waiting route has none.
func checkMoveAccessApps(ctx context.Context, q database.Querier, e *tunnelEngine, routes []database.AppMoveRoute) error {
	owners, err := activeOwnersRoutes(ctx, q, routes)
	if err != nil || len(owners) == 0 {
		return err
	}
	if e == nil {
		return requireTunnelAllowed(false, domain.Node{})
	}
	run, err := e.newInstanceRun(ctx, jobs.Lease{}, jobs.Job{})
	if err != nil {
		return err
	}
	state, err := database.GetCloudflareState(ctx, q)
	if err != nil {
		return err
	}
	if state.OwnersPolicyID == "" {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the instance has no owners policy yet: run a tunnel setup first")
	}
	idps, err := run.api.ResolveAllowedIdPs(ctx, e.opts.Config.AccessIdentityProviders)
	if err != nil {
		return err
	}
	for _, r := range owners {
		spec := cloudflare.AppSpec{
			Name: cloudflare.RouteAccessAppName(run.instanceID, r.ID.String()), Domain: r.Hostname,
			PolicyIDs: []string{state.OwnersPolicyID}, AllowedIdPs: idps,
		}
		apps, err := run.api.FindAccessApps(ctx, spec.Name)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(apps, func(a cloudflare.AccessApp) bool { return a.ID == r.Objects.AccessAppID })
		if i < 0 || !accessAppMatches(apps[i], spec) {
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
				"the Access application of %s is missing or does not guard it with the owners policy only: fix it with a new `sm apps expose` before moving the target", r.Hostname))
		}
	}
	return nil
}

// accessAppMatches is the condition under which requireAccessApp leaves an application alone.
func accessAppMatches(app cloudflare.AccessApp, spec cloudflare.AppSpec) bool {
	return app.Type == accessAppType && app.Domain == spec.Domain && slices.Equal(app.PolicyIDs, spec.PolicyIDs) &&
		sameSet(app.AllowedIdPs, spec.AllowedIdPs)
}

// activeOwnersRoutes are the routes of the frozen set that are active with owners access.
func activeOwnersRoutes(ctx context.Context, q database.Querier, frozen []database.AppMoveRoute) ([]database.AppRoute, error) {
	var out []database.AppRoute
	for _, f := range frozen {
		if f.FrozenPhase != database.AppRouteActive {
			continue
		}
		r, err := database.GetAppRoute(ctx, q, f.RouteID)
		if err != nil {
			return nil, err
		}
		if r.Access == "owners" {
			out = append(out, r)
		}
	}
	return out, nil
}

// ---- revalidation ----------------------------------------------------------------------------------------------

// requireFrozenRoutes holds a move that has not committed to what its plan froze: the target has exactly the routes
// of the move's rows, in the frozen phase and with the frozen identity and record at A, and B still has the frozen
// tunnel. A route halted while the move runs keeps the phase it held. Compensation and everything after the commit
// read the move record only, so they never depend on this (spec §3).
func requireFrozenRoutes(ctx context.Context, q database.Querier, m database.AppMove) error {
	if pastCommit(m) || compensating(m) {
		return nil
	}
	rows, err := database.ListAppMoveRoutes(ctx, q, m.ID)
	if err != nil {
		return err
	}
	routes, err := database.ListAppRoutes(ctx, q, database.AppRouteFilter{TargetID: m.AppTargetID})
	if err != nil {
		return err
	}
	if len(routes) != len(rows) {
		return routesChanged("the target has %d routes, the move froze %d", len(routes), len(rows))
	}
	byID := map[domain.ID]database.AppRoute{}
	for _, r := range routes {
		byID[r.ID] = r
	}
	for _, row := range rows {
		r, ok := byID[row.RouteID]
		if !ok {
			return routesChanged("a route of the move is gone")
		}
		held := r.Phase
		if held.Halted() {
			held = r.HaltedPhase
		}
		if held != row.FrozenPhase || r.NodeID != row.FromNodeID || r.TunnelID != row.FromTunnelID ||
			r.TunnelGeneration != row.FromGeneration || r.Objects.DNSRecordID != row.DNSRecordID {
			return routesChanged("the route %s is not as the plan froze it", r.Hostname)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	dest, err := database.GetNode(ctx, q, m.DestNodeID)
	if err != nil {
		return err
	}
	tunnelID, generation, err := destTunnelIdentity(ctx, q, dest)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ToNodeID != dest.ID || row.ToTunnelID != tunnelID || row.ToGeneration != generation {
			return routesChanged("the tunnel of %s is not the one the plan froze", dest.Name)
		}
	}
	return nil
}

func routesChanged(format string, args ...any) error {
	return smerr.FromReason(smerr.ReasonPlanStale, "the routes of the target changed since the move was planned: "+fmt.Sprintf(format, args...))
}

// recheckRoutes repeats the admission of the routes under the locks the job holds (spec §1): the target has the
// routes the plan froze, they are movable, B holds them together with the other reservations, and their Access
// applications are in place. The move calls it before staged and before routes_dest_included.
func (r *moveRun) recheckRoutes(ctx context.Context) error {
	q := r.h.cfg.DB.Reader()
	source, dest := r.a.node, r.b.node
	frozen, err := admitMoveRoutes(ctx, q, r.h.core, r.target, source, dest, &r.move.ID)
	if err != nil {
		return err
	}
	rows, err := database.ListAppMoveRoutes(ctx, q, r.move.ID)
	if err != nil {
		return err
	}
	if !slices.EqualFunc(frozen, rows, sameFrozenRoute) {
		return routesChanged("the routes or the tunnels differ from what the plan froze")
	}
	return checkMoveAccessApps(ctx, q, r.h.tunnel, rows)
}

func sameFrozenRoute(a, b database.AppMoveRoute) bool {
	return a.RouteID == b.RouteID && a.FrozenPhase == b.FrozenPhase && a.FromNodeID == b.FromNodeID &&
		a.FromTunnelID == b.FromTunnelID && a.FromGeneration == b.FromGeneration && a.ToNodeID == b.ToNodeID &&
		a.ToTunnelID == b.ToTunnelID && a.ToGeneration == b.ToGeneration && a.DNSRecordID == b.DNSRecordID
}

// ---- what an open routed move refuses --------------------------------------------------------------------------

// openRoutedMoves are the moves that carry routes and are not over, halted ones included.
func openRoutedMoves(ctx context.Context, q database.Querier, keep func(database.AppMove) bool) ([]database.AppMove, error) {
	all, err := database.OpenRoutedMoves(ctx, q)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(m database.AppMove) bool { return !keep(m) }), nil
}

func routedMoveError(what string, m database.AppMove) error {
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"%s is refused while move %s of the target's routes to node %s is open (phase %s): wait for it, resume it with `sm apps move`, or abandon it",
		what, m.ID, m.DestNodeID, heldPhase(m)))
}

// routedMoveOf is the open routed move of the target, if any.
func routedMoveOf(ctx context.Context, q database.Querier, targetID domain.ID) (database.AppMove, bool, error) {
	open, err := openRoutedMoves(ctx, q, func(m database.AppMove) bool { return m.AppTargetID == targetID })
	if err != nil || len(open) == 0 {
		return database.AppMove{}, false, err
	}
	return open[0], true, nil
}

// requireNoRoutedMove refuses what, an expose or unexpose, on a target whose routes are being moved.
func requireNoRoutedMove(ctx context.Context, q database.Querier, targetID domain.ID, what string) error {
	m, found, err := routedMoveOf(ctx, q, targetID)
	if err != nil || !found {
		return err
	}
	return routedMoveError(what, m)
}

// requireNoRoutedMoveOnNode refuses what, a tunnel operation on the node, while a routed move has the node as its
// source or destination: it would change the generation or write the ingress outside the shared builder.
func requireNoRoutedMoveOnNode(ctx context.Context, q database.Querier, nodeID domain.ID, what string) error {
	open, err := openRoutedMoves(ctx, q, func(m database.AppMove) bool { return m.SourceNodeID == nodeID || m.DestNodeID == nodeID })
	if err != nil || len(open) == 0 {
		return err
	}
	return routedMoveError(what, open[0])
}

// requireNoRoutedMoveAnywhere is the refusal of the instance-wide service-token rotation: every node dials through
// the token it replaces, so no routed move may be open.
func requireNoRoutedMoveAnywhere(ctx context.Context, q database.Querier, what string) error {
	open, err := openRoutedMoves(ctx, q, func(database.AppMove) bool { return true })
	if err != nil || len(open) == 0 {
		return err
	}
	return routedMoveError(what, open[0])
}

// requireNoRoutedMoveForJob is the claim-time form of those refusals for the jobs that PlanLocks plans: an expose or
// unexpose of the job's target, a tunnel setup with tunnel, a tunnel disable and a token rotation.
func requireNoRoutedMoveForJob(ctx context.Context, q database.Querier, job jobs.Job, action string, tunnelSetup bool) error {
	switch {
	case job.Type == JobControlPlaneApply && isAppRouteAction(action):
		return requireNoRoutedMove(ctx, q, job.Resource.ID, "an "+strings.TrimPrefix(action, "app_route."))
	case tunnelSetup:
		return requireNoRoutedMoveOnNode(ctx, q, job.Resource.ID, "a tunnel setup")
	case job.Type == policy.ActionNodeTunnelDisable:
		return requireNoRoutedMoveOnNode(ctx, q, job.Resource.ID, "a tunnel disable")
	case job.Type == policy.ActionCloudflareRotate:
		return requireNoRoutedMoveAnywhere(ctx, q, "a service-token rotation")
	}
	return nil
}

// ---- abandon ---------------------------------------------------------------------------------------------------

// abandonBlockingStates are the route states in which a record may point at B, or B's ingress may carry a rule:
// abandoning would leave them without a running B (spec §12).
var abandonBlockingStates = []database.AppMoveRouteState{
	database.AppMoveRouteDNSSwitching, database.AppMoveRouteDNSSwitched, database.AppMoveRouteDNSRestoring,
	database.AppMoveRouteDestIncluded, database.AppMoveRouteDestPublished, database.AppMoveRouteDestExcluded,
}

// requireAbandonable refuses to abandon a routed move that has a route in a state where Cloudflare may still point
// at B; an operator resumes such a move instead. It names the rows.
func requireAbandonable(ctx context.Context, q database.Querier, m database.AppMove) error {
	rows, err := database.ListAppMoveRoutes(ctx, q, m.ID)
	if err != nil {
		return err
	}
	var blocking []string
	for _, row := range rows {
		if slices.Contains(abandonBlockingStates, row.State) {
			blocking = append(blocking, fmt.Sprintf("%s (%s)", row.RouteID, row.State))
		}
	}
	if len(blocking) == 0 {
		return nil
	}
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"the move cannot be abandoned while a route may point at the destination: %s; resume it with `sm apps move`", strings.Join(blocking, ", ")))
}
