package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// The expose and unexpose jobs of a node route (ADR-0040, ADR-0043). One job moves one route: expose walks
// provisioning -> ingress_ready -> access_ready -> active, unexpose walks removing -> dns_removed ->
// ingress_removed -> removed. Each step looks at what exists first and records its progress before the next,
// so a job taken over after a crash converges. Both jobs hold the instance Cloudflare lock and the lock of
// their route (locks.go), never the node's.

const (
	nodeRouteExposeAction   = policy.ActionNodeRouteExpose
	nodeRouteUnexposeAction = policy.ActionNodeRouteUnexpose

	eventNodeRouteExposed = "node_route.exposed"
	eventNodeRouteRemoved = "node_route.removed"
	eventNodeRouteHalted  = "node_route.halted"
)

// nodeRouteParams are the parameters of a node_route.expose / node_route.unexpose plan and of its job payload.
// Unexpose carries the hostname and the ID of the route it was requested for, so an approval that comes after
// the hostname was exposed again cannot remove the newer route. An expose finds its route by the plan
// that admitted it, or by these parameters when it resumes a halted route.
type nodeRouteParams struct {
	Hostname string `json:"hostname"`
	Port     string `json:"port,omitempty"`
	Access   string `json:"access,omitempty"`
	RouteID  string `json:"route_id,omitempty"`
}

func (p nodeRouteParams) validate(expose bool) error {
	if p.Hostname == "" {
		return invalidArgument("hostname is required")
	}
	if !expose {
		if p.Port != "" || p.Access != "" {
			return invalidArgument("unexpose takes no port or access")
		}
		return nil
	}
	if port, err := strconv.Atoi(p.Port); err != nil || port < 1 || port > 65535 {
		return invalidArgument("port must be a number between 1 and 65535")
	}
	if p.Access != "public" && p.Access != "owners" {
		return invalidArgument("access must be public or owners")
	}
	return nil
}

func isNodeRouteAction(action string) bool {
	return action == nodeRouteExposeAction || action == nodeRouteUnexposeAction
}

// nodeRouteTarget is the policy view of a node_route plan: the node it is about.
func nodeRouteTarget(ctx context.Context, q database.Querier, spec policy.ActionSpec, ref domain.ResourceRef, params map[string]any) (policy.Target, *int64, []plan.Input, error) {
	p, err := fromParams[nodeRouteParams](params)
	if err != nil {
		return policy.Target{}, nil, nil, err
	}
	if err := p.validate(spec.Name == nodeRouteExposeAction); err != nil {
		return policy.Target{}, nil, nil, err
	}
	r, err := resolveNode(ctx, q, ref.ID)
	if err != nil {
		return policy.Target{}, nil, nil, err
	}
	return r.target, &r.revision, r.inputs, nil
}

// nodeRouteHandler moves the route of a plan of node_route.expose or node_route.unexpose. It runs inside the
// control_plane.apply job, after the apply step has admitted the row; the plan is what revalidation checked
// at claim.
type nodeRouteHandler struct {
	core
	store  *jobs.Store
	tunnel *tunnelEngine
}

// routeHalt ends the route in failed or conflict. The route keeps the phase it held, and a new job resumes it.
type routeHalt struct {
	halt database.NodeRoutePhase
	// inner is the message the operator reads.
	inner *smerr.Error
}

func (e *routeHalt) Error() string { return e.inner.Error() }
func (e *routeHalt) Unwrap() error { return e.inner }

func routeConflict(kind, name string) error {
	return &routeHalt{halt: database.NodeRouteConflict, inner: smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"a Cloudflare %s named %q exists and was not created by this route; resolve it in Cloudflare and expose the route again", kind, name))}
}

func routeFailed(message string) error { return failedHalt(message) }

func failedHalt(message string) *routeHalt {
	return &routeHalt{halt: database.NodeRouteFailed, inner: smerr.New(smerr.CodeConflict, "", message)}
}

var errTunnelChanged = routeFailed("the node's tunnel changed; unexpose and expose again")

// routeRecord is the node_routes row a job moves, written under the job's lease.
type routeRecord struct {
	core
	lease jobs.Lease
	job   jobs.Job
	route database.NodeRoute
}

func (rr *routeRecord) emitRoute(ctx context.Context, tx *database.Tx, action string, result domain.Result, data map[string]any) error {
	actor, err := loadActor(ctx, tx, rr.job.ActorID, credentialOf(rr.job))
	if err != nil {
		return err
	}
	data["job_id"], data["route_id"], data["node_id"] = rr.job.ID.String(), rr.route.ID.String(), rr.route.NodeID.String()
	data["hostname"], data["access"] = rr.route.Hostname, rr.route.Access
	return rr.emit(ctx, tx, actor, action, nodeRef(rr.route.NodeID), result, data)
}

// advance moves the route to to and records the object IDs and the audit event in the same fenced transaction.
func (rr *routeRecord) advance(ctx context.Context, to database.NodeRoutePhase, objects database.NodeRouteObjects, action string, data map[string]any) error {
	return rr.change(ctx, func(ctx context.Context, tx *database.Tx) (database.NodeRoute, error) {
		next, err := database.AdvanceNodeRoutePhase(ctx, tx, rr.route.ID, rr.route.Phase, to, objects, rr.cfg.Clock.Now())
		if err != nil || action == "" {
			return next, err
		}
		return next, rr.emitRoute(ctx, tx, action, domain.ResultSucceeded, data)
	})
}

func (rr *routeRecord) change(ctx context.Context, step func(context.Context, *database.Tx) (database.NodeRoute, error)) error {
	var changed database.NodeRoute
	err := rr.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := rr.lease.Fence(ctx, tx); err != nil {
			return err
		}
		var err error
		changed, err = step(ctx, tx)
		return err
	})
	if err == nil {
		rr.route = changed
	}
	return err
}

// audit writes an event about the route under the lease fence.
func (rr *routeRecord) audit(ctx context.Context, action string, data map[string]any) error {
	return rr.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := rr.lease.Fence(ctx, tx); err != nil {
			return err
		}
		return rr.emitRoute(ctx, tx, action, domain.ResultSucceeded, data)
	})
}

// resume returns a halted route to the phase it held, keeping the phase start so the objects an earlier
// attempt created stay adoptable.
func (rr *routeRecord) resume(ctx context.Context) error {
	return rr.change(ctx, func(ctx context.Context, tx *database.Tx) (database.NodeRoute, error) {
		return database.ResumeHaltedNodeRoute(ctx, tx, rr.route.ID, rr.route.Phase, rr.cfg.Clock.Now())
	})
}

// halt records that the route stopped, with a sanitized message, and the audit event.
func (rr *routeRecord) halt(ctx context.Context, to database.NodeRoutePhase, cause error) error {
	message := textsafe.Line(audit.ScrubString(cause.Error()))
	if utf8.RuneCountInString(message) > maxRecordedErrorLength {
		message = string([]rune(message)[:maxRecordedErrorLength])
	}
	phase := rr.route.Phase
	return rr.change(context.WithoutCancel(ctx), func(ctx context.Context, tx *database.Tx) (database.NodeRoute, error) {
		halted, err := database.HaltNodeRoute(ctx, tx, rr.route.ID, phase, to, message, rr.cfg.Clock.Now())
		if err != nil {
			return halted, err
		}
		return halted, rr.emitRoute(ctx, tx, eventNodeRouteHalted, domain.ResultFailed, map[string]any{"phase": string(phase), "state": string(to)})
	})
}

func (h nodeRouteHandler) run(ctx context.Context, lease jobs.Lease, job jobs.Job, action string) error {
	unexpose := action == nodeRouteUnexposeAction
	params, err := payloadOf[nodeRouteParams](job)
	if err != nil {
		return err
	}
	route, found, err := h.routeOf(ctx, job, params, unexpose)
	if err != nil || !found {
		return err // not found: removed already, or the hostname belongs to another route now
	}
	rr := routeRecord{core: h.core, lease: lease, job: job, route: route}
	if nothingToDo(unexpose, route) {
		return nil
	}
	if route.Phase.Halted() {
		if job.Attempts > 1 {
			// As with a halted tunnel operation, an automatic retry must not undo the halt.
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the route %s is halted (%s); resolve it and run the command again", route.Hostname, route.LastError))
		}
		if unexpose {
			// An expose resumes in resumeAndExpose, after its DNS preflight.
			if err := rr.resume(ctx); err != nil {
				return err
			}
		}
	}
	if unexpose {
		if gone, err := h.abandoned(ctx, &rr); gone || err != nil {
			return err
		}
	}
	node, err := database.GetNode(ctx, h.cfg.DB.Reader(), rr.route.NodeID)
	if err != nil {
		return rr.giveUp(ctx, err)
	}
	run, err := h.tunnel.newRun(ctx, lease, job, node, rr.route.Hostname)
	if err != nil {
		return rr.giveUp(ctx, err)
	}
	r := &routeRun{routeRecord: rr, tun: run, unexposing: unexpose}
	if r.sshHostname, err = sshHostnameOf(node, h.tunnel.opts.Config.Zone); err != nil {
		return rr.giveUp(ctx, err)
	}
	if unexpose {
		err = r.removeRoute(ctx)
	} else {
		err = r.resumeAndExpose(ctx)
	}
	return r.settle(ctx, err)
}

// resumeAndExpose brings a halted route back to a serving phase only after its DNS preflight passed, so a
// failing check leaves it halted.
func (r *routeRun) resumeAndExpose(ctx context.Context) error {
	if r.route.Phase.Halted() {
		if _, err := r.checkDNS(ctx, r.route.HaltedPhase); err != nil {
			return err
		}
		if err := r.resume(ctx); err != nil {
			return err
		}
	}
	return r.exposeRoute(ctx)
}

// routeOf is the route the job moves. An unexpose moves the route it was requested for. An expose moves the
// route its plan admitted, removed or not, so a retry or a late job never reaches a route admitted by another
// request. A plan that admitted none (the request that resumes a halted route) moves the live route that has
// exactly its parameters. found is false when there is none: it was removed,
// or the hostname belongs to something else now.
func (h nodeRouteHandler) routeOf(ctx context.Context, job jobs.Job, params nodeRouteParams, unexpose bool) (route database.NodeRoute, found bool, err error) {
	q := h.cfg.DB.Reader()
	switch {
	case unexpose && params.RouteID == "":
		return route, false, nil
	case unexpose:
		route, err = database.GetNodeRoute(ctx, q, domain.ID(params.RouteID))
	case job.PlanID == nil:
		return route, false, smerr.New(smerr.CodeInternal, "", "node route job has no plan")
	default:
		route, err = database.GetNodeRouteByPlan(ctx, q, *job.PlanID)
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			route, err = database.GetLiveNodeRouteByHostname(ctx, q, params.Hostname)
			if err == nil && !routeHas(route, job.Resource.ID, params) {
				err = smerr.New(smerr.CodeNotFound, "", "node route")
			}
		}
	}
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return database.NodeRoute{}, false, nil
	}
	if err != nil {
		return database.NodeRoute{}, false, err
	}
	return route, route.NodeID == job.Resource.ID && route.Hostname == params.Hostname, nil
}

// jobAction is the action of the plan the job carries.
func jobAction(ctx context.Context, q database.Querier, job jobs.Job) (string, error) {
	if job.PlanID == nil {
		return "", smerr.New(smerr.CodeInternal, "", "control_plane.apply job has no plan")
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	return rec.Action, err
}

// abandoned ends the removal of a route whose Cloudflare account, zone or instance is no longer the configured
// one: its objects belong to a place this instance cannot reach, so the route is marked removed with no
// Cloudflare call, and the object IDs it recorded are listed in the audit event for the operator to clean up.
func (h nodeRouteHandler) abandoned(ctx context.Context, rr *routeRecord) (bool, error) {
	instance, err := database.GetInstance(ctx, h.cfg.DB.Reader())
	if err != nil {
		return false, err
	}
	cfg := h.tunnel.opts.Config
	route := rr.route
	if route.AccountID == cfg.AccountID && route.Zone == cfg.Zone && route.InstanceID == instance.ID.String() {
		return false, nil
	}
	leftover := map[string]any{
		"abandoned": true, "account_id": route.AccountID, "zone": route.Zone, "tunnel_id": route.TunnelID,
		"dns_record_id": route.Objects.DNSRecordID, "access_app_id": route.Objects.AccessAppID,
	}
	return true, rr.advance(ctx, database.NodeRouteRemoved, database.NodeRouteObjects{}, eventNodeRouteRemoved, leftover)
}

// nothingToDo reports whether the job has no work: its route is where the job takes it, or another job's
// removal (or the removal itself) has taken it past.
func nothingToDo(unexpose bool, route database.NodeRoute) bool {
	if unexpose {
		return route.Phase == database.NodeRouteRemoved
	}
	switch route.Phase {
	case database.NodeRouteActive, database.NodeRouteRemoving, database.NodeRouteDNSRemoved,
		database.NodeRouteIngressRemoved, database.NodeRouteRemoved:
		return true
	case database.NodeRouteAdmitted, database.NodeRouteProvisioning, database.NodeRouteIngressReady, database.NodeRouteAccessReady,
		database.NodeRouteFailed, database.NodeRouteConflict:
	}
	return route.Phase.Halted() && slices.Contains([]database.NodeRoutePhase{
		database.NodeRouteRemoving, database.NodeRouteDNSRemoved, database.NodeRouteIngressRemoved,
	}, route.HaltedPhase)
}

func sshHostnameOf(node domain.Node, zone string) (string, error) {
	if node.Endpoint.TunnelHostname != "" {
		return node.Endpoint.TunnelHostname, nil
	}
	return tunnelHostnameOf(node.Name, zone)
}

// routeRun is one attempt of one route's job.
type routeRun struct {
	routeRecord
	tun         *tunnelRun
	sshHostname string
	// unexposing is set for a removal, which only needs the account, zone and instance to be the frozen ones:
	// the objects it deletes are found by their marker or recorded ID, whatever tunnel the node has now.
	unexposing bool
}

// settle halts the route when err ends it and returns err. The error ends it when it is a halt, or when it is
// the job's last: no retry is left to finish the work, so the route stops in failed, where a new command resumes
// it. A route halted while exposing first has its rule taken out of the ingress: a halt fails closed.
func (r *routeRun) settle(ctx context.Context, err error) error {
	if err == nil || r.route.Phase.Halted() {
		return err
	}
	var halt *routeHalt
	cause := err
	if !errors.As(err, &halt) {
		if !r.exhausted(ctx, err) {
			return err
		}
		halt = gaveUp(err)
		cause = halt
	}
	if r.exposing() {
		_ = r.syncIngress(context.WithoutCancel(ctx), r.route.ID) // best effort: the next writer drops the rule too
	}
	if herr := r.halt(ctx, halt.halt, cause); herr != nil {
		return errors.Join(err, herr)
	}
	return err
}

func gaveUp(err error) *routeHalt { return failedHalt(fmt.Sprintf("the job gave up: %s", err)) }

// giveUp halts the route as failed when err ends the job before a routeRun exists to settle it. There is no
// tunnel run to withdraw the rule with: a halted route does not serve, so the next ingress writer drops it.
func (rr *routeRecord) giveUp(ctx context.Context, err error) error {
	if rr.route.Phase.Halted() || !rr.exhausted(ctx, err) {
		return err
	}
	halt := gaveUp(err)
	if herr := rr.halt(ctx, halt.halt, halt); herr != nil {
		return errors.Join(err, herr)
	}
	return err
}

// exhausted reports whether err is the failure that ends the job: its last attempt, outside a shutdown or an
// outcome the job cannot tell.
func (rr *routeRecord) exhausted(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, jobs.ErrOutcomeUnknown) || errors.Is(err, jobs.ErrLeaseLost) {
		return false
	}
	return rr.job.RetryClass != domain.RetryIdempotent || rr.job.Attempts >= rr.job.MaxAttempts
}

func (r *routeRun) exposing() bool {
	switch r.route.Phase {
	case database.NodeRouteAdmitted, database.NodeRouteProvisioning, database.NodeRouteIngressReady, database.NodeRouteAccessReady:
		return true
	case database.NodeRouteActive, database.NodeRouteRemoving, database.NodeRouteDNSRemoved,
		database.NodeRouteIngressRemoved, database.NodeRouteRemoved, database.NodeRouteFailed, database.NodeRouteConflict:
	}
	return false
}

// requireIdentity halts the route unless the Cloudflare account, zone, instance and tunnel it froze at
// admission are still the configured ones and the node's current tunnel.
func (r *routeRun) requireIdentity(ctx context.Context) error {
	cfg := r.tun.opts.Config
	if r.route.AccountID != cfg.AccountID || r.route.Zone != cfg.Zone || r.route.InstanceID != r.tun.instanceID {
		return errTunnelChanged
	}
	if r.unexposing {
		return nil
	}
	return r.requireTunnel(ctx)
}

// requireTunnel is errTunnelChanged unless the frozen tunnel, at the frozen generation or a later setup
// rerun of it, is still the node's tunnel.
func (r *routeRun) requireTunnel(ctx context.Context) error {
	ops, err := database.ListTunnelOperations(ctx, r.cfg.DB.Reader(), r.route.NodeID)
	if err != nil {
		return err
	}
	if !routeTunnelCarries(ops, r.route) {
		return errTunnelChanged
	}
	return nil
}

// guard precedes every Cloudflare mutation: the route's identity still holds and the lease is still ours.
func (r *routeRun) guard(ctx context.Context) error {
	if err := r.requireIdentity(ctx); err != nil {
		return err
	}
	return r.tun.mayMutate(ctx)
}

func (r *routeRun) fenced() fencedCreate {
	return fencedCreate{mayMutate: r.guard, sleep: r.tun.opts.sleep, conflict: routeConflict}
}

// createdSince reports whether an object stamped created belongs to an attempt of the current phase.
func (r *routeRun) createdSince(created time.Time) bool {
	return !created.Before(r.route.PhaseStartedAt.Add(-clockSkewAllowance))
}

func (r *routeRun) objectGone(kind string) func() error {
	return func() error {
		return routeFailed(fmt.Sprintf("the %s recorded for this route no longer exists in Cloudflare; unexpose the route and expose it again", kind))
	}
}

// syncIngress makes the tunnel's ingress the node's desired list without the route skip. It reports a tunnel
// that no longer exists as errTunnelChanged.
func (r *routeRun) syncIngress(ctx context.Context, skip domain.ID) error {
	want, err := desiredIngress(ctx, r.cfg.DB.Reader(), r.route.NodeID, r.sshHostname, skip)
	if err != nil {
		return err
	}
	current, err := r.tun.api.GetTunnelConfig(ctx, r.route.TunnelID)
	if cloudflare.IsNotFound(err) {
		return errTunnelChanged
	}
	if err != nil {
		return err
	}
	if slices.Equal(current.Ingress, want) {
		return nil
	}
	if err := r.guard(ctx); err != nil {
		return err
	}
	if _, err := r.tun.api.PutTunnelIngress(ctx, r.route.TunnelID, want); err != nil {
		return err
	}
	return r.audit(ctx, eventIngressSet, map[string]any{"tunnel_id": r.route.TunnelID, "rules": len(want)})
}
