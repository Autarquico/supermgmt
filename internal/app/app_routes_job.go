package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// The expose and unexpose jobs of an app route (ADR-0040). One job moves one route: expose walks
// provisioning -> ingress_ready -> access_ready -> active, unexpose walks removing -> dns_removed ->
// ingress_removed -> removed. Each step looks at what exists first and records its progress before the next,
// so a job taken over after a crash converges. Both jobs hold the instance Cloudflare lock and the app
// target's lock (locks.go).

const (
	appRouteExposeAction   = policy.ActionAppRouteExpose
	appRouteUnexposeAction = policy.ActionAppRouteUnexpose

	eventAppRouteExposed = "app_route.exposed"
	eventAppRouteRemoved = "app_route.removed"
	eventAppRouteHalted  = "app_route.halted"
)

// appRouteJobPayload is what an expose or unexpose job carries: the route it moves.
type appRouteJobPayload struct {
	RouteID domain.ID `json:"route_id"`
}

// newAppRouteJob is the job that moves route, for action (appRouteExposeAction or appRouteUnexposeAction).
// The caller sets the actor, the credential and the plan, and enqueues it in its own transaction.
func newAppRouteJob(action string, route database.AppRoute) (jobs.NewJob, error) {
	payload, err := json.Marshal(appRouteJobPayload{RouteID: route.ID})
	if err != nil {
		return jobs.NewJob{}, err
	}
	return jobs.NewJob{
		Type: action, Resource: appTargetRef(route.AppTargetID), Risk: domain.RiskOperational,
		RetryClass: domain.RetryIdempotent, MaxAttempts: 3, Payload: payload,
	}, nil
}

func isAppRouteJob(jobType string) bool {
	return jobType == appRouteExposeAction || jobType == appRouteUnexposeAction
}

// revalidateAppRouteJob is the claim check of a route job, which carries no plan: the route exists and is the
// one of the job's target. Who may expose was decided when the route was admitted, and the job only carries
// that decision out.
func revalidateAppRouteJob(ctx context.Context, q database.Querier, job jobs.Job) error {
	payload, err := payloadOf[appRouteJobPayload](job)
	if err != nil {
		return err
	}
	route, err := database.GetAppRoute(ctx, q, payload.RouteID)
	if err != nil {
		return err
	}
	if route.AppTargetID != job.Resource.ID {
		return smerr.New(smerr.CodeInternal, "", "the route does not belong to the target of its job")
	}
	return nil
}

// appRouteHandler executes app_route.expose and app_route.unexpose; unexpose selects the second.
type appRouteHandler struct {
	core
	store    *jobs.Store
	tunnel   *tunnelEngine
	unexpose bool
}

// routeHalt ends the route in failed or conflict. The route keeps the phase it held, and a new job resumes it.
type routeHalt struct {
	halt database.AppRoutePhase
	// inner is the message the operator reads.
	inner *smerr.Error
}

func (e *routeHalt) Error() string { return e.inner.Error() }
func (e *routeHalt) Unwrap() error { return e.inner }

func routeConflict(kind, name string) error {
	return &routeHalt{halt: database.AppRouteConflict, inner: smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"a Cloudflare %s named %q exists and was not created by this route; resolve it in Cloudflare and expose the route again", kind, name))}
}

func routeFailed(message string) error {
	return &routeHalt{halt: database.AppRouteFailed, inner: smerr.New(smerr.CodeConflict, "", message)}
}

var errTunnelChanged = routeFailed("the node's tunnel changed; unexpose and expose again")

// routeRecord is the app_routes row a job moves, written under the job's lease.
type routeRecord struct {
	core
	lease jobs.Lease
	job   jobs.Job
	route database.AppRoute
}

func (rr *routeRecord) emitRoute(ctx context.Context, tx *database.Tx, action string, result domain.Result, data map[string]any) error {
	actor, err := loadActor(ctx, tx, rr.job.ActorID, credentialOf(rr.job))
	if err != nil {
		return err
	}
	data["job_id"], data["route_id"], data["node_id"] = rr.job.ID.String(), rr.route.ID.String(), rr.route.NodeID.String()
	data["hostname"], data["access"] = rr.route.Hostname, rr.route.Access
	return rr.emit(ctx, tx, actor, action, appTargetRef(rr.route.AppTargetID), result, data)
}

// advance moves the route to to and records the object IDs and the audit event in the same fenced transaction.
func (rr *routeRecord) advance(ctx context.Context, to database.AppRoutePhase, objects database.AppRouteObjects, action string, data map[string]any) error {
	return rr.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppRoute, error) {
		next, err := database.AdvanceAppRoutePhase(ctx, tx, rr.route.ID, rr.route.Phase, to, objects, rr.cfg.Clock.Now())
		if err != nil || action == "" {
			return next, err
		}
		return next, rr.emitRoute(ctx, tx, action, domain.ResultSucceeded, data)
	})
}

func (rr *routeRecord) change(ctx context.Context, step func(context.Context, *database.Tx) (database.AppRoute, error)) error {
	var changed database.AppRoute
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
	return rr.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppRoute, error) {
		return database.ResumeHaltedAppRoute(ctx, tx, rr.route.ID, rr.route.Phase, rr.cfg.Clock.Now())
	})
}

// halt records that the route stopped, with a sanitized message, and the audit event.
func (rr *routeRecord) halt(ctx context.Context, to database.AppRoutePhase, cause error) error {
	message := textsafe.Line(audit.ScrubString(cause.Error()))
	if utf8.RuneCountInString(message) > maxRecordedErrorLength {
		message = string([]rune(message)[:maxRecordedErrorLength])
	}
	phase := rr.route.Phase
	return rr.change(context.WithoutCancel(ctx), func(ctx context.Context, tx *database.Tx) (database.AppRoute, error) {
		halted, err := database.HaltAppRoute(ctx, tx, rr.route.ID, phase, to, message, rr.cfg.Clock.Now())
		if err != nil {
			return halted, err
		}
		return halted, rr.emitRoute(ctx, tx, eventAppRouteHalted, domain.ResultFailed, map[string]any{"phase": string(phase), "state": string(to)})
	})
}

func (h appRouteHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	payload, err := payloadOf[appRouteJobPayload](job)
	if err != nil {
		return err
	}
	route, err := database.GetAppRoute(ctx, h.cfg.DB.Reader(), payload.RouteID)
	if err != nil {
		return err
	}
	if route.AppTargetID != job.Resource.ID {
		return smerr.New(smerr.CodeInternal, "", "the route does not belong to the target of its job")
	}
	rr := routeRecord{core: h.core, lease: lease, job: job, route: route}
	if h.nothingToDo(route) {
		return nil
	}
	if route.Phase.Halted() {
		if job.Attempts > 1 {
			// As with a halted tunnel operation, an automatic retry must not undo the halt.
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the route %s is halted (%s); resolve it and run the command again", route.Hostname, route.LastError))
		}
		if err := rr.resume(ctx); err != nil {
			return err
		}
	}
	if h.unexpose && rr.route.Phase == database.AppRouteWaiting {
		// Nothing happened in Cloudflare, so nothing is called.
		return rr.advance(ctx, database.AppRouteRemoved, database.AppRouteObjects{}, eventAppRouteRemoved, map[string]any{})
	}
	node, err := database.GetNode(ctx, h.cfg.DB.Reader(), rr.route.NodeID)
	if err != nil {
		return err
	}
	run, err := h.tunnel.newRun(ctx, lease, job, node, rr.route.Hostname)
	if err != nil {
		return err
	}
	r := &routeRun{routeRecord: rr, tun: run}
	if r.sshHostname, err = sshHostnameOf(node, h.tunnel.opts.Config.Zone); err != nil {
		return err
	}
	if h.unexpose {
		err = r.removeRoute(ctx)
	} else {
		err = r.exposeRoute(ctx)
	}
	return r.settle(ctx, err)
}

// nothingToDo reports whether the job has no work: its route is where the job takes it, or the other job's
// removal (or the removal itself) has taken it past.
func (h appRouteHandler) nothingToDo(route database.AppRoute) bool {
	if h.unexpose {
		return route.Phase == database.AppRouteRemoved
	}
	switch route.Phase {
	case database.AppRouteActive, database.AppRouteRemoving, database.AppRouteDNSRemoved,
		database.AppRouteIngressRemoved, database.AppRouteRemoved:
		return true
	}
	return route.Phase.Halted() && slices.Contains([]database.AppRoutePhase{
		database.AppRouteRemoving, database.AppRouteDNSRemoved, database.AppRouteIngressRemoved,
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
}

// settle halts the route when err ends it and returns err. A conflict while exposing first takes the rule
// out of the ingress: a record nobody here owns may point at the tunnel, and the halted route must not serve.
func (r *routeRun) settle(ctx context.Context, err error) error {
	var halt *routeHalt
	if !errors.As(err, &halt) || r.route.Phase.Halted() {
		return err
	}
	if halt.halt == database.AppRouteConflict && r.exposing() {
		_ = r.syncIngress(context.WithoutCancel(ctx), r.route.ID) // best effort: the next writer drops the rule too
	}
	if herr := r.halt(ctx, halt.halt, err); herr != nil {
		return errors.Join(err, herr)
	}
	return err
}

func (r *routeRun) exposing() bool {
	switch r.route.Phase {
	case database.AppRouteProvisioning, database.AppRouteIngressReady, database.AppRouteAccessReady:
		return true
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
