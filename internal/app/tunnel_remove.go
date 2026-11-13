package app

import (
	"cmp"
	"context"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// Removing a node that has a Cloudflare tunnel (#103). The retirement of the node frees its name, so what
// the node holds in Cloudflare goes first: a control_plane.apply job of node.remove with tunnel=true runs the
// teardown of a disable (the route closed, then the Access application, then the tunnel) and only then
// retires the node. It needs no SSH: it does not stop the connector that still runs on the host, which
// simply stops being served once the tunnel is deleted.

const eventTunnelTakenDown = "node.tunnel.taken_down"

// nodeRemoveTunnelSteps are the lines the approver reads on a node.remove that takes a tunnel down.
var nodeRemoveTunnelSteps = []string{
	"close the route and delete the Cloudflare DNS record of the node",
	"delete the Cloudflare Access application and the tunnel of the node",
	"retire the node and free its name",
}

// recordsTunnel reports whether the node's tunnel operations (newest first) leave something to take down: an
// operation that has not finished (running, halted or failed: it may have created objects it never
// recorded), or a finished enable that recorded objects, since the newest finished disable took its own down.
func recordsTunnel(ops []database.TunnelOperation) bool {
	for _, op := range ops {
		switch {
		case !op.Phase.Finished():
			return true
		case op.Kind == database.TunnelDisable:
			return false
		case op.Objects != database.TunnelObjects{}:
			return true
		}
	}
	return false
}

// requireTunnelTakedownPossible refuses, when the removal is asked for, what the job could not do: no
// cloudflare: block, a tunnel provisioned in another account or zone than the configured one, and routes
// that still publish ports through it. The job repeats the check once it holds the locks.
func requireTunnelTakedownPossible(ctx context.Context, q database.Querier, cfg *config.Cloudflare, node domain.Node, ops []database.TunnelOperation) error {
	switch {
	case cfg == nil:
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the node has a Cloudflare tunnel, and removing the node takes the tunnel down in Cloudflare: "+
			"configure the cloudflare: block of the account and zone that created it, then remove the node again")
	case ops[0].AccountID != cfg.AccountID || ops[0].Zone != cfg.Zone:
		return smerr.New(smerr.CodeConflict, "", "the tunnel of this node was provisioned in another Cloudflare account or zone than the configured one: "+
			"restore that cloudflare: block to remove the node, or delete the tunnel, the Access application and the DNS record in the dashboard first")
	}
	return requireNoLiveRoutes(ctx, q, node.ID)
}

// planRequestsTakedown reports whether the plan of the job says the removal takes the tunnel down.
func planRequestsTakedown(ctx context.Context, q database.Querier, job jobs.Job) (bool, error) {
	if job.PlanID == nil {
		return false, smerr.New(smerr.CodeInternal, "", "control_plane.apply job has no plan")
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	if err != nil {
		return false, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return false, err
	}
	return stored.Parameters[policy.ParamTunnel] == "true", nil
}

// nodeRemoval takes the Cloudflare objects of a node down before the apply step retires it. tunnel is nil
// without a cloudflare: block.
type nodeRemoval struct {
	core
	tunnel *tunnelEngine
}

// run is the step before the retirement of a node.remove job. It does nothing when the node records no
// tunnel. Otherwise the plan has made the job hold the node and the instance's Cloudflare lock, and the job
// takes the tunnel down through the phases of a disable. Every step looks at what exists first, so a retry
// converges, and a failure leaves the node as it was.
func (h nodeRemoval) run(ctx context.Context, lease jobs.Lease, job jobs.Job) error {
	q := h.cfg.DB.Reader()
	node, err := database.GetNode(ctx, q, job.Resource.ID)
	if err != nil {
		return err
	}
	ops, err := database.ListTunnelOperations(ctx, q, node.ID)
	if err != nil || !recordsTunnel(ops) {
		return err
	}
	requested, err := planRequestsTakedown(ctx, q, job)
	if err != nil {
		return err
	}
	if !requested {
		// The node got its tunnel after the removal was planned: the job did not take the Cloudflare lock.
		return smerr.New(smerr.CodeConflict, "", "the node got a Cloudflare tunnel after this removal was requested; remove the node again so that its tunnel is taken down")
	}
	if h.tunnel == nil {
		return requireTunnelTakedownPossible(ctx, q, nil, node, ops)
	}
	cfg := h.tunnel.opts.Config
	// Repeated here because the job holds the locks now: a route admitted while it waited is seen, and none
	// is left pointing at a deleted tunnel.
	if err := requireTunnelTakedownPossible(ctx, q, &cfg, node, ops); err != nil {
		return err
	}
	hostname := cmp.Or(ops[0].Hostname, node.Endpoint.TunnelHostname)
	if hostname == "" {
		if hostname, err = tunnelHostnameOf(node.Name, cfg.Zone); err != nil {
			return err
		}
	}
	run, err := h.tunnel.newRun(ctx, lease, job, node, hostname)
	if err != nil {
		return err
	}
	run.disabling = true
	if err := run.beginTakedown(ctx); err != nil {
		return err
	}
	if err := run.tearDownCloud(ctx); err != nil {
		return err
	}
	return run.step("completion", run.advance(ctx, database.PhaseDone, database.TunnelObjects{}, eventTunnelTakenDown,
		map[string]any{"hostname": hostname, "tunnel_id": run.known().TunnelID}))
}

// beginTakedown opens the disable record that takes the node's Cloudflare objects down, or resumes the one
// an earlier attempt opened, without touching the node: an unfinished enable is taken over as a disable's
// takeover does, minus the proof of the direct path.
func (r *tunnelRun) beginTakedown(ctx context.Context) error {
	active, err := database.ActiveTunnelOperation(ctx, r.cfg.DB.Reader(), r.node.ID)
	switch {
	case err == nil && active.Kind == database.TunnelEnable:
		if err := r.requireSameCloudflare(active); err != nil {
			return err
		}
		return r.closeEnableForTakedown(ctx, active)
	case err == nil:
		if err := r.resume(ctx, active, database.TunnelDisable); err != nil {
			return err
		}
	case smerr.CodeOf(err) != smerr.CodeNotFound:
		return err
	default:
		if err := r.requireEnabledNode(ctx); err != nil {
			return err
		}
		if err := r.createOperation(ctx, database.TunnelDisable); err != nil {
			return err
		}
	}
	return r.findLastEnabled(ctx)
}
