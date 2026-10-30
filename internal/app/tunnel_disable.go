package app

import (
	"cmp"
	"context"
	"maps"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
)

// tunnelDisableHandler executes node.tunnel.disable (ADR-0037): the node
// returns to its direct path, and only then is the Cloudflare side taken down
// in the reverse of the order it was built, the route first.
type tunnelDisableHandler struct {
	core
	store  *jobs.Store
	conn   Connector
	prober *Prober
	tunnel *tunnelEngine // nil: no cloudflare: block
}

// metaTunnelOnly is the node metadata key of a node enrolled through the tunnel
// (ADR-0039): it never had a direct path. It lives in metadata_json, which no
// later setup or endpoint update rewrites, and is never inferred from admin_user
// or the endpoint host.
const metaTunnelOnly = "tunnel_only"

// tunnelOnly reports whether the node was enrolled through the tunnel.
func tunnelOnly(node domain.Node) bool {
	only, _ := node.Metadata[metaTunnelOnly].(bool)
	return only
}

// withTunnelOnly is metadata with the tunnel-only provenance set; the commit of
// an enrollment writes the node with it.
func withTunnelOnly(metadata map[string]any) map[string]any {
	marked := maps.Clone(metadata)
	if marked == nil {
		marked = map[string]any{}
	}
	marked[metaTunnelOnly] = true
	return marked
}

// requireDirectPath refuses a node that has no direct path to fall back to.
func requireDirectPath(node domain.Node) error {
	if tunnelOnly(node) {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the node was enrolled through the tunnel and has no direct path to fall back to, so its tunnel cannot be disabled; remove the node instead")
	}
	return nil
}

// disableRun is one disable attempt of one node.
type disableRun struct {
	*tunnelRun
	conn Connector
	meta runtimes.SetupMeta
	// hasSetup is false for a node that never completed setup: only an
	// unfinished first enable can be taken down from such a node.
	hasSetup bool
}

func (h tunnelDisableHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	node, err := database.GetNode(ctx, h.cfg.DB.Reader(), job.Resource.ID)
	if err != nil {
		return err
	}
	if err := requireTunnelAllowed(h.tunnel != nil, node); err != nil {
		return err
	}
	if err := requireDirectPath(node); err != nil {
		return err
	}
	run, err := h.begin(ctx, lease, job, node)
	if err != nil {
		return err
	}
	if err := run.walk(ctx, h.core); err != nil {
		return err
	}
	_ = h.prober.Probe(ctx, node.ID, ProbeFull, nil) // best effort: the refresher repeats it
	return nil
}

// begin opens the disable record. The direct path is verified before a new
// record is written, so a node that cannot be reached directly is left exactly
// as it was.
func (h tunnelDisableHandler) begin(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node) (*disableRun, error) {
	meta, err := loadSetup(ctx, h.cfg.DB.Reader(), node.ID)
	if err != nil {
		return nil, err
	}
	unfinished, err := unfinishedEnable(ctx, h.cfg.DB.Reader(), node.ID)
	if err != nil {
		return nil, err
	}
	if meta == nil && unfinished.ID == "" {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "the node has not completed setup, so it has no tunnel to disable")
	}
	hostname, err := h.hostnameOf(node, unfinished)
	if err != nil {
		return nil, err
	}
	base, err := h.tunnel.newRun(ctx, lease, job, node, hostname)
	if err != nil {
		return nil, err
	}
	base.disabling = true
	run := &disableRun{tunnelRun: base, conn: h.conn, hasSetup: meta != nil}
	if meta != nil {
		run.meta = *meta
	}
	if unfinished.ID != "" {
		return run, run.takeOverEnable(ctx, unfinished)
	}
	found, err := run.resumeActive(ctx, database.TunnelDisable)
	if err != nil {
		return nil, err
	}
	if !found {
		if err := run.requireEnabledNode(ctx); err != nil {
			return nil, err
		}
	}
	// A direct path proven before the switch is proven again after a crash:
	// the proof may be arbitrarily old once the phase reaches the switch.
	if !found || phaseIndex(run.op.Phase) < phaseIndex(database.PhaseSwitched) {
		if err := run.verifyDirect(ctx); err != nil {
			return nil, err
		}
	}
	if !found {
		if err := run.createOperation(ctx, database.TunnelDisable); err != nil {
			return nil, err
		}
	}
	return run, run.findLastEnabled(ctx)
}

// unfinishedEnable is the node's enable that has not finished (running, halted
// or failed), or the zero operation.
func unfinishedEnable(ctx context.Context, q database.Querier, nodeID domain.ID) (database.TunnelOperation, error) {
	op, err := database.ActiveTunnelOperation(ctx, q, nodeID)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return database.TunnelOperation{}, nil
	case err != nil || op.Kind != database.TunnelEnable:
		return database.TunnelOperation{}, err
	}
	return op, nil
}

// hostnameOf is the hostname the disable works on: the one the enable
// recorded, else the node's tunnel hostname, else the derived one.
func (h tunnelDisableHandler) hostnameOf(node domain.Node, unfinished database.TunnelOperation) (string, error) {
	if hostname := cmp.Or(unfinished.Hostname, node.Endpoint.TunnelHostname); hostname != "" {
		return hostname, nil
	}
	return tunnelHostnameOf(node.Name, h.tunnel.opts.Config.Zone)
}

// takeOverEnable lets a disable end an enable that is unfinished, halted or
// failing: it proves the direct path (the node never switched, so its
// endpoint stays as it is), closes the enable and starts the disable, which
// takes down whatever the enable recorded.
func (r *disableRun) takeOverEnable(ctx context.Context, enable database.TunnelOperation) error {
	if enable.AccountID != r.opts.Config.AccountID || enable.Zone != r.opts.Config.Zone {
		return smerr.New(smerr.CodeConflict, "", "the unfinished tunnel enable of this node belongs to another Cloudflare account or zone than the configured one")
	}
	if err := r.verifyDirect(ctx); err != nil {
		return err
	}
	enable, err := r.recordUnrecordedCreate(ctx, enable)
	if err != nil {
		return err
	}
	if err := r.replaceOperation(ctx, enable, database.TunnelDisable); err != nil {
		return err
	}
	return r.findLastEnabled(ctx)
}

// recordUnrecordedCreate settles the create-to-record window of an unfinished
// enable before anything is deleted (reconcileUnrecorded), while the enable
// still carries the phase and phase start that say which attempt could have
// created an object.
func (r *disableRun) recordUnrecordedCreate(ctx context.Context, enable database.TunnelOperation) (database.TunnelOperation, error) {
	phase := cmp.Or(enable.HaltedPhase, enable.Phase)
	if phase != database.PhaseTokenReady && phase != database.PhaseIngressSet {
		return enable, nil
	}
	r.op = enable
	if err := r.findLastEnabled(ctx); err != nil {
		return enable, err
	}
	if err := r.reconcileUnrecorded(ctx, phase); err != nil {
		return enable, err
	}
	return r.op, nil
}

// requireEnabledNode refuses to disable a node whose newest finished operation
// is not a committed enable in the configured account and zone: there is
// nothing of ours to take down, or it lives somewhere this instance does not
// manage.
func (r *disableRun) requireEnabledNode(ctx context.Context) error {
	if err := r.findLastEnabled(ctx); err != nil {
		return err
	}
	last := r.lastEnabled // committed, or abandoned with objects to take down
	switch {
	case last.ID == "":
		return smerr.New(smerr.CodeInvalidArgument, "", "the node has no tunnel to disable")
	case last.AccountID != r.opts.Config.AccountID || last.Zone != r.opts.Config.Zone:
		return smerr.New(smerr.CodeConflict, "", "the tunnel of this node was provisioned in another Cloudflare account or zone than the configured one")
	}
	return nil
}

// walk runs the phases after the direct path was verified. Every phase looks
// at what exists first, so a retry or a takeover converges.
func (r *disableRun) walk(ctx context.Context, c core) error {
	if err := r.advance(ctx, database.PhaseDirectVerified, r.lastEnabled.Objects, eventTunnelVerifiedDP,
		map[string]any{"hostname": r.hostname}); err != nil {
		return err
	}
	if err := r.step("switch to the direct path", r.switchToDirect(ctx)); err != nil {
		return err
	}
	if err := r.step("removal of the node service", r.removeService(ctx, c)); err != nil {
		return err
	}
	if err := r.tearDownCloud(ctx); err != nil {
		return err
	}
	return r.step("completion", r.finish(ctx))
}

// directNode is the node as it is reached without the tunnel.
func (r *tunnelRun) directNode() domain.Node {
	d := r.node
	d.Endpoint.Transport, d.Endpoint.TunnelHostname = domain.TransportDirect, ""
	return d
}

// verifyDirect proves the direct path with fresh connections for both
// accounts before anything changes: the admin account (which the removal runs
// as) and the dedicated account with the pinned key and its recorded setup.
// The pool keys connections by transport and the old ones are dropped first,
// so no pooled tunnel connection can answer for it.
func (r *disableRun) verifyDirect(ctx context.Context) error {
	direct := r.directNode()
	if direct.Endpoint.AdminUser == "" {
		return r.step("verification of the direct path", smerr.New(smerr.CodeCapabilityUnavailable, "", "the node has no admin_user, which the removal of the node service needs"))
	}
	r.conn.Invalidate(direct, direct.Endpoint.AdminUser)
	admin, err := r.conn.Admin(direct)
	if err != nil {
		return r.step("verification of the direct path (admin account)", err)
	}
	if err := requireBootstrap(ctx, admin, direct.Endpoint.AdminUser == adminRoot); err != nil {
		return r.step("verification of the direct path (admin account)", err)
	}
	if !r.hasSetup {
		return nil // the dedicated account was never set up
	}
	req := setupRequest{Grants: r.meta.Units, LogsMode: r.meta.LogsMode, DockerAccess: r.meta.DockerAccess}
	if err := verifyDedicated(ctx, r.conn, direct, sshnode.PinnedRef(r.meta), r.meta.SystemctlPath, req); err != nil {
		return r.step("verification of the direct path (dedicated account)", err)
	}
	return nil
}

// switchToDirect commits the direct transport against the revision this
// attempt read, in the transaction that records the phase, then retires every
// pooled connection of the node.
func (r *disableRun) switchToDirect(ctx context.Context) error {
	switched := r.directNode()
	switched.UpdatedAt = r.cfg.Clock.Now()
	err := r.advanceWith(ctx, database.PhaseSwitched, database.TunnelObjects{}, eventTunnelSwitched,
		map[string]any{"hostname": r.hostname}, func(ctx context.Context, tx *database.Tx) error {
			if r.node.Endpoint.Transport.Effective() == domain.TransportDirect && r.node.Endpoint.TunnelHostname == "" {
				return nil
			}
			_, err := database.UpdateNodeSpec(ctx, tx, switched, r.node.SpecRevision)
			return err
		})
	if err != nil {
		return err
	}
	r.conn.InvalidateNode(r.node)
	return nil
}

// removeService stops and removes the connector from the node, as the admin
// account over the direct path. It removes only what setup installed.
func (r *disableRun) removeService(ctx context.Context, c core) error {
	if phaseIndex(r.op.Phase) >= phaseIndex(database.PhaseServiceRemoved) {
		return nil
	}
	if err := r.mayMutate(ctx); err != nil {
		return err
	}
	direct := r.directNode()
	admin, err := r.conn.Admin(direct)
	if err != nil {
		return err
	}
	asRoot := direct.Endpoint.AdminUser == adminRoot
	c.sessionEvent(ctx, r.lease, r.job, direct, "start", asRoot, nil)
	err = systemd.RemoveTunnel(ctx, admin, systemd.RemoveTunnelParams{AdminIsRoot: asRoot})
	c.sessionEvent(context.WithoutCancel(ctx), r.lease, r.job, direct, "end", asRoot, err)
	if err != nil {
		return err
	}
	return r.advance(ctx, database.PhaseServiceRemoved, database.TunnelObjects{}, eventTunnelServiceOff,
		map[string]any{"hostname": r.hostname})
}

// finish records the operation as done and drops the tunnel from the node's
// setup metadata, in one fenced transaction.
func (r *disableRun) finish(ctx context.Context) error {
	var withCapability func(context.Context, *database.Tx) error
	if r.hasSetup {
		meta := r.meta
		meta.Tunnel = nil
		capability, err := setupCapability(meta, r.cfg.Clock.Now())
		if err != nil {
			return err
		}
		withCapability = func(ctx context.Context, tx *database.Tx) error {
			return database.SetNodeCapability(ctx, tx, r.node.ID, capability)
		}
	}
	return r.advanceWith(ctx, database.PhaseDone, database.TunnelObjects{}, eventTunnelDisabled,
		map[string]any{"hostname": r.hostname, "tunnel_id": r.known().TunnelID}, withCapability)
}
