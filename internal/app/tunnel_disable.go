package app

import (
	"cmp"
	"context"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
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

// eventObjectLeft audits a same-name object the abandon found and left alone
// because the enable could not have created it.
const eventObjectLeft = "cloudflare.object.left_untouched"

// recordUnrecordedCreate settles the one create-to-record window the enable
// was left in, while the enable still carries the phase and phase start that
// say which attempt could have created an object. The tunnel (phase
// token_ready) and the Access application (phase ingress_set) are the objects
// the teardown deletes only by recorded ID. Exactly one unrecorded object that
// passes the adoption rule the enable applies is recorded on the enable,
// fenced and before anything is deleted. Objects of that name that do not pass
// it are foreign: they are audited and left alone, and the abandon goes on.
// Foreign objects next to one that passes are ambiguous: an ownership conflict,
// nothing touched. The DNS record needs no record: its removal already
// recognises the ownership comment.
func (r *disableRun) recordUnrecordedCreate(ctx context.Context, enable database.TunnelOperation) (database.TunnelOperation, error) {
	phase := cmp.Or(enable.HaltedPhase, enable.Phase)
	if phase != database.PhaseTokenReady && phase != database.PhaseIngressSet {
		return enable, nil
	}
	r.op = enable
	if err := r.findLastEnabled(ctx); err != nil {
		return enable, err
	}
	found, err := r.unrecordedCreate(ctx, phase)
	if err != nil {
		return enable, r.step("reconciliation of the abandoned enable", err)
	}
	if found.left > 0 {
		if err := r.step("audit of the foreign object left alone", r.auditLeft(ctx, found)); err != nil {
			return enable, err
		}
	}
	if found.action == "" {
		return enable, nil
	}
	return enable, r.step("reconciliation of the abandoned enable", r.recordOnEnable(ctx, &enable, phase, found.objects, found.action, found.data))
}

// unrecordedFind is what the abandon found of the object the phase creates:
// the ID to record (empty action: nothing to adopt) and how many same-name
// objects it must leave alone.
type unrecordedFind struct {
	objects database.TunnelObjects
	action  string
	data    map[string]any
	kind    string
	name    string
	left    int
}

// claim applies the enable's adoption rule to the objects of one name.
func claim[T any](kind, name string, objects []T, adoptable func(T) bool) (T, unrecordedFind, error) {
	var picked T
	find := unrecordedFind{kind: kind, name: name}
	var mine int
	for _, o := range objects {
		if adoptable(o) {
			picked, mine = o, mine+1
		}
	}
	switch {
	case mine == 0:
		find.left = len(objects)
	case mine == 1 && len(objects) == 1:
	default:
		return picked, find, newOwnershipConflict(kind, name)
	}
	return picked, find, nil
}

// lookUpCreated lists the objects of one name. An empty listing for an object
// with no recorded ID is looked at again after each of the enable's own
// lookupBackoff waits: Cloudflare may list a created object a few seconds late,
// and concluding nothing was created would leave it behind. A non-empty
// listing, or one for a recorded ID, is taken as it is.
func lookUpCreated[T any](ctx context.Context, r *disableRun, unrecorded bool, find func() ([]T, error)) ([]T, error) {
	found, err := find()
	for _, wait := range lookupBackoff {
		if err != nil || len(found) > 0 || !unrecorded {
			break
		}
		if err = r.opts.sleep(ctx, wait); err != nil {
			return nil, err
		}
		found, err = find()
	}
	return found, err
}

// unrecordedCreate looks up the object the phase creates.
func (r *disableRun) unrecordedCreate(ctx context.Context, phase database.TunnelPhase) (unrecordedFind, error) {
	known := r.known()
	if phase == database.PhaseTokenReady {
		name := cloudflare.TunnelName(r.instanceID, r.node.ID.String())
		tunnels, err := lookUpCreated(ctx, r, known.TunnelID == "", func() ([]cloudflare.Tunnel, error) { return r.api.FindTunnels(ctx, name) })
		if err != nil || slices.ContainsFunc(tunnels, func(t cloudflare.Tunnel) bool { return t.ID == known.TunnelID }) {
			return unrecordedFind{}, err // a recorded tunnel existing means nothing was created
		}
		tunnel, find, err := claim("tunnel", name, tunnels, r.ownsTunnel)
		if err == nil && len(tunnels) == 1 && find.left == 0 {
			find.objects, find.action = database.TunnelObjects{TunnelID: tunnel.ID}, eventTunnelAdopted
			find.data = map[string]any{"tunnel_id": tunnel.ID, "name": name}
		}
		return find, err
	}
	name := cloudflare.AccessAppName(r.instanceID, r.node.ID.String())
	apps, err := lookUpCreated(ctx, r, known.AccessAppID == "", func() ([]cloudflare.AccessApp, error) { return r.api.FindAccessApps(ctx, name) })
	if err != nil || slices.ContainsFunc(apps, func(a cloudflare.AccessApp) bool { return a.ID == known.AccessAppID }) {
		return unrecordedFind{}, err
	}
	state, err := database.GetCloudflareState(ctx, r.cfg.DB.Reader())
	if err != nil {
		return unrecordedFind{}, err
	}
	app, find, err := claim("Access application", name, apps, func(a cloudflare.AccessApp) bool { return r.ownsAccessApp(state, a) })
	if err == nil && len(apps) == 1 && find.left == 0 {
		find.objects, find.action = database.TunnelObjects{AccessAppID: app.ID}, eventAccessAppAdopted
		find.data = map[string]any{"access_app_id": app.ID, "name": name, "hostname": r.hostname}
	}
	return find, err
}

// auditLeft records, under the lease fence, that same-name objects the enable
// could not have created were left alone.
func (r *disableRun) auditLeft(ctx context.Context, found unrecordedFind) error {
	if err := r.mayMutate(ctx); err != nil {
		return err
	}
	return r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		return r.emitFor(ctx, tx, eventObjectLeft, domain.ResultSucceeded,
			map[string]any{"kind": found.kind, "name": found.name, "count": found.left})
	})
}

// recordOnEnable stores the adopted ID on the unfinished enable under the lease
// fence, with its audit event. A halted enable returns to the phase it held,
// where the ID is recorded; the abandon that follows closes it from there.
func (r *disableRun) recordOnEnable(ctx context.Context, enable *database.TunnelOperation, phase database.TunnelPhase, objects database.TunnelObjects, action string, data map[string]any) error {
	if err := r.mayMutate(ctx); err != nil {
		return err
	}
	var recorded database.TunnelOperation
	err := r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		var err error
		recorded, err = database.AdvanceTunnelPhase(ctx, tx, enable.ID, enable.Generation, enable.Phase, phase, objects, r.cfg.Clock.Now())
		if err != nil {
			return err
		}
		return r.emitFor(ctx, tx, action, domain.ResultSucceeded, data)
	})
	if err == nil {
		*enable = recorded
	}
	return err
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
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"switch to the direct path", r.switchToDirect},
		{"removal of the node service", func(ctx context.Context) error { return r.removeService(ctx, c) }},
		{"closing of the route", r.closeRoute},
		{"removal of the Access application", r.removeAccess},
		{"deletion of the tunnel", r.deleteTunnel},
	}
	for _, s := range steps {
		if err := r.step(s.name, s.run(ctx)); err != nil {
			return err
		}
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

// closeRoute removes the DNS record and then answers 404 to everything at the
// tunnel, so nothing can reach the node through Cloudflare before the Access
// application, which protects the hostname, is removed.
func (r *disableRun) closeRoute(ctx context.Context) error {
	if phaseIndex(r.op.Phase) >= phaseIndex(database.PhaseRouteClosed) {
		return nil
	}
	known := r.known()
	if err := r.removeDNS(ctx, known.DNSRecordID); err != nil {
		return err
	}
	if err := r.closeIngress(ctx, known.TunnelID); err != nil {
		return err
	}
	return r.advance(ctx, database.PhaseRouteClosed, database.TunnelObjects{}, "", nil)
}

func (r *disableRun) removeDNS(ctx context.Context, recorded string) error {
	records, err := r.api.FindDNSRecords(ctx, r.zoneID, r.hostname)
	if err != nil {
		return err
	}
	comment := cloudflare.DNSComment(r.instanceID, r.node.ID.String())
	found := false
	for _, record := range records {
		ours := record.ID == recorded || (recorded == "" && record.Type == "CNAME" && record.Comment == comment)
		if !ours {
			continue // somebody else's record on the hostname is never touched
		}
		found = true
		if err := r.mayMutate(ctx); err != nil {
			return err
		}
		if err := r.api.DeleteDNSRecord(ctx, r.zoneID, record.ID); err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
		if err := r.auditNode(ctx, eventDNSDeleted, map[string]any{"dns_record_id": record.ID, "hostname": r.hostname}); err != nil {
			return err
		}
	}
	if !found && recorded != "" {
		return r.auditVanished(ctx, "DNS record", recorded)
	}
	return nil
}

func (r *disableRun) closeIngress(ctx context.Context, tunnelID string) error {
	if tunnelID == "" {
		return nil // the tunnel was never created
	}
	current, err := r.api.GetTunnelConfig(ctx, tunnelID)
	if cloudflare.IsNotFound(err) {
		return r.auditVanished(ctx, "tunnel", tunnelID)
	}
	if err != nil {
		return err
	}
	if slices.Equal(current.Ingress, cloudflare.ClosedIngress()) {
		return nil
	}
	if err := r.mayMutate(ctx); err != nil {
		return err
	}
	if _, err := r.api.PutTunnelIngress(ctx, tunnelID, cloudflare.ClosedIngress()); err != nil {
		return err
	}
	return r.auditNode(ctx, eventIngressClosed, map[string]any{"tunnel_id": tunnelID, "hostname": r.hostname})
}

// removeAccess deletes this node's Access application. The reusable policies
// and the service token belong to the instance and stay.
func (r *disableRun) removeAccess(ctx context.Context) error {
	if phaseIndex(r.op.Phase) >= phaseIndex(database.PhaseAccessRemoved) {
		return nil
	}
	name, recorded := cloudflare.AccessAppName(r.instanceID, r.node.ID.String()), r.known().AccessAppID
	apps, err := r.api.FindAccessApps(ctx, name)
	if err != nil {
		return err
	}
	found := false
	for _, app := range apps {
		if app.ID != recorded {
			continue // an application of this name that was never recorded is not provably ours
		}
		found = true
		if err := r.mayMutate(ctx); err != nil {
			return err
		}
		if err := r.api.DeleteAccessApp(ctx, app.ID); err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
		if err := r.auditNode(ctx, eventAccessAppGone, map[string]any{"access_app_id": app.ID, "name": name}); err != nil {
			return err
		}
	}
	if !found && recorded != "" {
		if err := r.auditVanished(ctx, "Access application", recorded); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.PhaseAccessRemoved, database.TunnelObjects{}, "", nil)
}

// deleteTunnel deletes the tunnel last. Its connector has been stopped on the
// node; the connections Cloudflare still lists are cleared first.
func (r *disableRun) deleteTunnel(ctx context.Context) error {
	if phaseIndex(r.op.Phase) >= phaseIndex(database.PhaseTunnelDeleted) {
		return nil
	}
	name, recorded := cloudflare.TunnelName(r.instanceID, r.node.ID.String()), r.known().TunnelID
	tunnels, err := r.api.FindTunnels(ctx, name)
	if err != nil {
		return err
	}
	found := false
	for _, tunnel := range tunnels {
		if tunnel.ID != recorded {
			continue // a tunnel of this name that was never recorded is not provably ours
		}
		found = true
		if err := r.mayMutate(ctx); err != nil {
			return err
		}
		if err := r.api.CleanupTunnelConnections(ctx, tunnel.ID); err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
		if err := r.api.DeleteTunnel(ctx, tunnel.ID); err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
		if err := r.auditNode(ctx, eventTunnelGone, map[string]any{"tunnel_id": tunnel.ID, "name": name}); err != nil {
			return err
		}
	}
	if !found && recorded != "" {
		if err := r.auditVanished(ctx, "tunnel", recorded); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.PhaseTunnelDeleted, database.TunnelObjects{}, "", nil)
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
