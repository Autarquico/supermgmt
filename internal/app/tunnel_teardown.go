package app

import (
	"cmp"
	"context"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// The cloud-only teardown of a tunnel (ADR-0037, ADR-0039): it works on the run's tunnelRecord, so it takes
// down the objects of a node's disable operation and of an enrollment that has no node row and no direct path.
// The order is the reverse of the build, the route first: DNS, then the ingress closed, then the Access
// application, then the tunnel. The instance's shared policies and service token stay.

// eventObjectLeft audits a same-name object the abandon found and left alone
// because the enable could not have created it.
const eventObjectLeft = "cloudflare.object.left_untouched"

const eventEnrollmentEnded = "node.tunnel.enrollment_ended"

// tearDownCloud runs the teardown steps, each persisted on the record when done. It returns nil only when
// nothing is left, so the caller may go terminal on nil and on nothing else.
func (r *tunnelRun) tearDownCloud(ctx context.Context) error {
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"closing of the route", r.closeRoute},
		{"removal of the Access application", r.removeAccess},
		{"deletion of the tunnel", r.deleteTunnel},
	}
	for _, s := range steps {
		if err := r.step(s.name, s.run(ctx)); err != nil {
			return err
		}
	}
	return nil
}

// reconcileUnrecorded settles the one create-to-record window an unfinished enable or enrollment was left
// in, while the record still carries the phase and phase start that say which attempt could have created an
// object (phase is the phase it held, the halted one for a halted record). The tunnel (phase token_ready) and
// the Access application (phase ingress_set) are the objects the teardown deletes only by recorded ID.
// Exactly one unrecorded object that passes the adoption rule the enable applies is recorded on the record,
// fenced and before anything is deleted. Objects of that name that do not pass it are foreign: they are
// audited and left alone, and the teardown goes on. Foreign objects next to one that passes are ambiguous:
// an ownership conflict, nothing touched. The DNS record needs no record: its removal already recognises the
// ownership comment.
func (r *tunnelRun) reconcileUnrecorded(ctx context.Context, phase database.TunnelPhase) error {
	if phase != database.PhaseTokenReady && phase != database.PhaseIngressSet {
		return nil
	}
	found, err := r.unrecordedCreate(ctx, phase)
	if err != nil {
		return r.step("reconciliation of the abandoned enable", err)
	}
	if found.left > 0 {
		if err := r.step("audit of the foreign object left alone", r.auditLeft(ctx, found)); err != nil {
			return err
		}
	}
	if found.action == "" {
		return nil
	}
	return r.step("reconciliation of the abandoned enable", r.recordFound(ctx, phase, found))
}

// recordFound stores the adopted ID on the record under the lease fence, with its audit event. A halted
// record returns to the phase it held, where the ID is recorded; the teardown that follows closes it from there.
func (r *tunnelRun) recordFound(ctx context.Context, phase database.TunnelPhase, found unrecordedFind) error {
	if err := r.mayMutate(ctx); err != nil {
		return err
	}
	return r.record().Advance(ctx, phase, found.objects, recordHooks{After: func(ctx context.Context, tx *database.Tx) error {
		return r.emitFor(ctx, tx, found.action, domain.ResultSucceeded, found.data)
	}})
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
func lookUpCreated[T any](ctx context.Context, r *tunnelRun, unrecorded bool, find func() ([]T, error)) ([]T, error) {
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
func (r *tunnelRun) unrecordedCreate(ctx context.Context, phase database.TunnelPhase) (unrecordedFind, error) {
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
func (r *tunnelRun) auditLeft(ctx context.Context, found unrecordedFind) error {
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

// closeRoute removes the DNS record and then answers 404 to everything at the
// tunnel, so nothing can reach the node through Cloudflare before the Access
// application, which protects the hostname, is removed.
func (r *tunnelRun) closeRoute(ctx context.Context) error {
	if phaseIndex(r.record().Phase()) >= phaseIndex(database.PhaseRouteClosed) {
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

func (r *tunnelRun) removeDNS(ctx context.Context, recorded string) error {
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

func (r *tunnelRun) closeIngress(ctx context.Context, tunnelID string) error {
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
func (r *tunnelRun) removeAccess(ctx context.Context) error {
	if phaseIndex(r.record().Phase()) >= phaseIndex(database.PhaseAccessRemoved) {
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
func (r *tunnelRun) deleteTunnel(ctx context.Context) error {
	if phaseIndex(r.record().Phase()) >= phaseIndex(database.PhaseTunnelDeleted) {
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

// removeEnrollment takes down everything an enrollment created and ends it as end (expired or cancelled),
// which releases its name. It reconciles the objects created but not recorded, starts the removal, tears
// the objects down with the progress persisted after each step and ends the record last. It returns nil
// only when the enrollment is terminal: a failed delete leaves it removing, or at the last step done, for
// the next attempt.
func (r *tunnelRun) removeEnrollment(ctx context.Context, rec *enrollmentRecord, reason string, end database.TunnelPhase) error {
	r.disabling = true
	if e := rec.Enrollment(); !removalStarted(e.Phase) {
		if err := r.reconcileUnrecorded(ctx, cmp.Or(e.HaltedPhase, e.Phase)); err != nil {
			return err
		}
		if err := r.step("start of the removal", rec.startRemoval(ctx, reason)); err != nil {
			return err
		}
	}
	if err := r.tearDownCloud(ctx); err != nil {
		return err
	}
	return r.step("completion", rec.end(ctx, end, func(ctx context.Context, tx *database.Tx) error {
		return r.emitFor(ctx, tx, eventEnrollmentEnded, domain.ResultSucceeded,
			map[string]any{"phase": string(end), "reason": reason, "tunnel_id": r.known().TunnelID})
	}))
}

// removalStarted reports whether the phase is one of the removal's own.
func removalStarted(p database.TunnelPhase) bool {
	return slices.Contains([]database.TunnelPhase{
		database.PhaseRemoving, database.PhaseRouteClosed, database.PhaseAccessRemoved, database.PhaseTunnelDeleted,
	}, p)
}

// startRemoval moves the enrollment to removing, recording why, under the lease fence.
func (e *enrollmentRecord) startRemoval(ctx context.Context, reason string) error {
	return e.transition(ctx, func(ctx context.Context, tx *database.Tx) (database.TunnelEnrollment, error) {
		return database.StartTunnelEnrollmentRemoval(ctx, tx, e.e.ID, e.e.Phase, reason, e.now())
	}, nil)
}

// end finishes a removed enrollment as expired or cancelled; after commits with it.
func (e *enrollmentRecord) end(ctx context.Context, end database.TunnelPhase, after txStep) error {
	return e.transition(ctx, func(ctx context.Context, tx *database.Tx) (database.TunnelEnrollment, error) {
		return database.EndTunnelEnrollment(ctx, tx, e.e.ID, e.e.Phase, end, e.now())
	}, after)
}

func (e *enrollmentRecord) transition(ctx context.Context, change func(context.Context, *database.Tx) (database.TunnelEnrollment, error), after txStep) error {
	var changed database.TunnelEnrollment
	err := e.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := e.lease.Fence(ctx, tx); err != nil {
			return err
		}
		var err error
		if changed, err = change(ctx, tx); err != nil {
			return err
		}
		return runStep(ctx, tx, after)
	})
	if err == nil {
		e.e = changed
	}
	return err
}
