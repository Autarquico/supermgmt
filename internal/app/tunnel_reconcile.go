package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// Audit events of the post-restore reconciliation (ADR-0037 "Restore"). Each
// carries object IDs and names, never a credential.
const (
	eventReconcileMissing   = "cloudflare.reconcile.missing"
	eventReconcileRecreated = "cloudflare.reconcile.recreated"
	eventReconcileDone      = "cloudflare.reconcile.completed"
)

// ObjectState is what the reconciliation found for one recorded object.
type ObjectState string

const (
	// ObjectPresent: Cloudflare holds the recorded ID.
	ObjectPresent ObjectState = "present"
	// ObjectMissing: neither the recorded ID nor an object of the ADR name
	// exists. The next enable run takes the vanished-object repair path.
	ObjectMissing ObjectState = "missing"
	// ObjectRecreated: the recorded ID is gone but an object of the ADR name
	// exists under another ID. It is a conflict for the operator: the next
	// enable run adopts it only if it passes the adoption rule (created by
	// that run, with the expected content), which an object that predates the
	// run never does.
	ObjectRecreated ObjectState = "recreated"
)

// TunnelFinding is one recorded object compared with Cloudflare. NodeID is
// empty for the instance-level objects (policies, service token).
type TunnelFinding struct {
	NodeID     domain.ID
	Kind       string
	Name       string
	RecordedID string
	FoundID    string // the object of the same name under another ID, when recreated
	State      ObjectState
}

// TunnelReconcileReport is the outcome of one pass.
type TunnelReconcileReport struct {
	Checked  int
	Findings []TunnelFinding // only the objects that are not present
}

// TunnelReconciler compares the tunnel records of a restored instance with
// Cloudflare once the restore hold ended. It reads Cloudflare and writes
// audit events; it creates, adopts, updates and deletes nothing, in
// Cloudflare or in the records. The repair itself is the next enable run.
type TunnelReconciler struct {
	engine *tunnelEngine
}

// TunnelReconciler returns the reconciler, or nil when the Cloudflare
// connection is not configured.
func (h *Handlers) TunnelReconciler() *TunnelReconciler {
	if h.setup.tunnel == nil {
		return nil
	}
	return &TunnelReconciler{engine: h.setup.tunnel}
}

// Run does one pass. It refuses while the restore hold is in force.
func (t *TunnelReconciler) Run(ctx context.Context) (TunnelReconcileReport, error) {
	e := t.engine
	held, err := database.GetRestoreHold(ctx, e.cfg.DB.Reader())
	switch {
	case err != nil:
		return TunnelReconcileReport{}, smerr.Wrap(err, smerr.CodeConflict, smerr.ReasonRestoreHold, "the restore hold cannot be read; not reconciling")
	case held:
		return TunnelReconcileReport{}, smerr.FromReason(smerr.ReasonRestoreHold, holdMessage)
	}
	r, err := e.newInstanceRun(ctx, jobs.Lease{}, jobs.Job{})
	if err != nil {
		return TunnelReconcileReport{}, err
	}
	zone, err := r.api.ZoneByName(ctx, e.opts.Config.Zone)
	if err != nil {
		return TunnelReconcileReport{}, r.step("zone lookup", err)
	}
	var report TunnelReconcileReport
	if err := t.checkNodes(ctx, r, zone.ID, &report); err != nil {
		return report, err
	}
	if err := t.checkInstance(ctx, r, &report); err != nil {
		return report, err
	}
	return report, t.record(ctx, r.instanceID, report)
}

func (t *TunnelReconciler) checkNodes(ctx context.Context, r *tunnelRun, zoneID string, report *TunnelReconcileReport) error {
	nodes, err := database.ListNodes(ctx, t.engine.cfg.DB.Reader())
	if err != nil {
		return err
	}
	for _, node := range nodes {
		ops, err := database.ListTunnelOperations(ctx, t.engine.cfg.DB.Reader(), node.ID)
		if err != nil {
			return err
		}
		if len(ops) == 0 || ops[0].Kind != database.TunnelEnable || ops[0].AccountID != t.engine.opts.Config.AccountID {
			continue // never tunnelled, disabled, or recorded against another account
		}
		op := ops[0]
		if err := t.checkNode(ctx, r, node.ID, op, zoneID, report); err != nil {
			return err
		}
	}
	return nil
}

func (t *TunnelReconciler) checkNode(ctx context.Context, r *tunnelRun, nodeID domain.ID, op database.TunnelOperation, zoneID string, report *TunnelReconcileReport) error {
	tunnelName := cloudflare.TunnelName(r.instanceID, nodeID.String())
	if id := op.Objects.TunnelID; id != "" {
		state, found, err := t.tunnelState(ctx, r.api, id, tunnelName)
		if err := t.note(report, nodeID, "tunnel", tunnelName, id, found, state, err); err != nil {
			return err
		}
	}
	if id := op.Objects.AccessAppID; id != "" {
		name := cloudflare.AccessAppName(r.instanceID, nodeID.String())
		apps, err := r.api.FindAccessApps(ctx, name)
		state, found := byID(apps, id, func(a cloudflare.AccessApp) string { return a.ID })
		if err := t.note(report, nodeID, "Access application", name, id, found, state, err); err != nil {
			return err
		}
	}
	if id := op.Objects.DNSRecordID; id != "" {
		records, err := r.api.FindDNSRecords(ctx, zoneID, op.Hostname)
		state, found := byID(records, id, func(d cloudflare.DNSRecord) string { return d.ID })
		if err := t.note(report, nodeID, "DNS record", op.Hostname, id, found, state, err); err != nil {
			return err
		}
	}
	return nil
}

func (t *TunnelReconciler) checkInstance(ctx context.Context, r *tunnelRun, report *TunnelReconcileReport) error {
	state, err := database.GetCloudflareState(ctx, t.engine.cfg.DB.Reader())
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return nil
	} else if err != nil {
		return err
	}
	if id := state.ServicePolicyID; id != "" {
		name := cloudflare.ServicePolicyName(r.instanceID)
		policies, err := r.api.FindAccessPolicies(ctx, name)
		s, found := byID(policies, id, func(p cloudflare.AccessPolicy) string { return p.ID })
		if err := t.note(report, "", "Access policy", name, id, found, s, err); err != nil {
			return err
		}
	}
	if id := state.OwnersPolicyID; id != "" {
		name := cloudflare.OwnersPolicyName(r.instanceID)
		policies, err := r.api.FindAccessPolicies(ctx, name)
		s, found := byID(policies, id, func(p cloudflare.AccessPolicy) string { return p.ID })
		if err := t.note(report, "", "Access policy", name, id, found, s, err); err != nil {
			return err
		}
	}
	if id := state.Token.ID; id != "" && state.Token.Name != "" {
		tokens, err := r.api.FindServiceTokens(ctx, state.Token.Name)
		s, found := byID(tokens, id, func(k cloudflare.ServiceToken) string { return k.ID })
		return t.note(report, "", "service token", state.Token.Name, id, found, s, err)
	}
	return nil
}

// tunnelState looks the tunnel up by its recorded ID, then by name.
func (t *TunnelReconciler) tunnelState(ctx context.Context, api CloudflareAPI, id, name string) (ObjectState, string, error) {
	switch tunnel, err := api.GetTunnel(ctx, id); {
	case err == nil && tunnel.DeletedAt.IsZero():
		return ObjectPresent, "", nil
	case err != nil && !cloudflare.IsNotFound(err):
		return "", "", err
	}
	tunnels, err := api.FindTunnels(ctx, name)
	if err != nil {
		return "", "", err
	}
	for _, other := range tunnels {
		if other.DeletedAt.IsZero() && other.ID != id {
			return ObjectRecreated, other.ID, nil
		}
	}
	return ObjectMissing, "", nil
}

// byID classifies the objects found under the ADR name against the recorded ID.
func byID[T any](found []T, recorded string, idOf func(T) string) (ObjectState, string) {
	other := ""
	for _, obj := range found {
		if idOf(obj) == recorded {
			return ObjectPresent, ""
		}
		other = idOf(obj)
	}
	if other != "" {
		return ObjectRecreated, other
	}
	return ObjectMissing, ""
}

func (t *TunnelReconciler) note(report *TunnelReconcileReport, node domain.ID, kind, name, recorded, found string, state ObjectState, err error) error {
	if err != nil {
		return fmt.Errorf("reconcile the %s %q: %w", kind, name, err)
	}
	report.Checked++
	if state != ObjectPresent {
		report.Findings = append(report.Findings, TunnelFinding{NodeID: node, Kind: kind, Name: name, RecordedID: recorded, FoundID: found, State: state})
	}
	return nil
}

// record audits the findings and the pass in one transaction.
func (t *TunnelReconciler) record(ctx context.Context, instanceID string, report TunnelReconcileReport) error {
	e := t.engine
	return e.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		for _, f := range report.Findings {
			action, ref := eventReconcileMissing, domain.ResourceRef{Type: domain.ResourceInstance, ID: domain.ID(instanceID)}
			if f.State == ObjectRecreated {
				action = eventReconcileRecreated
			}
			if f.NodeID != "" {
				ref = nodeRef(f.NodeID)
			}
			data := map[string]any{"kind": f.Kind, "name": f.Name, "recorded_id": f.RecordedID}
			if f.FoundID != "" {
				data["found_id"] = f.FoundID
			}
			if err := e.emit(ctx, tx, systemActor, action, ref, domain.ResultFailed, data); err != nil {
				return err
			}
		}
		return e.emit(ctx, tx, systemActor, eventReconcileDone, domain.ResourceRef{Type: domain.ResourceInstance, ID: domain.ID(instanceID)},
			domain.ResultSucceeded, map[string]any{"checked": report.Checked, "findings": len(report.Findings)})
	})
}
