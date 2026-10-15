package app

import (
	"context"
	"slices"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// known is the ID of each object of this node: the one recorded by this
// operation, else the one of the previous committed enable.
func (r *tunnelRun) known() database.TunnelObjects {
	known := r.op.Objects
	if known.TunnelID == "" {
		known.TunnelID = r.lastEnabled.Objects.TunnelID
	}
	if known.AccessAppID == "" {
		known.AccessAppID = r.lastEnabled.Objects.AccessAppID
	}
	if known.DNSRecordID == "" {
		known.DNSRecordID = r.lastEnabled.Objects.DNSRecordID
	}
	return known
}

// provisionCloudflare walks the Cloudflare side of the enable state machine in
// the ADR-0037 order and returns the tunnel token for the node. Every step
// looks at what already exists first, so a retry or takeover converges and no
// object is created twice. The DNS record is created last: the hostname is
// never routable without its Access application.
func (r *tunnelRun) provisionCloudflare(ctx context.Context) (audit.Secret, error) {
	steps := []struct {
		name string
		run  func(context.Context, database.CloudflareState) error
	}{
		{"tunnel", r.ensureTunnel},
		{"tunnel ingress", r.ensureIngress},
		{"Access application", r.ensureAccessApp},
		{"DNS record", r.ensureDNS},
	}
	state, err := r.ensureInstanceAccess(ctx)
	if err != nil {
		return "", r.fail(ctx, r.step("Access service token and policies", err))
	}
	if err := r.advance(ctx, database.PhaseTokenReady, database.TunnelObjects{}, "", nil); err != nil {
		return "", err
	}
	for _, s := range steps {
		if err := s.run(ctx, state); err != nil {
			return "", r.fail(ctx, r.step(s.name, err))
		}
	}
	token, err := r.api.TunnelToken(ctx, r.known().TunnelID)
	if err != nil {
		return "", r.step("tunnel token", err)
	}
	return token, nil
}

func (r *tunnelRun) ensureTunnel(ctx context.Context, _ database.CloudflareState) error {
	name := cloudflare.TunnelName(r.instanceID, r.node.ID.String())
	tunnel, how, err := ensureNamed(ctx, r, namedObject[cloudflare.Tunnel]{
		kind: "tunnel", name: name, known: r.known().TunnelID, recreate: r.op.Objects.TunnelID == "",
		find:   func(ctx context.Context) ([]cloudflare.Tunnel, error) { return r.api.FindTunnels(ctx, name) },
		create: func(ctx context.Context) (cloudflare.Tunnel, error) { return r.api.CreateTunnel(ctx, name) },
		idOf:   func(t cloudflare.Tunnel) string { return t.ID },
		adoptable: func(t cloudflare.Tunnel) bool {
			return r.createdSince(t.CreatedAt) && (t.ConfigSrc == "" || t.ConfigSrc == "cloudflare")
		},
	})
	if err != nil {
		return err
	}
	return r.advance(ctx, database.PhaseTunnelCreated, database.TunnelObjects{TunnelID: tunnel.ID},
		tunnelEvent(how, eventTunnelCreated, eventTunnelAdopted), map[string]any{"tunnel_id": tunnel.ID, "name": name})
}

func (r *tunnelRun) ensureIngress(ctx context.Context, _ database.CloudflareState) error {
	tunnelID, want := r.known().TunnelID, cloudflare.SSHIngress(r.hostname)
	current, err := r.api.GetTunnelConfig(ctx, tunnelID)
	if err != nil {
		return err
	}
	if !slices.Equal(current.Ingress, want) {
		if err := r.mayMutate(ctx); err != nil {
			return err
		}
		if _, err := r.api.PutTunnelIngress(ctx, tunnelID, want); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.PhaseIngressSet, database.TunnelObjects{}, eventIngressSet,
		map[string]any{"tunnel_id": tunnelID, "hostname": r.hostname})
}

func (r *tunnelRun) ensureAccessApp(ctx context.Context, state database.CloudflareState) error {
	name := cloudflare.AccessAppName(r.instanceID, r.node.ID.String())
	spec := cloudflare.AppSpec{
		Name: name, Domain: r.hostname, PolicyIDs: []string{state.ServicePolicyID, state.OwnersPolicyID},
		AllowedIdPs: r.opts.Config.AccessIdentityProviders,
	}
	app, how, err := ensureNamed(ctx, r, namedObject[cloudflare.AccessApp]{
		kind: "Access application", name: name, known: r.known().AccessAppID, recreate: r.op.Objects.AccessAppID == "",
		find:   func(ctx context.Context) ([]cloudflare.AccessApp, error) { return r.api.FindAccessApps(ctx, name) },
		create: func(ctx context.Context) (cloudflare.AccessApp, error) { return r.api.CreateAccessApp(ctx, spec) },
		idOf:   func(a cloudflare.AccessApp) string { return a.ID },
		adoptable: func(a cloudflare.AccessApp) bool {
			return r.createdSince(a.CreatedAt) && a.Domain == r.hostname &&
				slices.Contains(a.PolicyIDs, state.ServicePolicyID) && slices.Contains(a.PolicyIDs, state.OwnersPolicyID)
		},
	})
	if err != nil {
		return err
	}
	if how != foundCreated {
		if err := r.reconcileAccessApp(ctx, app, spec); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.PhaseAccessReady, database.TunnelObjects{AccessAppID: app.ID},
		tunnelEvent(how, eventAccessAppCreated, eventAccessAppAdopted),
		map[string]any{"access_app_id": app.ID, "name": name, "hostname": r.hostname})
}

// reconcileAccessApp brings an existing application to what the configuration
// and the instance state say: its policies (a policy recreated after it
// vanished has a new ID) and the identity providers owners may log in with.
func (r *tunnelRun) reconcileAccessApp(ctx context.Context, app cloudflare.AccessApp, spec cloudflare.AppSpec) error {
	if slices.Equal(app.PolicyIDs, spec.PolicyIDs) && sameSet(app.AllowedIdPs, spec.AllowedIdPs) {
		return nil
	}
	if err := r.mayMutate(ctx); err != nil {
		return err
	}
	if _, err := r.api.UpdateAccessApp(ctx, app.ID, spec); err != nil {
		return err
	}
	return r.auditNode(ctx, eventAccessAppUpdated, map[string]any{"access_app_id": app.ID, "name": spec.Name, "hostname": r.hostname})
}

func (r *tunnelRun) ensureDNS(ctx context.Context, _ database.CloudflareState) error {
	if r.known().AccessAppID == "" || phaseIndex(r.op.Phase) < phaseIndex(database.PhaseAccessReady) {
		return smerr.New(smerr.CodeInternal, "", "the DNS record is created only after the Access application is recorded")
	}
	tunnelID, comment := r.known().TunnelID, cloudflare.DNSComment(r.instanceID, r.node.ID.String())
	object := func(known string) namedObject[cloudflare.DNSRecord] {
		return namedObject[cloudflare.DNSRecord]{
			kind: "DNS record", name: r.hostname, known: known, recreate: r.op.Objects.DNSRecordID == "",
			find: func(ctx context.Context) ([]cloudflare.DNSRecord, error) {
				return r.api.FindDNSRecords(ctx, r.zoneID, r.hostname)
			},
			create: func(ctx context.Context) (cloudflare.DNSRecord, error) {
				return r.api.CreateTunnelCNAME(ctx, r.zoneID, r.hostname, tunnelID, comment)
			},
			idOf: func(d cloudflare.DNSRecord) string { return d.ID },
			adoptable: func(d cloudflare.DNSRecord) bool {
				return r.createdSince(d.CreatedOn) && d.Type == "CNAME" && d.Comment == comment && d.Content == cloudflare.TunnelTarget(tunnelID)
			},
		}
	}
	record, how, err := ensureNamed(ctx, r, object(r.known().DNSRecordID))
	if err != nil {
		return err
	}
	if how == foundRecorded && record.Content != cloudflare.TunnelTarget(tunnelID) {
		// The tunnel was recreated, so the record points at the old one. There
		// is no update call: delete it (the Access application is in place, so
		// the hostname stays protected) and create it again.
		if record, how, err = r.replaceStaleDNS(ctx, record, object); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.PhaseDNSCreated, database.TunnelObjects{DNSRecordID: record.ID},
		tunnelEvent(how, eventDNSCreated, eventDNSAdopted), map[string]any{"dns_record_id": record.ID, "hostname": r.hostname})
}

func (r *tunnelRun) replaceStaleDNS(ctx context.Context, stale cloudflare.DNSRecord, object func(string) namedObject[cloudflare.DNSRecord]) (cloudflare.DNSRecord, howFound, error) {
	if r.op.Objects.DNSRecordID != "" {
		return stale, 0, r.newRecordGone("the DNS record recorded for this node points at another tunnel")
	}
	if err := r.mayMutate(ctx); err != nil {
		return stale, 0, err
	}
	if err := r.api.DeleteDNSRecord(ctx, r.zoneID, stale.ID); err != nil && !cloudflare.IsNotFound(err) {
		return stale, 0, err
	}
	if err := r.auditNode(ctx, eventDNSReplaced, map[string]any{"dns_record_id": stale.ID, "hostname": r.hostname}); err != nil {
		return stale, 0, err
	}
	return ensureNamed(ctx, r, object(""))
}

// tunnelEvent picks the audit action: objects that already existed under their
// recorded ID need no event beyond the phase advance.
func tunnelEvent(how howFound, created, adopted string) string {
	switch how {
	case foundCreated:
		return created
	case foundAdopted:
		return adopted
	case foundRecorded:
		return ""
	}
	return ""
}

// candidate is the node as it would be reached through the tunnel.
func (r *tunnelRun) candidate() domain.Node {
	c := r.node
	c.Endpoint.Transport = domain.TransportCloudflare
	c.Endpoint.TunnelHostname = r.hostname
	return c
}

// verifyTunnelPath runs the dedicated-account verification over a fresh
// connection through the candidate transport. The pool keys connections by
// transport, so a pooled direct connection cannot answer for it, and the
// host key pinned for the node is enforced over the tunnel.
func (h setupHandler) verifyTunnelPath(ctx context.Context, r *tunnelRun, req setupRequest, id secrets.Identity, outcome systemd.SetupOutcome) error {
	if err := h.verify(ctx, r.candidate(), req, id, outcome); err != nil {
		return r.step("verification over the tunnel", err)
	}
	return r.advance(ctx, database.PhaseVerified, database.TunnelObjects{}, "", nil)
}

// commit is the switch: in one fenced transaction it records the node.setup
// capability (with the tunnel state), moves the endpoint to the cloudflare
// transport against the revision the job started from, and finishes the
// operation. The pooled connections of the old transport are retired after.
func (h setupHandler) commitTunnel(ctx context.Context, r *tunnelRun, req setupRequest, deployRoot string, id secrets.Identity, outcome systemd.SetupOutcome) error {
	now := h.cfg.Clock.Now()
	meta := h.setupMeta(req, deployRoot, id, outcome)
	meta.Tunnel = &runtimes.TunnelMeta{Hostname: r.hostname, InstalledAt: now}
	capability, err := setupCapability(meta, now)
	if err != nil {
		return err
	}
	switched := r.node
	switched.Endpoint.Transport, switched.Endpoint.TunnelHostname = domain.TransportCloudflare, r.hostname
	switched.UpdatedAt = now
	err = h.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if r.node.Endpoint.Transport != switched.Endpoint.Transport || r.node.Endpoint.TunnelHostname != r.hostname {
			if _, err := database.UpdateNodeSpec(ctx, tx, switched, r.node.SpecRevision); err != nil {
				return err
			}
		}
		if err := database.SetNodeCapability(ctx, tx, r.node.ID, capability); err != nil {
			return err
		}
		if _, err := database.AdvanceTunnelPhase(ctx, tx, r.op.ID, r.op.Generation, r.op.Phase, database.PhaseCommitted,
			database.TunnelObjects{}, now); err != nil {
			return err
		}
		if err := r.emitFor(ctx, tx, eventTunnelEnabled, domain.ResultSucceeded, map[string]any{
			"hostname": r.hostname, "tunnel_id": r.known().TunnelID,
		}); err != nil {
			return err
		}
		return h.emitSetupCompleted(ctx, tx, r.job, r.node, req, deployRoot, id)
	})
	if err != nil {
		return err
	}
	h.conn.InvalidateNode(r.node)
	return nil
}
