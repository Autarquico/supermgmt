package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// Audit events of repairs and of the disable job. As with the enable events,
// each carries object IDs and never a credential.
const (
	eventObjectVanished   = "cloudflare.object.vanished"
	eventAccessAppUpdated = "cloudflare.access_app.updated"
	eventDNSReplaced      = "cloudflare.dns_record.replaced"
	eventDNSDeleted       = "cloudflare.dns_record.deleted"
	eventIngressClosed    = "cloudflare.tunnel.ingress_closed"
	eventAccessAppGone    = "cloudflare.access_app.deleted"
	eventTunnelGone       = "cloudflare.tunnel.deleted"
	eventTunnelDisabled   = "node.tunnel.disabled"
	eventTunnelServiceOff = "node.tunnel.service_removed"
	eventTunnelSwitched   = "node.tunnel.switched_to_direct"
	eventTunnelVerifiedDP = "node.tunnel.direct_verified"
)

// auditVanished records that an object whose ID was known to this node (or to
// the instance) is no longer in Cloudflare. It is the audit trail of a
// repair: enable creates the object again, disable treats it as removed.
func (r *tunnelRun) auditVanished(ctx context.Context, kind, id string) error {
	return r.auditNode(ctx, eventObjectVanished, map[string]any{"kind": kind, "object_id": id})
}

// auditNode writes one event about the run's node, or about the instance when
// the run is not about a node (rotation).
func (r *tunnelRun) auditNode(ctx context.Context, action string, data map[string]any) error {
	if r.node.ID == "" {
		return r.auditInstance(ctx, action, data)
	}
	return r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		return r.emitFor(ctx, tx, action, domain.ResultSucceeded, data)
	})
}
