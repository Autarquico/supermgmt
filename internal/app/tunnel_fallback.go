package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// eventTunnelSetupDirect records that a tunnel setup ran its bootstrap admin
// session over direct SSH because the tunnel could not carry it. It names the
// node and a fixed reason; the carrier's own words stay out of the audit log.
const eventTunnelSetupDirect = "node.tunnel.setup_direct_fallback"

// reasonCarrierFailure is the only reason a setup falls back.
const reasonCarrierFailure = "carrier_failure"

// bootstrapAdmin returns the admin executor of a setup, after the bootstrap
// requirements held on it. A tunnel setup (run != nil) of a node whose
// committed transport is cloudflare can repair a broken connector only if the
// admin session does not depend on it: when the tunnel itself cannot carry the
// stream, the same admin session runs over the pinned direct route instead.
// Nothing else falls back: not an Access refusal, an authentication failure, a
// host key mismatch nor a cancelled or timed out attempt. The stored endpoint
// is untouched; the switch still waits for the verification over the tunnel.
func (h setupHandler) bootstrapAdmin(ctx context.Context, run *tunnelRun, node domain.Node, asRoot bool) (transport.Executor, error) {
	admin, err := h.conn.Admin(node)
	if err != nil {
		return nil, err
	}
	err = requireBootstrap(ctx, admin, asRoot)
	if err == nil || !mayFallBackToDirect(ctx, run, node, err) {
		return admin, err
	}
	return h.bootstrapDirect(ctx, run, asRoot, err)
}

// mayFallBackToDirect is the whole fallback rule.
func mayFallBackToDirect(ctx context.Context, run *tunnelRun, node domain.Node, err error) bool {
	return run != nil && ctx.Err() == nil &&
		node.Endpoint.Transport.Effective() == domain.TransportCloudflare && ssh.IsCarrierFailure(err)
}

func (h setupHandler) bootstrapDirect(ctx context.Context, run *tunnelRun, asRoot bool, tunnelErr error) (transport.Executor, error) {
	direct := run.directNode()
	h.conn.Invalidate(direct, direct.Endpoint.AdminUser)
	if err := run.auditNode(ctx, eventTunnelSetupDirect, map[string]any{"reason": reasonCarrierFailure}); err != nil {
		return nil, err
	}
	admin, err := h.conn.Admin(direct)
	if err == nil {
		err = requireBootstrap(ctx, admin, asRoot)
	}
	if err == nil {
		return admin, nil
	}
	if smerr.CodeOf(err) != smerr.CodeNodeUnreachable || ssh.IsAuthRejected(err) {
		return nil, smerr.Wrap(err, smerr.CodeOf(err), "",
			"setup failed over direct SSH, after the tunnel could not carry the stream")
	}
	return nil, smerr.Wrap(err, smerr.CodeNodeUnreachable, "", fmt.Sprintf(
		"the node could not be reached for setup through the tunnel (%v) nor over direct SSH", tunnelErr))
}
