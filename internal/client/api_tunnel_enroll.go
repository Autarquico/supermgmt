package client

import (
	"context"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- nodes reached only through Cloudflare Tunnel (ADR-0039) ----------------

// StartTunnelEnrollment begins adding a node that is reachable only through the tunnel. Applied carries the
// enrollment; Pending the job awaiting approval, after which GetTunnelEnrollment finds the enrollment.
func (c *Client) StartTunnelEnrollment(ctx context.Context, r wire.StartTunnelEnrollmentRequest) (wire.Direct[wire.TunnelEnrollment], error) {
	return call[wire.Direct[wire.TunnelEnrollment]](ctx, c, post(wire.PathTunnelEnrollments, r))
}

// ListTunnelEnrollments returns the enrollments that have not finished.
func (c *Client) ListTunnelEnrollments(ctx context.Context) (wire.Page[wire.TunnelEnrollment], error) {
	return call[wire.Page[wire.TunnelEnrollment]](ctx, c, get(wire.PathTunnelEnrollments, nil))
}

// GetTunnelEnrollment returns the newest enrollment of the name, finished ones included.
func (c *Client) GetTunnelEnrollment(ctx context.Context, name string) (wire.TunnelEnrollment, error) {
	return call[wire.TunnelEnrollment](ctx, c, get(wire.Path(wire.PathTunnelEnrollment, name), nil))
}

// TunnelEnrollmentToken reads the connector token of an open enrollment. It is a credential route: it
// carries no Idempotency-Key, so nothing is stored or replayed.
func (c *Client) TunnelEnrollmentToken(ctx context.Context, name string) (wire.TunnelEnrollmentToken, error) {
	return call[wire.TunnelEnrollmentToken](ctx, c, get(wire.Path(wire.PathTunnelEnrollmentToken, name), nil))
}

// ConfirmTunnelEnrollment binds the operator's confirmation to the enrollment and the exact scanned key shown.
func (c *Client) ConfirmTunnelEnrollment(ctx context.Context, name string, enrollment domain.ID, hostPublicKey string) (wire.TunnelEnrollment, error) {
	return call[wire.TunnelEnrollment](ctx, c, post(wire.Path(wire.PathTunnelEnrollmentConfirm, name),
		wire.ConfirmTunnelEnrollmentRequest{EnrollmentID: enrollment, HostPublicKey: hostPublicKey}))
}

// RefuseTunnelEnrollment records that the operator did not accept the scanned key. The daemon answers with
// SSH_HOST_KEY_MISMATCH, which is the expected outcome.
func (c *Client) RefuseTunnelEnrollment(ctx context.Context, name string, enrollment domain.ID, hostPublicKey string) error {
	_, err := call[wire.TunnelEnrollment](ctx, c, post(wire.Path(wire.PathTunnelEnrollmentRefuse, name),
		wire.RefuseTunnelEnrollmentRequest{EnrollmentID: enrollment, HostPublicKey: hostPublicKey}))
	return err
}

// CancelTunnelEnrollment asks for the enrollment to be taken down.
func (c *Client) CancelTunnelEnrollment(ctx context.Context, name string) (wire.TunnelEnrollment, error) {
	return call[wire.TunnelEnrollment](ctx, c, post(wire.Path(wire.PathTunnelEnrollmentCancel, name), nil))
}
