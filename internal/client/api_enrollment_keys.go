package client

import (
	"context"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

// CreateEnrollment issues a join token (ADR-0022). The response carries the
// token once; the call is credential-issuing, so it never takes an
// Idempotency-Key.
func (c *Client) CreateEnrollment(ctx context.Context, r wire.EnrollmentRequest) (wire.EnrollmentIssued, error) {
	return call[wire.EnrollmentIssued](ctx, c, postUnkeyed(wire.PathEnrollments, r))
}

// ListMasterKeys describes the master keys the server knows, without any key
// material.
func (c *Client) ListMasterKeys(ctx context.Context) (wire.Page[wire.MasterKey], error) {
	return call[wire.Page[wire.MasterKey]](ctx, c, get(wire.PathMasterKeys, nil))
}
