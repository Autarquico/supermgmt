package client

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- app routes through the node's Cloudflare Tunnel (ADR-0040) ---------------

// ExposeAppRoute asks to publish a service port of the target. The answer is the job, which waits for approval
// when policy asks; Route is nil until then.
func (c *Client) ExposeAppRoute(ctx context.Context, target domain.ID, r wire.ExposeAppRouteRequest) (wire.AppRouteSubmission, error) {
	return call[wire.AppRouteSubmission](ctx, c, post(wire.Path(wire.PathAppTargetRoutes, string(target)), r))
}

// UnexposeAppRoute asks to remove the target's route for hostname.
func (c *Client) UnexposeAppRoute(ctx context.Context, target domain.ID, hostname string) (wire.AppRouteSubmission, error) {
	return call[wire.AppRouteSubmission](ctx, c, request{method: http.MethodDelete, path: wire.Path(wire.PathAppTargetRoute, string(target), hostname)})
}

// ListAppTargetRoutes returns the routes of one target that are not removed.
func (c *Client) ListAppTargetRoutes(ctx context.Context, target domain.ID) (wire.Page[wire.AppRoute], error) {
	return call[wire.Page[wire.AppRoute]](ctx, c, get(wire.Path(wire.PathAppTargetRoutes, string(target)), nil))
}

// ListAppRoutes returns the routes of every target the caller may read.
func (c *Client) ListAppRoutes(ctx context.Context) (wire.Page[wire.AppRoute], error) {
	return call[wire.Page[wire.AppRoute]](ctx, c, get(wire.PathAppRoutes, nil))
}
