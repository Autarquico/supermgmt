package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- node routes through the node's Cloudflare Tunnel (ADR-0043) ---------------

// ExposeNodeRoute asks to publish a port of the node. The answer is the job, which waits for approval when
// policy asks; Route is nil until then.
func (c *Client) ExposeNodeRoute(ctx context.Context, node domain.ID, r wire.ExposeNodeRouteRequest) (wire.NodeRouteSubmission, error) {
	return call[wire.NodeRouteSubmission](ctx, c, post(wire.Path(wire.PathNodeRoutes, string(node)), r))
}

// UnexposeNodeRoute asks to remove the node's route for hostname.
func (c *Client) UnexposeNodeRoute(ctx context.Context, node domain.ID, hostname string) (wire.NodeRouteSubmission, error) {
	return call[wire.NodeRouteSubmission](ctx, c, request{method: http.MethodDelete, path: wire.Path(wire.PathNodeRoute, string(node), hostname)})
}

// ListNodeRoutes returns the routes of one node, those removed included when includeRemoved is set.
func (c *Client) ListNodeRoutes(ctx context.Context, node domain.ID, includeRemoved bool) (wire.Page[wire.NodeRoute], error) {
	return call[wire.Page[wire.NodeRoute]](ctx, c, get(wire.Path(wire.PathNodeRoutes, string(node)), removedQuery(includeRemoved)))
}

// ListAllNodeRoutes returns the routes of every node the caller may read, those removed included when
// includeRemoved is set.
func (c *Client) ListAllNodeRoutes(ctx context.Context, includeRemoved bool) (wire.Page[wire.NodeRoute], error) {
	return call[wire.Page[wire.NodeRoute]](ctx, c, get(wire.PathNodeRoutesAll, removedQuery(includeRemoved)))
}

func removedQuery(includeRemoved bool) url.Values {
	if !includeRemoved {
		return nil
	}
	return url.Values{wire.QueryIncludeRemoved: {"true"}}
}
