package client

import (
	"context"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- apps: Compose projects on a node --------------------------------------------

// ListApps returns the apps of every node the caller may read.
func (c *Client) ListApps(ctx context.Context, q wire.AppsQuery) (wire.Page[wire.NodeApps], error) {
	return call[wire.Page[wire.NodeApps]](ctx, c, get(wire.PathApps, q.Values()))
}

// ListNodeApps returns the apps of one node and its other services.
func (c *Client) ListNodeApps(ctx context.Context, node domain.ID, q wire.AppsQuery) (wire.NodeApps, error) {
	return call[wire.NodeApps](ctx, c, get(wire.Path(wire.PathNodeApps, string(node)), q.Values()))
}

// GetNodeApp returns one app, with the redacted configuration of its components.
func (c *Client) GetNodeApp(ctx context.Context, node domain.ID, project string, q wire.AppsQuery) (wire.App, error) {
	return call[wire.App](ctx, c, get(wire.Path(wire.PathNodeApp, string(node), project), q.Values()))
}

// NodeAppStats takes one sample of the resource use of an app.
func (c *Client) NodeAppStats(ctx context.Context, node domain.ID, project string) (wire.AppStats, error) {
	return call[wire.AppStats](ctx, c, get(wire.Path(wire.PathNodeAppStats, string(node), project), nil))
}

// NodeAppLogs reads the logs of one component: recent, after a cursor, or a search of a recent window.
func (c *Client) NodeAppLogs(ctx context.Context, node domain.ID, project string, q wire.AppLogQuery) (wire.AppLogs, error) {
	return call[wire.AppLogs](ctx, c, get(wire.Path(wire.PathNodeAppLogs, string(node), project), q.Values()))
}
