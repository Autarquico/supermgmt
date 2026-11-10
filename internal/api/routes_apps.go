package api

import (
	"context"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
)

// apps registers the reads of Compose projects on a node (spec app-panels). They are node-scoped: an app has
// no resource of its own, so what authorizes a read is service.read on the node, and logs need service.logs
// on it. Every project name is validated in the app layer before it is used.
func (rs *routeSet) apps() {
	s := rs.s
	inventory := s.svc.Inventory
	rs.read(wire.PathApps, "service.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.NodeApps], error) {
		q, err := wire.ParseAppsQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[wire.NodeApps]{}, err
		}
		return inventory.Apps(ctx, by, q)
	}))
	rs.read(wire.PathNodeApps, "service.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.NodeApps, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.NodeApps{}, err
		}
		q, err := wire.ParseAppsQuery(in.r.URL.Query())
		if err != nil {
			return wire.NodeApps{}, err
		}
		return inventory.NodeApps(ctx, by, id, q)
	}))
	rs.read(wire.PathNodeApp, "service.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.App, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.App{}, err
		}
		q, err := wire.ParseAppsQuery(in.r.URL.Query())
		if err != nil {
			return wire.App{}, err
		}
		return inventory.GetApp(ctx, by, id, in.r.PathValue("project"), q)
	}))
	rs.read(wire.PathNodeAppStats, "service.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.AppStats, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.AppStats{}, err
		}
		return inventory.AppStats(ctx, by, id, in.r.PathValue("project"))
	}))
	rs.read(wire.PathNodeAppLogs, "service.logs", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.AppLogs, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.AppLogs{}, err
		}
		q, err := wire.ParseAppLogQuery(in.r.URL.Query())
		if err != nil {
			return wire.AppLogs{}, err
		}
		return inventory.AppLogs(ctx, by, id, in.r.PathValue("project"), q)
	}))
}
