package api

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
)

const (
	actionAppRouteExpose   = "app_route.expose"
	actionAppRouteUnexpose = "app_route.unexpose"
)

// appRoutes registers the routes that publish an app target's port through its node's Cloudflare Tunnel
// (ADR-0040). Exposing and unexposing are plans that always become a job, which waits for approval when policy
// asks, so both answer 202; reading is app_target.read.
func (rs *routeSet) appRoutes() {
	s := rs.s
	routes := s.svc.Apps.Routes()
	rs.read(wire.PathAppTargetRoutes, "app_target.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.AppRoute], error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Page[wire.AppRoute]{}, err
		}
		rows, err := routes.List(ctx, by, id)
		return appRoutePage(rows), err
	}))
	rs.read(wire.PathAppRoutes, "app_target.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.AppRoute], error) {
		rows, err := routes.List(ctx, by, "")
		return appRoutePage(rows), err
	}))
	rs.write(http.MethodPost, wire.PathAppTargetRoutes, actionAppRouteExpose, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.AppRouteResult, error) {
			id, err := in.id("id")
			if err != nil {
				return app.AppRouteResult{}, err
			}
			req, err := decode[wire.ExposeAppRouteRequest](in)
			if err != nil {
				return app.AppRouteResult{}, err
			}
			return routes.Expose(ctx, by, id, app.ExposeRouteRequest{Hostname: req.Hostname, Service: req.Service, Port: req.Port, Access: req.Access})
		},
		appRouteSubmitted))
	rs.write(http.MethodDelete, wire.PathAppTargetRoute, actionAppRouteUnexpose, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.AppRouteResult, error) {
			id, err := in.id("id")
			if err != nil {
				return app.AppRouteResult{}, err
			}
			return routes.Unexpose(ctx, by, id, in.r.PathValue("hostname"))
		},
		appRouteSubmitted))
}

func appRouteSubmitted(r app.AppRouteResult) (int, any) {
	out := wire.AppRouteSubmission{Submission: app.SubmissionView(r.Submission)}
	if r.Route != nil {
		route := appRouteView(*r.Route)
		out.Route = &route
	}
	return http.StatusAccepted, out
}

func appRoutePage(rows []database.AppRoute) wire.Page[wire.AppRoute] {
	items := make([]wire.AppRoute, len(rows))
	for i, r := range rows {
		items[i] = appRouteView(r)
	}
	return wire.Page[wire.AppRoute]{Items: items}
}

func appRouteView(r database.AppRoute) wire.AppRoute {
	return wire.AppRoute{
		ID: r.ID, AppTargetID: r.AppTargetID, Hostname: r.Hostname, Service: r.Service, Port: r.Port,
		Access: r.Access, Phase: string(r.Phase), LastError: r.LastError, CreatedAt: r.CreatedAt,
	}
}
