package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	actionNodeRouteExpose   = "node_route.expose"
	actionNodeRouteUnexpose = "node_route.unexpose"
)

// nodeRoutes registers the routes that publish a node's port through its Cloudflare Tunnel (ADR-0043).
// Exposing and unexposing are plans that always become a job, which waits for approval when policy asks, so
// both answer 202; reading is node_route.read. Without the node routes service the routes are not served.
func (rs *routeSet) nodeRoutes() {
	s := rs.s
	routes := s.svc.Routes
	if routes == nil {
		return
	}
	rs.read(wire.PathNodeRoutes, "node_route.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.NodeRoute], error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Page[wire.NodeRoute]{}, err
		}
		removed, err := includeRemoved(in)
		if err != nil {
			return wire.Page[wire.NodeRoute]{}, err
		}
		rows, err := routes.List(ctx, by, id, removed)
		return nodeRoutePage(rows), err
	}))
	rs.read(wire.PathNodeRoutesAll, "node_route.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.NodeRoute], error) {
		removed, err := includeRemoved(in)
		if err != nil {
			return wire.Page[wire.NodeRoute]{}, err
		}
		rows, err := routes.List(ctx, by, "", removed)
		return nodeRoutePage(rows), err
	}))
	rs.write(http.MethodPost, wire.PathNodeRoutes, actionNodeRouteExpose, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.NodeRouteResult, error) {
			id, err := in.id("id")
			if err != nil {
				return app.NodeRouteResult{}, err
			}
			req, err := decode[wire.ExposeNodeRouteRequest](in)
			if err != nil {
				return app.NodeRouteResult{}, err
			}
			return routes.Expose(ctx, by, id, app.ExposeRouteRequest{Hostname: req.Hostname, Port: req.Port, Access: req.Access})
		},
		nodeRouteSubmitted))
	rs.write(http.MethodDelete, wire.PathNodeRoute, actionNodeRouteUnexpose, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.NodeRouteResult, error) {
			id, err := in.id("id")
			if err != nil {
				return app.NodeRouteResult{}, err
			}
			return routes.Unexpose(ctx, by, id, in.r.PathValue("hostname"))
		},
		nodeRouteSubmitted))
}

func includeRemoved(in input) (bool, error) {
	value := in.r.URL.Query().Get(wire.QueryIncludeRemoved)
	if value == "" {
		return false, nil
	}
	removed, err := strconv.ParseBool(value)
	if err != nil {
		return false, smerr.New(smerr.CodeInvalidArgument, "", wire.QueryIncludeRemoved+" must be true or false")
	}
	return removed, nil
}

func nodeRouteSubmitted(r app.NodeRouteResult) (int, any) {
	out := wire.NodeRouteSubmission{Submission: app.SubmissionView(r.Submission)}
	if r.Route != nil {
		route := nodeRouteView(*r.Route)
		out.Route = &route
	}
	return http.StatusAccepted, out
}

func nodeRoutePage(rows []database.NodeRoute) wire.Page[wire.NodeRoute] {
	items := make([]wire.NodeRoute, len(rows))
	for i, r := range rows {
		items[i] = nodeRouteView(r)
	}
	return wire.Page[wire.NodeRoute]{Items: items}
}

func nodeRouteView(r database.NodeRoute) wire.NodeRoute {
	return wire.NodeRoute{
		ID: r.ID, NodeID: r.NodeID, Hostname: r.Hostname, Port: r.Port,
		Access: r.Access, Phase: string(r.Phase), LastError: r.LastError, CreatedAt: r.CreatedAt,
	}
}
