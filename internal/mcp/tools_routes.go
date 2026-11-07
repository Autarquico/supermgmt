package mcp

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The node route tools (ADR-0043). Exposing is a plan the API always turns into a job: a public route is high
// risk and an mcp identity's writes of operational risk or more wait for approval.

const (
	routeAccessPublic = "public"
	routeAccessOwners = "owners"
)

type listRoutesInput struct {
	Node           string `json:"node,omitempty" jsonschema:"only routes of this node (id or exact name)"`
	IncludeRemoved bool   `json:"include_removed,omitempty" jsonschema:"also list removed routes, with the note that says why"`
}

type exposePortInput struct {
	Node     string `json:"node" jsonschema:"node id or exact node name"`
	Hostname string `json:"hostname" jsonschema:"hostname under the configured Cloudflare zone"`
	Port     int    `json:"port" jsonschema:"port of the node to publish"`
	Access   string `json:"access,omitempty" jsonschema:"public (reachable from the internet with no authentication, high risk) or owners (behind Cloudflare Access); default public"`
}

type unexposePortInput struct {
	Node     string `json:"node" jsonschema:"node id or exact node name"`
	Hostname string `json:"hostname" jsonschema:"hostname of the route to remove"`
}

func listRoutes(ctx context.Context, api API, in listRoutesInput) (listResult[RouteView], error) {
	var node domain.ID
	if in.Node != "" {
		id, err := resolveNode(ctx, api, in.Node)
		if err != nil {
			return listResult[RouteView]{}, err
		}
		node = id
	}
	page, err := api.ListAllNodeRoutes(ctx, in.IncludeRemoved)
	if err != nil {
		return listResult[RouteView]{}, err
	}
	items := []RouteView{}
	for _, r := range page.Items {
		if node == "" || r.NodeID == node {
			items = append(items, ViewRoute(r))
		}
	}
	return listResult[RouteView]{Items: items}, nil
}

func exposePort(ctx context.Context, api API, in exposePortInput) (WriteResult, error) {
	access := in.Access
	if access == "" {
		access = routeAccessPublic
	}
	if access != routeAccessPublic && access != routeAccessOwners {
		return WriteResult{}, invalidArgument("access must be public or owners")
	}
	node, err := resolveNode(ctx, api, in.Node)
	if err != nil {
		return WriteResult{}, err
	}
	res, err := api.ExposeNodeRoute(ctx, node, wire.ExposeNodeRouteRequest{Hostname: in.Hostname, Port: in.Port, Access: access})
	return routeResult(res, fmt.Sprintf("expose %s of %s", access, operatorLine(in.Hostname)), node), err
}

func unexposePort(ctx context.Context, api API, in unexposePortInput) (WriteResult, error) {
	node, err := resolveNode(ctx, api, in.Node)
	if err != nil {
		return WriteResult{}, err
	}
	res, err := api.UnexposeNodeRoute(ctx, node, in.Hostname)
	return routeResult(res, "unexpose "+operatorLine(in.Hostname), node), err
}

// routeResult is built from control-plane fields and the caller's own input only.
func routeResult(res wire.NodeRouteSubmission, what string, node domain.ID) WriteResult {
	out := submissionResult(res.Submission)
	out.Summary = fmt.Sprintf("%s on node %s: job %s", what, node, res.Submission.Job.State)
	return out
}
