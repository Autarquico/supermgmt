package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
)

// The port guard (ADR-0040): a deployment or rollback whose model stops publishing the service and port of a
// route that is not removed would leave the route pointing at nothing, so it is refused. It runs at
// finalization, at the request of a rollback, and again under the target's lock before a run touches the node.

// requireRoutesServed refuses ports, the host ports of the model named by what, when the target has a route
// they no longer serve.
func requireRoutesServed(ctx context.Context, q database.Querier, targetID domain.ID, ports []compose.HostPort, what string) error {
	routes, err := database.ListAppRoutes(ctx, q, database.AppRouteFilter{TargetID: targetID})
	if err != nil {
		return err
	}
	for _, r := range routes {
		if !routeServed(ports, r.Service, r.Port) {
			return invalidArgument(
				"%s would stop publishing service %q on port %d over TCP at 127.0.0.1 or 0.0.0.0, which the route %s serves; remove the route first with `sm apps unexpose`",
				what, r.Service, r.Port, r.Hostname)
		}
	}
	return nil
}

// requireRollbackTargetServes is requireRoutesServed for the model of the known-good deployment an automatic
// rollback would restore.
func requireRollbackTargetServes(ctx context.Context, q database.Querier, targetID domain.ID, target *plan.RollbackTarget) error {
	if target == nil {
		return nil
	}
	good, err := database.GetDeployment(ctx, q, domain.ID(target.DeploymentID))
	if err != nil {
		return err
	}
	ports, err := deploymentHostPorts(ctx, q, good)
	if err != nil {
		return err
	}
	return requireRoutesServed(ctx, q, targetID, ports, fmt.Sprintf("the automatic rollback to deployment %s", good.ID))
}

// requireContentServesRoutes holds the model a plan froze, and the one of its automatic rollback, to the
// target's routes.
func requireContentServesRoutes(ctx context.Context, q database.Querier, targetID domain.ID, c plan.Content) error {
	ports, err := frozenHostPorts(ctx, q, c.ComposeHash)
	if err != nil {
		return err
	}
	if err := requireRoutesServed(ctx, q, targetID, ports, "the deployment"); err != nil {
		return err
	}
	return requireRollbackTargetServes(ctx, q, targetID, c.RollbackTarget)
}
