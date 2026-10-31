package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
)

// activateRoutes runs in the transaction that settles a deployment as succeeded. It moves the target's
// waiting routes whose port the new version publishes to provisioning and gives each an expose job submitted
// by the system identity (ADR-0040). An expose job still open for the route (the request that admitted it
// queued one behind this deployment) is the job that will do the work, so no second one is submitted.
func (h deployHandler) activateRoutes(ctx context.Context, tx *database.Tx, targetID domain.ID, ports []compose.HostPort) error {
	waiting, err := database.ListWaitingAppRoutes(ctx, tx, targetID)
	if err != nil {
		return err
	}
	for _, route := range waiting {
		if !routeServed(ports, route.Service, route.Port) {
			continue
		}
		open, err := hasOpenExposeJob(ctx, tx, route)
		if err != nil {
			return err
		}
		if _, err := database.AdvanceAppRoutePhase(ctx, tx, route.ID, database.AppRouteWaiting, database.AppRouteProvisioning, database.AppRouteObjects{}, h.cfg.Clock.Now()); err != nil {
			return err
		}
		if !open {
			if err := h.submitExpose(ctx, tx, route); err != nil {
				return err
			}
		}
	}
	return nil
}

// submitExpose plans and enqueues the expose job of route as the system identity. The plan is the one a
// request for the same route would make, so the claim revalidates it like any other.
func (h deployHandler) submitExpose(ctx context.Context, tx *database.Tx, route database.AppRoute) error {
	by := Caller{ID: h.systemID, Credential: systemCredential, Source: scheduledSource}
	actor, err := loadActor(ctx, tx, h.systemID, systemCredential)
	if err != nil {
		return err
	}
	params, err := toParams(appRouteParams{
		Hostname: route.Hostname, Service: route.Service, Port: fmt.Sprint(route.Port), Access: route.Access,
	})
	if err != nil {
		return err
	}
	b, err := build(ctx, tx, appRouteExposeAction, h.systemID, appTargetRef(route.AppTargetID), params)
	if err != nil {
		return err
	}
	res, err := h.evaluate(ctx, tx, actor, b)
	if err != nil {
		return err
	}
	plans := Plans{core: h.core, jobs: h.store}
	_, err = plans.planAndSubmit(ctx, tx, by, actor, b, res)
	return err
}

// hasOpenExposeJob reports whether an expose job of the route's hostname on its target is waiting for
// approval, queued, running or interrupted.
func hasOpenExposeJob(ctx context.Context, q database.Querier, route database.AppRoute) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM jobs
		WHERE type = ? AND resource_type = ? AND resource_id = ?
		  AND json_extract(payload_json, '$.hostname') = ? AND json_extract(payload_json, '$.service') IS NOT NULL
		  AND state IN (?, ?, ?, ?)`,
		JobControlPlaneApply, domain.ResourceAppTarget, route.AppTargetID, route.Hostname,
		domain.JobAwaitingApproval, domain.JobQueued, domain.JobRunning, domain.JobInterrupted).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count the open jobs of route %s: %w", route.Hostname, err)
	}
	return n > 0, nil
}
