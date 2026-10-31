package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// applyApprovedAppRoute is the seam of the approved apply of app_route.expose and app_route.unexpose
// (control_plane.apply, apply.go). The service in app_routes.go replaces this stub by defining the method
// there, and deletes this file: on expose it writes the route row and enqueues its job (newAppRouteJob) in
// the apply transaction, as the request path does when policy needs no approval; on unexpose it enqueues the
// removal job.
func (a *Apps) applyApprovedAppRoute(_ context.Context, _ database.Querier, _ domain.Actor, action string, _ jobs.Job) error {
	return smerr.New(smerr.CodeInternal, "", "control_plane.apply: "+action+" is not available yet")
}
