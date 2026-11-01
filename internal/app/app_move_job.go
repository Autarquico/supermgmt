package app

import (
	"context"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// appMoveHandler runs app_target.move, app_target.cleanup_source and app_target.abandon_move (ADR-0041). The run
// is not implemented yet: the job types are registered so that a claim finds a handler, and fail with a typed
// error until the run replaces Run.
type appMoveHandler struct {
	core
}

func (appMoveHandler) Run(context.Context, jobs.Lease) error {
	return smerr.New(smerr.CodeInternal, "", "app moves are not implemented yet")
}
