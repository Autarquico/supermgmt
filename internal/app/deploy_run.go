package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/deployments"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// deployRun starts the verified project on the node (spec §20.4).
type deployRun struct {
	exec transport.Executor
}

// Up is the forward deploy step: `compose up` on the materialized directory,
// under the node-side project flock. It refuses under safety_recovery.
func (r deployRun) Up(ctx context.Context, mode deployments.RecoveryMode, dir deployDir, marker string) error {
	if err := refuseForwardStep(deployments.StepDeploy, mode); err != nil {
		return err
	}
	return r.runUp(ctx, dir, marker)
}

// runUp is Up without the mode refusal, shared with the restore-deploy step.
func (r deployRun) runUp(ctx context.Context, dir deployDir, marker string) error {
	cmd, err := templates.RenderMutatingInput("compose.up", marker, dir.args(), nil, dir.Project)
	if err != nil {
		return fmt.Errorf("render compose up: %w", err)
	}
	res, err := r.exec.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("compose up: %w", err)
	}
	switch res.ExitStatus {
	case 0:
		return nil
	case templates.LockConflictExit:
		return smerr.New(smerr.CodeConflict, smerr.ReasonResourceLocked, "another compose command holds the project lock")
	}
	return smerr.New(smerr.CodeDeploymentFailed, "", fmt.Sprintf("compose up exited %d", res.ExitStatus))
}
