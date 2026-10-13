package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	// keptDeploymentDirectories is how many of a target's newest deployment
	// directories are always kept (ADR-0029).
	keptDeploymentDirectories = 5
	// gcScanLimit bounds how many of a target's deployments one pass reads.
	gcScanLimit = 1000

	eventDeploymentGCFailed = "deployment.gc_failed"
)

// collectDeploymentDirectories removes the node directories of old, unneeded
// deployments once this one reached a terminal success. It never fails the
// deployment: a failure only leaves a deployment.gc_failed event.
func (h deployHandler) collectDeploymentDirectories(ctx context.Context, j *deployJob) {
	failed, err := h.collect(ctx, j)
	if err == nil && len(failed) == 0 {
		return
	}
	_ = h.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		return h.emit(ctx, tx, systemActor, eventDeploymentGCFailed, deploymentResource(j.dep.ID), domain.ResultFailed,
			map[string]any{"failed_directories": failed, "read_failed": err != nil})
	})
}

func (h deployHandler) collect(ctx context.Context, j *deployJob) (failed []domain.ID, err error) {
	q := h.cfg.DB.Reader()
	current, err := database.GetDeployment(ctx, q, j.dep.ID)
	if err != nil {
		return nil, err
	}
	if current.State != deployments.StateSucceeded && current.State != deployments.StateRolledBack {
		return nil, nil
	}
	rows, err := database.ListDeployments(ctx, q, database.DeploymentFilter{AppTargetID: j.dep.AppTargetID}, gcScanLimit)
	if err != nil {
		return nil, err
	}
	for _, id := range collectableDeployments(rows, j.dep.ID, j.plan.Content.RollbackTarget) {
		dir := deployDir{Root: j.root, Project: j.target.ComposeProject, Deployment: id}
		if removeDeploymentDirectory(ctx, j.ex, dir) != nil {
			failed = append(failed, id)
		}
	}
	return failed, nil
}

// collectableDeployments picks, from a target's deployments newest first, the
// ones whose directory may go: beyond the newest keptDeploymentDirectories,
// ended as failed or rolled_back, not known-good, and neither the current
// deployment nor its frozen rollback target. A failed deployment that
// started changing services is spared: its directory may still serve them.
func collectableDeployments(newestFirst []database.Deployment, current domain.ID, rollbackTarget *plan.RollbackTarget) []domain.ID {
	var ids []domain.ID
	for _, d := range newestFirst[min(keptDeploymentDirectories, len(newestFirst)):] {
		switch {
		case d.ID == current, d.KnownGood, rollbackTarget != nil && d.ID.String() == rollbackTarget.DeploymentID:
		case d.State == deployments.StateRolledBack, d.State == deployments.StateFailed && !d.MutationStarted:
			ids = append(ids, d.ID)
		}
	}
	return ids
}

func removeDeploymentDirectory(ctx context.Context, node transport.Executor, dir deployDir) error {
	cmd, err := templates.RenderMutating("compose.gc", "gc-"+dir.Deployment.String(), dir.args())
	if err != nil {
		return fmt.Errorf("render gc: %w", err)
	}
	res, err := node.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("gc: %w", err)
	}
	if res.ExitStatus != 0 {
		return fmt.Errorf("gc exited %d", res.ExitStatus)
	}
	return nil
}
