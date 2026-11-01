package app

import (
	"context"
	"fmt"
	"sort"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const eventAppMoveSourceCleaned = "app_move.source_cleaned"

// loadPlanned loads what a cleanup or an abandon works on: the move its plan names, which belongs to the job's
// target. The target lock the job holds serialises it against every other job of the target.
func (h appMoveHandler) loadPlanned(ctx context.Context, lease jobs.Lease, job jobs.Job) (*moveRun, error) {
	q := h.cfg.DB.Reader()
	if job.PlanID == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "move job has no plan")
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	if err != nil {
		return nil, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return nil, err
	}
	move, err := movePlanned(ctx, q, job.Resource.ID, *stored)
	if err != nil {
		return nil, err
	}
	target, err := database.GetAppTarget(ctx, q, move.AppTargetID)
	if err != nil {
		return nil, err
	}
	return &moveRun{h: h, lease: lease, job: job, move: move, target: target}, nil
}

// cleanup removes the containers a done move left parked on its source node (spec §11), never its volumes. It
// refuses a target that runs on that node again, another target that uses the project there, and any project
// container that does not belong to the deployment the plan froze.
func (h appMoveHandler) cleanup(ctx context.Context, lease jobs.Lease, job jobs.Job) error {
	r, err := h.loadPlanned(ctx, lease, job)
	if err != nil {
		return err
	}
	q := h.cfg.DB.Reader()
	if r.move.Phase != database.AppMoveDone {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the move is in phase %s: only a done move leaves a source to clean", r.move.Phase))
	}
	target, err := database.GetAppTarget(ctx, q, r.target.ID)
	if err != nil {
		return err
	}
	if err := requireCleanable(ctx, q, target, r.move); err != nil {
		return err
	}
	if r.a, err = h.dial(ctx, q, r.move.SourceNodeID); err != nil {
		return err
	}
	containers, err := r.containers(ctx, r.a)
	if err != nil {
		return err
	}
	parked := r.move.KnownGoodDeploymentID
	for _, c := range containers {
		if c.Labels[compose.LabelOwner] != target.ID.String() || c.Labels[compose.LabelDeployment] != parked.String() {
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
				"container %s on node %s does not belong to the parked deployment %s: it is not removed", c.Name, r.a.node.Name, parked))
		}
	}
	if len(containers) > 0 {
		dir := deployDir{Root: r.a.root, Project: target.ComposeProject, Deployment: parked}
		if err := r.mustSend(ctx, r.a, parked, "cleanup-source", "compose.down", dir.args(), true); err != nil {
			return err
		}
		if err := r.requireGone(ctx, r.a); err != nil {
			return err
		}
	}
	kept, err := r.sourceVolumes(ctx)
	if err != nil {
		return err
	}
	return r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		return r.emitMove(ctx, tx, eventAppMoveSourceCleaned, domain.ResultSucceeded, map[string]any{"kept_volumes": kept})
	})
}

func (r *moveRun) requireGone(ctx context.Context, n moveNode) error {
	containers, err := r.containers(ctx, n)
	if err != nil {
		return err
	}
	if len(containers) > 0 {
		return smerr.New(smerr.CodeDeploymentFailed, "", fmt.Sprintf("node %s still has %d container(s) of the project after compose down", n.node.Name, len(containers)))
	}
	return nil
}

// sourceVolumes are the volumes of the move's map that A still holds, which cleanup keeps and lists.
func (r *moveRun) sourceVolumes(ctx context.Context) ([]string, error) {
	names, err := r.volumeNames(ctx)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	found, err := r.existingVolumes(ctx, r.a, names)
	if err != nil {
		return nil, err
	}
	kept := make([]string, 0, len(found))
	for name := range found {
		kept = append(kept, name)
	}
	sort.Strings(kept)
	return kept, nil
}
