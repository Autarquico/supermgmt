package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Compensation (ADR-0041, spec §7) undoes a move that failed before its commit, one persisted phase at a time:
//
//	compensating_b_stopped         B's containers are stopped, never removed
//	compensating_source_started    A runs again (started only if it was stopped)
//	compensating_source_verified   A passed its node-scope health checks
//	compensating_b_removed         B's containers and the volumes this move created are gone (B never started only)
//	rolled_back
//
// Every step reads the node first, so a run resumed at any phase repeats nothing that already took effect.

const (
	eventAppMoveRolledBack = "app_move.rolled_back"

	causeMoveDestStillActive = "DEST_STILL_ACTIVE"

	stepCompensateStopDest    = "compensate-stop-dest"
	stepCompensateHoldDest    = "compensate-hold-dest-"
	stepCompensateRestoreA    = "compensate-restore-restart-"
	stepCompensateStartSource = "compensate-start-source"
	stepCompensateDownDest    = "compensate-down-dest"
	// stepCompensateRmPrefix is followed by the name of the volume, which is how the reconciler knows what to look for.
	stepCompensateRmPrefix = "compensate-rm-"
)

// compensate rolls the move back. cause is the failure that ended the forward path, or errCompensationResumed when
// a later run takes up a compensation already begun. It returns cause (the job still failed) once the move is rolled
// back, and halts the move in its compensation phase when a step cannot be completed.
func (h appMoveHandler) compensate(ctx context.Context, r *moveRun, cause error) error {
	resumed := errors.Is(cause, errCompensationResumed)
	if err := r.compensation(ctx, cause); err != nil {
		if r.ends(ctx, err) && !r.move.Phase.Halted() {
			if herr := r.halt(ctx, err); herr != nil {
				err = errors.Join(err, herr)
			}
		}
		if resumed {
			return err
		}
		return errors.Join(cause, err)
	}
	if resumed {
		return smerr.New(smerr.CodeDeploymentFailed, "", "the move was rolled back")
	}
	return cause
}

func (r *moveRun) compensation(ctx context.Context, cause error) error {
	if pastCommit(r.move) {
		return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("a move in phase %s cannot be compensated", r.move.Phase))
	}
	if r.untouched() {
		return r.rollBack(ctx, cause)
	}
	for r.move.Phase != database.AppMoveRolledBack {
		var err error
		switch r.move.Phase {
		case database.AppMoveCompensatingBStopped:
			err = r.restoreSource(ctx)
		case database.AppMoveCompensatingSourceStarted:
			err = r.verifySource(ctx)
		case database.AppMoveCompensatingSourceVerified:
			err = r.removeDest(ctx, cause)
		case database.AppMoveCompensatingBRemoved:
			err = r.rollBack(ctx, cause)
		case database.AppMovePreflight, database.AppMoveStaged, database.AppMoveSourceStop, database.AppMoveDataCopied,
			database.AppMoveStarted, database.AppMoveVerified:
			err = r.stopDest(ctx)
		case database.AppMoveCommitted, database.AppMoveSourceParked, database.AppMoveDone, database.AppMoveRolledBack,
			database.AppMoveFailed, database.AppMoveConflict:
			err = smerr.New(smerr.CodeInternal, "", fmt.Sprintf("a move in phase %s cannot be compensated", r.move.Phase))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// untouched reports a move that ended before it changed anything on any node: still at preflight with no
// deployment on B. It settles without a node command.
func (r *moveRun) untouched() bool {
	return r.move.Phase == database.AppMovePreflight && r.move.DestDeploymentID == nil
}

// stopDest stops whatever of B runs. Containers that were only created have nothing to stop.
func (r *moveRun) stopDest(ctx context.Context) error {
	if r.move.DestDeploymentID != nil {
		containers, err := r.containers(ctx, r.b)
		if err != nil {
			return err
		}
		if slices.ContainsFunc(containers, running) || r.move.BStartedAt != nil {
			for _, c := range containers {
				if err := r.setRestart(ctx, r.b, r.bDep.ID, stepCompensateHoldDest+c.Name, c, restartHeld); err != nil {
					return err
				}
			}
		}
		if slices.ContainsFunc(containers, running) {
			err := r.mustSend(ctx, r.b, r.bDep.ID, stepCompensateStopDest, "compose.stop", r.destJob().dir().args(), true)
			if err != nil {
				return err
			}
			if err := r.requireStopped(ctx, r.b); err != nil {
				return err
			}
		}
	}
	return r.advance(ctx, database.AppMoveCompensatingBStopped, "")
}

func running(c templates.ContainerState) bool {
	return c.State == "running" || c.State == "restarting" || c.State == "paused"
}

func (r *moveRun) requireStopped(ctx context.Context, n moveNode) error {
	containers, err := r.containers(ctx, n)
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(containers, running); i >= 0 {
		return preflightFailed(causeMoveDestStillActive, "container %s on node %s is %s after it was stopped",
			containers[i].Name, n.node.Name, containers[i].State)
	}
	return nil
}

// restoreSource starts A when any of its containers is not running. A source that was never stopped is left alone.
func (r *moveRun) restoreSource(ctx context.Context) error {
	containers, err := r.containers(ctx, r.a)
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return preflightFailed(causeMoveSourceNotRunning, "node %s runs no container of the project", r.a.node.Name)
	}
	if err := r.restoreRestartPolicies(ctx, containers); err != nil {
		return err
	}
	if slices.ContainsFunc(containers, func(c templates.ContainerState) bool { return c.State != "running" }) {
		err := r.mustSend(ctx, r.a, r.good.deployment.ID, stepCompensateStartSource, "compose.start", r.sourceDir().args(), true)
		if err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppMoveCompensatingSourceStarted, "")
}

// restoreRestartPolicies gives A's containers back the restart policy of the frozen model, but only those the move
// held at "no" while A was stopped (a stateful move holds them before it stops A, and a move that failed earlier
// held nothing). A is the authority again, so it comes back with its daemon as it always did.
func (r *moveRun) restoreRestartPolicies(ctx context.Context, containers []templates.ContainerState) error {
	held, err := database.AppMoveRestartSteps(ctx, r.h.cfg.DB.Reader(), r.move.ID)
	if err != nil {
		return err
	}
	fz, err := r.freeze(ctx)
	if err != nil {
		return err
	}
	policies, err := restartPolicies(fz.frozen.Effective)
	if err != nil {
		return smerr.New(smerr.CodeInternal, "", err.Error())
	}
	for _, c := range containers {
		if policy, known := policies[c.Service]; known && held[stepHoldSource+"-"+c.Name] {
			if err := r.setRestart(ctx, r.a, r.good.deployment.ID, stepCompensateRestoreA+c.Name, c, policy); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifySource runs the node-scope health checks of the known-good deployment against A.
func (r *moveRun) verifySource(ctx context.Context) error {
	fz, err := r.freeze(ctx)
	if err != nil {
		return err
	}
	verdict, err := r.h.dep.healthVerifier(r.a.ex).verify(ctx, fz.healthRun(r.destJob().container()))
	if err != nil {
		return err
	}
	if !verdict.Healthy {
		return smerr.FromReason(smerr.ReasonHealthFailed, "the source did not come back healthy: "+verdict.Failure)
	}
	return r.advance(ctx, database.AppMoveCompensatingSourceVerified, "")
}

// removeDest removes what the move created on B, but only while B was never started: from the first start on, B may
// hold writes that A lacks, and its volumes are kept. An import that may still be running keeps B untouched until
// its deadline has passed.
func (r *moveRun) removeDest(ctx context.Context, cause error) error {
	if r.move.BStartedAt != nil || r.move.DestDeploymentID == nil {
		return r.rollBack(ctx, cause)
	}
	volumes, err := database.ListAppMoveVolumes(ctx, r.h.cfg.DB.Reader(), r.move.ID)
	if err != nil {
		return err
	}
	for _, v := range volumes {
		if v.State == database.AppMoveVolumeImporting {
			if err := r.awaitImportEnd(ctx, v); err != nil {
				return err
			}
		}
	}
	containers, err := r.containers(ctx, r.b)
	if err != nil {
		return err
	}
	if len(containers) > 0 {
		if err := r.mustSend(ctx, r.b, r.bDep.ID, stepCompensateDownDest, "compose.down", r.destJob().dir().args(), true); err != nil {
			return err
		}
	}
	if err := r.removeCreatedVolumes(ctx, volumes); err != nil {
		return err
	}
	return r.advance(ctx, database.AppMoveCompensatingBRemoved, "")
}

// removeCreatedVolumes removes from B the volumes whose row says this move created them. A volume without that
// evidence is never touched.
func (r *moveRun) removeCreatedVolumes(ctx context.Context, volumes []database.AppMoveVolume) error {
	var names []string
	for _, v := range volumes {
		if v.CreatedByMove {
			names = append(names, v.VolumeName)
		}
	}
	if len(names) == 0 {
		return nil
	}
	found, err := r.existingVolumes(ctx, r.b, names)
	if err != nil {
		return err
	}
	for _, name := range names {
		existing, exists := found[name]
		if !exists {
			continue
		}
		if err := r.requireOwnedVolume(existing); err != nil {
			return err
		}
		if err := r.mustSend(ctx, r.b, r.bDep.ID, stepCompensateRmPrefix+name, "docker.volume_rm", map[string]string{"volume": name}, false); err != nil {
			return err
		}
	}
	return nil
}

// rollBack ends the move as rolled_back. The volumes left on B are those of a B that was started.
func (r *moveRun) rollBack(ctx context.Context, cause error) error {
	var kept []string
	if r.move.BStartedAt != nil {
		var err error
		if kept, err = r.createdVolumes(ctx, r.h.cfg.DB.Reader()); err != nil {
			return err
		}
	}
	return r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		return r.rolledBack(ctx, tx, map[string]any{"cause": recordedError(cause), "kept_volumes": kept})
	})
}

// createdVolumes names the volumes the move created on B.
func (r *moveRun) createdVolumes(ctx context.Context, q database.Querier) ([]string, error) {
	volumes, err := database.ListAppMoveVolumes(ctx, q, r.move.ID)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, v := range volumes {
		if v.CreatedByMove {
			names = append(names, v.VolumeName)
		}
	}
	return names, nil
}

// rolledBack, inside a fenced transaction, marks B's deployment failed, moves the move from its running phase to
// rolled_back and audits it.
func (r *moveRun) rolledBack(ctx context.Context, tx *database.Tx, data map[string]any) (database.AppMove, error) {
	if err := r.failDestDeployment(ctx, tx); err != nil {
		return database.AppMove{}, err
	}
	rolled, err := database.AdvanceAppMovePhase(ctx, tx, r.move.ID, r.move.Phase, database.AppMoveRolledBack, r.h.cfg.Clock.Now())
	if err != nil {
		return database.AppMove{}, err
	}
	data["phase"] = string(rolled.Phase)
	return rolled, r.emitMove(ctx, tx, eventAppMoveRolledBack, domain.ResultFailed, data)
}

// failDestDeployment settles B's deployment as failed, unless it already ended.
func (r *moveRun) failDestDeployment(ctx context.Context, tx *database.Tx) error {
	if r.move.DestDeploymentID == nil {
		return nil
	}
	dep, err := database.GetDeployment(ctx, tx, *r.move.DestDeploymentID)
	if err != nil || dep.State.Terminal() {
		return err
	}
	failure := database.StateFailure{Code: string(smerr.CodeDeploymentFailed)}
	return r.h.dep.moveTo(ctx, tx, dep.ID, deployments.StateFailed, failure)
}

// unrestoredContainers are the containers of A that the move held at restart "no" and did not give back, by name: an
// abandoned move leaves them so, and the operator has to restore their policy.
func unrestoredContainers(steps map[string]bool) []string {
	var out []string
	for step := range steps {
		if name, ok := strings.CutPrefix(step, stepHoldSource+"-"); ok && !steps[stepCompensateRestoreA+name] {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// ---- abandon (spec §12) --------------------------------------------------------------------------------------------

// abandon records the operator's decision to leave a move that halted in compensation as it is: no node is touched,
// so A's containers still held at restart "no" are listed in the event.
// The target lock serialises it against a resumed move, so the move is read again under the fence and refused unless
// it still is halted in compensation.
func (h appMoveHandler) abandon(ctx context.Context, lease jobs.Lease, job jobs.Job) error {
	r, err := h.loadPlanned(ctx, lease, job)
	if err != nil {
		return err
	}
	return r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		current, err := database.GetAppMove(ctx, tx, r.move.ID)
		if err != nil {
			return err
		}
		if !current.Phase.Halted() || !strings.HasPrefix(string(current.HaltedPhase), "compensating_") {
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
				"the move is in phase %s: only a move halted in compensation can be abandoned", current.Phase))
		}
		resumed, err := database.ResumeHaltedAppMove(ctx, tx, current.ID, current.Phase, h.cfg.Clock.Now())
		if err != nil {
			return err
		}
		r.move = resumed
		kept, err := r.createdVolumes(ctx, tx)
		if err != nil {
			return err
		}
		held, err := database.AppMoveRestartSteps(ctx, tx, current.ID)
		if err != nil {
			return err
		}
		_, err = r.rolledBack(ctx, tx, map[string]any{
			"abandoned": true, "halted_phase": string(current.HaltedPhase), "kept_volumes": kept, "restart_held": unrestoredContainers(held),
		})
		return err
	})
}
