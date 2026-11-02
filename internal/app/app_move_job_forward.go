package app

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The forward path of a move (ADR-0041, spec §3 to §10). Each phase of the move row names the work done: the run
// resumes at the recorded phase and does the work of the next. Everything that changes a node goes through the
// intent dispatcher, under the job's lease.

// stepCreate is the step row of compose create on B; the other staging steps keep the deployment step names.
const stepCreate = "create"

func (r *moveRun) forward(ctx context.Context) error {
	for r.move.Phase != database.AppMoveDone {
		var err error
		switch r.move.Phase {
		case database.AppMovePreflight:
			err = r.stage(ctx)
		case database.AppMoveStaged:
			if r.move.Stateful {
				err = r.stopSource(ctx)
			} else {
				err = r.startDest(ctx)
			}
		case database.AppMoveSourceStop:
			err = r.copyData(ctx)
		case database.AppMoveDataCopied:
			err = r.startDest(ctx)
		case database.AppMoveStarted:
			err = r.verifyDest(ctx)
		case database.AppMoveVerified:
			err = r.afterVerified(ctx)
		case database.AppMoveRoutesDestIncluded:
			err = r.switchRoutes(ctx)
		case database.AppMoveRoutesSwitched:
			err = r.commit(ctx)
		case database.AppMoveCommitted:
			if r.routed {
				err = r.cleanSource(ctx)
			} else {
				err = r.parkSource(ctx)
			}
		case database.AppMoveRoutesSourceCleaned:
			err = r.parkSource(ctx)
		case database.AppMoveSourceParked:
			err = r.finish(ctx)
		case database.AppMoveDone, database.AppMoveRolledBack, database.AppMoveFailed, database.AppMoveConflict,
			database.AppMoveCompensatingRoutesRestored, database.AppMoveCompensatingRoutesWithdrawn,
			database.AppMoveCompensatingBStopped, database.AppMoveCompensatingSourceStarted,
			database.AppMoveCompensatingSourceVerified, database.AppMoveCompensatingBRemoved:
			err = smerr.New(smerr.CodeInternal, "", fmt.Sprintf("the forward path has no work for phase %s", r.move.Phase))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// afterVerified is the step out of verified: the commit for an unrouted move, the routes for a routed one.
func (r *moveRun) afterVerified(ctx context.Context) error {
	if !r.routed {
		return r.commit(ctx)
	}
	return r.publishRoutes(ctx)
}

// ---- stage (spec §4) ---------------------------------------------------------------------------------------------

// stage re-checks, proves B fit by reading both nodes, gives B a deployment of kind move and prepares it: pull,
// materialize, verify and create. Nothing is started and A keeps serving.
func (r *moveRun) stage(ctx context.Context) error {
	if err := r.recheck(ctx); err != nil {
		return err
	}
	fz, err := r.freeze(ctx)
	if err != nil {
		return err
	}
	if err := r.preflight(ctx, fz); err != nil {
		return err
	}
	if err := r.ensureDestDeployment(ctx); err != nil {
		return err
	}
	j := r.destJob()
	for _, state := range []deployments.State{deployments.StatePreparing, deployments.StateStaging} {
		if err := r.h.dep.enter(ctx, j, state); err != nil {
			return err
		}
	}
	steps := []struct {
		name string
		run  func() error
	}{
		{deployments.StepPull, func() error { return r.h.dep.pull(ctx, j, fz, deployments.Step{Name: deployments.StepPull}) }},
		{deployments.StepMaterialize, func() error {
			return r.h.dep.materialize(ctx, j, fz, deployments.Step{Name: deployments.StepMaterialize})
		}},
		{deployments.StepVerifyOnNode, func() error { return j.stage().Verify(ctx, j.mode, j.dir(), fz.frozen, fz.secrets) }},
		{stepCreate, func() error { return r.createDest(ctx) }},
	}
	for i, s := range steps {
		if err := r.step(ctx, j, i+1, s.name, s.run); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppMoveStaged, eventAppMoveStarted)
}

// ensureDestDeployment gives the move its deployment on B, built like a rollback from the known-good one: the same
// plan content, so the same digests, Compose model and secret versions. It is bound to the move's plan and job, and
// to the move, once.
func (r *moveRun) ensureDestDeployment(ctx context.Context) error {
	if r.move.DestDeploymentID != nil {
		return nil
	}
	rec, err := database.GetPlan(ctx, r.h.cfg.DB.Reader(), r.move.PlanID)
	if err != nil {
		return err
	}
	requested, err := requestedFromRefs(r.good.deployment)
	if err != nil {
		return err
	}
	now := r.h.cfg.Clock.Now()
	row := database.Deployment{
		ID: r.h.cfg.IDs.NewID(), Kind: deployments.KindMove, AppID: r.app.ID, AppTargetID: r.target.ID,
		EnvironmentID: r.env.ID, NodeID: r.b.node.ID, ArtifactID: r.good.deployment.ArtifactID, State: deployments.StateCreated,
		RequestedBy: r.move.CreatedBy, PreviousDeploymentID: &r.good.deployment.ID, CommitSha: r.good.deployment.CommitSha,
		RequestedRaw: requested, Credential: credentialOf(r.job), CreatedAt: now, UpdatedAt: now,
	}
	return r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		ctx = audit.WithCorrelationID(ctx, row.ID)
		if err := database.InsertDeployment(ctx, tx, row); err != nil {
			return database.AppMove{}, err
		}
		if err := database.BindDeploymentPlan(ctx, tx, row.ID, rec.ID, r.job.ID, rec.PlanHash, r.good.deployment.ComposeHash, now); err != nil {
			return database.AppMove{}, err
		}
		if err := database.TransitionDeployment(ctx, tx, row.ID, deployments.StateQueued, database.StateFailure{}, now); err != nil {
			return database.AppMove{}, err
		}
		bound, err := database.BindAppMoveDestDeployment(ctx, tx, r.move.ID, row.ID, now)
		if err != nil {
			return database.AppMove{}, err
		}
		r.bDep = row
		return bound, nil
	})
}

// step runs one staging step once: a step an earlier run finished is skipped. Its row records each attempt.
func (r *moveRun) step(ctx context.Context, j *deployJob, ordinal int, name string, run func() error) error {
	rows, err := database.ListDeploymentSteps(ctx, r.h.cfg.DB.Reader(), j.dep.ID)
	if err != nil {
		return err
	}
	attempt := 1
	for _, row := range rows {
		if row.Name != name {
			continue
		}
		if row.State == database.StepSucceeded {
			return nil
		}
		attempt = max(attempt, row.Attempt+1)
	}
	now := r.h.cfg.Clock.Now()
	row := database.DeploymentStep{
		ID: r.h.cfg.IDs.NewID(), DeploymentID: j.dep.ID, Ordinal: ordinal, Name: name, Attempt: attempt,
		State: database.StepRunning, StartedAt: &now,
	}
	if err := r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error { return database.InsertDeploymentStep(ctx, tx, row) }); err != nil {
		return err
	}
	err = run()
	switch {
	case err == nil:
		return r.finishStep(ctx, j, row, database.StepSucceeded, "")
	case ctx.Err() != nil, errors.Is(err, jobs.ErrOutcomeUnknown), errors.Is(err, jobs.ErrLeaseLost):
		return err
	}
	if ferr := r.finishStep(ctx, j, row, database.StepFailed, audit.ScrubString(err.Error())); ferr != nil {
		return ferr
	}
	return err
}

func (r *moveRun) finishStep(ctx context.Context, j *deployJob, row database.DeploymentStep, state database.StepState, detail string) error {
	if err := r.h.dep.finishStep(ctx, j, row, state, "", detail); err != nil {
		return err
	}
	if r.h.checkpoint != nil {
		return r.h.checkpoint()
	}
	return nil
}

// createDest creates B's containers and volumes without starting anything. The volumes of the map are recorded as
// created by this move first: preflight proved they did not exist, and that record is the evidence for removing
// them later.
func (r *moveRun) createDest(ctx context.Context) error {
	err := r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.MarkAppMoveVolumesCreatedByMove(ctx, tx, r.move.ID, r.h.cfg.Clock.Now())
		return err
	})
	if err != nil {
		return err
	}
	return r.mustSend(ctx, r.b, r.bDep.ID, "create", "compose.create", r.destJob().dir().args(), true)
}

// ---- node commands -----------------------------------------------------------------------------------------------

// send renders the mutating template, records its intent against deployment dep and runs it on n.
func (r *moveRun) send(ctx context.Context, n moveNode, dep domain.ID, step, template string, args map[string]string, locked bool) (transport.Result, error) {
	marker := r.h.cfg.IDs.NewID().String()
	var (
		cmd templates.Command
		err error
	)
	if locked {
		cmd, err = templates.RenderMutatingInput(template, marker, args, nil, r.target.ComposeProject)
	} else {
		cmd, err = templates.RenderMutating(template, marker, args)
	}
	if err != nil {
		return transport.Result{}, smerr.New(smerr.CodeInternal, "", template+" cannot be rendered for the node")
	}
	pre, _ := json.Marshal(map[string]string{"move": r.move.ID.String(), "node": n.node.ID.String(), "project": r.target.ComposeProject})
	dispatcher := commandDispatcher{Node: n.ex, Ledger: deployLedger{h: *r.h.dep, lease: r.lease}, Clock: r.h.cfg.Clock}
	return dispatcher.dispatch(ctx, nodeCommand{
		Step: step, Operation: template, Deployment: dep, Marker: marker, PreState: pre, Command: cmd,
	})
}

// mustSend is send for a command that has to exit 0. A busy project lock is for the retry; any other status is the
// command's failure.
func (r *moveRun) mustSend(ctx context.Context, n moveNode, dep domain.ID, step, template string, args map[string]string, locked bool) error {
	res, err := r.send(ctx, n, dep, step, template, args, locked)
	switch {
	case err != nil:
		return err
	case res.ExitStatus == templates.LockConflictExit:
		return fmt.Errorf("another compose command holds the project lock on node %s", n.node.Name)
	case res.ExitStatus != 0:
		return smerr.New(smerr.CodeDeploymentFailed, "", fmt.Sprintf("%s exited %d on node %s", template, res.ExitStatus, n.node.Name))
	}
	return nil
}

// sourceDir is the directory of the known-good deployment on A, where its containers were created from.
func (r *moveRun) sourceDir() deployDir {
	return deployDir{Root: r.a.root, Project: r.target.ComposeProject, Deployment: r.good.deployment.ID}
}

// ---- data (spec §5) ----------------------------------------------------------------------------------------------

const stepHoldSource = "hold-source"

// stopSource stops A, verifies every project container exited, and checks B's space again with fresh sizes.
// Downtime starts here.
func (r *moveRun) stopSource(ctx context.Context) error {
	if err := r.holdRestart(ctx, r.a, r.good.deployment.ID, stepHoldSource); err != nil {
		return err
	}
	if err := r.mustSend(ctx, r.a, r.good.deployment.ID, "stop-source", "compose.stop", r.sourceDir().args(), true); err != nil {
		return err
	}
	if err := r.requireExited(ctx, r.a); err != nil {
		return err
	}
	fz, err := r.freeze(ctx)
	if err != nil {
		return err
	}
	if err := r.requireVolumeSpace(ctx, fz); err != nil {
		return err
	}
	return r.advance(ctx, database.AppMoveSourceStop, "")
}

// ---- start and verify B (spec §6) ----------------------------------------------------------------------------------

// startDest re-checks under the locks, records the first start of B, then starts it.
func (r *moveRun) startDest(ctx context.Context) error {
	if err := r.recheck(ctx); err != nil {
		return err
	}
	if err := r.requireSourceStillStopped(ctx); err != nil {
		return err
	}
	j := r.destJob()
	if err := r.h.dep.enter(ctx, j, deployments.StateDeploying); err != nil {
		return err
	}
	err := r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		return database.SetAppMoveBStartedAt(ctx, tx, r.move.ID, r.h.cfg.Clock.Now())
	})
	if err != nil {
		return err
	}
	if err := r.mustSend(ctx, r.b, r.bDep.ID, "start", "compose.start", j.dir().args(), true); err != nil {
		return err
	}
	return r.advance(ctx, database.AppMoveStarted, "")
}

// verifyDest runs the target's node-scope health checks against B's executor. Admission refused a model whose check
// runs in the control plane, which could not prove B healthy.
func (r *moveRun) verifyDest(ctx context.Context) error {
	j := r.destJob()
	if err := r.h.dep.enter(ctx, j, deployments.StateVerifying); err != nil {
		return err
	}
	fz, err := r.freeze(ctx)
	if err != nil {
		return err
	}
	verdict, err := r.h.dep.healthVerifier(r.b.ex).verify(ctx, fz.healthRun(j.container()))
	if err != nil {
		return err
	}
	if !verdict.Healthy {
		return smerr.FromReason(smerr.ReasonHealthFailed, verdict.Failure)
	}
	return r.advance(ctx, database.AppMoveVerified, "")
}

// ---- commit and park (spec §8, §10) ----------------------------------------------------------------------------------

// commit points the target at B in one fenced transaction: the compare-and-set of the plan's revision and node, B's
// deployment settled as known good and the move committed.
func (r *moveRun) commit(ctx context.Context) error {
	if r.move.DestDeploymentID == nil {
		return smerr.New(smerr.CodeInternal, "", "the move reached its commit without a deployment on the destination")
	}
	if err := r.requireSourceStillStopped(ctx); err != nil {
		return err
	}
	revision, err := r.plannedRevision(ctx)
	if err != nil {
		return err
	}
	return r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		committed, err := database.CommitAppMove(ctx, tx, r.move.ID, r.target.ID, revision,
			r.move.SourceNodeID, r.move.DestNodeID, *r.move.DestDeploymentID, r.h.cfg.Clock.Now())
		if err != nil {
			return database.AppMove{}, err
		}
		return committed, r.emitMove(ctx, tx, eventAppMoveCommitted, domain.ResultSucceeded, map[string]any{
			"phase": string(committed.Phase), "committed_revision": committed.CommittedRevision,
		})
	})
}

// plannedRevision is the revision of the target the move's plan froze.
func (r *moveRun) plannedRevision(ctx context.Context) (int64, error) {
	rec, err := database.GetPlan(ctx, r.h.cfg.DB.Reader(), r.move.PlanID)
	if err != nil {
		return 0, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return 0, err
	}
	if len(stored.Targets) != 1 || stored.Targets[0].SpecRevision == nil {
		return 0, smerr.New(smerr.CodeInternal, "", "the move's plan does not freeze the target's revision")
	}
	return *stored.Targets[0].SpecRevision, nil
}

// parkSource leaves A stopped, never removed. A stateful A was stopped for the copy already.
func (r *moveRun) parkSource(ctx context.Context) error {
	if !r.move.Stateful {
		if err := r.holdRestart(ctx, r.a, r.good.deployment.ID, "hold-parked"); err != nil {
			return err
		}
		if err := r.mustSend(ctx, r.a, r.good.deployment.ID, "park-source", "compose.stop", r.sourceDir().args(), true); err != nil {
			return err
		}
		if err := r.requireExited(ctx, r.a); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppMoveSourceParked, "")
}

// ---- restart policies (spec §5, §8) --------------------------------------------------------------------------------

// restartHeld is the policy a container stopped by the move is held at: Docker does not start such a container again
// when its daemon restarts, so a stopped A (or a stopped B) never comes back as a second writer.
const restartHeld = "no"

// holdRestart sets the restart policy of every project container on n to restartHeld, one command per container,
// before the containers are stopped.
func (r *moveRun) holdRestart(ctx context.Context, n moveNode, dep domain.ID, stepPrefix string) error {
	containers, err := r.containers(ctx, n)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if err := r.setRestart(ctx, n, dep, stepPrefix+"-"+c.Name, c, restartHeld); err != nil {
			return err
		}
	}
	return nil
}

func (r *moveRun) setRestart(ctx context.Context, n moveNode, dep domain.ID, step string, c templates.ContainerState, policy string) error {
	return r.mustSend(ctx, n, dep, step, "docker.update_restart", map[string]string{"container": c.ID, "policy": policy}, false)
}

// requireSourceStillStopped reads A again: a stateful move holds A stopped from the copy to the commit, and a
// container that came back would be a second writer next to B.
func (r *moveRun) requireSourceStillStopped(ctx context.Context) error {
	if !r.move.Stateful {
		return nil
	}
	return r.requireExited(ctx, r.a)
}

// restartPolicies are the restart policies the frozen Compose model sets, by service; a service that sets none has
// Compose's default, no.
func restartPolicies(effective json.RawMessage) (map[string]string, error) {
	var model struct {
		Services map[string]struct {
			Restart string `json:"restart"`
		} `json:"services"`
	}
	if err := json.Unmarshal(effective, &model); err != nil {
		return nil, fmt.Errorf("the model's restart policies are unreadable: %w", err)
	}
	out := make(map[string]string, len(model.Services))
	for name, s := range model.Services {
		policy := cmp.Or(s.Restart, "no")
		if templates.ValidateRestartPolicy(policy) != nil {
			return nil, fmt.Errorf("service %s: restart policy %q is not known", name, policy)
		}
		out[name] = policy
	}
	return out, nil
}
