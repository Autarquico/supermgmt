package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// restoreOrdinalBase places restore step rows after every forward step.
const restoreOrdinalBase = 100

// restoreSnapshot is the known-good state a restore redeploys, decoded by the
// caller from the immutable snapshot rows the plan's frozen rollback target
// names (ADR-0007): never from live configuration. Deployment is the one being
// restored; it owns the step rows. Attempt keeps step rows apart across
// claims (the lease generation).
type restoreSnapshot struct {
	Deployment domain.ID
	Attempt    int
	Project    string
	Root       string // deploy_root
	Frozen     compose.Frozen
	Secrets    []compose.ResolvedSecret
	Health     healthRun // the known-good health snapshot (Q13)
}

// restoreVerification is what the node-side equivalence check (spec §20.3
// step 10) needs for the restored directory.
type restoreVerification struct {
	Snapshot  restoreSnapshot
	Directory domain.ID
}

// restoreLedger is the lease-fenced record of what a restore dispatches and
// which steps it ran. Every write is fenced by the job's lease; the handler that
// owns the lease provides the implementation.
type restoreLedger interface {
	RecordIntent(ctx context.Context, ni jobs.NewIntent) (domain.ID, error)
	MarkDispatched(ctx context.Context, intent domain.ID) error
	CompleteIntent(ctx context.Context, intent domain.ID, outcome string, evidence json.RawMessage) error
	StartStep(ctx context.Context, s database.DeploymentStep) error
	FinishStep(ctx context.Context, s database.DeploymentStep) error
}

// restorer redeploys a known-good snapshot into a new directory (spec §20.4,
// ADR-0029). It serves automatic rollback and safety recovery alike: both run
// the same restore steps, and only these.
type restorer struct {
	Node   transport.Executor
	Ledger restoreLedger
	Health healthVerifier
	IDs    domain.IDGenerator
	Clock  domain.Clock
	// Verify is the node-side equivalence check of the materialized directory
	// (the staging verify step); it returns the differences it found, never
	// values.
	Verify func(ctx context.Context, v restoreVerification) (diffs []string, err error)
}

// restoreResult is how a restore ended. A restore that fails at a step is a
// result, not an error: the deployment ends rollback_failed and a human takes
// over. Errors are reserved for what leaves the outcome unknown (lost
// connection, lost lease, cancelled context).
type restoreResult struct {
	Restored   bool
	Directory  domain.ID // where the snapshot was materialized
	FailedStep string
	Detail     string // never a value
}

// restoreStepFailed is a definite failure of one step.
type restoreStepFailed struct{ detail string }

func (e restoreStepFailed) Error() string { return e.detail }

// restoreRun is the state one restore carries between steps.
type restoreRun struct {
	restorer
	snap      restoreSnapshot
	directory domain.ID
}

func (r restorer) run(ctx context.Context, snap restoreSnapshot) (restoreResult, error) {
	run := &restoreRun{restorer: r, snap: snap}
	steps := []struct {
		name string
		do   func(context.Context) (output string, err error)
	}{
		{deployments.StepRestorePull, run.pull},
		{deployments.StepRestoreMaterialize, run.materialize},
		{deployments.StepRestoreVerify, run.verify},
		{deployments.StepRestoreDeploy, run.deploy},
		{deployments.StepRestoreHealthCheck, run.healthCheck},
	}
	for i, step := range steps {
		row := database.DeploymentStep{
			ID: r.IDs.NewID(), DeploymentID: snap.Deployment, Ordinal: restoreOrdinalBase + i, Name: step.name,
			Attempt: snap.Attempt, State: database.StepRunning, StartedAt: r.now(),
		}
		if err := r.Ledger.StartStep(ctx, row); err != nil {
			return restoreResult{}, err
		}
		output, err := step.do(ctx)
		var failed restoreStepFailed
		switch {
		case errors.As(err, &failed):
			err = r.finishStep(ctx, row, database.StepFailed, output, failed.detail)
			return restoreResult{Directory: run.directory, FailedStep: step.name, Detail: failed.detail}, err
		case err != nil:
			return restoreResult{}, err
		}
		if err := r.finishStep(ctx, row, database.StepSucceeded, output, ""); err != nil {
			return restoreResult{}, err
		}
	}
	return restoreResult{Restored: true, Directory: run.directory}, nil
}

func (r restorer) now() *time.Time {
	t := r.Clock.Now()
	return &t
}

func (r restorer) finishStep(ctx context.Context, row database.DeploymentStep, state database.StepState, output, detail string) error {
	row.State, row.FinishedAt, row.OutputRef = state, r.now(), output
	if detail != "" {
		row.ErrorJSON, _ = json.Marshal(map[string]string{"detail": detail})
	}
	return r.Ledger.FinishStep(ctx, row)
}

// pull fetches every image of the snapshot by its exact digest.
func (r *restoreRun) pull(ctx context.Context) (string, error) {
	refs := restoreImageRefs(r.snap.Frozen)
	if len(refs) == 0 {
		return "", restoreStepFailed{"the snapshot binds no image"}
	}
	for _, ref := range refs {
		err := r.dispatch(ctx, deployments.StepRestorePull, "compose.pull", nil, func(marker string) (templates.Command, error) {
			return templates.RenderMutatingInput("compose.pull", marker, map[string]string{"image": ref}, nil, "")
		})
		if err != nil {
			return "", err
		}
	}
	return "", nil
}

func restoreImageRefs(f compose.Frozen) []string {
	refs := make([]string, 0, len(f.Images))
	for _, image := range f.Images {
		refs = append(refs, image.Ref)
	}
	slices.Sort(refs)
	return slices.Compact(refs)
}

// materialize writes the snapshot into a directory named by a fresh id: the
// directory of the failed deployment still exists, and rollback never reuses
// or deletes it. The id is the step's output.
func (r *restoreRun) materialize(ctx context.Context) (string, error) {
	r.directory = r.IDs.NewID()
	bundle, err := compose.Materialize(r.snap.Frozen, r.directory, r.snap.Secrets)
	if err != nil {
		return "", restoreStepFailed{"the snapshot cannot be materialized"}
	}
	stdin, err := restoreStagedInput(bundle)
	if err != nil {
		return "", restoreStepFailed{"the snapshot cannot be staged"}
	}
	pre, _ := json.Marshal(map[string]string{"directory": r.directory.String()})
	err = r.dispatch(ctx, deployments.StepRestoreMaterialize, "compose.materialize", pre, func(marker string) (templates.Command, error) {
		return templates.RenderMutatingInput("compose.materialize", marker, r.directoryArgs(), stdin, "")
	})
	return r.directory.String(), err
}

func restoreStagedInput(b compose.Bundle) ([]byte, error) {
	files := []templates.StagedFile{{Path: "compose.yaml", Content: b.ComposeYAML}}
	paths := make([]string, 0, len(b.EnvFiles))
	for path := range b.EnvFiles {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		files = append(files, templates.StagedFile{Path: path, Content: []byte(b.EnvFiles[path].Reveal())})
	}
	return templates.EncodeMaterialization(files)
}

func (r *restoreRun) directoryArgs() map[string]string {
	return map[string]string{"root": r.snap.Root, "project": r.snap.Project, "deployment": r.directory.String()}
}

// verify proves the node's Compose resolves the directory to the snapshot.
func (r *restoreRun) verify(ctx context.Context) (string, error) {
	diffs, err := r.Verify(ctx, restoreVerification{Snapshot: r.snap, Directory: r.directory})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}
	switch {
	case err != nil:
		return "", restoreStepFailed{"the node verification failed: " + err.Error()}
	case len(diffs) > 0:
		return "", restoreStepFailed{fmt.Sprintf("the node model differs from the snapshot in %d places (first: %s)", len(diffs), diffs[0])}
	}
	return "", nil
}

// deploy starts the snapshot under the node-side project lock.
func (r *restoreRun) deploy(ctx context.Context) (string, error) {
	return "", r.dispatch(ctx, deployments.StepRestoreDeploy, "compose.up", nil, func(marker string) (templates.Command, error) {
		return templates.RenderMutatingInput("compose.up", marker, r.directoryArgs(), nil, r.snap.Project)
	})
}

// healthCheck verifies the restored version with the known-good health snapshot.
func (r *restoreRun) healthCheck(ctx context.Context) (string, error) {
	verdict, err := r.Health.verify(ctx, r.snap.Health)
	if err != nil {
		return "", err
	}
	if !verdict.Healthy {
		return "", restoreStepFailed{verdict.Failure}
	}
	return "", nil
}

// dispatch sends one mutating command: the intent is durable and marked
// dispatched before the command leaves, and closed by its exit status. A
// command that ran and failed is a definite step failure. A transport failure
// leaves the intent recorded and the outcome unknown (spec §20.4): the job is
// interrupted and reconciliation decides.
func (r *restoreRun) dispatch(ctx context.Context, step, operation string, pre json.RawMessage,
	render func(marker string) (templates.Command, error),
) error {
	marker := r.IDs.NewID().String()
	cmd, err := render(marker)
	if err != nil {
		return restoreStepFailed{operation + " cannot be rendered for the node"}
	}
	intent, err := r.Ledger.RecordIntent(ctx, jobs.NewIntent{
		Step: step, Operation: operation, TargetType: string(domain.ResourceDeployment), TargetID: r.snap.Deployment.String(),
		Marker: marker, PreState: pre, DeadlineAt: r.Clock.Now().Add(cmd.Deadline + templates.KillAfter),
	})
	if err != nil {
		return err
	}
	if err := r.Ledger.MarkDispatched(ctx, intent); err != nil {
		return err
	}
	res, runErr := r.Node.Run(ctx, cmd)
	if runErr != nil {
		return restoreOutcomeUnknown(step, runErr)
	}
	return r.concludeDispatch(ctx, intent, step, res.ExitStatus)
}

func (r *restoreRun) concludeDispatch(ctx context.Context, intent domain.ID, step string, exit int) error {
	outcome := jobs.OutcomeSucceeded
	if exit != 0 {
		outcome = jobs.OutcomeFailed
	}
	if err := r.Ledger.CompleteIntent(ctx, intent, outcome, commandExitEvidence(outcome, exit)); err != nil {
		return err
	}
	if exit != 0 {
		return restoreStepFailed{fmt.Sprintf("%s exited with status %d", step, exit)}
	}
	return nil
}

func restoreOutcomeUnknown(step string, cause error) error {
	return smerr.Wrap(fmt.Errorf("%w: %w", jobs.ErrOutcomeUnknown, cause), smerr.CodeNodeUnreachable, "",
		step+" was dispatched but its outcome could not be established; check the node and resolve the job")
}

// rollBackOrFail decides what follows a failed update or failed health check
// (spec §20.1): rolling_back when rollback is available, else failed with
// ROLLBACK_UNAVAILABLE and the cause. It returns the state entered.
func rollBackOrFail(ctx context.Context, q database.Querier, id domain.ID, in deployments.RollbackInputs, now time.Time) (deployments.State, error) {
	ok, cause := deployments.RollbackAvailable(in)
	if ok {
		return deployments.StateRollingBack,
			database.TransitionDeployment(ctx, q, id, deployments.StateRollingBack, database.StateFailure{}, now)
	}
	failure := database.StateFailure{
		Code: string(smerr.CodeDeploymentFailed), Reason: string(smerr.ReasonRollbackUnavailable), Cause: cause,
	}
	return deployments.StateFailed, database.TransitionDeployment(ctx, q, id, deployments.StateFailed, failure, now)
}

// settleRestore ends a deployment in rolling_back: rolled_back when the
// previous known-good version is restored and healthy, rollback_failed (a
// human is required) otherwise.
func settleRestore(ctx context.Context, q database.Querier, id domain.ID, res restoreResult, now time.Time) (deployments.State, error) {
	if res.Restored {
		return deployments.StateRolledBack,
			database.TransitionDeployment(ctx, q, id, deployments.StateRolledBack, database.StateFailure{}, now)
	}
	failure := database.StateFailure{Code: string(smerr.CodeRollbackFailed)}
	return deployments.StateRollbackFailed, database.TransitionDeployment(ctx, q, id, deployments.StateRollbackFailed, failure, now)
}
