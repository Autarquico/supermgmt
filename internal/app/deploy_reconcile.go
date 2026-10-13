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
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// DeploymentPolicy is the jobs.TypePolicy of deployment.create and
// deployment.rollback (ADR-0029). It never weakens the fixed rule that every
// dispatched intent needs a .done exit 0 proof; it decides what the proven
// evidence means for a deployment, and keeps the deployment row in step with
// the job.
//
//	before deploying   services untouched: resume forward, or fail
//	                   INTERRUPTED_BEFORE_DEPLOY when no attempt is left
//	after deploying    complete and verified: succeeded; complete: resume
//	                   forward; partial_stable: safety recovery to the plan's
//	                   frozen rollback target, or ROLLBACK_UNAVAILABLE
//	while restoring    restored and verified: rolled_back; otherwise restore
//	                   again, or rollback_failed when no attempt is left
type DeploymentPolicy struct {
	core
	revalidator *Revalidator
}

var _ jobs.TypePolicy = (*DeploymentPolicy)(nil)

// NewDeploymentPolicy validates cfg. revalidator supplies RevalidateRecovery.
func NewDeploymentPolicy(cfg Config, revalidator *Revalidator) (*DeploymentPolicy, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if revalidator == nil {
		return nil, errors.New("app: a deployment policy needs the revalidator")
	}
	return &DeploymentPolicy{core: c, revalidator: revalidator}, nil
}

// Admit lets a proven classification take part in a confirmed pair of samples.
// partial_stable is what a deployment needs and the fixed table refuses.
func (*DeploymentPolicy) Admit(ev jobs.Evidence) bool {
	switch ev.Classification {
	case jobs.ClassComplete, jobs.ClassNotStarted, jobs.ClassPartialStable:
		return true
	case jobs.ClassUnknown:
	}
	return false
}

// ClaimMode reads the durable recovery record.
func (*DeploymentPolicy) ClaimMode(ctx context.Context, q database.Querier, job jobs.Job) (jobs.ClaimMode, error) {
	dep, err := database.GetDeploymentByJob(ctx, q, job.ID)
	if err != nil {
		return jobs.ClaimForward, err
	}
	if dep.Recovery != nil && dep.Recovery.Mode == deployments.RecoverySafetyRecovery {
		return jobs.ClaimRecovery, nil
	}
	return jobs.ClaimForward, nil
}

// RevalidateRecovery checks that the frozen restoration target is restorable.
func (p *DeploymentPolicy) RevalidateRecovery(ctx context.Context, q database.Querier, job jobs.Job) error {
	return p.revalidator.RevalidateRecovery(ctx, q, job)
}

// EscalateToRecovery turns a forward revalidation failure into a safety
// recovery when the services were already touched and the plan can roll back.
// Before that point the claim fails with the revalidation's own reason.
func (p *DeploymentPolicy) EscalateToRecovery(ctx context.Context, tx *database.Tx, job jobs.Job, cause error) (bool, error) {
	dep, err := database.GetDeploymentByJob(ctx, tx, job.ID)
	if err != nil {
		return false, err
	}
	if !dep.MutationStarted {
		return false, nil
	}
	pl, err := planOfDeployment(ctx, tx, dep)
	if err != nil {
		return false, err
	}
	ok, _, err := p.rollbackAvailability(ctx, tx, dep, pl)
	if err != nil || !ok {
		return false, err
	}
	record := safetyRecovery(pl, "forward revalidation failed: "+failureLabel(jobs.FailureOf(cause)))
	return true, database.SetDeploymentRecovery(ctx, tx, dep.ID, *record, p.cfg.Clock.Now())
}

// Reconcile decides an interrupted deployment whose dispatched intents are all
// proven and admitted. It persists the recovery record and, for a final
// verdict, settles the deployment row in the same transaction.
func (p *DeploymentPolicy) Reconcile(ctx context.Context, tx *database.Tx, job jobs.Job, intents []jobs.Intent,
	observed map[domain.ID]jobs.Evidence,
) (jobs.Verdict, error) {
	facts, err := p.reconcileFacts(ctx, tx, job, intents, observed)
	if err != nil {
		return jobs.Verdict{}, err
	}
	outcome := decideDeployment(facts)
	if err := p.apply(ctx, tx, facts, outcome); err != nil {
		return jobs.Verdict{}, err
	}
	return outcome.verdict, nil
}

// ---- Mirror ---------------------------------------------------------------------------------------

// Mirror keeps the deployment row in step with every coarse transition of its
// job, in the same transaction (ADR-0013, ADR-0029). The fine states past
// preparing are the worker's; a deployment the handler or the reconciler
// already settled is left alone.
func (p *DeploymentPolicy) Mirror(ctx context.Context, q database.Querier, job jobs.Job, _, to domain.JobState,
	mode jobs.ClaimMode, f *jobs.Failure,
) error {
	dep, err := database.GetDeploymentByJob(ctx, q, job.ID)
	if err != nil {
		return err
	}
	next, ok := mirroredState(dep.State, to, mode)
	if !ok {
		return nil
	}
	var failure database.StateFailure
	if f != nil {
		failure = database.StateFailure{Code: string(f.Code), Reason: string(f.Reason)}
	}
	return p.move(ctx, q, dep.ID, next, failure)
}

var inFlightStates = []deployments.State{
	deployments.StatePreparing, deployments.StateStaging, deployments.StateDeploying,
	deployments.StateVerifying, deployments.StateRollingBack,
}

// mirroredState is the deployment state a job's new coarse state implies, or
// false when the deployment stays where it is.
func mirroredState(cur deployments.State, to domain.JobState, mode jobs.ClaimMode) (deployments.State, bool) {
	if cur.Terminal() {
		return "", false
	}
	switch to {
	case domain.JobQueued:
		return deployments.StateQueued, cur == deployments.StateAwaitingApproval
	case domain.JobAwaitingApproval:
		return deployments.StateAwaitingApproval, cur == deployments.StateQueued
	case domain.JobRunning:
		return runningMirror(cur, mode)
	case domain.JobInterrupted:
		return deployments.StateInterrupted, slices.Contains(inFlightStates, cur)
	case domain.JobSucceeded:
		return deployments.StateSucceeded, deployments.Transition(cur, deployments.StateSucceeded) == nil
	case domain.JobFailed:
		return failedMirror(cur)
	case domain.JobCancelled:
		return deployments.StateCancelled, deployments.Transition(cur, deployments.StateCancelled) == nil
	}
	return "", false
}

// runningMirror is the claim: a forward claim prepares, a recovery claim rolls
// back. A deployment that already is past that point (a retry) stays.
func runningMirror(cur deployments.State, mode jobs.ClaimMode) (deployments.State, bool) {
	switch {
	case mode == jobs.ClaimRecovery:
		return deployments.StateRollingBack, cur == deployments.StateInterrupted
	case cur == deployments.StateQueued || cur == deployments.StateInterrupted:
		return deployments.StatePreparing, true
	}
	return "", false
}

// failedMirror: a deployment that was restoring cannot simply fail.
func failedMirror(cur deployments.State) (deployments.State, bool) {
	if cur == deployments.StateRollingBack {
		return deployments.StateRollbackFailed, true
	}
	return deployments.StateFailed, deployments.Transition(cur, deployments.StateFailed) == nil
}

// ---- the decision ---------------------------------------------------------------------------------

// deployReconcileFacts is everything the decision reads.
type deployReconcileFacts struct {
	job           jobs.Job
	dep           database.Deployment
	plan          plan.Plan
	intents       []jobs.Intent
	observed      map[domain.ID]jobs.Evidence
	steps         []database.DeploymentStep
	rollbackOK    bool
	rollbackCause string
}

// deployOutcome is a decision: the verdict for the job, the recovery record
// to write, the final state to settle the deployment in, and the steps the
// evidence proved finished.
type deployOutcome struct {
	verdict  jobs.Verdict
	recovery *deployments.Recovery
	settle   deployments.State
	failure  database.StateFailure
	proven   []string
}

func (p *DeploymentPolicy) reconcileFacts(ctx context.Context, q database.Querier, job jobs.Job, intents []jobs.Intent,
	observed map[domain.ID]jobs.Evidence,
) (deployReconcileFacts, error) {
	dep, err := database.GetDeploymentByJob(ctx, q, job.ID)
	if err != nil {
		return deployReconcileFacts{}, err
	}
	pl, err := planOfDeployment(ctx, q, dep)
	if err != nil {
		return deployReconcileFacts{}, err
	}
	steps, err := database.ListDeploymentSteps(ctx, q, dep.ID)
	if err != nil {
		return deployReconcileFacts{}, err
	}
	ok, cause, err := p.rollbackAvailability(ctx, q, dep, pl)
	if err != nil {
		return deployReconcileFacts{}, err
	}
	return deployReconcileFacts{
		job: job, dep: dep, plan: pl, intents: intents, observed: observed, steps: steps,
		rollbackOK: ok, rollbackCause: cause,
	}, nil
}

// rollbackAvailability applies §20.1 to the plan's frozen policy. A policy
// snapshot that can no longer be read makes the rollback unavailable.
func (*DeploymentPolicy) rollbackAvailability(ctx context.Context, q database.Querier, dep database.Deployment, pl plan.Plan) (bool, string, error) {
	pol, err := readSnapshotJSON[policySnapshot](ctx, q, pl.Content.DeploymentPolicyHash)
	if isTyped(err) {
		return false, deployments.CauseSnapshotGone, nil
	}
	if err != nil {
		return false, "", err
	}
	env, err := database.GetEnvironment(ctx, q, dep.EnvironmentID)
	if err != nil {
		return false, "", err
	}
	ok, cause := deployments.RollbackAvailable(deployments.RollbackInputs{
		Mode: pol.Rollback, Stateful: pol.Stateful, EnvAllows: env.AllowAutomaticRollback,
		HasKnownGood: pl.Content.RollbackTarget != nil, Kind: dep.Kind,
	})
	return ok, cause, nil
}

func decideDeployment(f deployReconcileFacts) deployOutcome {
	switch {
	case f.restoring():
		return f.decideRestoring()
	case !f.dep.MutationStarted:
		return f.resumeOrFailBeforeDeploy()
	}
	return f.decideAfterDeploy()
}

func (f deployReconcileFacts) attemptsLeft() bool { return f.job.Attempts < f.job.MaxAttempts }

// restoring reports that the run was already restoring: the durable record says
// safety recovery, or a restore step dispatched.
func (f deployReconcileFacts) restoring() bool {
	if f.dep.Recovery != nil && f.dep.Recovery.Mode == deployments.RecoverySafetyRecovery {
		return true
	}
	return slices.ContainsFunc(f.intents, func(in jobs.Intent) bool { return strings.HasPrefix(in.Step, "restore-") })
}

// lastUp is the newest dispatched compose up of step, or nil.
func (f deployReconcileFacts) lastUp(step string) *jobs.Intent {
	for _, in := range slices.Backward(f.intents) {
		if in.Dispatched() && in.Step == step && in.Operation == operationComposeUp {
			return &in
		}
	}
	return nil
}

func (f deployReconcileFacts) classOf(in *jobs.Intent) jobs.Classification {
	if in == nil {
		return jobs.ClassNotStarted
	}
	return f.observed[in.ID].Classification
}

// stepDone reports a succeeded row of step, from this attempt on when since > 0.
func (f deployReconcileFacts) stepDone(step string, since int64) bool {
	return slices.ContainsFunc(f.steps, func(s database.DeploymentStep) bool {
		return s.Name == step && s.State == database.StepSucceeded && int64(s.Attempt) >= since
	})
}

func (f deployReconcileFacts) resumeOrFailBeforeDeploy() deployOutcome {
	if !f.attemptsLeft() {
		return f.fail(smerr.FromReason(smerr.ReasonInterruptedBeforeDeploy,
			"the deployment was interrupted before it changed any service and has no attempt left"))
	}
	return f.resumeForward("interrupted before deploying; services untouched")
}

func (f deployReconcileFacts) decideAfterDeploy() deployOutcome {
	up := f.lastUp(deployments.StepDeploy)
	switch f.classOf(up) {
	case jobs.ClassNotStarted:
		return f.resumeOrFailBeforeDeploy()
	case jobs.ClassComplete:
		return f.decideDeployed()
	case jobs.ClassPartialStable:
		return f.rollBack("the update stopped half way and the project is stable")
	case jobs.ClassUnknown:
	}
	return deployOutcome{verdict: jobs.Verdict{Action: jobs.VerdictHeld, Reason: "the deploy step has no usable classification"}}
}

// decideDeployed: compose up completed. Verified means finished; otherwise the
// health check still has to run, which only a forward claim can do.
func (f deployReconcileFacts) decideDeployed() deployOutcome {
	switch {
	case f.stepDone(deployments.StepHealthCheck, 0):
		return deployOutcome{
			verdict: jobs.Verdict{Action: jobs.VerdictSucceeded, Reason: "deployed and verified"},
			settle:  deployments.StateSucceeded,
		}
	case f.attemptsLeft():
		return f.resumeForward("deployed; the health check did not finish")
	}
	return deployOutcome{verdict: jobs.Verdict{
		Action: jobs.VerdictHeld, Reason: "deployed but not verified, and no attempt is left",
	}}
}

func (f deployReconcileFacts) decideRestoring() deployOutcome {
	if f.plan.Content.RollbackTarget == nil {
		return f.settleRollbackFailed("the plan froze no rollback target")
	}
	up := f.lastUp(deployments.StepRestoreDeploy)
	if up != nil && f.classOf(up) == jobs.ClassComplete && f.stepDone(deployments.StepRestoreHealthCheck, up.LeaseGeneration) {
		return deployOutcome{
			verdict: jobs.Verdict{
				Action: jobs.VerdictFailed, Reason: "the previous version is restored and verified",
				Failure: &jobs.Failure{Code: smerr.CodeDeploymentFailed, Message: "the deployment was interrupted and rolled back"},
			},
			settle: deployments.StateRolledBack,
		}
	}
	if !f.attemptsLeft() {
		return f.settleRollbackFailed("the restore did not finish and no attempt is left")
	}
	return deployOutcome{
		verdict:  jobs.Verdict{Action: jobs.VerdictRequeuedRecovery, Reason: "the restore did not finish; restoring again"},
		recovery: safetyRecovery(f.plan, f.recoveryReason("the restore was interrupted")),
	}
}

// recoveryReason keeps the reason that first caused the recovery.
func (f deployReconcileFacts) recoveryReason(fallback string) string {
	if f.dep.Recovery != nil && f.dep.Recovery.Reason != "" {
		return f.dep.Recovery.Reason
	}
	return fallback
}

func (f deployReconcileFacts) settleRollbackFailed(reason string) deployOutcome {
	return deployOutcome{
		verdict: jobs.Verdict{
			Action: jobs.VerdictFailed, Reason: reason,
			Failure: &jobs.Failure{Code: smerr.CodeRollbackFailed, Message: reason},
		},
		settle:  deployments.StateRollbackFailed,
		failure: database.StateFailure{Code: string(smerr.CodeRollbackFailed)},
	}
}

// rollBack starts a safety recovery, or fails with the reason the rollback is
// unavailable. A recovery needs an attempt to run in.
func (f deployReconcileFacts) rollBack(reason string) deployOutcome {
	switch {
	case !f.rollbackOK:
		return f.fail(rollbackUnavailable(f.rollbackCause, "the deployment was interrupted mid-update and cannot be rolled back"))
	case !f.attemptsLeft():
		return deployOutcome{verdict: jobs.Verdict{
			Action: jobs.VerdictHeld, Reason: "the update stopped half way and no attempt is left to roll it back",
		}}
	}
	return deployOutcome{
		verdict:  jobs.Verdict{Action: jobs.VerdictRequeuedRecovery, Reason: reason},
		recovery: safetyRecovery(f.plan, reason),
	}
}

// resumeForward requeues the job to continue where the evidence says it
// stopped. Single-intent steps the evidence proved complete are marked
// succeeded, so the handler does not run them again.
func (f deployReconcileFacts) resumeForward(reason string) deployOutcome {
	proven := f.provenSteps()
	return deployOutcome{
		verdict: jobs.Verdict{Action: jobs.VerdictRequeued, Reason: reason},
		recovery: &deployments.Recovery{
			Mode: deployments.RecoveryForward, ResumeStep: f.nextForwardStep(proven), Reason: reason,
		},
		proven: proven,
	}
}

// provenSteps are the steps whose only intent the evidence proved complete,
// among those whose success the handler would otherwise repeat for nothing.
func (f deployReconcileFacts) provenSteps() []string {
	var proven []string
	for _, step := range []string{deployments.StepMaterialize, deployments.StepDeploy} {
		dispatched := slices.DeleteFunc(slices.Clone(f.intents), func(in jobs.Intent) bool {
			return !in.Dispatched() || in.Step != step
		})
		if len(dispatched) == 1 && f.classOf(&dispatched[0]) == jobs.ClassComplete {
			proven = append(proven, step)
		}
	}
	return proven
}

func (f deployReconcileFacts) nextForwardStep(proven []string) string {
	for _, step := range deployments.Steps(f.plan, deployments.RecoveryForward) {
		if !f.stepDone(step.Name, 0) && !slices.Contains(proven, step.Name) {
			return step.Name
		}
	}
	return ""
}

// fail ends the deployment as failed with err's code, reason and cause.
func (f deployReconcileFacts) fail(err error) deployOutcome {
	failure := jobs.FailureOf(err)
	return deployOutcome{
		verdict: jobs.Verdict{Action: jobs.VerdictFailed, Reason: failureLabel(failure), Failure: &failure},
		settle:  deployments.StateFailed,
		failure: failureOfDeployment(err),
	}
}

func failureLabel(f jobs.Failure) string {
	if f.Reason != "" {
		return string(f.Reason)
	}
	return string(f.Code)
}

// safetyRecovery is the record that sends a job to restore the plan's frozen
// rollback target, never the newest known-good at the time.
func safetyRecovery(pl plan.Plan, reason string) *deployments.Recovery {
	target := domain.ID(pl.Content.RollbackTarget.DeploymentID)
	return &deployments.Recovery{
		Mode: deployments.RecoverySafetyRecovery, ResumeStep: deployments.StepRestorePull, Reason: reason, Target: &target,
	}
}

// ---- applying -------------------------------------------------------------------------------------

func (p *DeploymentPolicy) apply(ctx context.Context, tx *database.Tx, f deployReconcileFacts, o deployOutcome) error {
	if err := p.markProvenSteps(ctx, tx, f, o.proven); err != nil {
		return err
	}
	if o.recovery != nil {
		if err := database.SetDeploymentRecovery(ctx, tx, f.dep.ID, *o.recovery, p.cfg.Clock.Now()); err != nil {
			return err
		}
	}
	if o.settle == "" {
		return nil
	}
	if err := p.move(ctx, tx, f.dep.ID, o.settle, o.failure); err != nil {
		return err
	}
	if o.settle == deployments.StateSucceeded {
		return database.MarkDeploymentKnownGood(ctx, tx, f.dep.ID, p.cfg.Clock.Now())
	}
	return nil
}

// markProvenSteps finishes the open row of each step the evidence proved.
func (p *DeploymentPolicy) markProvenSteps(ctx context.Context, q database.Querier, f deployReconcileFacts, names []string) error {
	now := p.cfg.Clock.Now()
	for _, name := range names {
		for _, row := range f.steps {
			if row.Name != name || row.State != database.StepRunning {
				continue
			}
			row.State, row.FinishedAt = database.StepSucceeded, &now
			if err := database.UpdateDeploymentStep(ctx, q, row); err != nil {
				return fmt.Errorf("finish proven step %s: %w", name, err)
			}
		}
	}
	return nil
}

// move transitions the deployment and records the state it entered, like the
// handler does (announce only reads the shared core).
func (p *DeploymentPolicy) move(ctx context.Context, q database.Querier, id domain.ID, to deployments.State, failure database.StateFailure) error {
	if err := database.TransitionDeployment(ctx, q, id, to, failure, p.cfg.Clock.Now()); err != nil {
		return err
	}
	return deployHandler{core: p.core}.announce(ctx, q, id, to)
}

// TypePolicies is Config.TypePolicies for the daemon: one policy for both
// deployment job types.
func (p *DeploymentPolicy) TypePolicies() map[string]jobs.TypePolicy {
	return map[string]jobs.TypePolicy{deploymentCreateAction: p, deploymentRollbackAction: p}
}
