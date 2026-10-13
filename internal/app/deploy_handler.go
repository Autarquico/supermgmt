package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// DeploySecrets reads the secret versions a deployment binds (ADR-0008).
// *secrets.Store implements it.
type DeploySecrets interface {
	Get(ctx context.Context, ref secrets.Ref) (audit.Secret, error)
}

// DeployOptions are the collaborators only the deployment handler needs.
// HTTP runs the control_plane health checks and must be a netguard client.
type DeployOptions struct {
	Secrets DeploySecrets
	HTTP    *http.Client
	Sleep   func(ctx context.Context, d time.Duration) // default: a real timer
}

// causeRestoreSnapshot names the restore step that could not even start
// because the known-good snapshot cannot be read.
const causeRestoreSnapshot = "restore-snapshot"

// deployHandler executes deployment.create and deployment.rollback (spec §20,
// ADR-0029). It walks the plan's steps in the job's recovery mode: forward
// steps normally, restore steps only under safety recovery. Every dispatched
// command has a durable, fenced intent; a dispatched command whose outcome is
// unknown ends the run with jobs.ErrOutcomeUnknown and the reconciler decides.
// The handler settles the deployment row itself, so a failing job always
// leaves its deployment in the state the failure deserves.
type deployHandler struct {
	core
	store   *jobs.Store
	dial    func(domain.Node, *runtimes.SetupMeta) (transport.Executor, error)
	secrets DeploySecrets
	http    *http.Client
	sleep   func(ctx context.Context, d time.Duration)
}

// deployJob is everything one run reads before it touches the node.
type deployJob struct {
	lease  jobs.Lease
	job    jobs.Job
	dep    database.Deployment
	plan   plan.Plan
	target database.AppTarget
	app    database.App
	env    domain.Environment
	node   domain.Node
	ex     transport.Executor
	root   string
	caps   map[string]bool
	mode   deployments.RecoveryMode
}

func (j *deployJob) dir() deployDir {
	return deployDir{Root: j.root, Project: j.target.ComposeProject, Deployment: j.dep.ID}
}

func (j *deployJob) stage() deployStage { return deployStage{exec: j.ex} }

// container is the default Compose name of the deployed service's container.
func (j *deployJob) container() string {
	return fmt.Sprintf("%s-%s-1", j.target.ComposeProject, j.app.DeployedService)
}

// frozenDeployment is the content a run executes, read from the immutable
// snapshot rows the plan binds (ADR-0007) and the secret versions it pins.
type frozenDeployment struct {
	frozen  compose.Frozen
	health  *health.Check
	policy  policySnapshot
	secrets []compose.ResolvedSecret
}

func (fz frozenDeployment) healthRun(container string) healthRun {
	var checks []health.Check
	if fz.health != nil {
		checks = []health.Check{*fz.health}
	}
	return healthRun{
		Checks: checks, Ports: fz.frozen.HostPorts, AllowedBind: fz.policy.AllowedBindAddresses, Container: container,
	}
}

func (fz frozenDeployment) rollbackInputs(j *deployJob) deployments.RollbackInputs {
	return deployments.RollbackInputs{
		Mode: fz.policy.Rollback, Stateful: fz.policy.Stateful, EnvAllows: j.env.AllowAutomaticRollback,
		HasKnownGood: j.plan.Content.RollbackTarget != nil, Kind: j.dep.Kind,
	}
}

func newDeployHandler(c core, store *jobs.Store, conn Connector, o DeployOptions) (*deployHandler, error) {
	switch {
	case o.Secrets == nil:
		return nil, errors.New("app: deployments need a secret source")
	case o.HTTP == nil:
		return nil, errors.New("app: deployments need an HTTP client for control-plane health checks")
	}
	if o.Sleep == nil {
		o.Sleep = sleepFor
	}
	return &deployHandler{core: c, store: store, dial: conn.Automated, secrets: o.Secrets, http: o.HTTP, sleep: o.Sleep}, nil
}

func (h deployHandler) Run(ctx context.Context, lease jobs.Lease) error {
	j, err := h.load(ctx, lease)
	if err != nil {
		return err
	}
	ctx = audit.WithCorrelationID(ctx, j.dep.ID)
	if j.mode == deployments.RecoverySafetyRecovery {
		err = h.recover(ctx, j)
	} else {
		err = h.forward(ctx, j)
	}
	h.collectDeploymentDirectories(ctx, j)
	return err
}

func (h deployHandler) load(ctx context.Context, lease jobs.Lease) (*deployJob, error) {
	q := h.cfg.DB.Reader()
	job, err := h.store.Get(ctx, q, lease.JobID)
	if err != nil {
		return nil, err
	}
	if job.PlanID == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "deployment job has no plan")
	}
	dep, err := database.GetDeploymentByJob(ctx, q, job.ID)
	if err != nil {
		return nil, err
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	if err != nil {
		return nil, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return nil, err
	}
	j := &deployJob{lease: lease, job: job, dep: dep, plan: *stored, mode: deployments.RecoveryForward}
	if dep.Recovery != nil {
		j.mode = dep.Recovery.Mode
	}
	return j, h.loadScope(ctx, j)
}

func (h deployHandler) loadScope(ctx context.Context, j *deployJob) error {
	q := h.cfg.DB.Reader()
	var err error
	if j.target, err = database.GetAppTarget(ctx, q, j.dep.AppTargetID); err != nil {
		return err
	}
	if j.app, err = database.GetApp(ctx, q, j.dep.AppID); err != nil {
		return err
	}
	if j.env, err = database.GetEnvironment(ctx, q, j.dep.EnvironmentID); err != nil {
		return err
	}
	if j.node, err = database.GetNode(ctx, q, j.dep.NodeID); err != nil {
		return err
	}
	setup, err := loadSetup(ctx, q, j.node.ID)
	if err != nil {
		return err
	}
	if setup == nil {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "node.setup has not completed on the node")
	}
	j.root = templates.DefaultDeployRoot
	if setup.DeployRoot != "" {
		j.root = setup.DeployRoot
	}
	capabilities, err := database.ListNodeCapabilities(ctx, q, j.node.ID)
	if err != nil {
		return err
	}
	j.caps = make(map[string]bool, len(capabilities))
	for _, c := range capabilities {
		j.caps[c.Capability] = c.Available
	}
	j.ex, err = h.dial(j.node, setup)
	return err
}

// ---- forward --------------------------------------------------------------------------------

func (h deployHandler) forward(ctx context.Context, j *deployJob) error {
	fz, err := h.freeze(ctx, j.plan.Content)
	if err != nil {
		return h.failDeployment(ctx, j, err)
	}
	done, err := h.succeededSteps(ctx, j)
	if err != nil {
		return err
	}
	for i, step := range deployments.Steps(j.plan, deployments.RecoveryForward) {
		if done[step.Name] {
			continue
		}
		if err := h.runStep(ctx, j, fz, i, step); err != nil {
			return err
		}
	}
	return h.settleHealth(ctx, j, fz, healthVerdict{Healthy: true})
}

// succeededSteps are the forward steps an earlier attempt finished; a resumed
// run does not repeat them.
func (h deployHandler) succeededSteps(ctx context.Context, j *deployJob) (map[string]bool, error) {
	rows, err := database.ListDeploymentSteps(ctx, h.cfg.DB.Reader(), j.dep.ID)
	if err != nil {
		return nil, err
	}
	done := map[string]bool{}
	for _, row := range rows {
		if row.State == database.StepSucceeded {
			done[row.Name] = true
		}
	}
	return done, nil
}

// unhealthyError is the health step's failure: not an error of the run, but the
// verdict that decides between rollback and failure.
type unhealthyError struct{ detail string }

func (e unhealthyError) Error() string { return e.detail }

func (h deployHandler) runStep(ctx context.Context, j *deployJob, fz frozenDeployment, index int, step deployments.Step) error {
	if err := h.enter(ctx, j, stateOfStep(step.Name)); err != nil {
		return err
	}
	row, err := h.startStep(ctx, j, index+1, step.Name)
	if err != nil {
		return err
	}
	output, err := h.execute(ctx, j, fz, step)
	var unhealthy unhealthyError
	switch {
	case err == nil:
		return h.finishStep(ctx, j, row, database.StepSucceeded, output, "")
	case errors.As(err, &unhealthy):
		if err := h.finishStep(ctx, j, row, database.StepFailed, "", unhealthy.detail); err != nil {
			return err
		}
		return h.settleHealth(ctx, j, fz, healthVerdict{Failure: unhealthy.detail})
	case ctx.Err() != nil, errors.Is(err, jobs.ErrOutcomeUnknown), errors.Is(err, jobs.ErrLeaseLost):
		return err
	}
	if ferr := h.finishStep(ctx, j, row, database.StepFailed, "", audit.ScrubString(err.Error())); ferr != nil {
		return ferr
	}
	return h.stepFailed(ctx, j, fz, step, err)
}

func (h deployHandler) execute(ctx context.Context, j *deployJob, fz frozenDeployment, step deployments.Step) (string, error) {
	switch step.Name {
	case deployments.StepPreflight:
		return "", h.preflight(ctx, j, fz)
	case deployments.StepPreDeployBackup:
		return h.backup(ctx, j, fz)
	case deployments.StepPull:
		return "", h.pull(ctx, j, fz, step)
	case deployments.StepMaterialize:
		return "", h.materialize(ctx, j, fz, step)
	case deployments.StepVerifyOnNode:
		return "", j.stage().Verify(ctx, j.mode, j.dir(), fz.frozen, fz.secrets)
	case deployments.StepDeploy:
		return "", h.deploy(ctx, j, step)
	case deployments.StepHealthCheck:
		return "", h.verifyHealth(ctx, j, fz)
	}
	return "", smerr.New(smerr.CodeInternal, "", "deployment step "+step.Name+" has no executor")
}

// stepFailed settles a definite failure of a forward step. Before the deploy
// step nothing running was touched, so the deployment simply fails; a failed
// deploy step goes through the rollback decision of §20.1, unless Compose never
// ran because the project lock was busy.
func (h deployHandler) stepFailed(ctx context.Context, j *deployJob, fz frozenDeployment, step deployments.Step, cause error) error {
	if step.Name != deployments.StepDeploy || smerr.FromReason(smerr.ReasonResourceLocked, "").Is(cause) {
		return h.failDeployment(ctx, j, cause)
	}
	var state deployments.State
	err := h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		var err error
		if state, err = rollBackOrFail(ctx, tx, j.dep.ID, fz.rollbackInputs(j), h.cfg.Clock.Now()); err != nil {
			return err
		}
		return h.announce(ctx, tx, j.dep.ID, state)
	})
	if err != nil {
		return err
	}
	return h.conclude(ctx, j, state, cause)
}

func (h deployHandler) settleHealth(ctx context.Context, j *deployJob, fz frozenDeployment, v healthVerdict) error {
	if err := h.enter(ctx, j, deployments.StateVerifying); err != nil {
		return err
	}
	var state deployments.State
	err := h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		var err error
		if state, err = settleVerification(ctx, tx, j.dep.ID, v, fz.rollbackInputs(j), h.cfg.Clock.Now()); err != nil {
			return err
		}
		return h.announce(ctx, tx, j.dep.ID, state)
	})
	if err != nil {
		return err
	}
	return h.conclude(ctx, j, state, smerr.FromReason(smerr.ReasonHealthFailed, v.Failure))
}

// conclude turns the state a failed update settled in into the job's outcome:
// a rollback runs now; no rollback is the typed ROLLBACK_UNAVAILABLE with the
// cause the state machine recorded.
func (h deployHandler) conclude(ctx context.Context, j *deployJob, state deployments.State, cause error) error {
	if state == deployments.StateSucceeded {
		return nil
	}
	if state == deployments.StateRollingBack {
		target := domain.ID(j.plan.Content.RollbackTarget.DeploymentID)
		return h.restoreAndSettle(ctx, j, target, cause)
	}
	row, err := database.GetDeployment(ctx, h.cfg.DB.Reader(), j.dep.ID)
	if err != nil {
		return err
	}
	return rollbackUnavailable(row.Failure.Cause, "the deployment failed and cannot be rolled back: %v", cause)
}

// ---- steps ----------------------------------------------------------------------------------

func (h deployHandler) preflight(ctx context.Context, j *deployJob, fz frozenDeployment) error {
	return runPreflight(ctx, j.ex, preflightInput{
		Project: j.target.ComposeProject, Owner: j.target.ID, DeployRoot: j.root,
		Images: distinctImageRefs(fz.frozen.Images), HostPorts: fz.frozen.HostPorts,
		Health: fz.healthRun("").Checks, Capabilities: j.caps,
	})
}

func (h deployHandler) backup(ctx context.Context, j *deployJob, fz frozenDeployment) (string, error) {
	req := backupRequest{Deployment: j.dep.ID, Plan: j.plan}
	if b := fz.policy.PreDeployBackup; b != nil {
		req.Template, req.Args, req.Timeout = b.Template, b.Args, b.Timeout
	}
	step := backupStep{store: h.store, clock: h.cfg.Clock, ids: h.cfg.IDs, gate: h.backupGate(j)}
	return step.run(ctx, j.ex, j.lease, req)
}

// backupGate re-evaluates the plan's backup sub-action for the requester under
// the policy in force (spec §11.3): the deployment's own action with the
// sub-action on the node the plan pinned, exactly as the claim evaluates it.
func (h deployHandler) backupGate(j *deployJob) backupSubActionGate {
	return func(ctx context.Context, sub plan.SubAction) error {
		q := h.cfg.DB.Reader()
		if sub.Target.Type != string(domain.ResourceNode) || sub.Target.ID != j.node.ID.String() {
			return smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "the backup sub-action does not name the deployment's node")
		}
		actor, err := loadActor(ctx, q, j.job.ActorID, credentialOf(j.job))
		if err != nil {
			return err
		}
		scope, err := loadDeploymentScope(ctx, q, j.target.ID)
		if err != nil {
			return err
		}
		main, err := scope.policyTarget(ctx, q, appTargetRef(j.target.ID))
		if err != nil {
			return err
		}
		node, err := scope.policyTarget(ctx, q, domain.ResourceRef{Type: domain.ResourceNode, ID: j.node.ID})
		if err != nil {
			return err
		}
		return decisionError(h.authorize(policy.Request{
			Actor: actor, Action: j.plan.Action, Params: j.plan.Parameters, Targets: []policy.Target{main},
			SubActions: []policy.SubAction{{Action: sub.Action, Target: node}},
		}))
	}
}

// pull fetches each distinct image under its own intent, so every pull has its
// own proof on the node.
func (h deployHandler) pull(ctx context.Context, j *deployJob, fz frozenDeployment, step deployments.Step) error {
	for _, ref := range distinctImageRefs(fz.frozen.Images) {
		marker := h.cfg.IDs.NewID().String()
		image := []compose.ImageUse{{Ref: ref}}
		// compose.pull derives the node marker as "<marker>-<n>"; one image per
		// call makes the intent's marker the node's exact one.
		err := h.dispatch(ctx, j, step, "compose.pull", marker+"-0", nil, func() error {
			return j.stage().Pull(ctx, j.mode, marker, image)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (h deployHandler) materialize(ctx context.Context, j *deployJob, fz frozenDeployment, step deployments.Step) error {
	if _, err := compose.Materialize(fz.frozen, j.dep.ID, fz.secrets); err != nil {
		return stagingFailed("the frozen model cannot be materialized", "")
	}
	marker := h.cfg.IDs.NewID().String()
	pre, _ := json.Marshal(map[string]string{"directory": j.dep.ID.String()})
	return h.dispatch(ctx, j, step, "compose.materialize", marker, pre, func() error {
		return j.stage().Materialize(ctx, j.mode, j.dir(), marker, fz.frozen, fz.secrets)
	})
}

func (h deployHandler) deploy(ctx context.Context, j *deployJob, step deployments.Step) error {
	marker := h.cfg.IDs.NewID().String()
	return h.dispatch(ctx, j, step, "compose.up", marker, nil, func() error {
		return deployRun{exec: j.ex}.Up(ctx, j.mode, j.dir(), marker)
	})
}

func (h deployHandler) verifyHealth(ctx context.Context, j *deployJob, fz frozenDeployment) error {
	verdict, err := h.healthVerifier(j.ex).verify(ctx, fz.healthRun(j.container()))
	if err != nil {
		return err
	}
	if !verdict.Healthy {
		return unhealthyError{verdict.Failure}
	}
	return nil
}

func (h deployHandler) healthVerifier(node transport.Executor) healthVerifier {
	return healthVerifier{Node: node, HTTP: h.http, Sleep: h.sleep}
}

// dispatch records a durable intent, marks it dispatched, runs the command and
// closes the intent. A command that ran and failed (the typed failures of the
// step functions) is a definite failure; anything else after dispatch, a lost
// connection or a cancelled context, leaves the intent recorded and the outcome
// unknown (spec §20.4).
func (h deployHandler) dispatch(ctx context.Context, j *deployJob, step deployments.Step, operation, marker string,
	pre json.RawMessage, run func() error,
) error {
	intent, err := h.store.RecordIntent(ctx, j.lease, jobs.NewIntent{
		Step: step.Name, Operation: operation, TargetType: string(domain.ResourceDeployment), TargetID: j.dep.ID.String(),
		Marker: marker, PreState: pre, DeadlineAt: h.cfg.Clock.Now().Add(step.Deadline + templates.KillAfter),
	})
	if err != nil {
		return err
	}
	if err := h.store.MarkDispatched(ctx, j.lease, intent.ID); err != nil {
		return err
	}
	runErr := run()
	switch {
	case runErr == nil:
		return h.closeIntent(ctx, j, intent.ID, jobs.OutcomeSucceeded)
	case !commandFailed(runErr):
		return restoreOutcomeUnknown(step.Name, runErr)
	}
	if err := h.closeIntent(ctx, j, intent.ID, jobs.OutcomeFailed); err != nil {
		return err
	}
	return runErr
}

func (h deployHandler) closeIntent(ctx context.Context, j *deployJob, intent domain.ID, outcome string) error {
	return h.store.CompleteIntent(ctx, j.lease, intent, outcome, commandExitEvidence(outcome, 0))
}

// commandExitEvidence is what the worker knows when a command's session ended:
// a succeeded command is closed with its live exit status as proven, complete
// evidence, so the reconciler never has to ask the node about it again. A failed
// one records its outcome and status only; it proves nothing.
func commandExitEvidence(outcome string, exit int) json.RawMessage {
	if outcome != jobs.OutcomeSucceeded {
		raw, _ := json.Marshal(map[string]any{"outcome": outcome, "exit_status": exit})
		return raw
	}
	raw, _ := json.Marshal(jobs.Evidence{
		Done: true, ExitStatus: exit, Proof: "ssh_exit", Classification: jobs.ClassComplete,
		Fingerprint: json.RawMessage(`{"marker":"live","exit":0}`),
	})
	return raw
}

// commandFailed reports whether err says the command ran (or was refused by the
// node's lock) and failed, as opposed to its outcome being unknown.
func commandFailed(err error) bool {
	var typed *smerr.Error
	if !errors.As(err, &typed) {
		return false
	}
	return typed.Code == smerr.CodeDeploymentFailed || typed.Reason == smerr.ReasonResourceLocked
}

// ---- recovery and restore -------------------------------------------------------------------

// recover runs a safety recovery: only restore steps, toward the frozen
// rollback target the durable record names (ADR-0029).
func (h deployHandler) recover(ctx context.Context, j *deployJob) error {
	target, err := frozenRecoveryTarget(j.plan, j.dep)
	if err != nil {
		return err
	}
	if err := h.enterRollingBack(ctx, j); err != nil {
		return err
	}
	cause := smerr.New(smerr.CodeDeploymentFailed, "",
		fmt.Sprintf("the deployment was interrupted (%s) and rolled back", j.dep.Recovery.Reason))
	return h.restoreAndSettle(ctx, j, target, cause)
}

func (h deployHandler) enterRollingBack(ctx context.Context, j *deployJob) error {
	return h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		dep, err := database.GetDeployment(ctx, tx, j.dep.ID)
		if err != nil || dep.State == deployments.StateRollingBack {
			return err
		}
		return h.moveTo(ctx, tx, j.dep.ID, deployments.StateRollingBack, database.StateFailure{})
	})
}

// restoreAndSettle redeploys the known-good snapshot and settles the deployment
// as rolled_back or rollback_failed. The job still ends failed: the deployment
// did not reach its goal.
func (h deployHandler) restoreAndSettle(ctx context.Context, j *deployJob, target domain.ID, cause error) error {
	res, err := h.restore(ctx, j, target)
	if err != nil {
		return err
	}
	err = h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		state, err := settleRestore(ctx, tx, j.dep.ID, res, h.cfg.Clock.Now())
		if err != nil {
			return err
		}
		return h.announce(ctx, tx, j.dep.ID, state)
	})
	if err != nil {
		return err
	}
	if res.Restored {
		return fmt.Errorf("rolled back to deployment %s: %w", target, cause)
	}
	return smerr.Wrap(cause, smerr.CodeRollbackFailed, "", "the previous version could not be restored: "+res.Detail)
}

func (h deployHandler) restore(ctx context.Context, j *deployJob, target domain.ID) (restoreResult, error) {
	snap, err := h.restoreSnapshot(ctx, j, target)
	if isTyped(err) {
		return restoreResult{FailedStep: causeRestoreSnapshot, Detail: err.Error()}, nil
	}
	if err != nil {
		return restoreResult{}, err
	}
	r := restorer{
		Node: j.ex, Ledger: deployLedger{h: h, lease: j.lease}, Health: h.healthVerifier(j.ex),
		IDs: h.cfg.IDs, Clock: h.cfg.Clock,
		Verify: func(ctx context.Context, v restoreVerification) ([]string, error) {
			dir := deployDir{Root: v.Snapshot.Root, Project: v.Snapshot.Project, Deployment: v.Directory}
			return nil, j.stage().stageVerify(ctx, dir, v.Snapshot.Frozen, v.Snapshot.Secrets)
		},
	}
	return r.run(ctx, snap)
}

func (h deployHandler) restoreSnapshot(ctx context.Context, j *deployJob, target domain.ID) (restoreSnapshot, error) {
	q := h.cfg.DB.Reader()
	good, err := database.GetDeployment(ctx, q, target)
	if err != nil {
		return restoreSnapshot{}, err
	}
	kg, err := loadKnownGood(ctx, q, good)
	if err != nil {
		return restoreSnapshot{}, err
	}
	fz, err := h.freeze(ctx, kg.plan.Content)
	if err != nil {
		return restoreSnapshot{}, err
	}
	return restoreSnapshot{
		Deployment: j.dep.ID, Attempt: int(j.lease.Generation), Project: j.target.ComposeProject, Root: j.root,
		Frozen: fz.frozen, Secrets: fz.secrets, Health: fz.healthRun(j.container()),
	}, nil
}

// deployLedger is the lease-fenced restoreLedger: intents through the job
// store, step rows through a fenced write.
type deployLedger struct {
	h     deployHandler
	lease jobs.Lease
}

func (l deployLedger) RecordIntent(ctx context.Context, ni jobs.NewIntent) (domain.ID, error) {
	intent, err := l.h.store.RecordIntent(ctx, l.lease, ni)
	return intent.ID, err
}

func (l deployLedger) MarkDispatched(ctx context.Context, intent domain.ID) error {
	return l.h.store.MarkDispatched(ctx, l.lease, intent)
}

func (l deployLedger) CompleteIntent(ctx context.Context, intent domain.ID, outcome string, evidence json.RawMessage) error {
	return l.h.store.CompleteIntent(ctx, l.lease, intent, outcome, evidence)
}

func (l deployLedger) StartStep(ctx context.Context, s database.DeploymentStep) error {
	return l.h.fenced(ctx, l.lease, func(ctx context.Context, tx *database.Tx) error {
		return database.InsertDeploymentStep(ctx, tx, s)
	})
}

func (l deployLedger) FinishStep(ctx context.Context, s database.DeploymentStep) error {
	return l.h.fenced(ctx, l.lease, func(ctx context.Context, tx *database.Tx) error {
		return database.UpdateDeploymentStep(ctx, tx, s)
	})
}

// ---- frozen content ---------------------------------------------------------------------------

// freeze reads the snapshot rows a plan's content binds and resolves the
// secret versions it pins. A missing row or version fails closed.
func (h deployHandler) freeze(ctx context.Context, c plan.Content) (frozenDeployment, error) {
	q := h.cfg.DB.Reader()
	var fz frozenDeployment
	model, err := readSnapshotJSON[composeSnapshot](ctx, q, c.ComposeHash)
	if err != nil {
		return fz, err
	}
	if fz.frozen, err = model.Frozen(*c.ComposeHash); err != nil {
		return fz, err
	}
	if fz.health, err = readSnapshotJSON[*health.Check](ctx, q, c.HealthHash); err != nil {
		return fz, err
	}
	if fz.policy, err = readSnapshotJSON[policySnapshot](ctx, q, c.DeploymentPolicyHash); err != nil {
		return fz, err
	}
	fz.secrets, err = h.resolveSecrets(ctx, fz.frozen.Secrets)
	return fz, err
}

func readSnapshotJSON[T any](ctx context.Context, q database.Querier, hash *string) (T, error) {
	var out T
	if hash == nil {
		return out, smerr.New(smerr.CodeInternal, "", "the plan binds no snapshot")
	}
	row, err := database.GetExecutionSnapshot(ctx, q, *hash)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return out, revalidationStagingFailed(deployments.CauseSnapshotGone, "snapshot %s no longer exists", *hash)
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(row.Content, &out); err != nil {
		return out, fmt.Errorf("snapshot %s is unreadable: %w", *hash, err)
	}
	return out, nil
}

func (h deployHandler) resolveSecrets(ctx context.Context, uses []compose.SecretUse) ([]compose.ResolvedSecret, error) {
	var out []compose.ResolvedSecret
	seen := map[secrets.Ref]bool{}
	for _, use := range uses {
		ref := secrets.Ref{Name: use.Ref, Version: int(use.Version)}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		value, err := h.secrets.Get(ctx, ref)
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			return nil, revalidationStagingFailed(deployments.CauseSecretVersionGone, "version %d of secret %s no longer exists", use.Version, use.Ref)
		}
		if err != nil {
			return nil, fmt.Errorf("resolve secret %s: %w", use.Ref, err)
		}
		out = append(out, compose.ResolvedSecret{Ref: use.Ref, Version: use.Version, Value: value})
	}
	return out, nil
}

// ---- deployment state and step rows -----------------------------------------------------------

// fenced runs fn in a write transaction whose first statement is the fence.
func (h deployHandler) fenced(ctx context.Context, lease jobs.Lease, fn func(ctx context.Context, tx *database.Tx) error) error {
	return h.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
}

var forwardStates = []deployments.State{
	deployments.StatePreparing, deployments.StateStaging, deployments.StateDeploying, deployments.StateVerifying,
}

// stateOfStep is the fine state a forward step runs in (spec §20.1).
func stateOfStep(step string) deployments.State {
	switch step {
	case deployments.StepPull, deployments.StepMaterialize, deployments.StepVerifyOnNode:
		return deployments.StateStaging
	case deployments.StepDeploy:
		return deployments.StateDeploying
	case deployments.StepHealthCheck:
		return deployments.StateVerifying
	}
	return deployments.StatePreparing
}

// enter walks the deployment forward to state to, one §20.1 transition at a
// time: a claim leaves it queued or interrupted, and a resumed run may start
// past the states it already went through.
func (h deployHandler) enter(ctx context.Context, j *deployJob, to deployments.State) error {
	return h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		dep, err := database.GetDeployment(ctx, tx, j.dep.ID)
		if err != nil {
			return err
		}
		from, target := slices.Index(forwardStates, dep.State), slices.Index(forwardStates, to)
		if target <= from {
			return nil
		}
		for _, next := range forwardStates[from+1 : target+1] {
			if err := h.moveTo(ctx, tx, j.dep.ID, next, database.StateFailure{}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (h deployHandler) moveTo(ctx context.Context, tx *database.Tx, id domain.ID, to deployments.State, failure database.StateFailure) error {
	if err := database.TransitionDeployment(ctx, tx, id, to, failure, h.cfg.Clock.Now()); err != nil {
		return err
	}
	return h.announce(ctx, tx, id, to)
}

// announce records the state a deployment entered as an audit event.
func (h deployHandler) announce(ctx context.Context, q database.Querier, id domain.ID, state deployments.State) error {
	result := domain.ResultSucceeded
	if state == deployments.StateFailed || state == deployments.StateRollbackFailed || state == deployments.StateRolledBack {
		result = domain.ResultFailed
	}
	return h.emit(ctx, q, systemActor, "deployment."+string(state), deploymentResource(id), result, map[string]any{"state": string(state)})
}

// failDeployment ends the deployment as failed with the code, reason and cause
// of err, and returns err for the job.
func (h deployHandler) failDeployment(ctx context.Context, j *deployJob, err error) error {
	failure := failureOfDeployment(err)
	if ferr := h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		return h.moveTo(ctx, tx, j.dep.ID, deployments.StateFailed, failure)
	}); ferr != nil {
		return ferr
	}
	return err
}

func failureOfDeployment(err error) database.StateFailure {
	var typed *smerr.Error
	if !errors.As(err, &typed) {
		return database.StateFailure{Code: string(smerr.CodeInternal)}
	}
	failure := database.StateFailure{Code: string(typed.Code), Reason: string(typed.Reason)}
	if cause, ok := typed.Details["cause"].(string); ok && typed.Reason != "" {
		failure.Cause = cause
	}
	return failure
}

func (h deployHandler) startStep(ctx context.Context, j *deployJob, ordinal int, name string) (database.DeploymentStep, error) {
	now := h.cfg.Clock.Now()
	row := database.DeploymentStep{
		ID: h.cfg.IDs.NewID(), DeploymentID: j.dep.ID, Ordinal: ordinal, Name: name,
		Attempt: int(j.lease.Generation), State: database.StepRunning, StartedAt: &now,
	}
	return row, h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		return database.InsertDeploymentStep(ctx, tx, row)
	})
}

func (h deployHandler) finishStep(ctx context.Context, j *deployJob, row database.DeploymentStep, state database.StepState, output, detail string) error {
	now := h.cfg.Clock.Now()
	row.State, row.FinishedAt, row.OutputRef = state, &now, output
	if detail != "" {
		row.ErrorJSON, _ = json.Marshal(map[string]string{"detail": detail})
	}
	return h.fenced(ctx, j.lease, func(ctx context.Context, tx *database.Tx) error {
		return database.UpdateDeploymentStep(ctx, tx, row)
	})
}
