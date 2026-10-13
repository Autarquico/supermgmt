package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// reconcileWorld is a deployWorld whose job store runs the production
// DeploymentPolicy and whose reconciler reads the production
// DeploymentEvidence, over a fake node that answers marker.state and the
// project's containers as the test scripts them.
type reconcileWorld struct {
	*deployWorld
	router *EvidenceRouter

	markersMu sync.Mutex
	markers   map[string]string // marker -> marker.state output; default "done 0"
}

func newReconcileWorld(t *testing.T) *reconcileWorld {
	t.Helper()
	w := &reconcileWorld{deployWorld: newDeployWorld(t), markers: map[string]string{}}
	revalidator, err := NewRevalidator(w.cfg)
	mustf(t, err, "NewRevalidator")
	policy, err := NewDeploymentPolicy(w.cfg, revalidator)
	mustf(t, err, "NewDeploymentPolicy")
	w.store, err = jobs.NewStore(jobs.Config{
		DB: w.db, Clock: w.clock, IDs: w.ids, Revalidator: revalidator, LockPlanner: LockPlanner{},
		TypePolicies: policy.TypePolicies(),
	})
	mustf(t, err, "NewStore")
	w.handler.store = w.store
	evidence, err := NewDeploymentEvidence(w.cfg, Connector{}, w.store)
	mustf(t, err, "NewDeploymentEvidence")
	evidence.dial = func(domain.Node, *runtimes.SetupMeta) (transport.Executor, error) { return w.remote, nil }
	w.router, err = NewEvidenceRouter(w.cfg, Connector{}, nil, WithDeploymentEvidence(evidence))
	mustf(t, err, "NewEvidenceRouter")
	w.remote.on("marker.state", w.markerReply)
	return w
}

func (r *reconcileWorld) markerReply(c templates.Command) (transport.Result, error) {
	fields := strings.Fields(c.Line)
	marker := strings.Trim(fields[len(fields)-1], "'")
	r.markersMu.Lock()
	defer r.markersMu.Unlock()
	state, ok := r.markers[marker]
	if !ok {
		state = "done 0"
	}
	return transport.Result{Stdout: []byte(state + "\n")}, nil
}

func (r *reconcileWorld) markerIs(in jobs.Intent, state string) {
	r.markersMu.Lock()
	defer r.markersMu.Unlock()
	r.markers[in.Marker] = state
}

// crashAt claims the next job and runs it until the command of template is
// sent and the connection is lost, then lets the lease expire, interrupts the
// job and moves the clock past every dispatched command's deadline plus the
// reconcile grace, so the reconciler may ask for evidence.
func (r *reconcileWorld) crashAt(template string) jobs.Job {
	r.t.Helper()
	r.remote.down(template, errors.New("connection lost"))
	claimed, ok := r.claim()
	if !ok {
		r.t.Fatal("no deployment job to claim")
	}
	if err := r.handler.Run(context.Background(), claimed.Lease); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		r.t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	r.remote.exit(template, 0) // the node is back for whatever runs next
	r.interrupt()
	return claimed.Job
}

// interrupt lets the lease expire and the reconciler take the job over.
func (r *reconcileWorld) interrupt() {
	r.t.Helper()
	r.clock.Advance(31 * time.Second)
	taken, err := r.store.Takeover(context.Background(), "test")
	if err != nil || len(taken) != 1 {
		r.t.Fatalf("Takeover = %v, %v", taken, err)
	}
	r.workerRecordedLiveExits(taken[0])
	r.pastEveryDeadline(taken[0])
}

// liveExitEvidence is what a worker knows when its ssh session returns exit 0
// for a command: the command completed. The handler closes its intents with it
// (see Open Questions), so an earlier step's proof does not depend on the
// reconciler asking the node inside that step's evidence window.
const liveExitEvidence = `{"done":true,"exit_status":0,"proof":"ssh_exit","classification":"complete","fingerprint":{"marker":"live","exit":0}}`

func (r *reconcileWorld) workerRecordedLiveExits(job domain.ID) {
	r.t.Helper()
	r.exec(`UPDATE operation_intents SET evidence_json = ? WHERE job_id = ? AND state = 'completed' AND outcome = 'succeeded'`,
		liveExitEvidence, job)
}

// pastEveryDeadline moves the clock just beyond the latest deadline plus grace
// among the job's intents the worker never closed.
func (r *reconcileWorld) pastEveryDeadline(job domain.ID) {
	r.t.Helper()
	latest := r.clock.Now()
	for _, in := range r.intents(job) {
		if settled := in.DeadlineAt.Add(46 * time.Second); in.State == jobs.IntentRecorded && settled.After(latest) {
			latest = settled
		}
	}
	r.clock.Advance(latest.Sub(r.clock.Now()))
}

// settle runs the reconciler twice, spaced like two samples.
func (r *reconcileWorld) settle() {
	r.t.Helper()
	r.reconcile()
	r.clock.Advance(31 * time.Second)
	r.reconcile()
}

func (r *reconcileWorld) reconcile() {
	r.t.Helper()
	if _, err := r.store.Reconcile(context.Background(), r.router); err != nil {
		r.t.Fatalf("Reconcile: %v", err)
	}
}

func (r *reconcileWorld) intentOf(job domain.ID, step string) jobs.Intent {
	r.t.Helper()
	for _, in := range slices.Backward(r.intents(job)) {
		if in.Step == step {
			return in
		}
	}
	r.t.Fatalf("job %s has no intent of step %s", job, step)
	return jobs.Intent{}
}

func (r *reconcileWorld) containersOf(content plan.Content, directory domain.ID) []upContainer {
	r.t.Helper()
	images, err := frozenImagesOf(context.Background(), r.db.Reader(), content)
	mustf(r.t, err, "frozenImagesOf")
	var out []upContainer
	for service, ref := range images {
		out = append(out, evidenceContainer(service, "ctr-"+service, ref, directory, "running", 0))
	}
	slices.SortFunc(out, func(a, b upContainer) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (r *reconcileWorld) projectIs(containers []upContainer) {
	r.t.Helper()
	raw, err := json.Marshal(containers)
	mustf(r.t, err, "marshal containers")
	r.remote.reply("compose.project_containers", string(raw))
}

func (r *reconcileWorld) recovery(id domain.ID) *deployments.Recovery { return r.row(id).Recovery }

func (r *reconcileWorld) revokeRequester(id domain.ID) {
	r.creds.set(r.row(id).Credential.ID, CredentialRevoked)
}

// systemRecoveryClaims counts the claims the system made in safety recovery.
func (r *reconcileWorld) systemRecoveryClaims(job domain.ID) int {
	r.t.Helper()
	var n int
	err := r.db.Reader().QueryRowContext(context.Background(), `
		SELECT count(*) FROM events WHERE action = 'job.running' AND resource_id = ? AND actor_type = 'system'
		  AND json_extract(data_json, '$.mode') = 'safety_recovery'`, job).Scan(&n)
	mustf(r.t, err, "count recovery claims")
	return n
}

// ---- the policy as a pure table -----------------------------------------------------------------

func TestDeploymentPolicy_AdmitsEveryProvenClassificationButUnknown(t *testing.T) {
	policy := &DeploymentPolicy{}
	for class, want := range map[jobs.Classification]bool{
		jobs.ClassComplete: true, jobs.ClassNotStarted: true, jobs.ClassPartialStable: true, jobs.ClassUnknown: false, "": false,
	} {
		if got := policy.Admit(jobs.Evidence{Classification: class}); got != want {
			t.Errorf("Admit(%q) = %v, want %v", class, got, want)
		}
	}
}

func TestMirroredState(t *testing.T) {
	type step struct {
		cur  deployments.State
		to   domain.JobState
		mode jobs.ClaimMode
		want deployments.State // "" = the deployment stays
	}
	for _, s := range []step{
		{deployments.StateAwaitingApproval, domain.JobQueued, jobs.ClaimForward, deployments.StateQueued},
		{deployments.StateInterrupted, domain.JobQueued, jobs.ClaimForward, ""},
		{deployments.StateQueued, domain.JobAwaitingApproval, jobs.ClaimForward, deployments.StateAwaitingApproval},
		{deployments.StateQueued, domain.JobRunning, jobs.ClaimForward, deployments.StatePreparing},
		{deployments.StateInterrupted, domain.JobRunning, jobs.ClaimForward, deployments.StatePreparing},
		{deployments.StateStaging, domain.JobRunning, jobs.ClaimForward, ""}, // a retry keeps its place
		{deployments.StateInterrupted, domain.JobRunning, jobs.ClaimRecovery, deployments.StateRollingBack},
		{deployments.StateQueued, domain.JobRunning, jobs.ClaimRecovery, ""},
		{deployments.StateDeploying, domain.JobInterrupted, jobs.ClaimForward, deployments.StateInterrupted},
		{deployments.StateRollingBack, domain.JobInterrupted, jobs.ClaimForward, deployments.StateInterrupted},
		{deployments.StateQueued, domain.JobInterrupted, jobs.ClaimForward, ""},
		{deployments.StateVerifying, domain.JobSucceeded, jobs.ClaimForward, deployments.StateSucceeded},
		{deployments.StateStaging, domain.JobFailed, jobs.ClaimForward, deployments.StateFailed},
		{deployments.StateQueued, domain.JobFailed, jobs.ClaimForward, deployments.StateFailed},
		{deployments.StateRollingBack, domain.JobFailed, jobs.ClaimForward, deployments.StateRollbackFailed},
		{deployments.StateQueued, domain.JobCancelled, jobs.ClaimForward, deployments.StateCancelled},
		{deployments.StateStaging, domain.JobCancelled, jobs.ClaimForward, ""},
		{deployments.StateRolledBack, domain.JobFailed, jobs.ClaimForward, ""}, // settled by the handler
		{deployments.StateSucceeded, domain.JobSucceeded, jobs.ClaimForward, ""},
	} {
		got, moved := mirroredState(s.cur, s.to, s.mode)
		if (s.want == "") == moved || got != s.want && moved {
			t.Errorf("mirroredState(%s, job %s, mode %d) = %q, %v; want %q", s.cur, s.to, s.mode, got, moved, s.want)
		}
	}
}

func TestNewDeploymentPolicy_NeedsTheRevalidator(t *testing.T) {
	f := newFixture(t)
	if _, err := NewDeploymentPolicy(f.cfg, nil); err == nil {
		t.Fatal("a policy without the revalidator was accepted")
	}
}

// ---- the claim mirrors the deployment ---------------------------------------------------------------

func TestDeploymentMirror_TheJobCarriesTheDeploymentThroughClaimAndInterruption(t *testing.T) {
	w := newReconcileWorld(t)
	dep := w.queued()
	w.want(dep.ID, deployments.StateQueued)

	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no claim")
	}
	w.want(dep.ID, deployments.StatePreparing)

	w.clock.Advance(31 * time.Second)
	if _, err := w.store.Takeover(context.Background(), "test"); err != nil {
		t.Fatalf("Takeover: %v", err)
	}
	w.want(dep.ID, deployments.StateInterrupted)
	if got := w.job(claimed.Job.ID).State; got != domain.JobInterrupted {
		t.Errorf("job = %s, want interrupted", got)
	}
}

// ---- killed CLI: no proof, no decision ---------------------------------------------------------

func TestReconcileDeploy_KilledCLIHeldDespiteStableSamples(t *testing.T) {
	w := newReconcileWorld(t)
	next, _ := w.afterKnownGood()
	job := w.crashAt("compose.up")
	up := w.intentOf(job.ID, deployments.StepDeploy)
	w.markerIs(up, "started") // compose was killed: there is no .done
	w.projectIs(w.containersOf(w.planOf(next.ID).Content, next.ID))

	w.settle()
	w.settle()

	ev, err := w.router.Collect(context.Background(), up)
	mustf(t, err, "Collect")
	if ev.Classification != jobs.ClassComplete || ev.Proven() {
		t.Fatalf("evidence %+v: the containers must look complete and stable while nothing is proven", ev)
	}
	if got := w.job(job.ID).State; got != domain.JobInterrupted {
		t.Errorf("job = %s, want it held interrupted", got)
	}
	if len(w.heldLocks(job.ID)) == 0 {
		t.Error("a held job must keep its locks")
	}
	row := w.want(next.ID, deployments.StateInterrupted)
	if row.Recovery != nil {
		t.Errorf("recovery record %+v written without proof", row.Recovery)
	}
}

// ---- after deploying -------------------------------------------------------------------------------

func TestReconcileDeploy_ProvenPartialUpdateIsRolledBackBySystemToTheFrozenTarget(t *testing.T) {
	w := newReconcileWorld(t)
	next, good := w.afterKnownGood()
	job := w.crashAt("compose.up")
	w.markerIs(w.intentOf(job.ID, deployments.StepDeploy), "done 0")
	half := w.containersOf(w.planOf(next.ID).Content, next.ID)
	half[0].Config.Image = "ghcr.io/acme/other@sha256:" + strings.Repeat("f", 64)
	w.projectIs(half)

	w.settle()

	if got := w.job(job.ID).State; got != domain.JobQueued {
		t.Fatalf("job = %s, want queued for the recovery", got)
	}
	record := w.recovery(next.ID)
	if record == nil || record.Mode != deployments.RecoverySafetyRecovery || record.Target == nil || *record.Target != good.ID {
		t.Fatalf("recovery record %+v, want safety recovery toward the frozen target %s", record, good.ID)
	}
	if len(w.heldLocks(job.ID)) == 0 {
		t.Error("locks must survive the requeue")
	}

	w.revokeRequester(next.ID) // the requester is gone; recovery does not ask them
	claimed, ok := w.claim()
	if !ok {
		t.Fatal("the recovery claim was refused")
	}
	w.want(next.ID, deployments.StateRollingBack)
	if w.systemRecoveryClaims(job.ID) != 1 {
		t.Error("the claim must be recorded as the system's safety recovery")
	}
	err := w.handler.Run(context.Background(), claimed.Lease)
	wantError(t, err, smerr.CodeDeploymentFailed, "")
	w.want(next.ID, deployments.StateRolledBack)
	if got := w.remote.count("compose.pull"); got != 2 {
		t.Errorf("compose.pull ran %d times, want the interrupted update's and the restore's only", got)
	}
	names := w.stepNames(next.ID)
	if tail := names[len(names)-5:]; tail[0] != deployments.StepRestorePull || tail[4] != deployments.StepRestoreHealthCheck {
		t.Errorf("last step rows = %v, want the five restore steps", tail)
	}
}

func TestReconcileDeploy_ProvenPartialUpdateWithoutRollbackFailsWithItsCause(t *testing.T) {
	w := newReconcileWorld(t)
	dep := w.queued() // the first deployment of the target: nothing to go back to
	job := w.crashAt("compose.up")
	w.markerIs(w.intentOf(job.ID, deployments.StepDeploy), "done 0")
	half := w.containersOf(w.planOf(dep.ID).Content, dep.ID)
	half[0].Config.Image = "ghcr.io/acme/other@sha256:" + strings.Repeat("e", 64)
	w.projectIs(half)

	w.settle()

	if got := w.job(job.ID).State; got != domain.JobFailed {
		t.Fatalf("job = %s, want failed", got)
	}
	row := w.want(dep.ID, deployments.StateFailed)
	if row.Failure.Reason != string(smerr.ReasonRollbackUnavailable) || row.Failure.Cause != deployments.CauseNoKnownGood {
		t.Errorf("failure %+v, want ROLLBACK_UNAVAILABLE / NO_KNOWN_GOOD", row.Failure)
	}
	if len(w.heldLocks(job.ID)) != 0 {
		t.Error("a failed job must release its locks")
	}
}

func TestReconcileDeploy_CompleteAndVerifiedIsSucceededAndKnownGood(t *testing.T) {
	w := newReconcileWorld(t)
	dep := w.queued()
	job := w.crashAt("compose.up")
	w.markerIs(w.intentOf(job.ID, deployments.StepDeploy), "done 0")
	w.projectIs(w.containersOf(w.planOf(dep.ID).Content, dep.ID))
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := w.clock.Now()
		return database.InsertDeploymentStep(ctx, tx, database.DeploymentStep{
			ID: w.ids.NewID(), DeploymentID: dep.ID, Ordinal: 6, Name: deployments.StepHealthCheck,
			State: database.StepSucceeded, Attempt: 1, StartedAt: &now, FinishedAt: &now,
		})
	})

	w.settle()

	if got := w.job(job.ID).State; got != domain.JobSucceeded {
		t.Fatalf("job = %s, want succeeded", got)
	}
	if row := w.want(dep.ID, deployments.StateSucceeded); !row.KnownGood {
		t.Error("a deployment the evidence proved healthy must be known good")
	}
}

func TestReconcileDeploy_CompleteButUnverifiedResumesForwardAndSkipsTheProvenDeploy(t *testing.T) {
	w := newReconcileWorld(t)
	next, _ := w.afterKnownGood()
	job := w.crashAt("compose.up")
	w.markerIs(w.intentOf(job.ID, deployments.StepDeploy), "done 0")
	w.projectIs(w.containersOf(w.planOf(next.ID).Content, next.ID))

	w.settle()

	if got := w.job(job.ID).State; got != domain.JobQueued {
		t.Fatalf("job = %s, want queued", got)
	}
	record := w.recovery(next.ID)
	if record == nil || record.Mode != deployments.RecoveryForward || record.ResumeStep != deployments.StepHealthCheck {
		t.Fatalf("recovery record %+v, want a forward resume at the health check", record)
	}
	if got := w.steps(next.ID)[deployments.StepDeploy]; got != database.StepSucceeded {
		t.Errorf("deploy step = %s, want succeeded by the evidence", got)
	}
	upsBefore := w.remote.count("compose.up")

	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no claim")
	}
	mustf(t, w.handler.Run(context.Background(), claimed.Lease), "resumed Run")

	w.want(next.ID, deployments.StateSucceeded)
	if w.remote.count("compose.up") != upsBefore {
		t.Error("the proven compose up was run again")
	}
}

// ---- before deploying -------------------------------------------------------------------------------

func TestReconcileDeploy_InterruptedBeforeDeployResumesForwardAndFinishes(t *testing.T) {
	w := newReconcileWorld(t)
	dep := w.queued()
	job := w.crashAt("compose.pull")
	w.markerIs(w.intentOf(job.ID, deployments.StepPull), "absent") // the pull never began

	w.settle()

	record := w.recovery(dep.ID)
	if record == nil || record.Mode != deployments.RecoveryForward || record.ResumeStep != deployments.StepPull {
		t.Fatalf("recovery record %+v, want a forward resume at pull", record)
	}
	if w.row(dep.ID).MutationStarted {
		t.Fatal("the services were never touched")
	}
	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no forward claim")
	}
	mustf(t, w.handler.Run(context.Background(), claimed.Lease), "resumed Run")
	if row := w.want(dep.ID, deployments.StateSucceeded); !row.KnownGood {
		t.Error("the resumed deployment must end known good")
	}
}

func TestReconcileDeploy_InterruptedBeforeDeployWithNoAttemptLeftFailsWithItsReason(t *testing.T) {
	w := newReconcileWorld(t)
	dep := w.queued()
	job := w.crashAt("compose.pull")
	w.markerIs(w.intentOf(job.ID, deployments.StepPull), "absent")
	w.exec(`UPDATE jobs SET attempts = max_attempts WHERE id = ?`, job.ID)

	w.settle()

	if got := w.job(job.ID).State; got != domain.JobFailed {
		t.Fatalf("job = %s, want failed", got)
	}
	w.wantFailedWith(dep.ID, smerr.CodeDeploymentFailed, smerr.ReasonInterruptedBeforeDeploy)
}

// ---- forward resume re-runs the claim revalidation ----------------------------------------------------

func TestReconcileDeploy_ForwardResumeBeforeDeployFailsWithTheRevalidationReason(t *testing.T) {
	w := newReconcileWorld(t)
	dep := w.queued()
	job := w.crashAt("compose.pull")
	w.markerIs(w.intentOf(job.ID, deployments.StepPull), "absent")
	w.settle()
	w.revokeRequester(dep.ID)

	if _, ok := w.claim(); ok {
		t.Fatal("a revoked requester's deployment was claimed")
	}

	if got := w.job(job.ID).State; got != domain.JobFailed {
		t.Fatalf("job = %s, want failed", got)
	}
	w.wantFailedWith(dep.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestReconcileDeploy_ForwardResumeAfterDeployingOnlyRollsBack(t *testing.T) {
	w := newReconcileWorld(t)
	next, good := w.afterKnownGood()
	job := w.crashAt("compose.up")
	w.markerIs(w.intentOf(job.ID, deployments.StepDeploy), "done 0")
	w.projectIs(w.containersOf(w.planOf(next.ID).Content, next.ID))
	w.settle() // complete but unverified: a forward resume
	if record := w.recovery(next.ID); record == nil || record.Mode != deployments.RecoveryForward {
		t.Fatalf("recovery record %+v, want a forward resume", record)
	}
	w.revokeRequester(next.ID) // the forward revalidation will now fail

	claimed, ok := w.claim()
	if !ok {
		t.Fatal("the claim must proceed as a safety recovery")
	}

	row := w.want(next.ID, deployments.StateRollingBack)
	if row.Recovery == nil || row.Recovery.Mode != deployments.RecoverySafetyRecovery || *row.Recovery.Target != good.ID {
		t.Errorf("recovery record %+v, want safety recovery toward %s", row.Recovery, good.ID)
	}
	if !strings.Contains(row.Recovery.Reason, string(smerr.ReasonCredentialRevoked)) {
		t.Errorf("recovery reason %q must keep the failed revalidation", row.Recovery.Reason)
	}
	if w.systemRecoveryClaims(job.ID) != 1 {
		t.Error("the escalated claim must be recorded as the system's")
	}
	_ = w.handler.Run(context.Background(), claimed.Lease)
	w.want(next.ID, deployments.StateRolledBack)
	if n := w.remote.count("compose.up"); n != 2 {
		t.Errorf("compose.up count = %d, want the interrupted update and the restore", n)
	}
}

// ---- interrupted while restoring ------------------------------------------------------------------------

// crashDuringRestore interrupts a safety recovery at the restore's compose up.
func (w *reconcileWorld) crashDuringRestore() (next, good database.Deployment, restoreUp jobs.Intent) {
	w.t.Helper()
	next, good = w.afterKnownGood()
	job := w.crashAt("compose.up")
	w.markerIs(w.intentOf(job.ID, deployments.StepDeploy), "done 0")
	half := w.containersOf(w.planOf(next.ID).Content, next.ID)
	half[0].Config.Image = "ghcr.io/acme/other@sha256:" + strings.Repeat("d", 64)
	w.projectIs(half)
	w.settle()

	w.remote.down("compose.up", errors.New("connection lost"))
	claimed, ok := w.claim()
	if !ok {
		w.t.Fatal("the recovery claim was refused")
	}
	if err := w.handler.Run(context.Background(), claimed.Lease); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		w.t.Fatalf("recovery Run = %v, want an unknown outcome", err)
	}
	w.remote.exit("compose.up", 0)
	w.interrupt()
	return next, good, w.intentOf(claimed.Job.ID, deployments.StepRestoreDeploy)
}

func TestReconcileDeploy_RestoreThatCompletedAndWasVerifiedIsRolledBack(t *testing.T) {
	w := newReconcileWorld(t)
	next, good, restoreUp := w.crashDuringRestore()
	w.markerIs(restoreUp, "done 0")
	directory := w.restoredDirectory(restoreUp)
	w.projectIs(w.containersOf(w.planOf(good.ID).Content, directory))
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := w.clock.Now()
		return database.InsertDeploymentStep(ctx, tx, database.DeploymentStep{
			ID: w.ids.NewID(), DeploymentID: next.ID, Ordinal: 12, Name: deployments.StepRestoreHealthCheck,
			State: database.StepSucceeded, Attempt: int(restoreUp.LeaseGeneration), StartedAt: &now, FinishedAt: &now,
		})
	})

	w.settle()

	if got := w.job(restoreUp.JobID).State; got != domain.JobFailed {
		t.Fatalf("job = %s, want failed: the deployment did not reach its goal", got)
	}
	w.want(next.ID, deployments.StateRolledBack)
}

func TestReconcileDeploy_RestoreThatWasNotVerifiedRestoresAgain(t *testing.T) {
	w := newReconcileWorld(t)
	next, good, restoreUp := w.crashDuringRestore()
	w.markerIs(restoreUp, "done 0")
	w.projectIs(w.containersOf(w.planOf(good.ID).Content, w.restoredDirectory(restoreUp)))

	w.settle()

	if got := w.job(restoreUp.JobID).State; got != domain.JobQueued {
		t.Fatalf("job = %s, want queued for another restore", got)
	}
	record := w.recovery(next.ID)
	if record == nil || record.Mode != deployments.RecoverySafetyRecovery || *record.Target != good.ID {
		t.Fatalf("recovery record %+v, want safety recovery toward %s", record, good.ID)
	}
	if !strings.Contains(record.Reason, "half way") {
		t.Errorf("recovery reason %q must keep the first cause", record.Reason)
	}
}

func TestReconcileDeploy_RestoreWithNoAttemptLeftIsRollbackFailed(t *testing.T) {
	w := newReconcileWorld(t)
	next, good, restoreUp := w.crashDuringRestore()
	w.markerIs(restoreUp, "done 0")
	w.projectIs(w.containersOf(w.planOf(good.ID).Content, w.restoredDirectory(restoreUp)))
	w.exec(`UPDATE jobs SET attempts = max_attempts WHERE id = ?`, restoreUp.JobID)

	w.settle()

	if got := w.job(restoreUp.JobID).State; got != domain.JobFailed {
		t.Fatalf("job = %s, want failed", got)
	}
	w.want(next.ID, deployments.StateRollbackFailed)
}

// restoredDirectory is the directory the attempt's restore-materialize wrote.
func (w *reconcileWorld) restoredDirectory(up jobs.Intent) domain.ID {
	w.t.Helper()
	pre := w.intentOf(up.JobID, deployments.StepRestoreMaterialize).PreState
	var parsed struct {
		Directory domain.ID `json:"directory"`
	}
	mustf(w.t, json.Unmarshal(pre, &parsed), "restore-materialize pre-state")
	return parsed.Directory
}

// wantFailedWith checks a deployment that failed after it had a plan and a job.
func (r *reconcileWorld) wantFailedWith(id domain.ID, code smerr.Code, reason smerr.Reason) {
	r.t.Helper()
	row := r.want(id, deployments.StateFailed)
	if row.Failure.Code != string(code) || row.Failure.Reason != string(reason) {
		r.t.Fatalf("failure %+v, want %s/%s", row.Failure, code, reason)
	}
}
