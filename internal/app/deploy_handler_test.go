package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const dhSecretValue = "hunter2 $uper s3cret"

// dhSecrets answers every secret version with a recognizable value, so a test
// can look for it where it must never appear.
type dhSecrets struct{ missing bool }

func (s dhSecrets) Get(_ context.Context, ref secrets.Ref) (audit.Secret, error) {
	if s.missing {
		return "", smerr.New(smerr.CodeNotFound, "", "secret version "+ref.String())
	}
	return audit.Secret(dhSecretValue), nil
}

// deployWorld is a finalized deployment, a fake node that behaves like a
// healthy one, and the production handler wired to both.
type deployWorld struct {
	*finFixture
	remote  *fakeNode
	secrets *dhSecrets
	handler deployHandler
	// restoreContent is the known-good content a restore verifies against.
	restoreContent plan.Content
}

var dhDirectory = regexp.MustCompile(`'([0-9a-f-]{36})'$`)

func newDeployWorld(t *testing.T) *deployWorld {
	t.Helper()
	f := newFinFixture(t, finOptions{pinned: true})
	w := &deployWorld{finFixture: f, remote: newFakeNode(t), secrets: &dhSecrets{}}
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		err := database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: capabilitySetup, Available: true, CheckedAt: f.clock.Now(),
			Metadata: map[string]any{"setup_version": 2, "deploy_root": "/srv/supermgmt"},
		})
		if err != nil {
			return err
		}
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: "health.http", Available: true, CheckedAt: f.clock.Now(),
		})
	})
	f.exec(`UPDATE environments SET config_json = json_set(config_json, '$.allow_automatic_rollback', json('true'))`)
	c, err := newCore(f.cfg)
	mustf(t, err, "newCore")
	w.handler = deployHandler{
		core: c, store: f.store, secrets: w.secrets, http: &http.Client{},
		dial:  func(domain.Node, *runtimes.SetupMeta) (transport.Executor, error) { return w.remote, nil },
		sleep: func(context.Context, time.Duration) {},
	}
	w.healthyNode()
	return w
}

// healthyNode makes every template of a deployment succeed.
func (w *deployWorld) healthyNode() {
	w.remote.reply("compose.docker_root", "/var/lib/docker\n")
	w.remote.reply("compose.project_containers", "")
	w.remote.reply("compose.project_resources", "")
	w.remote.reply("compose.listeners", "")
	w.remote.exit("compose.image_inspect", 1)
	w.remote.reply("compose.image_size", "1000\n")
	w.remote.reply("compose.disk_free", preflightDF(1<<40))
	w.remote.exit("compose.pull", 0).exit("compose.materialize", 0).exit("compose.up", 0)
	w.remote.reply("health.http", "200")
	w.remote.on("compose.verify", w.verifyReply)
}

// verifyReply prints what a faithful node resolves for the directory named in
// the command: the deployment's own content, or the known-good one it restores.
func (w *deployWorld) verifyReply(c templates.Command) (transport.Result, error) {
	match := dhDirectory.FindStringSubmatch(c.Line)
	if match == nil {
		return transport.Result{ExitStatus: 2}, nil
	}
	directory := domain.ID(match[1])
	content, ok := w.contentOf(directory)
	if !ok {
		content = w.restoreContent
	}
	fz, err := w.handler.freeze(context.Background(), content)
	if err != nil {
		w.t.Errorf("freeze: %v", err)
		return transport.Result{ExitStatus: 2}, nil
	}
	hashes := compose.ExpectedEnvHashes(fz.frozen, fz.secrets, nil)
	model, err := expectedMaskedModel(fz.frozen, directory, hashes)
	mustf(w.t, err, "expectedMaskedModel")
	out := nodeVerification{Model: model}
	for _, h := range hashes {
		sum := h.SHA256
		out.Set = append(out.Set, nodeEnvHash{Service: h.Service, EnvName: h.EnvName, SHA256: &sum})
	}
	raw, err := json.Marshal(out)
	mustf(w.t, err, "marshal verification")
	return transport.Result{Stdout: raw}, nil
}

func (w *deployWorld) contentOf(directory domain.ID) (plan.Content, bool) {
	row, err := database.GetDeployment(context.Background(), w.db.Reader(), directory)
	if err != nil || row.PlanID == nil {
		return plan.Content{}, false
	}
	return w.planOf(directory).Content, true
}

// queued finalizes one deployment of the target and returns it.
func (w *deployWorld) queued(mutate ...func(*CreateDeployment)) database.Deployment {
	w.t.Helper()
	return w.mustFinalize(w.create(mutate...).ID)
}

// afterKnownGood finalizes a first deployment, settles it as known-good and
// finalizes a second one that froze it as its rollback target.
func (w *deployWorld) afterKnownGood() (next, good database.Deployment) {
	w.t.Helper()
	first := w.queued()
	w.markKnownGood(first.ID)
	w.exec(`UPDATE jobs SET state = 'succeeded' WHERE id = ?`, *first.JobID)
	w.clock.Advance(time.Second)
	next = w.queued(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })
	w.restoreContent = w.planOf(first.ID).Content
	return next, w.row(first.ID)
}

// run claims the next job and runs the handler on its lease.
func (w *deployWorld) run() error {
	w.t.Helper()
	claimed, ok := w.claim()
	if !ok {
		w.t.Fatal("no deployment job to claim")
	}
	return w.handler.Run(context.Background(), claimed.Lease)
}

func (w *deployWorld) templatesRun() []string { return w.remote.ran() }

func (w *deployWorld) calls() []templates.Command {
	w.remote.mu.Lock()
	defer w.remote.mu.Unlock()
	return slices.Clone(w.remote.calls)
}

func (w *deployWorld) callsOf(template string) []templates.Command {
	return slices.DeleteFunc(w.calls(), func(c templates.Command) bool { return c.Template != template })
}

func (w *deployWorld) steps(id domain.ID) map[string]database.StepState {
	w.t.Helper()
	rows, err := database.ListDeploymentSteps(context.Background(), w.db.Reader(), id)
	mustf(w.t, err, "ListDeploymentSteps")
	out := map[string]database.StepState{}
	for _, r := range rows {
		out[r.Name] = r.State
	}
	return out
}

func (w *deployWorld) stepNames(id domain.ID) []string {
	w.t.Helper()
	rows, err := database.ListDeploymentSteps(context.Background(), w.db.Reader(), id)
	mustf(w.t, err, "ListDeploymentSteps")
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Name
	}
	return names
}

func (w *deployWorld) intents(job domain.ID) []jobs.Intent {
	w.t.Helper()
	in, err := w.store.Intents(context.Background(), w.db.Reader(), job)
	mustf(w.t, err, "Intents")
	return in
}

func (w *deployWorld) want(id domain.ID, state deployments.State) database.Deployment {
	w.t.Helper()
	row := w.row(id)
	if row.State != state {
		w.t.Fatalf("deployment state = %s (failure %+v), want %s", row.State, row.Failure, state)
	}
	return row
}

func dhIndexOf(ran []string, template string) int { return slices.Index(ran, template) }

// ---- forward -------------------------------------------------------------------------------------

func TestDeployHandler_ForwardRunSucceedsAndMarksKnownGood(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()

	if err := w.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	row := w.want(dep.ID, deployments.StateSucceeded)
	if !row.KnownGood || !row.MutationStarted {
		t.Errorf("row = %+v, want known good after mutation", row)
	}
	wantSteps := []string{"preflight", "pull", "materialize", "verify-on-node", "deploy", "health-check"}
	if got := w.stepNames(dep.ID); !slices.Equal(got, wantSteps) {
		t.Errorf("step rows = %v, want %v", got, wantSteps)
	}
	for name, state := range w.steps(dep.ID) {
		if state != database.StepSucceeded {
			t.Errorf("step %s is %s", name, state)
		}
	}
	ran := w.templatesRun()
	order := []string{"compose.pull", "compose.materialize", "compose.verify", "compose.up", "health.http"}
	last := -1
	for _, name := range order {
		at := dhIndexOf(ran, name)
		if at <= last {
			t.Errorf("%s ran at %d; want strictly after the previous step in %v", name, at, ran)
		}
		last = at
	}
}

func TestDeployHandler_EveryMutatingCommandHasADurableDispatchedIntent(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()

	if err := w.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	byStep := map[string]jobs.Intent{}
	for _, in := range w.intents(*dep.JobID) {
		byStep[in.Step] = in
		if !in.Dispatched() || in.State != jobs.IntentCompleted || in.Outcome != jobs.OutcomeSucceeded {
			t.Errorf("intent %s = %+v, want completed and succeeded", in.Step, in)
		}
		if in.TargetType != "deployment" || in.TargetID != dep.ID.String() {
			t.Errorf("intent %s targets %s/%s", in.Step, in.TargetType, in.TargetID)
		}
	}
	for _, step := range []string{"pull", "materialize", "deploy"} {
		if _, ok := byStep[step]; !ok {
			t.Errorf("no intent for %s", step)
		}
	}
	pull := w.callsOf("compose.pull")
	if len(pull) != 1 || !strings.Contains(pull[0].Line, byStep["pull"].Marker) {
		t.Errorf("pull ran as %v; its node marker must be the intent's %q", pull, byStep["pull"].Marker)
	}
	up := w.callsOf("compose.up")
	if len(up) != 1 || !strings.Contains(up[0].Line, byStep["deploy"].Marker) {
		t.Errorf("compose.up ran as %v; its node marker must be the intent's %q", up, byStep["deploy"].Marker)
	}
}

func TestDeployHandler_SecretValuesOnlyTravelOnStdin(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()

	if err := w.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sawOnStdin := false
	for _, c := range w.calls() {
		if strings.Contains(c.Line, dhSecretValue) {
			t.Errorf("%s carries the secret in its command line", c.Template)
		}
		if strings.Contains(string(c.Stdin), dhSecretValue) {
			sawOnStdin = true
			if !c.Sensitive {
				t.Errorf("%s sends the secret on stdin without being Sensitive", c.Template)
			}
		}
	}
	if !sawOnStdin {
		t.Error("the secret never reached the node, so this test proves nothing")
	}
	rows, err := database.ListDeploymentSteps(context.Background(), w.db.Reader(), dep.ID)
	mustf(t, err, "ListDeploymentSteps")
	stored, _ := json.Marshal(rows)
	events, _ := json.Marshal(w.events())
	if strings.Contains(string(stored)+string(events), dhSecretValue) {
		t.Error("the secret value leaked into step rows or events")
	}
}

func TestDeployHandler_EntersEachStateOfTheDeploymentInOrder(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()

	if err := w.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var states []string
	for _, e := range w.events() {
		if strings.HasPrefix(e.Action, "deployment.") && e.ResourceID == dep.ID {
			states = append(states, strings.TrimPrefix(e.Action, "deployment."))
		}
	}
	want := []string{"created", "finalized", "preparing", "staging", "deploying", "verifying", "succeeded"}
	if !slices.Equal(states, want) {
		t.Errorf("deployment events = %v, want %v", states, want)
	}
}

// ---- failures before the services change ---------------------------------------------------------

func TestDeployHandler_PreflightFailureStopsBeforeAnythingIsPulled(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	w.remote.reply("compose.project_containers", "") // healthy, then a foreign project owner:
	w.remote.reply("compose.listeners", "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n")

	err := w.run()

	wantError(t, err, smerr.CodeDeploymentFailed, smerr.ReasonPreflightFailed)
	row := w.want(dep.ID, deployments.StateFailed)
	if row.Failure.Reason != string(smerr.ReasonPreflightFailed) || row.Failure.Cause != causePreflightPortInUse {
		t.Errorf("failure = %+v, want PREFLIGHT_FAILED / %s", row.Failure, causePreflightPortInUse)
	}
	for _, name := range []string{"compose.pull", "compose.materialize", "compose.up"} {
		if n := w.remote.count(name); n != 0 {
			t.Errorf("%s ran %d times after a failed preflight", name, n)
		}
	}
	if got := w.steps(dep.ID)["preflight"]; got != database.StepFailed {
		t.Errorf("preflight step = %s, want failed", got)
	}
	if row.MutationStarted {
		t.Error("a failed preflight must not mark the services as touched")
	}
}

func TestDeployHandler_StagingFailureLeavesTheServicesUntouched(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	w.remote.exit("compose.materialize", 1)

	err := w.run()

	wantError(t, err, smerr.CodeDeploymentFailed, smerr.ReasonStagingFailed)
	row := w.want(dep.ID, deployments.StateFailed)
	if row.MutationStarted || w.remote.count("compose.up") != 0 {
		t.Errorf("services were touched: mutation_started=%v, compose.up ran %d times", row.MutationStarted, w.remote.count("compose.up"))
	}
	var failedIntent bool
	for _, in := range w.intents(*dep.JobID) {
		failedIntent = failedIntent || (in.Step == "materialize" && in.Outcome == jobs.OutcomeFailed)
	}
	if !failedIntent {
		t.Error("the failed materialize must close its intent as failed")
	}
}

func TestDeployHandler_AMissingSecretVersionFailsBeforeTheNodeIsTouched(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	w.secrets.missing = true

	err := w.run()

	wantStagingCause(t, err, deployments.CauseSecretVersionGone)
	w.want(dep.ID, deployments.StateFailed)
	if len(w.calls()) != 0 {
		t.Errorf("the node was reached: %v", w.templatesRun())
	}
}

func TestDeployHandler_AMissingSnapshotFailsTheDeployment(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no job")
	}
	w.dropSnapshotRow(*w.planOf(dep.ID).Content.ComposeHash)

	err := w.handler.Run(context.Background(), claimed.Lease)

	wantStagingCause(t, err, deployments.CauseSnapshotGone)
	w.want(dep.ID, deployments.StateFailed)
}

// ---- outcome unknown ----------------------------------------------------------------------------

func TestDeployHandler_ALostConnectionDuringComposeUpLeavesTheOutcomeUnknown(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	w.remote.down("compose.up", errors.New("connection reset"))

	err := w.run()

	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("error = %v, want the outcome to be unknown", err)
	}
	w.want(dep.ID, deployments.StateDeploying)
	var up jobs.Intent
	for _, in := range w.intents(*dep.JobID) {
		if in.Step == "deploy" {
			up = in
		}
	}
	if up.State != jobs.IntentRecorded || !up.Dispatched() {
		t.Errorf("deploy intent = %+v, want recorded and dispatched so the reconciler decides", up)
	}
	if w.remote.count("health.http") != 0 || w.remote.count("compose.pull") > 1 {
		t.Errorf("the run went on after an unknown outcome: %v", w.templatesRun())
	}
}

func TestDeployHandler_ACancelledRunIsNotAFailedDeployment(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no job")
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.remote.on("compose.pull", func(templates.Command) (transport.Result, error) {
		cancel()
		return transport.Result{}, ctx.Err()
	})

	err := w.handler.Run(ctx, claimed.Lease)

	if err == nil {
		t.Fatal("Run returned nil after cancellation")
	}
	if got := w.row(dep.ID).State; got.Terminal() {
		t.Errorf("state = %s; a cancelled run must leave the deployment to takeover", got)
	}
}

// ---- resume --------------------------------------------------------------------------------------

func TestDeployHandler_AResumedRunSkipsTheStepsAnEarlierAttemptFinished(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	now := w.clock.Now()
	for i, name := range []string{"preflight", "pull"} {
		w.inTx(func(ctx context.Context, tx *database.Tx) error {
			return database.InsertDeploymentStep(ctx, tx, database.DeploymentStep{
				ID: w.ids.NewID(), DeploymentID: dep.ID, Ordinal: i + 1, Name: name, State: database.StepSucceeded,
				Attempt: 1, StartedAt: &now, FinishedAt: &now,
			})
		})
	}

	if err := w.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	w.want(dep.ID, deployments.StateSucceeded)
	for _, name := range []string{"compose.pull", "compose.docker_root"} {
		if n := w.remote.count(name); n != 0 {
			t.Errorf("%s ran %d times although its step had finished", name, n)
		}
	}
	if w.remote.count("compose.up") != 1 {
		t.Errorf("compose.up ran %d times, want 1", w.remote.count("compose.up"))
	}
}

// ---- rollback ------------------------------------------------------------------------------------

func TestDeployHandler_AFailedUpdateIsRolledBackToTheFrozenKnownGood(t *testing.T) {
	w := newDeployWorld(t)
	next, good := w.afterKnownGood()
	w.remote.on("compose.up", dhFirstFails(w.remote))

	err := w.run()

	wantError(t, err, smerr.CodeDeploymentFailed, "")
	row := w.want(next.ID, deployments.StateRolledBack)
	if !row.MutationStarted {
		t.Error("the services were touched, mutation_started must say so")
	}
	if n := w.remote.count("compose.up"); n != 2 {
		t.Errorf("compose.up ran %d times, want the update and the restore", n)
	}
	want := []string{"restore-pull", "restore-materialize", "restore-verify-on-node", "restore-deploy", "restore-health-check"}
	names := w.stepNames(next.ID)
	if tail := names[len(names)-len(want):]; !slices.Equal(tail, want) {
		t.Errorf("last step rows = %v, want the restore steps %v (target %s)", tail, want, good.ID)
	}
}

// dhFirstFails fails the first compose.up and lets the next ones succeed.
func dhFirstFails(node *fakeNode) func(templates.Command) (transport.Result, error) {
	return func(templates.Command) (transport.Result, error) {
		if node.count("compose.up") == 1 {
			return transport.Result{ExitStatus: 1}, nil
		}
		return transport.Result{}, nil
	}
}

func TestDeployHandler_UnhealthyDeploymentRollsBackWhenItIsSafe(t *testing.T) {
	w := newDeployWorld(t)
	next, _ := w.afterKnownGood()
	w.remote.on("health.http", func(templates.Command) (transport.Result, error) {
		if w.remote.count("compose.up") == 1 {
			return transport.Result{Stdout: []byte("503")}, nil
		}
		return transport.Result{Stdout: []byte("200")}, nil
	})

	err := w.run()

	wantError(t, err, smerr.CodeDeploymentFailed, smerr.ReasonHealthFailed)
	w.want(next.ID, deployments.StateRolledBack)
	if got := w.steps(next.ID)["health-check"]; got != database.StepFailed {
		t.Errorf("health-check step = %s, want failed", got)
	}
	if got := w.steps(next.ID)["restore-health-check"]; got != database.StepSucceeded {
		t.Errorf("restore-health-check = %s, want succeeded", got)
	}
}

func TestDeployHandler_UnhealthyWithoutAKnownGoodFailsWithItsCause(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	w.remote.reply("health.http", "503")

	err := w.run()

	wantError(t, err, smerr.CodeDeploymentFailed, smerr.ReasonRollbackUnavailable)
	row := w.want(dep.ID, deployments.StateFailed)
	if row.Failure.Reason != string(smerr.ReasonRollbackUnavailable) || row.Failure.Cause != deployments.CauseNoKnownGood {
		t.Errorf("failure = %+v, want ROLLBACK_UNAVAILABLE / %s", row.Failure, deployments.CauseNoKnownGood)
	}
	if row.KnownGood {
		t.Error("an unhealthy deployment must never become known good")
	}
	if w.remote.count("compose.up") != 1 {
		t.Errorf("compose.up ran %d times, want only the update", w.remote.count("compose.up"))
	}
}

func TestDeployHandler_AFailedRestoreNeedsAHuman(t *testing.T) {
	w := newDeployWorld(t)
	next, _ := w.afterKnownGood()
	w.remote.reply("health.http", "503") // never healthy: neither the update nor the restore

	err := w.run()

	wantError(t, err, smerr.CodeRollbackFailed, "")
	w.want(next.ID, deployments.StateRollbackFailed)
}

// ---- safety recovery -----------------------------------------------------------------------------

func TestDeployHandler_RecoveryDispatchesOnlyRestoreSteps(t *testing.T) {
	w := newDeployWorld(t)
	next, good := w.afterKnownGood()
	w.exec(`UPDATE deployments SET state = 'rolling_back', mutation_started = 1 WHERE id = ?`, next.ID)
	w.recordRecovery(next.ID, &good.ID)

	err := w.run()

	if err == nil {
		t.Fatal("a recovered deployment did not reach its goal; the job must end failed")
	}
	w.want(next.ID, deployments.StateRolledBack)
	forwardOnly := []string{
		"compose.docker_root", "compose.project_containers", "compose.project_resources", "compose.listeners",
		"compose.image_inspect", "compose.image_size", "compose.disk_free",
	}
	for _, name := range forwardOnly {
		if n := w.remote.count(name); n != 0 {
			t.Errorf("forward-only template %s ran %d times under safety recovery", name, n)
		}
	}
	for _, name := range w.stepNames(next.ID) {
		if !strings.HasPrefix(name, "restore-") {
			t.Errorf("step row %q is not a restore step", name)
		}
	}
	for _, in := range w.intents(*next.JobID) {
		if !strings.HasPrefix(in.Step, "restore-") {
			t.Errorf("intent for %q is not a restore step", in.Step)
		}
	}
	if w.remote.count("compose.up") != 1 {
		t.Errorf("compose.up ran %d times, want only the restore", w.remote.count("compose.up"))
	}
}

func TestDeployHandler_RecoveryRestoresTheFrozenTargetNotANewerKnownGood(t *testing.T) {
	w := newDeployWorld(t)
	next, good := w.afterKnownGood()
	w.exec(`UPDATE deployments SET state = 'rolling_back', mutation_started = 1 WHERE id = ?`, next.ID)
	w.recordRecovery(next.ID, &good.ID)
	w.clock.Advance(time.Second)
	w.exec(`UPDATE deployments SET known_good = 1, finished_at = ? WHERE id = ?`, domain.UnixMillis(w.clock.Now()), next.ID)

	_ = w.run()

	row := w.want(next.ID, deployments.StateRolledBack)
	pulled := w.callsOf("compose.pull")
	if len(pulled) == 0 || !strings.Contains(pulled[0].Line, "@"+depWebDigest) {
		t.Errorf("restore pulled %v; want the frozen target's digest %s", pulled, depWebDigest)
	}
	if row.Recovery == nil || *row.Recovery.Target != good.ID {
		t.Errorf("recovery record = %+v, want the frozen target %s", row.Recovery, good.ID)
	}
}

func TestDeployHandler_RecoveryWithAnUnreadableTargetEndsRollbackFailed(t *testing.T) {
	w := newDeployWorld(t)
	next, good := w.afterKnownGood()
	w.exec(`UPDATE deployments SET state = 'rolling_back', mutation_started = 1 WHERE id = ?`, next.ID)
	w.recordRecovery(next.ID, &good.ID)
	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no job")
	}
	w.dropSnapshotRow(*w.planOf(good.ID).Content.ComposeHash)

	err := w.handler.Run(context.Background(), claimed.Lease)

	wantError(t, err, smerr.CodeRollbackFailed, "")
	w.want(next.ID, deployments.StateRollbackFailed)
	if len(w.calls()) != 0 {
		t.Errorf("the node was reached with an unreadable snapshot: %v", w.templatesRun())
	}
}

// ---- backup and its gate ---------------------------------------------------------------------------

func TestDeployHandler_BackupGateDeniesASubActionOnAnotherNode(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no job")
	}
	j, err := w.handler.load(context.Background(), claimed.Lease)
	mustf(t, err, "load")
	sub := plan.SubAction{
		Action: policy.ActionNodeBackupTemplateRun,
		Target: plan.SubTarget{Type: "node", ID: w.ids.NewID().String()},
	}

	err = w.handler.backupGate(j)(context.Background(), sub)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	_ = dep
}

func TestDeployHandler_ABackupStepRunsBeforeTheImagesAreTouched(t *testing.T) {
	w := newDeployWorld(t)
	target := w.mustTarget(w.app, "prod", finHTTPHealth)
	backup := `,"pre_deploy_backup":{"template":"postgres-dump","args":{"container":"db","database":"app"},"timeout":"5m0s"}`
	w.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, fmt.Sprintf(finStatefulPolicy, backup), target.ID)
	dep := w.queued(func(r *CreateDeployment) { r.AppTargetID = target.ID })
	job := w.approveToQuorum(w.job(*dep.JobID))
	w.exec(`UPDATE deployments SET state = 'queued' WHERE id = ?`, dep.ID) // the approval mirror is the TypePolicy's (T12)
	w.remote.reply("postgres-dump", "/var/lib/supermgmt/db-backups/app-20261012T100000Z-42.dump\n")

	if err := w.runJob(job.ID); err != nil {
		t.Fatalf("Run: %v", err)
	}

	ran := w.templatesRun()
	if at, pull := dhIndexOf(ran, "postgres-dump"), dhIndexOf(ran, "compose.pull"); at < 0 || at > pull {
		t.Errorf("order = %v, want postgres-dump before compose.pull", ran)
	}
	rows, err := database.ListDeploymentSteps(context.Background(), w.db.Reader(), dep.ID)
	mustf(t, err, "ListDeploymentSteps")
	for _, r := range rows {
		if r.Name == deployments.StepPreDeployBackup && !strings.HasPrefix(r.OutputRef, "/var/lib/supermgmt/db-backups/") {
			t.Errorf("backup output_ref = %q, want the artifact path", r.OutputRef)
		}
	}
}

func TestDeployHandler_AFailedBackupNeverReachesPull(t *testing.T) {
	w := newDeployWorld(t)
	target := w.mustTarget(w.app, "prod", finHTTPHealth)
	backup := `,"pre_deploy_backup":{"template":"postgres-dump","args":{"container":"db","database":"app"},"timeout":"5m0s"}`
	w.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, fmt.Sprintf(finStatefulPolicy, backup), target.ID)
	dep := w.queued(func(r *CreateDeployment) { r.AppTargetID = target.ID })
	job := w.approveToQuorum(w.job(*dep.JobID))
	w.exec(`UPDATE deployments SET state = 'queued' WHERE id = ?`, dep.ID) // the approval mirror is the TypePolicy's (T12)
	w.remote.exit("postgres-dump", 1)

	err := w.runJob(job.ID)

	wantStagingCause(t, err, deployments.CauseBackupFailed)
	row := w.want(dep.ID, deployments.StateFailed)
	if row.Failure.Cause != deployments.CauseBackupFailed {
		t.Errorf("failure = %+v, want cause %s", row.Failure, deployments.CauseBackupFailed)
	}
	if w.remote.count("compose.pull") != 0 || w.remote.count("compose.up") != 0 {
		t.Errorf("services were reached after a failed backup: %v", w.templatesRun())
	}
}

// runJob claims the job (the oldest claimable one) and runs the handler.
func (w *deployWorld) runJob(id domain.ID) error {
	w.t.Helper()
	claimed, ok := w.claim()
	if !ok || claimed.Job.ID != id {
		w.t.Fatalf("claimed %v (%v), want job %s", claimed.Job.ID, ok, id)
	}
	return w.handler.Run(context.Background(), claimed.Lease)
}

// ---- construction -----------------------------------------------------------------------------------

func TestNewDeployHandlerRequiresItsCollaborators(t *testing.T) {
	w := newDeployWorld(t)
	c, err := newCore(w.cfg)
	mustf(t, err, "newCore")
	good := DeployOptions{Secrets: dhSecrets{}, HTTP: &http.Client{}}
	for name, mutate := range map[string]func(*DeployOptions){
		"secrets": func(o *DeployOptions) { o.Secrets = nil },
		"http":    func(o *DeployOptions) { o.HTTP = nil },
	} {
		o := good
		mutate(&o)
		if _, err := newDeployHandler(c, w.store, Connector{}, o); err == nil {
			t.Errorf("a handler without %s was accepted", name)
		}
	}
	if _, err := newDeployHandler(c, w.store, Connector{}, good); err != nil {
		t.Errorf("complete options refused: %v", err)
	}
}

func (n *nodeFixture) handlersWith(t *testing.T, apps *Apps, deploy *DeployOptions) *Handlers {
	t.Helper()
	adapters := fakeAdapters(newFakeAdapter(domain.RuntimeSystemd), newFakeAdapter(domain.RuntimeDocker))
	prober, err := NewProber(n.cfg, n.conn, adapters)
	mustf(t, err, "NewProber")
	h, err := NewHandlers(n.cfg, HandlersOptions{
		Store: n.store, Connector: n.conn, Adapters: adapters, Inventory: n.inv, Prober: prober,
		Identity: func(context.Context) (secrets.Identity, error) { return secrets.Identity{}, nil },
		Apps:     apps, Deploy: deploy,
	})
	mustf(t, err, "NewHandlers")
	return h
}

func TestHandlers_DeploymentTypesExistOnlyWhenDeploymentsAreConfigured(t *testing.T) {
	n := newNodeFixture(t)

	without := n.handlersWith(t, nil, nil).Map()
	with := n.handlersWith(t, nil, &DeployOptions{Secrets: dhSecrets{}, HTTP: &http.Client{}}).Map()

	for _, jobType := range []string{deploymentCreateAction, deploymentRollbackAction} {
		if _, ok := without[jobType]; ok {
			t.Errorf("%s has a handler without deployment options", jobType)
		}
		if _, ok := with[jobType]; !ok {
			t.Errorf("%s has no handler although deployments are configured", jobType)
		}
	}
	if with[deploymentCreateAction] != with[deploymentRollbackAction] {
		t.Error("deployment.create and deployment.rollback must share one handler")
	}
}

func TestHandlers_ApprovedAppWritesReachTheAppsCatalog(t *testing.T) {
	n := newNodeFixture(t)
	apps := &Apps{}

	h := n.handlersWith(t, apps, nil)

	if h.apply.apps != apps {
		t.Error("the control_plane.apply handler was built without the apps catalog; approved app writes would fail")
	}
}

func TestDeployHandler_SucceededCommandsAreClosedWithProvenExitEvidence(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	mustf(t, w.run(), "run")

	closed := 0
	for _, in := range w.intents(*dep.JobID) {
		if in.Outcome != jobs.OutcomeSucceeded {
			continue
		}
		var ev jobs.Evidence
		mustf(t, json.Unmarshal(in.Evidence, &ev), "decode evidence")
		if !ev.Proven() || ev.Classification != jobs.ClassComplete || ev.Proof != "ssh_exit" {
			t.Errorf("intent %s evidence %+v is not proven exit evidence", in.Step, ev)
		}
		closed++
	}
	if closed == 0 {
		t.Fatal("no succeeded intent was inspected")
	}
}

func TestCommandExitEvidence_FailureProvesNothing(t *testing.T) {
	var ev jobs.Evidence
	mustf(t, json.Unmarshal(commandExitEvidence(jobs.OutcomeFailed, 3), &ev), "decode evidence")
	if ev.Proven() || ev.ExitStatus != 3 {
		t.Fatalf("evidence %+v: a failed command must record its status without proving anything", ev)
	}
}

func TestReconcileDeploy_CrashAfterLongComposeUpReconcilesFromTheHandlersOwnEvidence(t *testing.T) {
	w := newReconcileWorld(t)
	next, good := w.afterKnownGood()
	w.remote.down("compose.up", errors.New("connection lost"))
	claimed, ok := w.claim()
	if !ok {
		t.Fatal("no deployment job to claim")
	}
	if err := w.handler.Run(context.Background(), claimed.Lease); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	w.remote.exit("compose.up", 0)
	w.clock.Advance(31 * time.Second)
	taken, err := w.store.Takeover(context.Background(), "test")
	if err != nil || len(taken) != 1 {
		t.Fatalf("Takeover = %v, %v", taken, err)
	}
	w.pastEveryDeadline(taken[0]) // the test writes no evidence of its own
	w.markerIs(w.intentOf(taken[0], deployments.StepDeploy), "done 0")
	half := w.containersOf(w.planOf(next.ID).Content, next.ID)
	half[0].Config.Image = "ghcr.io/acme/other@sha256:" + strings.Repeat("f", 64)
	w.projectIs(half)

	w.settle()

	if got := w.job(taken[0]).State; got != domain.JobQueued {
		t.Fatalf("job = %s, want queued for the recovery: the earlier steps' evidence must already be proven", got)
	}
	if record := w.recovery(next.ID); record == nil || record.Target == nil || *record.Target != good.ID {
		t.Fatalf("recovery record %+v, want a safety recovery toward %s", record, good.ID)
	}
}
