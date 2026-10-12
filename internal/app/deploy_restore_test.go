package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	restoreSecretValue = "hunter2-do-not-leak"
	restoreImageRef    = "ghcr.io/acme/web@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	restoreSidecarRef  = "docker.io/library/redis@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

const restorePublicModel = `services:
  cache:
    image: ` + restoreSidecarRef + `
  web:
    image: ` + restoreImageRef + `
    ports:
      - target: 8080
        published: "8080"
        host_ip: 127.0.0.1
        protocol: tcp
`

// restoreRecorder is a restoreLedger that remembers everything in order.
type restoreRecorder struct {
	mu         sync.Mutex
	intents    []jobs.NewIntent
	dispatched map[int]bool
	completed  map[int]string
	evidence   map[int]json.RawMessage
	started    []database.DeploymentStep
	finished   map[string]database.DeploymentStep
}

func newRestoreRecorder() *restoreRecorder {
	return &restoreRecorder{
		dispatched: map[int]bool{}, completed: map[int]string{}, evidence: map[int]json.RawMessage{},
		finished: map[string]database.DeploymentStep{},
	}
}

func (r *restoreRecorder) index(id domain.ID) int {
	var n int
	_, _ = fmt.Sscanf(id.String(), "intent-%d", &n)
	return n
}

func (r *restoreRecorder) RecordIntent(_ context.Context, ni jobs.NewIntent) (domain.ID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.intents = append(r.intents, ni)
	return domain.ID(fmt.Sprintf("intent-%d", len(r.intents)-1)), nil
}

func (r *restoreRecorder) MarkDispatched(_ context.Context, id domain.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dispatched[r.index(id)] = true
	return nil
}

func (r *restoreRecorder) CompleteIntent(_ context.Context, id domain.ID, outcome string, evidence json.RawMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completed[r.index(id)], r.evidence[r.index(id)] = outcome, evidence
	return nil
}

func (r *restoreRecorder) StartStep(_ context.Context, s database.DeploymentStep) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, s)
	return nil
}

func (r *restoreRecorder) FinishStep(_ context.Context, s database.DeploymentStep) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished[s.Name] = s
	return nil
}

// restoreWorld wires a restorer to a fake node and a recorder.
type restoreWorld struct {
	f      *fixture
	node   *fakeNode
	ledger *restoreRecorder
	verify func(context.Context, restoreVerification) ([]string, error)
	sleeps *healthvSleeps
}

func newRestoreWorld(t *testing.T) *restoreWorld {
	t.Helper()
	w := &restoreWorld{f: newFixture(t), node: newFakeNode(t), ledger: newRestoreRecorder(), sleeps: &healthvSleeps{}}
	w.node.exit("compose.pull", 0).exit("compose.materialize", 0).exit("compose.up", 0).reply("health.http", "200")
	w.verify = func(context.Context, restoreVerification) ([]string, error) { return nil, nil }
	return w
}

func (w *restoreWorld) restorer() restorer {
	return restorer{
		Node: w.node, Ledger: w.ledger, Health: healthvVerifier(w.node, w.sleeps), IDs: w.f.ids, Clock: w.f.clock,
		Verify: func(ctx context.Context, v restoreVerification) ([]string, error) { return w.verify(ctx, v) },
	}
}

func (w *restoreWorld) snapshot(deployment domain.ID) restoreSnapshot {
	return restoreSnapshot{
		Deployment: deployment, Attempt: 2, Project: "web-prod", Root: "/srv/supermgmt",
		Frozen: compose.Frozen{
			Public: []byte(restorePublicModel),
			Images: []compose.ImageUse{
				{Service: "web", Ref: restoreImageRef, Binding: compose.BindingPinned},
				{Service: "cache", Ref: restoreSidecarRef, Binding: compose.BindingPinned},
			},
			Secrets:   []compose.SecretUse{{Service: "web", EnvName: "DATABASE_URL", Ref: "apps/web/database_url", Version: 3}},
			HostPorts: []compose.HostPort{{Service: "web", Addr: healthvLoopback, Port: 8080, Proto: "tcp"}},
		},
		Secrets: []compose.ResolvedSecret{{Ref: "apps/web/database_url", Version: 3, Value: audit.Secret(restoreSecretValue)}},
		Health: healthRun{
			Checks: []health.Check{healthvManifestHTTP()}, Ports: healthvPorts(healthvLoopback),
		},
	}
}

func (w *restoreWorld) run(snap restoreSnapshot) (restoreResult, error) {
	return w.restorer().run(context.Background(), snap)
}

func TestDeployRestore_RedeploysTheKnownGoodSnapshotInANewDirectory(t *testing.T) {
	w := newRestoreWorld(t)
	failed := w.f.ids.NewID()
	var verified restoreVerification
	w.verify = func(_ context.Context, v restoreVerification) ([]string, error) { verified = v; return nil, nil }

	res, err := w.run(w.snapshot(failed))

	if err != nil || !res.Restored || res.FailedStep != "" {
		t.Fatalf("result = %+v, %v", res, err)
	}
	want := []string{"compose.pull", "compose.pull", "compose.materialize", "compose.up", "health.http"}
	if got := w.node.ran(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("node ran %v, want %v", got, want)
	}
	pulled := []string{pulledImage(w.node.calls[0]), pulledImage(w.node.calls[1])}
	if strings.Join(pulled, ",") != restoreSidecarRef+","+restoreImageRef {
		t.Fatalf("pulled %v, want exactly the known-good digests", pulled)
	}
	if res.Directory == "" || res.Directory == failed {
		t.Fatalf("directory = %q, want a fresh one next to the failed deployment %q", res.Directory, failed)
	}
	up := w.node.calls[3]
	if !strings.Contains(up.Line, res.Directory.String()) || strings.Contains(up.Line, failed.String()) {
		t.Fatalf("compose.up targets %q", up.Line)
	}
	if verified.Directory != res.Directory || verified.Snapshot.Project != "web-prod" {
		t.Fatalf("verify saw %+v", verified)
	}
}

var restorePullPattern = regexp.MustCompile(`docker pull --quiet '?([^ ';]+)`)

func pulledImage(c templates.Command) string {
	m := restorePullPattern.FindStringSubmatch(c.Line)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestDeployRestore_RecordsDurableIntentsAndSteps(t *testing.T) {
	w := newRestoreWorld(t)

	res, err := w.run(w.snapshot(w.f.ids.NewID()))
	if err != nil || !res.Restored {
		t.Fatalf("result = %+v, %v", res, err)
	}

	var operations []string
	for i, in := range w.ledger.intents {
		operations = append(operations, in.Operation)
		if !w.ledger.dispatched[i] || w.ledger.completed[i] != jobs.OutcomeSucceeded {
			t.Fatalf("intent %d (%s): dispatched=%v outcome=%q", i, in.Operation, w.ledger.dispatched[i], w.ledger.completed[i])
		}
		if in.TargetType != "deployment" || in.Marker == "" || !in.DeadlineAt.After(w.f.clock.Now()) {
			t.Fatalf("intent %d = %+v", i, in)
		}
	}
	if got := strings.Join(operations, ","); got != "compose.pull,compose.pull,compose.materialize,compose.up" {
		t.Fatalf("intents = %s", got)
	}
	steps := []string{
		deployments.StepRestorePull, deployments.StepRestoreMaterialize, deployments.StepRestoreVerify,
		deployments.StepRestoreDeploy, deployments.StepRestoreHealthCheck,
	}
	if len(w.ledger.started) != len(steps) {
		t.Fatalf("started %d steps, want %d", len(w.ledger.started), len(steps))
	}
	for i, name := range steps {
		started, finished := w.ledger.started[i], w.ledger.finished[name]
		if started.Name != name || started.Ordinal != restoreOrdinalBase+i || started.Attempt != 2 || started.State != database.StepRunning {
			t.Fatalf("started step %d = %+v", i, started)
		}
		if finished.State != database.StepSucceeded || finished.FinishedAt == nil || finished.ID != started.ID {
			t.Fatalf("finished %s = %+v", name, finished)
		}
	}
	if got := w.ledger.finished[deployments.StepRestoreMaterialize].OutputRef; got != res.Directory.String() {
		t.Fatalf("materialize output = %q, want the directory %q", got, res.Directory)
	}
}

func TestDeployRestore_MaterializeCarriesSecretsOnStdinOnly(t *testing.T) {
	w := newRestoreWorld(t)

	res, err := w.run(w.snapshot(w.f.ids.NewID()))
	if err != nil || !res.Restored {
		t.Fatalf("result = %+v, %v", res, err)
	}

	materialize := w.node.calls[2]
	if materialize.Template != "compose.materialize" || !materialize.Sensitive {
		t.Fatalf("command = %+v", materialize)
	}
	if !bytes.Contains(materialize.Stdin, []byte("DATABASE_URL="+restoreSecretValue)) {
		t.Fatal("the env file is not on stdin")
	}
	if !bytes.Contains(materialize.Stdin, []byte("dev.supermgmt.deployment")) || !bytes.Contains(materialize.Stdin, []byte(res.Directory.String())) {
		t.Fatal("the materialized model does not carry the new directory's deployment label")
	}
	for _, c := range w.node.calls {
		if strings.Contains(c.Line, restoreSecretValue) {
			t.Fatalf("secret on the command line of %s", c.Template)
		}
	}
	for i := range w.ledger.intents {
		recorded := string(w.ledger.intents[i].PreState) + string(w.ledger.evidence[i])
		if strings.Contains(recorded, restoreSecretValue) {
			t.Fatalf("secret in intent %d records: %s", i, recorded)
		}
	}
	for name, step := range w.ledger.finished {
		if strings.Contains(string(step.ErrorJSON)+step.OutputRef, restoreSecretValue) {
			t.Fatalf("secret in step %s", name)
		}
	}
}

func TestDeployRestore_StepFailuresStopTheRestore(t *testing.T) {
	tests := []struct {
		name       string
		arrange    func(*restoreWorld)
		failedStep string
		detail     string
		wantRan    []string
		neverRuns  string
	}{
		{
			"pull exits non-zero",
			func(w *restoreWorld) { w.node.exit("compose.pull", 1) },
			deployments.StepRestorePull, "exited with status 1",
			[]string{"compose.pull"},
			"compose.up",
		},
		{
			"materialize exits non-zero",
			func(w *restoreWorld) { w.node.exit("compose.materialize", 1) },
			deployments.StepRestoreMaterialize, "exited with status 1",
			[]string{"compose.pull", "compose.pull", "compose.materialize"},
			"compose.up",
		},
		{
			"the node model differs from the snapshot",
			func(w *restoreWorld) {
				w.verify = func(context.Context, restoreVerification) ([]string, error) {
					return []string{"services.web.image: changed", "services.web.ports: changed"}, nil
				}
			},
			deployments.StepRestoreVerify, "differs from the snapshot in 2 places (first: services.web.image: changed)",
			[]string{"compose.pull", "compose.pull", "compose.materialize"},
			"compose.up",
		},
		{
			"the verification itself fails",
			func(w *restoreWorld) {
				w.verify = func(context.Context, restoreVerification) ([]string, error) {
					return nil, errors.New("verify output is not JSON")
				}
			},
			deployments.StepRestoreVerify, "the node verification failed: verify output is not JSON",
			[]string{"compose.pull", "compose.pull", "compose.materialize"},
			"compose.up",
		},
		{
			"compose up exits non-zero",
			func(w *restoreWorld) { w.node.exit("compose.up", 1) },
			deployments.StepRestoreDeploy, "exited with status 1",
			[]string{"compose.pull", "compose.pull", "compose.materialize", "compose.up"},
			"health.http",
		},
		{
			"the restored version is unhealthy",
			func(w *restoreWorld) { w.node.reply("health.http", "503") },
			deployments.StepRestoreHealthCheck, "HTTP status 503 after 3 attempts",
			[]string{"compose.pull", "compose.pull", "compose.materialize", "compose.up", "health.http", "health.http", "health.http"},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newRestoreWorld(t)
			tt.arrange(w)

			res, err := w.run(w.snapshot(w.f.ids.NewID()))

			if err != nil || res.Restored || res.FailedStep != tt.failedStep || !strings.Contains(res.Detail, tt.detail) {
				t.Fatalf("result = %+v, %v; want failure at %s (%s)", res, err, tt.failedStep, tt.detail)
			}
			if got := w.node.ran(); strings.Join(got, ",") != strings.Join(tt.wantRan, ",") {
				t.Fatalf("node ran %v, want %v", got, tt.wantRan)
			}
			if tt.neverRuns != "" && w.node.count(tt.neverRuns) != 0 {
				t.Fatalf("%s ran after the failure", tt.neverRuns)
			}
			step := w.ledger.finished[tt.failedStep]
			if step.State != database.StepFailed || !strings.Contains(string(step.ErrorJSON), "detail") {
				t.Fatalf("failed step row = %+v", step)
			}
		})
	}
}

func TestDeployRestore_FailedCommandClosesItsIntentAsFailed(t *testing.T) {
	w := newRestoreWorld(t)
	w.node.exit("compose.up", 3)

	if _, err := w.run(w.snapshot(w.f.ids.NewID())); err != nil {
		t.Fatal(err)
	}

	last := len(w.ledger.intents) - 1
	if w.ledger.intents[last].Operation != "compose.up" || w.ledger.completed[last] != jobs.OutcomeFailed ||
		!strings.Contains(string(w.ledger.evidence[last]), `"exit_status":3`) {
		t.Fatalf("intent = %+v outcome=%q evidence=%s", w.ledger.intents[last], w.ledger.completed[last], w.ledger.evidence[last])
	}
}

func TestDeployRestore_LostConnectionLeavesTheOutcomeUnknown(t *testing.T) {
	w := newRestoreWorld(t)
	w.node.down("compose.up", errors.New("ssh: connection reset"))

	res, err := w.run(w.snapshot(w.f.ids.NewID()))

	if !errors.Is(err, jobs.ErrOutcomeUnknown) || smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
		t.Fatalf("err = %v, want an unknown outcome", err)
	}
	if res.Restored || w.node.count("health.http") != 0 {
		t.Fatalf("result = %+v; nothing may follow an undetermined compose up", res)
	}
	last := len(w.ledger.intents) - 1
	if !w.ledger.dispatched[last] || w.ledger.completed[last] != "" {
		t.Fatalf("the dispatched intent must stay open: dispatched=%v outcome=%q", w.ledger.dispatched[last], w.ledger.completed[last])
	}
	if step := w.ledger.finished[deployments.StepRestoreDeploy]; step.ID != "" {
		t.Fatalf("an undetermined step was closed: %+v", step)
	}
}

func TestDeployRestore_SnapshotWithoutImagesDispatchesNothing(t *testing.T) {
	w := newRestoreWorld(t)
	snap := w.snapshot(w.f.ids.NewID())
	snap.Frozen.Images = nil

	res, err := w.run(snap)

	if err != nil || res.Restored || res.FailedStep != deployments.StepRestorePull || len(w.node.ran()) != 0 {
		t.Fatalf("result = %+v, %v, ran %v", res, err, w.node.ran())
	}
}

func TestDeployRestore_SnapshotThatCannotBeMaterializedDispatchesNothing(t *testing.T) {
	w := newRestoreWorld(t)
	snap := w.snapshot(w.f.ids.NewID())
	snap.Secrets = nil // the bound secret version is gone

	res, err := w.run(snap)

	if err != nil || res.Restored || res.FailedStep != deployments.StepRestoreMaterialize {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if w.node.count("compose.materialize") != 0 || w.node.count("compose.up") != 0 {
		t.Fatalf("node ran %v", w.node.ran())
	}
}

func TestDeployRestore_CancelledContextIsAnErrorNotAFailedRestore(t *testing.T) {
	w := newRestoreWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	w.verify = func(context.Context, restoreVerification) ([]string, error) {
		cancel()
		return nil, ctx.Err()
	}

	_, err := w.restorer().run(ctx, w.snapshot(w.f.ids.NewID()))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if w.node.count("compose.up") != 0 {
		t.Fatal("compose up ran after cancellation")
	}
}

func TestDeployRestore_HealthFailedRollsBack(t *testing.T) {
	w := newRestoreWorld(t)
	id := healthvSeedDeployment(w.f, deployments.KindDeploy, deployments.StateVerifying)
	// The new version answers 503 on its three attempts; the restored one 200.
	w.node.on("health.http", healthvSequence(healthvStatus("503"), healthvStatus("503"), healthvStatus("503"), healthvStatus("200")))
	run := healthRun{Checks: []health.Check{healthvManifestHTTP()}, Ports: healthvPorts(healthvLoopback)}

	verdict, err := w.restorer().Health.verify(context.Background(), run)
	if err != nil || verdict.Healthy {
		t.Fatalf("verdict = %+v, %v", verdict, err)
	}
	if state := healthvSettle(w.f, id, verdict, healthvRollbackable()); state != deployments.StateRollingBack {
		t.Fatalf("state after failed health = %s", state)
	}
	res, err := w.run(w.snapshot(id))
	if err != nil || !res.Restored {
		t.Fatalf("restore = %+v, %v", res, err)
	}
	var state deployments.State
	w.f.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		state, err = settleRestore(ctx, tx, id, res, w.f.clock.Now())
		return err
	})

	d := healthvGet(w.f, id)
	if state != deployments.StateRolledBack || d.State != deployments.StateRolledBack || d.KnownGood || d.FinishedAt == nil || d.Failure != (database.StateFailure{}) {
		t.Fatalf("state = %s, deployment = %+v", state, d)
	}
	if got := pulledImage(w.node.calls[3]) + "," + pulledImage(w.node.calls[4]); got != restoreSidecarRef+","+restoreImageRef {
		t.Fatalf("restore pulled %s, want the known-good digests", got)
	}
}

func TestDeployRestore_FailedRestoreNeedsAHuman(t *testing.T) {
	w := newRestoreWorld(t)
	id := healthvSeedDeployment(w.f, deployments.KindDeploy, deployments.StateRollingBack)
	w.node.reply("health.http", "503")
	res, err := w.run(w.snapshot(id))
	if err != nil || res.Restored {
		t.Fatalf("restore = %+v, %v", res, err)
	}

	var state deployments.State
	w.f.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		state, err = settleRestore(ctx, tx, id, res, w.f.clock.Now())
		return err
	})

	d := healthvGet(w.f, id)
	if state != deployments.StateRollbackFailed || d.State != deployments.StateRollbackFailed || d.Failure.Code != string(smerr.CodeRollbackFailed) || d.KnownGood {
		t.Fatalf("state = %s, deployment = %+v", state, d)
	}
}

func TestDeployRestore_RollbackUnavailableCauses(t *testing.T) {
	tests := []struct {
		name  string
		tweak func(*deployments.RollbackInputs)
		cause string // "" means rollback is available
	}{
		{"available", func(*deployments.RollbackInputs) {}, ""},
		{"stateful", func(in *deployments.RollbackInputs) { in.Stateful = true }, deployments.CauseStateful},
		{"manual", func(in *deployments.RollbackInputs) { in.Mode = deployments.RollbackManual }, deployments.CauseManualMode},
		{"first deployment", func(in *deployments.RollbackInputs) { in.HasKnownGood = false }, deployments.CauseNoKnownGood},
		{"environment forbids", func(in *deployments.RollbackInputs) { in.EnvAllows = false }, deployments.CauseEnvironmentForbids},
		{"rollback kind", func(in *deployments.RollbackInputs) { in.Kind = deployments.KindRollback }, deployments.CauseRollbackKind},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			id := healthvSeedDeployment(f, deployments.KindDeploy, deployments.StateDeploying) // the update itself failed
			in := healthvRollbackable()
			tt.tweak(&in)

			var state deployments.State
			f.inTx(func(ctx context.Context, tx *database.Tx) error {
				var err error
				state, err = rollBackOrFail(ctx, tx, id, in, f.clock.Now())
				return err
			})

			d := healthvGet(f, id)
			if tt.cause == "" {
				if state != deployments.StateRollingBack || d.State != deployments.StateRollingBack {
					t.Fatalf("state = %s", state)
				}
				return
			}
			want := database.StateFailure{
				Code: string(smerr.CodeDeploymentFailed), Reason: string(smerr.ReasonRollbackUnavailable), Cause: tt.cause,
			}
			if state != deployments.StateFailed || d.State != deployments.StateFailed || d.Failure != want || !d.MutationStarted {
				t.Fatalf("state = %s, failure = %+v, want %+v", state, d.Failure, want)
			}
		})
	}
}

var _ transport.Executor = (*fakeNode)(nil)
