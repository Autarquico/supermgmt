package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// ---- helpers -------------------------------------------------------------------------------------------------------

func newStatefulWorld(t *testing.T) *runWorld {
	t.Helper()
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	return w
}

// disableDest makes B unable to deploy, which the re-check before B's first start refuses.
func (w *runWorld) disableDest() {
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, w.dest.ID, database.NodeCapability{
			Capability: capabilityComposeDeploy, Available: false, CheckedAt: w.clock.Now(),
		})
	})
}

// failBeforeStart ends the move after B was staged and the data copied, before B is ever started.
func (w *runWorld) failBeforeStart() {
	w.before = func(label string, c templates.Command) {
		if label == "B" && c.Template == "compose.create" {
			w.disableDest()
		}
	}
}

// failAfterStart makes B fail its health checks, while A answers its own.
func (w *runWorld) failAfterStart() { w.unhealthy, w.healthyA = true, true }

// endJob ends the move job the way the engine would, which releases the target lock for the next job.
func (w *runWorld) endJob(runErr error) {
	w.t.Helper()
	if runErr == nil {
		mustf(w.t, w.store.Succeed(context.Background(), w.lease), "Succeed")
		return
	}
	mustf(w.t, w.store.FailTerminal(context.Background(), w.lease, runErr), "FailTerminal")
}

// runClaimed claims the next queued job and runs the move handler on it.
func (w *runWorld) runClaimed(want jobs.Job) error {
	w.t.Helper()
	claimed, found := w.claim()
	if !found || claimed.Job.ID != want.ID {
		w.t.Fatalf("claimed %v (found %v), want job %s", claimed.Job.ID, found, want.ID)
	}
	w.lease = claimed.Lease
	return w.run()
}

func (w *runWorld) keptVolumes(event domain.Event) []any {
	w.t.Helper()
	kept, _ := event.Data["kept_volumes"].([]any)
	return kept
}

func (w *runWorld) wantVolumesOnB(present bool) {
	w.t.Helper()
	for _, name := range w.volumeNames() {
		if _, got := w.b.volumeFiles(name); got != present {
			w.t.Errorf("volume %s on B: present %v, want %v", name, got, present)
		}
	}
}

func (w *runWorld) wantSourceRunning() {
	w.t.Helper()
	if w.a.state != "running" {
		w.t.Errorf("A is %s, want running", w.a.state)
	}
	if got := w.targetRow().NodeID; got != w.node.ID {
		w.t.Errorf("target on %s, want A", got)
	}
}

// ---- compensation ----------------------------------------------------------------------------------------------------

func TestCompensation_AnUnhealthyBIsStoppedFirstThenAIsRestartedAndBKeepsItsVolumes(t *testing.T) {
	w := newStatefulWorld(t)
	w.failAfterStart()

	err := w.run()

	if appsReasonOf(err) != smerr.ReasonHealthFailed {
		t.Fatalf("Run = %v, want HEALTH_FAILED", err)
	}
	m := w.moveRow()
	if m.Phase != database.AppMoveRolledBack || m.BStartedAt == nil {
		t.Fatalf("move = %+v, want rolled back after B started", m)
	}
	w.wantSourceRunning()
	if w.b.state != "exited" {
		t.Errorf("B is %s, want stopped and not removed", w.b.state)
	}
	log := w.logged()
	bStop, aStart := logIndex(log, "B compose.stop", 0), logIndex(log, "A compose.start", 0)
	if bStop < 0 || aStart < bStop || logIndex(log, "A health.http", aStart) < 0 {
		t.Errorf("B stopped at %d, A started at %d, A checked after: want that order\n%v", bStop, aStart, log)
	}
	w.wantVolumesOnB(true)
	for _, name := range w.volumeNames() {
		a, _ := w.a.volumeFiles(name)
		if b, _ := w.b.volumeFiles(name); !maps_equal(a, b) {
			t.Errorf("volume %s: B holds %v, A holds %v", name, b, a)
		}
	}
	if got := w.mutations(w.b); slices.Contains(got, "compose.down") || slices.Contains(got, "docker.volume_rm") {
		t.Errorf("B mutations = %v: a B that was started is stopped, never removed", got)
	}
	if dep := w.row(*m.DestDeploymentID); dep.State != deployments.StateFailed || dep.KnownGood {
		t.Errorf("B's deployment = %s known good %v, want failed", dep.State, dep.KnownGood)
	}
	events := w.events("app_move.rolled_back")
	if len(events) != 1 || len(w.keptVolumes(events[0])) != 2 {
		t.Fatalf("rolled_back events = %+v, want one that lists the two volumes kept on B", events)
	}
}

func TestCompensation_AFailureBeforeBStartedRemovesOnlyWhatTheMoveCreated(t *testing.T) {
	w := newStatefulWorld(t)
	w.b.volumes["unrelated"] = map[string]string{"x": "y"}
	w.failBeforeStart()

	err := w.run()

	wantAppsCode(t, err, smerr.CodeCapabilityUnavailable)
	m := w.moveRow()
	if m.Phase != database.AppMoveRolledBack || m.BStartedAt != nil {
		t.Fatalf("move = %+v, want rolled back with B never started", m)
	}
	w.wantSourceRunning()
	if countOf(w.logged(), "A health.http") == 0 {
		t.Error("A was not checked after it came back")
	}
	w.wantVolumesOnB(false)
	if _, present := w.b.volumeFiles("unrelated"); !present {
		t.Error("a volume the move did not create was removed")
	}
	if w.b.state != "none" {
		t.Errorf("B is %s, want its containers removed", w.b.state)
	}
	got := w.mutations(w.b)
	if countOf(got, "compose.down") != 1 || countOf(got, "docker.volume_rm") != 2 || slices.Contains(got, "compose.start") || slices.Contains(got, "compose.stop") {
		t.Errorf("B mutations = %v, want one down and the removal of the two created volumes, no start or stop", got)
	}
	if events := w.events("app_move.rolled_back"); len(events) != 1 || len(w.keptVolumes(events[0])) != 0 {
		t.Errorf("rolled_back events = %+v, want one that keeps nothing", events)
	}
}

func TestCompensation_ASourceThatDoesNotComeBackHaltsWithBStoppedAndAbandonRecordsTheDecision(t *testing.T) {
	w := newStatefulWorld(t)
	w.unhealthy = true
	ctx := context.Background()

	err := w.run()

	if appsReasonOf(err) != smerr.ReasonHealthFailed {
		t.Fatalf("Run = %v, want HEALTH_FAILED", err)
	}
	m := w.moveRow()
	if m.Phase != database.AppMoveFailed || m.HaltedPhase != database.AppMoveCompensatingSourceStarted || m.LastError == "" {
		t.Fatalf("move = %+v, want halted in compensating_source_started", m)
	}
	if w.b.state != "exited" {
		t.Errorf("B is %s, want it stopped", w.b.state)
	}
	w.wantVolumesOnB(true)
	if len(w.events("app_move.halted")) != 1 || len(w.events("app_move.rolled_back")) != 0 {
		t.Errorf("halted %d, rolled back %d events, want 1 and 0", len(w.events("app_move.halted")), len(w.events("app_move.rolled_back")))
	}
	if err := requireNoOpenMove(ctx, w.db.Reader(), w.target.ID); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("a halted move must still block the target's deployments, got %v", err)
	}
	w.endJob(err)
	before := [][]string{slices.Clone(w.mutations(w.a)), slices.Clone(w.mutations(w.b))}

	first, err := w.svc.Abandon(ctx, w.caller(w.admin), w.target.ID)
	mustf(t, err, "Abandon")
	second, err := w.svc.Abandon(ctx, w.caller(w.admin), w.target.ID)
	mustf(t, err, "Abandon again")
	mustf(t, w.runClaimed(first.Job), "abandon job")

	m = w.moveRow()
	if m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if got := [][]string{w.mutations(w.a), w.mutations(w.b)}; !slices.EqualFunc(got, before, slices.Equal) {
		t.Errorf("mutations went from %v to %v: an abandon touches no node", before, got)
	}
	if dep := w.row(*m.DestDeploymentID); dep.State != deployments.StateFailed {
		t.Errorf("B's deployment = %s, want failed so the target is not blocked by it", dep.State)
	}
	if events := w.events("app_move.rolled_back"); len(events) != 1 || events[0].Data["abandoned"] != true {
		t.Errorf("rolled_back events = %+v, want one marked abandoned", events)
	}
	w.endJob(nil)

	err = w.runClaimed(second.Job)

	wantAppsCode(t, err, smerr.CodeConflict)
	if w.moveRow().Phase != database.AppMoveRolledBack {
		t.Error("a second abandon changed the move")
	}
}

func TestCompensation_ASourceThatCannotBeStartedHaltsBeforeItIsChecked(t *testing.T) {
	w := newStatefulWorld(t)
	w.a.node.exit("compose.start", 1)
	w.failAfterStart()

	err := w.run()

	wantAppsCode(t, err, smerr.CodeDeploymentFailed)
	if m := w.moveRow(); m.Phase != database.AppMoveFailed || m.HaltedPhase != database.AppMoveCompensatingBStopped {
		t.Fatalf("move = %+v, want halted in compensating_b_stopped", m)
	}
	if w.b.state != "exited" {
		t.Errorf("B is %s, want it stopped", w.b.state)
	}
	w.wantVolumesOnB(true)
}

func TestCompensation_AHaltedMoveIsResumedByANewMoveAndCompletesItsCompensation(t *testing.T) {
	w := newStatefulWorld(t)
	w.unhealthy = true
	err := w.run()
	if m := w.moveRow(); m.Phase != database.AppMoveFailed {
		t.Fatalf("move = %+v, want halted (Run = %v)", m, err)
	}
	w.endJob(err)
	w.unhealthy = false
	before := countOf(w.logged(), "A compose.start")

	res, err := w.move()
	mustf(t, err, "Move resumes the open move")
	if !res.Resumed {
		t.Fatal("the request did not resume the open move")
	}
	err = w.runClaimed(w.approved(res))

	wantAppsCode(t, err, smerr.CodeDeploymentFailed)
	if m := w.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back", m)
	}
	if got := countOf(w.logged(), "A compose.start"); got != before {
		t.Errorf("A was started %d more time(s): it already ran", got-before)
	}
	w.wantVolumesOnB(true)
}

func TestCompensation_AnImportWithAFutureDeadlineLeavesBUntouchedUntilItPasses(t *testing.T) {
	w := newStatefulWorld(t)
	w.fail("B", templates.StreamImport, "/data", 1, "lost")
	w.stuck = true
	ctx := context.Background()
	if err := w.run(); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	job, err := w.store.Get(ctx, w.db.Reader(), w.lease.JobID)
	mustf(t, err, "Get")
	r, err := w.handler.load(ctx, w.lease, job)
	mustf(t, err, "load")
	before := slices.Clone(w.mutations(w.b))
	cause := smerr.New(smerr.CodeDeploymentFailed, "", "the copy failed")

	err = w.handler.compensate(ctx, r, cause)

	if !errors.Is(err, jobs.ErrOutcomeUnknown) || !errors.Is(err, cause) {
		t.Fatalf("compensate = %v, want the unknown outcome next to the cause", err)
	}
	if m := w.moveRow(); m.Phase != database.AppMoveCompensatingSourceVerified {
		t.Errorf("move = %+v, want A restored and verified, the removal waiting", m)
	}
	w.wantSourceRunning()
	if got := w.mutations(w.b); !slices.Equal(got, before) {
		t.Errorf("B mutations went from %v to %v before the deadline", before, got)
	}
	if v := w.volumeRow(w.mounts["/data"]); v.State != database.AppMoveVolumeImporting {
		t.Errorf("volume = %+v, want it left importing", v)
	}

	w.stuck = false
	err = w.resume()

	wantAppsCode(t, err, smerr.CodeDeploymentFailed)
	if m := w.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Fatalf("move = %+v, want rolled back once the deadline passed", m)
	}
	w.wantVolumesOnB(false)
}

func TestCompensation_AMoveThatEndsAtPreflightIsRolledBackWithNoNodeCommand(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	w.started()
	w.b.node.down("compose.disk_free", errors.New("link down"))
	w.exec(`UPDATE jobs SET attempts = max_attempts WHERE id = ?`, w.lease.JobID)

	err := w.run()

	if err == nil {
		t.Fatal("Run succeeded")
	}
	m := w.moveRow()
	if m.Phase != database.AppMoveRolledBack || m.DestDeploymentID != nil {
		t.Errorf("move = %+v, want rolled back with nothing staged", m)
	}
	if got := append(w.mutations(w.a), w.mutations(w.b)...); len(got) != 0 {
		t.Errorf("a move that ended at preflight ran %v", got)
	}
	if len(w.events("app_move.rolled_back")) != 1 {
		t.Error("the rollback was not audited")
	}
	w.wantSourceRunning()
}

func TestCompensation_AStagingThatFailedPartwayRemovesNothingItDidNotCreate(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	w.started()
	w.b.node.exit("compose.pull", 1)

	err := w.run()

	if err == nil {
		t.Fatal("Run succeeded")
	}
	m := w.moveRow()
	if m.Phase != database.AppMoveRolledBack || m.DestDeploymentID == nil {
		t.Fatalf("move = %+v, want rolled back after B's deployment was made", m)
	}
	if got := w.mutations(w.b); !slices.Equal(got, []string{"compose.pull"}) {
		t.Errorf("B mutations = %v, want only the failed pull: there was nothing to stop or remove", got)
	}
	if got := w.mutations(w.a); len(got) != 0 {
		t.Errorf("A mutations = %v, want none: A kept running", got)
	}
	if dep := w.row(*m.DestDeploymentID); dep.State != deployments.StateFailed {
		t.Errorf("B's deployment = %s, want failed", dep.State)
	}
}

func TestCompensation_ALostLeaseWritesAndDispatchesNothing(t *testing.T) {
	w := newStatefulWorld(t)
	w.failAfterStart()
	bumped := false
	inner := w.handler.checkpoint
	w.handler.checkpoint = func() error {
		if err := inner(); err != nil {
			return err
		}
		if !bumped && w.moveRow().Phase == database.AppMoveCompensatingBStopped {
			bumped = true
			w.exec(`UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id = ?`, w.lease.JobID)
		}
		return nil
	}

	err := w.run()

	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("Run = %v, want the lost lease", err)
	}
	if m := w.moveRow(); m.Phase != database.AppMoveCompensatingBStopped {
		t.Errorf("move = %+v, want it left where the old worker's last write put it, not halted", m)
	}
	if got := w.mutations(w.a); slices.Contains(got, "compose.start") {
		t.Errorf("A mutations = %v: a worker that lost its lease started A", got)
	}
}

func TestCompensation_ACrashAtAnyDispatchOrCheckpointResumesToTheSameEnd(t *testing.T) {
	scenarios := []struct {
		name  string
		setup func(w *runWorld)
		check func(t *testing.T, w *runWorld)
	}{
		{
			"B started and unhealthy",
			(*runWorld).failAfterStart,
			func(t *testing.T, w *runWorld) {
				w.wantVolumesOnB(true)
				if w.b.state != "exited" {
					t.Errorf("B is %s, want stopped", w.b.state)
				}
			},
		},
		{
			"failure before B started",
			(*runWorld).failBeforeStart,
			func(t *testing.T, w *runWorld) {
				w.wantVolumesOnB(false)
				if w.b.state != "none" {
					t.Errorf("B is %s, want removed", w.b.state)
				}
			},
		},
	}
	for _, sc := range scenarios {
		dry := newStatefulWorld(t)
		sc.setup(dry)
		if err := dry.run(); err == nil {
			t.Fatalf("%s: the uninterrupted run did not fail", sc.name)
		}
		total := map[string]int{"dispatch": dry.ticks["dispatch"], "checkpoint": dry.ticks["checkpoint"]}
		for _, kind := range []string{"dispatch", "checkpoint"} {
			for n := 1; n <= total[kind]; n++ {
				t.Run(fmt.Sprintf("%s/%s %d", sc.name, kind, n), func(t *testing.T) {
					w := newStatefulWorld(t)
					sc.setup(w)
					w.crash[kind] = n

					if err := w.run(); err == nil {
						t.Fatal("the crash did not stop the run")
					}
					w.crash[kind], w.stuck = 0, false
					_ = w.resume() // a rolled back move answers with its own error

					if m := w.moveRow(); m.Phase != database.AppMoveRolledBack {
						t.Fatalf("move = %+v, want rolled back", m)
					}
					w.wantSourceRunning()
					sc.check(t, w)
					if got := countOf(w.mutations(w.a), "compose.start"); got > 1 {
						t.Errorf("A was started %d times", got)
					}
					if events := w.events("app_move.rolled_back"); len(events) < 1 {
						t.Error("the rollback was not audited")
					}
				})
			}
		}
	}
}

// ---- cleanup of the parked source ----------------------------------------------------------------------------------

func (w *runWorld) doneAndCleanupRequested(t *testing.T) jobs.Job {
	t.Helper()
	err := w.run()
	mustf(t, err, "Run")
	w.endJob(nil)
	sub, err := w.svc.CleanupSource(context.Background(), w.caller(w.admin), w.target.ID)
	mustf(t, err, "CleanupSource")
	return sub.Job
}

func TestCleanup_RemovesTheParkedSourceKeepsAndListsItsVolumesAndTouchesNothingOnB(t *testing.T) {
	w := newStatefulWorld(t)
	job := w.doneAndCleanupRequested(t)
	bBefore := slices.Clone(w.mutations(w.b))

	mustf(t, w.runClaimed(job), "cleanup job")

	if w.a.state != "none" {
		t.Errorf("A is %s, want its containers removed", w.a.state)
	}
	if got := w.mutations(w.a); !slices.Equal(got, []string{"compose.stop", "compose.down"}) {
		t.Errorf("A mutations = %v, want the stop of the move and then a down", got)
	}
	for _, name := range w.volumeNames() {
		if _, present := w.a.volumeFiles(name); !present {
			t.Errorf("A's volume %s was removed", name)
		}
	}
	if got := w.mutations(w.b); !slices.Equal(got, bBefore) {
		t.Errorf("B mutations went from %v to %v", bBefore, got)
	}
	events := w.events("app_move.source_cleaned")
	if len(events) != 1 || len(w.keptVolumes(events[0])) != 2 {
		t.Errorf("source_cleaned events = %+v, want one listing A's two volumes", events)
	}

	w.endJob(nil)
	again, err := w.svc.CleanupSource(context.Background(), w.caller(w.admin), w.target.ID)
	mustf(t, err, "CleanupSource again")
	mustf(t, w.runClaimed(again.Job), "cleanup job when nothing is left")
	if got := countOf(w.mutations(w.a), "compose.down"); got != 1 {
		t.Errorf("compose down ran %d times, want the second cleanup to find nothing to remove", got)
	}
}

func TestCleanup_RefusesWhatIsNotTheParkedSourceAnymore(t *testing.T) {
	tests := []struct {
		name   string
		change func(w *runWorld)
		want   string
	}{
		{"a container of another deployment", func(w *runWorld) { w.a.deployment = "00000000-0000-0000-0000-00000000dead" }, "parked deployment"},
		{"the target runs on the source again", func(w *runWorld) {
			w.exec(`UPDATE app_targets SET node_id = ? WHERE id = ?`, w.node.ID, w.target.ID)
		}, "again"},
		{"another target uses the project on the source", func(w *runWorld) {
			project := w.project()
			w.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := database.CreateAppTarget(ctx, tx, database.AppTarget{
					ID: w.ids.NewID(), AppID: w.target.AppID, EnvironmentID: w.staging.ID, NodeID: w.node.ID,
					ComposeProject: project, DeploymentPolicyJSON: []byte(`{}`), CreatedAt: w.clock.Now(), UpdatedAt: w.clock.Now(),
				})
				return err
			})
		}, "another target"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newStatefulWorld(t)
			job := w.doneAndCleanupRequested(t)
			claimed, found := w.claim()
			if !found || claimed.Job.ID != job.ID {
				t.Fatalf("claimed %v, want the cleanup job", claimed.Job.ID)
			}
			w.lease = claimed.Lease
			tc.change(w)
			before := slices.Clone(w.mutations(w.a))

			err := w.run()

			wantRefusal(t, err, smerr.CodeConflict, tc.want)
			if got := w.mutations(w.a); !slices.Equal(got, before) {
				t.Errorf("a refused cleanup ran %v", got[len(before):])
			}
		})
	}
}

// ---- reconcile -----------------------------------------------------------------------------------------------------

type passedOn struct{ called []string }

func (p *passedOn) Collect(_ context.Context, in jobs.Intent) (jobs.Evidence, error) {
	p.called = append(p.called, in.Operation)
	return jobs.Evidence{}, errors.New("not a move command")
}

func TestMoveEvidence_EachCommandIsProvenByItsMarkerAndJudgedByWhatItLeftOnTheNode(t *testing.T) {
	w := newStatefulWorld(t)
	mustf(t, w.run(), "Run")
	bDep := *w.moveRow().DestDeploymentID
	data := w.volumeNames()[0]
	other := &passedOn{}
	evidence := &MoveEvidence{core: w.handler.core, dial: w.handler.dep.dial, next: other}
	now := w.clock.Now()

	tests := []struct {
		name      string
		operation string
		step      string
		on        domain.ID
		setup     func()
		marker    string
		class     jobs.Classification
		proven    bool
	}{
		{"create leaves containers", operationComposeCreate, "create", bDep, func() { w.b.state = "created" }, "", jobs.ClassComplete, true},
		{"create but no container", operationComposeCreate, "create", bDep, func() { w.b.state = "none" }, "", jobs.ClassPartialStable, true},
		{"start leaves them running", operationComposeStart, "start", bDep, func() { w.b.state = "running" }, "", jobs.ClassComplete, true},
		{"start but they stopped since", operationComposeStart, "start", bDep, func() { w.b.state = "exited" }, "", jobs.ClassPartialStable, true},
		{"stop leaves them exited", operationComposeStop, "stop-source", w.good.ID, func() { w.a.state = "exited" }, "", jobs.ClassComplete, true},
		{"stop but one runs again", operationComposeStop, "stop-source", w.good.ID, func() { w.a.state = "running" }, "", jobs.ClassPartialStable, true},
		{"down leaves none", operationComposeDown, "cleanup-source", w.good.ID, func() { w.a.state = "none" }, "", jobs.ClassComplete, true},
		{"down but they are back", operationComposeDown, "cleanup-source", w.good.ID, func() { w.a.state = "created" }, "", jobs.ClassPartialStable, true},
		{"volume removal that names its volume: absent", operationVolumeRm, stepCompensateRmPrefix + data, bDep, func() {
			delete(w.b.volumes, data)
		}, "", jobs.ClassComplete, true},
		{"volume removal that names its volume: still there", operationVolumeRm, stepCompensateRmPrefix + data, bDep, func() {
			w.b.volumes[data] = map[string]string{}
		}, "", jobs.ClassPartialStable, true},
		{"a replacement's removal is judged by its marker", operationVolumeRm, "replace-volume-rm", bDep, func() {}, "", jobs.ClassComplete, true},
		{"a marker that never appeared", operationComposeStart, "start", bDep, func() {}, "absent\n", jobs.ClassNotStarted, true},
		{"a command still running", operationComposeStart, "start", bDep, func() {}, "started\n", jobs.ClassUnknown, false},
		{"a command that failed", operationComposeStart, "start", bDep, func() {}, "done 1\n", jobs.ClassUnknown, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := w.b
			if tc.on == w.good.ID {
				node = w.a
			}
			tc.setup()
			node.marker = tc.marker
			defer func() { node.marker = "" }()
			in := jobs.Intent{
				ID: w.ids.NewID(), Step: tc.step, Operation: tc.operation, TargetType: string(domain.ResourceDeployment),
				TargetID: tc.on.String(), Marker: "marker", DispatchedAt: &now, DeadlineAt: now,
			}

			got, err := evidence.Collect(context.Background(), in)

			mustf(t, err, "Collect")
			if got.Classification != tc.class || got.Proven() != tc.proven || len(got.Fingerprint) == 0 {
				t.Errorf("evidence = %+v, want class %s proven %v with a fingerprint", got, tc.class, tc.proven)
			}
		})
	}
	if len(other.called) != 0 {
		t.Errorf("move commands were passed on: %v", other.called)
	}
	if _, err := evidence.Collect(context.Background(), jobs.Intent{Operation: operationComposePull, DispatchedAt: &now}); err == nil || len(other.called) != 1 {
		t.Errorf("a deployment command must be answered by the next source, called %v, err %v", other.called, err)
	}
}

func TestMoveEvidence_AnImportIsProvenStoppedOnlyWhenItsDeadlineHasPassed(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	evidence := &MoveEvidence{core: w.handler.core, dial: w.handler.dep.dial, next: &passedOn{}}
	dispatched := w.clock.Now()
	in := jobs.Intent{
		ID: w.ids.NewID(), Step: "copy-v-1", Operation: operationVolumeImport, TargetType: string(domain.ResourceDeployment),
		TargetID: w.good.ID.String(), DispatchedAt: &dispatched, DeadlineAt: dispatched.Add(20 * time.Minute),
	}

	if _, err := evidence.Collect(context.Background(), in); err == nil {
		t.Fatal("an import before its deadline has evidence")
	}
	w.clock.Advance(20 * time.Minute)

	got, err := evidence.Collect(context.Background(), in)

	mustf(t, err, "Collect after the deadline")
	if !got.Proven() || got.Proof != proofImportDeadline || got.Classification != jobs.ClassPartialStable {
		t.Errorf("evidence = %+v, want proven by the deadline, partial_stable", got)
	}
	if calls := append(w.mutations(w.a), w.mutations(w.b)...); len(calls) != 0 {
		t.Errorf("collecting evidence dispatched %v", calls)
	}
}

func TestMovePolicy_AdmitsWhatAMoveProducesAndRequeuesWhileItHasAttempts(t *testing.T) {
	policy := MovePolicy{}
	for class, want := range map[jobs.Classification]bool{
		jobs.ClassComplete: true, jobs.ClassNotStarted: true, jobs.ClassPartialStable: true, jobs.ClassUnknown: false,
	} {
		if got := policy.Admit(jobs.Evidence{Classification: class}); got != want {
			t.Errorf("Admit(%s) = %v, want %v", class, got, want)
		}
	}
	tests := []struct {
		name string
		job  jobs.Job
		want jobs.VerdictAction
	}{
		{"attempts left", jobs.Job{Attempts: 1, MaxAttempts: 3, RetryClass: domain.RetryResumable}, jobs.VerdictRequeued},
		{"a resumable move without attempts waits for an operator", jobs.Job{Attempts: 3, MaxAttempts: 3, RetryClass: domain.RetryResumable}, jobs.VerdictHeld},
		{"an idempotent job without attempts fails", jobs.Job{Attempts: 3, MaxAttempts: 3, RetryClass: domain.RetryIdempotent}, jobs.VerdictFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := policy.Reconcile(context.Background(), nil, tc.job, nil, nil)
			if err != nil || v.Action != tc.want || v.Reason == "" || (tc.want == jobs.VerdictFailed) != (v.Failure != nil) {
				t.Errorf("verdict = %+v (%v), want %s", v, err, tc.want)
			}
		})
	}
	if mode, err := policy.ClaimMode(context.Background(), nil, jobs.Job{}); err != nil || mode != jobs.ClaimForward {
		t.Errorf("ClaimMode = %v, %v, want forward", mode, err)
	}
	if err := policy.RevalidateRecovery(context.Background(), nil, jobs.Job{}); err == nil {
		t.Error("a move has no safety recovery to revalidate")
	}
	if ok, err := policy.EscalateToRecovery(context.Background(), nil, jobs.Job{}, errors.New("x")); ok || err != nil {
		t.Errorf("EscalateToRecovery = %v, %v, want false", ok, err)
	}
	keys := policy.TypePolicies()
	for _, jobType := range []string{appMoveAction, appMoveCleanupAction, appMoveAbandonAction} {
		if keys[jobType] == nil {
			t.Errorf("no policy for %s", jobType)
		}
	}
}
