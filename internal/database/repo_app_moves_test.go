package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// moveWorld is a target on node a with a known-good deployment, and a second node b in the same environment.
type moveWorld struct {
	target    AppTarget
	a, b      domain.Node
	by        domain.ID
	knownGood domain.ID
	app       App
	appsWorld appsWorld
}

func newMoveWorld(ctx context.Context, f *fixture, q Querier) moveWorld {
	w := newAppsWorld(ctx, f, q)
	app := must(CreateApp(ctx, q, appsAppOf(f, "web")))
	target := must(CreateAppTarget(ctx, q, appsTargetOf(f, app, w, "sm-web-prod")))
	by := f.identity(ctx, q, domain.ActorHuman, "alice").ID
	mw := moveWorld{target: target, a: w.node, b: f.node(ctx, q, w.provider, "n2"), by: by, app: app, appsWorld: w}
	mw.knownGood = mw.deployment(ctx, f, q, deployments.KindDeploy, mw.a.ID)
	walkDeployment(f, ctx, q, mw.knownGood, deployments.StateQueued, deployments.StatePreparing, deployments.StateStaging,
		deployments.StateDeploying, deployments.StateVerifying, deployments.StateSucceeded)
	noErr(f.t, MarkDeploymentKnownGood(ctx, q, mw.knownGood, testEpoch))
	return mw
}

func (mw moveWorld) deployment(ctx context.Context, f *fixture, q Querier, kind string, node domain.ID) domain.ID {
	d := Deployment{
		ID: f.ids.NewID(), Kind: kind, AppID: mw.app.ID, AppTargetID: mw.target.ID, EnvironmentID: mw.target.EnvironmentID,
		NodeID: node, State: deployments.StateCreated, RequestedBy: mw.by, CommitSha: "abc",
		RequestedRaw: json.RawMessage(`{}`),
		Credential:   domain.CredentialContext{Kind: domain.CredentialSession, ID: "sess", Scopes: []string{"x"}},
		CreatedAt:    testEpoch, UpdatedAt: testEpoch,
	}
	noErr(f.t, InsertDeployment(ctx, q, d))
	return d.ID
}

func walkDeployment(f *fixture, ctx context.Context, q Querier, id domain.ID, states ...deployments.State) {
	f.t.Helper()
	for _, s := range states {
		noErr(f.t, TransitionDeployment(ctx, q, id, s, StateFailure{}, testEpoch))
	}
}

func (mw moveWorld) move(ctx context.Context, f *fixture, q Querier, stateful bool, volumes ...AppMoveVolume) AppMove {
	m := AppMove{
		ID: f.ids.NewID(), AppTargetID: mw.target.ID, SourceNodeID: mw.a.ID, DestNodeID: mw.b.ID,
		PlanID: f.plan(ctx, q, mw.by).ID, JobID: f.job(ctx, q, mw.by), KnownGoodDeploymentID: mw.knownGood,
		Stateful: stateful, CreatedBy: mw.by, CreatedAt: testEpoch,
	}
	return must(InsertAppMove(ctx, q, m, volumes))
}

// verifiedMove walks a stateless move to verified with B's move deployment bound and verifying.
func (mw moveWorld) verifiedMove(ctx context.Context, f *fixture, q Querier) (AppMove, domain.ID) {
	m := mw.move(ctx, f, q, false)
	dep := mw.deployment(ctx, f, q, deployments.KindMove, mw.b.ID)
	walkDeployment(f, ctx, q, dep, deployments.StateQueued, deployments.StatePreparing, deployments.StateStaging,
		deployments.StateDeploying, deployments.StateVerifying)
	must(BindAppMoveDestDeployment(ctx, q, m.ID, dep, testEpoch))
	for _, step := range [][2]AppMovePhase{{AppMovePreflight, AppMoveStaged}, {AppMoveStaged, AppMoveStarted}, {AppMoveStarted, AppMoveVerified}} {
		m = must(AdvanceAppMovePhase(ctx, q, m.ID, step[0], step[1], testEpoch))
	}
	return m, dep
}

func volumeOf(name, service string, others ...string) AppMoveVolume {
	return AppMoveVolume{VolumeName: name, Service: service, MountTarget: "/data", OtherServices: others, SourceBytes: 100}
}

func TestAppMoveLifecycle(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, true, volumeOf("sm-web-prod_db", "db", "worker", "api"), volumeOf("sm-web-prod_cache", "web"))
		if m.Phase != AppMovePreflight || !m.Stateful || m.DestDeploymentID != nil || m.BStartedAt != nil ||
			m.CommittedRevision != 0 || !m.PhaseStartedAt.Equal(testEpoch) || m.SourceNodeID != mw.a.ID || m.DestNodeID != mw.b.ID {
			t.Fatalf("inserted = %+v", m)
		}
		vols := must(ListAppMoveVolumes(ctx, q, m.ID))
		if len(vols) != 2 || vols[0].VolumeName != "sm-web-prod_cache" || vols[1].VolumeName != "sm-web-prod_db" {
			t.Fatalf("volumes = %+v", vols)
		}
		db := vols[1]
		if db.Service != "db" || strings.Join(db.OtherServices, ",") != "worker,api" || db.Attempt != 1 ||
			db.State != AppMoveVolumePending || db.SourceBytes != 100 || db.CreatedByMove || db.ImportDeadlineAt != nil {
			t.Fatalf("volume = %+v", db)
		}
		if got := must(GetOpenAppMoveByTarget(ctx, q, mw.target.ID)); got.ID != m.ID {
			t.Fatalf("open = %s", got.ID)
		}

		dep := mw.deployment(ctx, f, q, deployments.KindMove, mw.b.ID)
		later := testEpoch.Add(time.Minute)
		m = must(BindAppMoveDestDeployment(ctx, q, m.ID, dep, later))
		for _, step := range [][2]AppMovePhase{
			{AppMovePreflight, AppMoveStaged},
			{AppMoveStaged, AppMoveSourceStop},
			{AppMoveSourceStop, AppMoveDataCopied},
			{AppMoveDataCopied, AppMoveStarted},
			{AppMoveStarted, AppMoveVerified},
		} {
			m = must(AdvanceAppMovePhase(ctx, q, m.ID, step[0], step[1], later))
		}
		if m.Phase != AppMoveVerified || !m.PhaseStartedAt.Equal(later) || m.DestDeploymentID == nil || *m.DestDeploymentID != dep {
			t.Fatalf("verified = %+v", m)
		}
		walkDeployment(f, ctx, q, dep, deployments.StateQueued, deployments.StatePreparing, deployments.StateStaging,
			deployments.StateDeploying, deployments.StateVerifying)
		m = must(CommitAppMove(ctx, q, m.ID, mw.target.ID, mw.target.SpecRevision, mw.a.ID, mw.b.ID, dep, later))
		if m.Phase != AppMoveCommitted || m.CommittedRevision != mw.target.SpecRevision+1 {
			t.Fatalf("committed = %+v", m)
		}
		m = must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveCommitted, AppMoveSourceParked, later))
		m = must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveSourceParked, AppMoveDone, later))

		_, err := GetOpenAppMoveByTarget(ctx, q, mw.target.ID)
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = AdvanceAppMovePhase(ctx, q, m.ID, AppMoveDone, AppMoveStaged, later)
		if err == nil || !strings.Contains(err.Error(), "does not change phase") {
			t.Fatalf("a finished move moved: %v", err)
		}
		// a finished move frees the target: a later move is allowed and the history keeps both
		mw.knownGood = dep
		second := mw.move(ctx, f, q, false)
		if got := must(ListAppMovesByTarget(ctx, q, mw.target.ID)); len(got) != 2 || got[0].ID != second.ID || got[1].ID != m.ID {
			t.Fatalf("history = %+v", got)
		}
	})
}

func TestAppMoveAdvanceIsFencedAndRefusesSpecialPhases(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, false)
		_, err := AdvanceAppMovePhase(ctx, q, m.ID, AppMoveStaged, AppMoveStarted, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		var e *smerr.Error
		if !errors.As(err, &e) || e.Details["current_phase"] != "preflight" || e.Details["expected_phase"] != "staged" {
			t.Fatalf("conflict details = %v", err)
		}
		_, err = AdvanceAppMovePhase(ctx, q, "missing", AppMovePreflight, AppMoveStaged, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
		for _, bad := range [][2]AppMovePhase{
			{AppMoveVerified, AppMoveCommitted}, {AppMovePreflight, AppMoveFailed}, {AppMoveConflict, AppMoveStaged},
		} {
			_, err = AdvanceAppMovePhase(ctx, q, m.ID, bad[0], bad[1], testEpoch)
			wantError(t, err, smerr.CodeInvalidArgument, "")
		}
		// a stateless move never passes through the data phases
		_, err = AdvanceAppMovePhase(ctx, q, m.ID, AppMovePreflight, AppMoveSourceStop, testEpoch)
		if err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Fatalf("stateless move reached source_stopped: %v", err)
		}
		// compensation phases are plain phases
		must(AdvanceAppMovePhase(ctx, q, m.ID, AppMovePreflight, AppMoveCompensatingBStopped, testEpoch))
		must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveCompensatingBStopped, AppMoveCompensatingSourceStarted, testEpoch))
		must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveCompensatingSourceStarted, AppMoveCompensatingSourceVerified, testEpoch))
		must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveCompensatingSourceVerified, AppMoveRolledBack, testEpoch))
	})
}

func TestAppMoveHaltAndResumeKeepPhaseStart(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, false)
		started := testEpoch.Add(time.Minute)
		m = must(AdvanceAppMovePhase(ctx, q, m.ID, AppMovePreflight, AppMoveCompensatingBStopped, started))
		m = must(AdvanceAppMovePhase(ctx, q, m.ID, AppMoveCompensatingBStopped, AppMoveCompensatingSourceStarted, started))
		m = must(HaltAppMove(ctx, q, m.ID, AppMoveCompensatingSourceStarted, AppMoveConflict, "source unhealthy", started.Add(time.Minute)))
		if m.Phase != AppMoveConflict || m.HaltedPhase != AppMoveCompensatingSourceStarted || m.LastError == "" {
			t.Fatalf("halted = %+v", m)
		}
		if got := must(GetOpenAppMoveByTarget(ctx, q, mw.target.ID)); got.ID != m.ID {
			t.Fatal("a halted move must stay open")
		}
		_, err := HaltAppMove(ctx, q, m.ID, AppMoveConflict, AppMoveFailed, "x", started)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		_, err = HaltAppMove(ctx, q, m.ID, AppMoveRolledBack, AppMoveFailed, "x", started)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		_, err = ResumeHaltedAppMove(ctx, q, m.ID, AppMoveFailed, started)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = ResumeHaltedAppMove(ctx, q, m.ID, AppMoveCompensatingSourceStarted, started)
		wantError(t, err, smerr.CodeInvalidArgument, "")

		m = must(ResumeHaltedAppMove(ctx, q, m.ID, AppMoveConflict, started.Add(time.Hour)))
		if m.Phase != AppMoveCompensatingSourceStarted || m.HaltedPhase != "" || m.LastError != "" || !m.PhaseStartedAt.Equal(started) {
			t.Fatalf("resumed = %+v", m)
		}
	})
}

func TestAppMoveTriggersAndChecks(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, false)

		// one open move per target, even when the second would go to the same node
		dup := m
		dup.ID, dup.PlanID, dup.JobID = f.ids.NewID(), f.plan(ctx, q, mw.by).ID, f.job(ctx, q, mw.by)
		_, err := InsertAppMove(ctx, q, dup, nil)
		wantError(t, err, smerr.CodeConflict, "")

		// source and destination differ
		same := dup
		same.DestNodeID = same.SourceNodeID
		if _, err := InsertAppMove(ctx, q, same, nil); err == nil {
			t.Fatal("a move to its own source was accepted")
		}

		// the phase and its halted phase agree
		for _, stmt := range []string{
			`UPDATE app_moves SET phase = 'failed' WHERE id = ?`,
			`UPDATE app_moves SET halted_phase = 'staged' WHERE id = ?`,
		} {
			if _, err := q.ExecContext(ctx, stmt, m.ID); err == nil || !strings.Contains(err.Error(), "CHECK") {
				t.Errorf("%s: err = %v", stmt, err)
			}
		}

		// identity columns never change
		other := mw.deployment(ctx, f, q, deployments.KindMove, mw.b.ID)
		for _, stmt := range []string{
			`UPDATE app_moves SET dest_node_id = source_node_id WHERE id = ?`,
			`UPDATE app_moves SET app_target_id = 'x' WHERE id = ?`,
			`UPDATE app_moves SET stateful = 1 WHERE id = ?`,
			`UPDATE app_moves SET known_good_deployment_id = '` + other.String() + `' WHERE id = ?`,
			`UPDATE app_moves SET created_by = 'x' WHERE id = ?`,
		} {
			if _, err := q.ExecContext(ctx, stmt, m.ID); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
				t.Errorf("%s: err = %v", stmt, err)
			}
		}

		// B's deployment, B's first start and the committed revision are written once
		must(BindAppMoveDestDeployment(ctx, q, m.ID, other, testEpoch))
		must(SetAppMoveBStartedAt(ctx, q, m.ID, testEpoch))
		if _, err := q.ExecContext(ctx, `UPDATE app_moves SET committed_revision = 3 WHERE id = ?`, m.ID); err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			`UPDATE app_moves SET dest_deployment_id = known_good_deployment_id WHERE id = ?`,
			`UPDATE app_moves SET dest_deployment_id = NULL WHERE id = ?`,
			`UPDATE app_moves SET b_started_at = NULL WHERE id = ?`,
			`UPDATE app_moves SET b_started_at = 99 WHERE id = ?`,
			`UPDATE app_moves SET committed_revision = 4 WHERE id = ?`,
		} {
			if _, err := q.ExecContext(ctx, stmt, m.ID); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
				t.Errorf("%s: err = %v", stmt, err)
			}
		}
	})
}

func TestBindAppMoveDestDeployment(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, false)
		dep := mw.deployment(ctx, f, q, deployments.KindMove, mw.b.ID)

		for name, bad := range map[string]domain.ID{
			"a deploy deployment": mw.deployment(ctx, f, q, deployments.KindDeploy, mw.b.ID),
			"another node":        mw.deployment(ctx, f, q, deployments.KindMove, mw.a.ID),
			"an unknown":          "missing",
		} {
			if _, err := BindAppMoveDestDeployment(ctx, q, m.ID, bad, testEpoch); err == nil {
				t.Errorf("bound %s", name)
			}
		}
		bound := must(BindAppMoveDestDeployment(ctx, q, m.ID, dep, testEpoch))
		again := must(BindAppMoveDestDeployment(ctx, q, m.ID, dep, testEpoch.Add(time.Second)))
		if bound.DestDeploymentID == nil || again.DestDeploymentID == nil || *again.DestDeploymentID != dep {
			t.Fatalf("bound = %+v again = %+v", bound, again)
		}
		second := mw.deployment(ctx, f, q, deployments.KindMove, mw.b.ID)
		_, err := BindAppMoveDestDeployment(ctx, q, m.ID, second, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = BindAppMoveDestDeployment(ctx, q, "missing", dep, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestSetAppMoveBStartedAtKeepsTheFirstValue(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, false)
		first := testEpoch.Add(time.Minute)
		m = must(SetAppMoveBStartedAt(ctx, q, m.ID, first))
		if m.BStartedAt == nil || !m.BStartedAt.Equal(first) {
			t.Fatalf("b_started_at = %v", m.BStartedAt)
		}
		m = must(SetAppMoveBStartedAt(ctx, q, m.ID, first.Add(time.Hour)))
		if !m.BStartedAt.Equal(first) {
			t.Fatalf("b_started_at moved to %v", m.BStartedAt)
		}
		_, err := SetAppMoveBStartedAt(ctx, q, "missing", first)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestRebindAppMoveJobIsFencedOnTheStoredJob(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, false)
		plan, job := f.plan(ctx, q, mw.by).ID, f.job(ctx, q, mw.by)
		_, err := RebindAppMoveJob(ctx, q, m.ID, "stale", plan, job, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		got := must(RebindAppMoveJob(ctx, q, m.ID, m.JobID, plan, job, testEpoch))
		if got.JobID != job || got.PlanID != plan {
			t.Fatalf("rebound = %+v", got)
		}
		_, err = RebindAppMoveJob(ctx, q, m.ID, m.JobID, plan, job, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestOpenMoveDestinationsListOpenMovesOfTheProject(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		if got := must(OpenMoveDestinations(ctx, q, mw.target.ComposeProject)); len(got) != 0 {
			t.Fatalf("destinations without a move = %v", got)
		}
		m := mw.move(ctx, f, q, false)
		got := must(OpenMoveDestinations(ctx, q, mw.target.ComposeProject))
		if len(got) != 1 || got[0] != mw.b.ID {
			t.Fatalf("destinations = %v, want [%s]", got, mw.b.ID)
		}
		if other := must(OpenMoveDestinations(ctx, q, "other-project")); len(other) != 0 {
			t.Fatalf("another project = %v", other)
		}
		must(HaltAppMove(ctx, q, m.ID, AppMovePreflight, AppMoveFailed, "x", testEpoch))
		if got := must(OpenMoveDestinations(ctx, q, mw.target.ComposeProject)); len(got) != 1 {
			t.Fatalf("a halted move must still count, got %v", got)
		}
		must(ResumeHaltedAppMove(ctx, q, m.ID, AppMoveFailed, testEpoch))
		for _, step := range [][2]AppMovePhase{
			{AppMovePreflight, AppMoveCompensatingBStopped},
			{AppMoveCompensatingBStopped, AppMoveCompensatingSourceStarted},
			{AppMoveCompensatingSourceStarted, AppMoveCompensatingSourceVerified},
			{AppMoveCompensatingSourceVerified, AppMoveCompensatingBRemoved},
			{AppMoveCompensatingBRemoved, AppMoveRolledBack},
		} {
			must(AdvanceAppMovePhase(ctx, q, m.ID, step[0], step[1], testEpoch))
		}
		if got := must(OpenMoveDestinations(ctx, q, mw.target.ComposeProject)); len(got) != 0 {
			t.Fatalf("a rolled back move still counts: %v", got)
		}
	})
}

func TestAppMoveVolumeTransitionsAreFencedAndReplaceByAttempt(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, true, volumeOf("p_db", "db"))
		deadline := testEpoch.Add(time.Hour)

		if n := must(MarkAppMoveVolumesCreatedByMove(ctx, q, m.ID, testEpoch)); n != 1 {
			t.Fatalf("marked %d", n)
		}
		if n := must(MarkAppMoveVolumesCreatedByMove(ctx, q, m.ID, testEpoch)); n != 0 {
			t.Fatalf("marked again %d", n)
		}
		_, err := MarkAppMoveVolumesCreatedByMove(ctx, q, "missing", testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")

		// out of order and stale transitions are refused and change nothing
		_, err = CompleteAppMoveVolumeImport(ctx, q, m.ID, "p_db", 1, 5, "sha256:aa", testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = BeginAppMoveVolumeImport(ctx, q, m.ID, "p_db", 2, deadline, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = BeginAppMoveVolumeImport(ctx, q, m.ID, "nope", 1, deadline, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")

		v := must(BeginAppMoveVolumeImport(ctx, q, m.ID, "p_db", 1, deadline, testEpoch))
		if v.State != AppMoveVolumeImporting || v.ImportDeadlineAt == nil || !v.ImportDeadlineAt.Equal(deadline) || !v.CreatedByMove {
			t.Fatalf("importing = %+v", v)
		}
		_, err = BeginAppMoveVolumeImport(ctx, q, m.ID, "p_db", 1, deadline, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = CompleteAppMoveVolumeImport(ctx, q, m.ID, "p_db", 1, 5, "", testEpoch)
		wantError(t, err, smerr.CodeInvalidArgument, "")

		v = must(CompleteAppMoveVolumeImport(ctx, q, m.ID, "p_db", 1, 5, "sha256:aa", testEpoch))
		if v.State != AppMoveVolumeImported || v.ImportDeadlineAt != nil || v.SourceBytes != 5 || v.SourceDigest != "sha256:aa" {
			t.Fatalf("imported = %+v", v)
		}
		// a digest that differs from A's cannot be verified
		_, err = VerifyAppMoveVolume(ctx, q, m.ID, "p_db", 1, 5, "sha256:bb", testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		if got := must(GetAppMoveVolume(ctx, q, m.ID, "p_db")); got.State != AppMoveVolumeImported || got.DestDigest != "" {
			t.Fatalf("a mismatch changed the volume: %+v", got)
		}

		// the failed attempt is replaced: pending again, next attempt, nothing measured, ownership evidence kept
		v = must(ResetAppMoveVolume(ctx, q, m.ID, "p_db", 1, AppMoveVolumeImported, testEpoch))
		if v.State != AppMoveVolumePending || v.Attempt != 2 || v.SourceDigest != "" || v.DestDigest != "" || !v.CreatedByMove {
			t.Fatalf("reset = %+v", v)
		}
		_, err = ResetAppMoveVolume(ctx, q, m.ID, "p_db", 1, AppMoveVolumeImported, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = ResetAppMoveVolume(ctx, q, m.ID, "p_db", 2, AppMoveVolumePending, testEpoch)
		wantError(t, err, smerr.CodeInvalidArgument, "")

		must(BeginAppMoveVolumeImport(ctx, q, m.ID, "p_db", 2, deadline, testEpoch))
		v = must(ResetAppMoveVolume(ctx, q, m.ID, "p_db", 2, AppMoveVolumeImporting, testEpoch))
		if v.Attempt != 3 || v.State != AppMoveVolumePending || v.ImportDeadlineAt != nil {
			t.Fatalf("reset importing = %+v", v)
		}

		must(BeginAppMoveVolumeImport(ctx, q, m.ID, "p_db", 3, deadline, testEpoch))
		must(CompleteAppMoveVolumeImport(ctx, q, m.ID, "p_db", 3, 7, "sha256:cc", testEpoch))
		_, err = VerifyAppMoveVolume(ctx, q, m.ID, "p_db", 3, 7, "", testEpoch)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		v = must(VerifyAppMoveVolume(ctx, q, m.ID, "p_db", 3, 7, "sha256:cc", testEpoch))
		if v.State != AppMoveVolumeVerified || v.DestBytes != 7 || v.DestDigest != "sha256:cc" {
			t.Fatalf("verified = %+v", v)
		}
		_, err = ResetAppMoveVolume(ctx, q, m.ID, "p_db", 3, AppMoveVolumeImported, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestAppMoveVolumeConstraints(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw := newMoveWorld(ctx, f, q)
		m := mw.move(ctx, f, q, true, volumeOf("p_db", "db"))
		for _, stmt := range []string{
			`UPDATE app_move_volumes SET created_by_move = 1 WHERE move_id = ?`, // the setup for the next two
		} {
			if _, err := q.ExecContext(ctx, stmt, m.ID); err != nil {
				t.Fatal(err)
			}
		}
		for stmt, want := range map[string]string{
			`UPDATE app_move_volumes SET created_by_move = 0 WHERE move_id = ?`:           "ownership evidence",
			`UPDATE app_move_volumes SET service = 'other' WHERE move_id = ?`:             "keeps its identity",
			`UPDATE app_move_volumes SET mount_target = '/x' WHERE move_id = ?`:           "keeps its identity",
			`UPDATE app_move_volumes SET other_services_json = '["x"]' WHERE move_id = ?`: "keeps its identity",
			`UPDATE app_move_volumes SET state = 'importing' WHERE move_id = ?`:           "CHECK",
			`UPDATE app_move_volumes SET import_deadline_at = 5 WHERE move_id = ?`:        "CHECK",
			`UPDATE app_move_volumes SET state = 'verified' WHERE move_id = ?`:            "CHECK",
			`UPDATE app_move_volumes SET attempt = 0 WHERE move_id = ?`:                   "CHECK",
		} {
			if _, err := q.ExecContext(ctx, stmt, m.ID); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: err = %v, want %q", stmt, err, want)
			}
		}
		if _, err := q.ExecContext(ctx, `INSERT INTO app_move_volumes (move_id, volume_name, service, mount_target, other_services_json, created_at, updated_at)
			VALUES (?, 'p_x', 'db', '/data', 'not json', 1, 1)`, m.ID); err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("invalid other services: err = %v", err)
		}
		// a volume belongs to its move once
		dup := volumeOf("p_db", "db")
		if _, err := q.ExecContext(ctx, `INSERT INTO app_move_volumes (move_id, volume_name, service, mount_target, created_at, updated_at)
			VALUES (?, ?, 'db', '/data', 1, 1)`, m.ID, dup.VolumeName); err == nil {
			t.Error("a volume was recorded twice")
		}
	})
}

// commitFixture is a verified move with B's deployment verifying, ready to commit.
func commitFixture(ctx context.Context, f *fixture, q Querier) (moveWorld, AppMove, domain.ID) {
	mw := newMoveWorld(ctx, f, q)
	m, dep := mw.verifiedMove(ctx, f, q)
	return mw, m, dep
}

func TestCommitAppMoveWritesEverythingOrNothing(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		mw, m, dep := commitFixture(ctx, f, q)
		later := testEpoch.Add(time.Hour)
		rev := mw.target.SpecRevision

		got := must(CommitAppMove(ctx, q, m.ID, mw.target.ID, rev, mw.a.ID, mw.b.ID, dep, later))
		if got.Phase != AppMoveCommitted || got.CommittedRevision != rev+1 || !got.PhaseStartedAt.Equal(later) {
			t.Fatalf("move = %+v", got)
		}
		target := must(GetAppTarget(ctx, q, mw.target.ID))
		if target.NodeID != mw.b.ID || target.SpecRevision != rev+1 {
			t.Fatalf("target = node %s revision %d", target.NodeID, target.SpecRevision)
		}
		d := must(GetDeployment(ctx, q, dep))
		if d.State != deployments.StateSucceeded || !d.KnownGood || d.FinishedAt == nil {
			t.Fatalf("deployment = %+v", d)
		}
		if newest := must(NewestKnownGood(ctx, q, mw.target.ID, nil)); newest.ID != dep {
			t.Fatalf("newest known good = %s, want %s", newest.ID, dep)
		}
		// committing twice finds the move no longer verified
		_, err := CommitAppMove(ctx, q, m.ID, mw.target.ID, rev+1, mw.b.ID, mw.b.ID, dep, later)
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestCommitAppMoveMismatchesChangeNothing(t *testing.T) {
	type call struct {
		revision                         int64
		target, source, dest, deployment domain.ID
	}
	valid := func(mw moveWorld, dep domain.ID) call {
		return call{mw.target.SpecRevision, mw.target.ID, mw.a.ID, mw.b.ID, dep}
	}
	cases := map[string]struct {
		prepare func(ctx context.Context, q Querier, mw moveWorld, m AppMove)
		change  func(c *call, mw moveWorld)
	}{
		"stale revision":      {change: func(c *call, _ moveWorld) { c.revision += 5 }},
		"wrong source node":   {change: func(c *call, mw moveWorld) { c.source = mw.b.ID }},
		"wrong destination":   {change: func(c *call, mw moveWorld) { c.dest = mw.a.ID }},
		"unknown deployment":  {change: func(c *call, _ moveWorld) { c.deployment = "missing" }},
		"other target":        {change: func(c *call, _ moveWorld) { c.target = "other" }},
		"a deploy deployment": {change: func(c *call, mw moveWorld) { c.deployment = mw.knownGood }},
		"revision bumped after the plan": {
			prepare: func(ctx context.Context, q Querier, mw moveWorld, _ AppMove) {
				_, err := q.ExecContext(ctx, `UPDATE app_targets SET spec_revision = spec_revision + 1 WHERE id = ?`, mw.target.ID)
				noErr(t, err)
			},
		},
		"move no longer verified": {
			prepare: func(ctx context.Context, q Querier, _ moveWorld, m AppMove) {
				must(HaltAppMove(ctx, q, m.ID, AppMoveVerified, AppMoveFailed, "x", testEpoch))
			},
		},
		"project taken on the destination": {
			prepare: func(ctx context.Context, q Querier, mw moveWorld, _ AppMove) {
				otherApp := appsAppOf(&fixture{ids: domaintest.NewSequentialIDs()}, "other")
				otherApp.ID = "other-app"
				other := must(CreateApp(ctx, q, otherApp))
				must(CreateAppTarget(ctx, q, AppTarget{
					ID: "other-target", AppID: other.ID, EnvironmentID: mw.target.EnvironmentID,
					NodeID: mw.b.ID, ComposeProject: mw.target.ComposeProject, DeploymentPolicyJSON: []byte(`{}`),
					CreatedAt: testEpoch, UpdatedAt: testEpoch,
				}))
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.tx(func(ctx context.Context, q Querier) {
				mw, m, dep := commitFixture(ctx, f, q)
				if c.prepare != nil {
					c.prepare(ctx, q, mw, m)
				}
				args := valid(mw, dep)
				if c.change != nil {
					c.change(&args, mw)
				}
				before := snapshotMove(ctx, q, mw, m, dep)
				_, err := CommitAppMove(ctx, q, m.ID, args.target, args.revision, args.source, args.dest, args.deployment, testEpoch)
				if err == nil {
					t.Fatal("the commit succeeded")
				}
				if code := smerr.CodeOf(err); code != smerr.CodeConflict && code != smerr.CodeNotFound {
					t.Errorf("err = %v, want a typed conflict", err)
				}
				if after := snapshotMove(ctx, q, mw, m, dep); after != before {
					t.Fatalf("a failed commit wrote something\nbefore %s\nafter  %s", before, after)
				}
			})
		})
	}
}

// snapshotMove is every row a commit writes, as text.
func snapshotMove(ctx context.Context, q Querier, mw moveWorld, m AppMove, dep domain.ID) string {
	t := must(GetAppTarget(ctx, q, mw.target.ID))
	d := must(GetDeployment(ctx, q, dep))
	got := must(GetAppMove(ctx, q, m.ID))
	return fmt.Sprintf("target %s r%d | deployment %s known_good=%t | move %s halted=%s committed=%d",
		t.NodeID, t.SpecRevision, d.State, d.KnownGood, got.Phase, got.HaltedPhase, got.CommittedRevision)
}
