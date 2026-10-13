package app

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
)

func gcRow(id string, state deployments.State, mutate ...func(*database.Deployment)) database.Deployment {
	d := database.Deployment{ID: domain.ID(id), State: state}
	for _, m := range mutate {
		m(&d)
	}
	return d
}

func TestCollectableDeployments(t *testing.T) {
	knownGood := func(d *database.Deployment) { d.KnownGood = true }
	mutated := func(d *database.Deployment) { d.MutationStarted = true }
	recent := []database.Deployment{
		gcRow("r1", deployments.StateSucceeded), gcRow("r2", deployments.StateFailed), gcRow("r3", deployments.StateFailed),
		gcRow("r4", deployments.StateFailed), gcRow("r5", deployments.StateFailed),
	}
	tests := []struct {
		name     string
		old      []database.Deployment
		current  string
		rollback *plan.RollbackTarget
		want     []string
	}{
		{"the newest five are always kept", nil, "r1", nil, nil},
		{"old failed and rolled back directories go", []database.Deployment{
			gcRow("a", deployments.StateFailed), gcRow("b", deployments.StateRolledBack),
		}, "r1", nil, []string{"a", "b"}},
		{"a known-good directory is kept", []database.Deployment{
			gcRow("a", deployments.StateRolledBack, knownGood), gcRow("b", deployments.StateFailed),
		}, "r1", nil, []string{"b"}},
		{"the frozen rollback target is kept", []database.Deployment{
			gcRow("a", deployments.StateFailed), gcRow("b", deployments.StateFailed),
		}, "r1", &plan.RollbackTarget{DeploymentID: "a"}, []string{"b"}},
		{"the current deployment is kept", []database.Deployment{
			gcRow("a", deployments.StateRolledBack), gcRow("b", deployments.StateFailed),
		}, "a", nil, []string{"b"}},
		{"a failed deployment that touched services is kept", []database.Deployment{
			gcRow("a", deployments.StateFailed, mutated), gcRow("b", deployments.StateFailed),
		}, "r1", nil, []string{"b"}},
		{"states that are not settled or need a human are kept", []database.Deployment{
			gcRow("a", deployments.StateRollbackFailed), gcRow("b", deployments.StateInterrupted),
			gcRow("c", deployments.StateCancelled), gcRow("d", deployments.StateSucceeded),
		}, "r1", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := append(slices.Clone(recent), tt.old...)
			var got []string
			for _, id := range collectableDeployments(rows, domain.ID(tt.current), tt.rollback) {
				got = append(got, id.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("collectable = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollectableDeployments_FewerThanFiveRowsCollectNothing(t *testing.T) {
	rows := []database.Deployment{gcRow("a", deployments.StateFailed), gcRow("b", deployments.StateRolledBack)}
	if got := collectableDeployments(rows, "z", nil); len(got) != 0 {
		t.Errorf("collectable = %v, want none", got)
	}
}

// gcHistory inserts n failed deployments of the target older than the queued
// one, oldest first, and returns their ids oldest first.
func (w *deployWorld) gcHistory(of database.Deployment, n int) []domain.ID {
	w.t.Helper()
	ids := make([]domain.ID, n)
	for i := range ids {
		old := of
		old.ID = w.cfg.IDs.NewID()
		old.State = deployments.StateFailed
		old.JobID, old.PlanID, old.ArtifactID = nil, nil, nil
		old.CreatedAt = of.CreatedAt.Add(-time.Duration(n-i) * time.Hour)
		old.UpdatedAt = old.CreatedAt
		w.inTx(func(ctx context.Context, tx *database.Tx) error { return database.InsertDeployment(ctx, tx, old) })
		ids[i] = old.ID
	}
	return ids
}

func (w *deployWorld) gcEventCount() int {
	w.t.Helper()
	var n int
	err := w.db.Reader().QueryRowContext(context.Background(),
		`SELECT count(*) FROM events WHERE action = 'deployment.gc_failed'`).Scan(&n)
	mustf(w.t, err, "count gc events")
	return n
}

func TestDeployHandler_SuccessCollectsOldDirectoriesBeyondTheNewestFive(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	old := w.gcHistory(dep, 7)
	w.remote.exit("compose.gc", 0)

	if err := w.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var collected []string
	for _, c := range w.callsOf("compose.gc") {
		if !c.Mutating {
			t.Errorf("compose.gc ran without the marker wrapper: %s", c.Line)
		}
		collected = append(collected, c.Line)
	}
	if len(collected) != 3 {
		t.Fatalf("compose.gc ran %d times, want 3 (the 7 old ones minus the newest 4)", len(collected))
	}
	// Candidates are visited newest first, so the three oldest come last-to-first.
	for i, id := range []domain.ID{old[2], old[1], old[0]} {
		if !strings.Contains(collected[i], "gc-"+id.String()) {
			t.Errorf("collection %d does not name %s: %s", i, id, collected[i])
		}
		if strings.Contains(collected[i], dep.ID.String()) {
			t.Error("the current deployment was collected")
		}
	}
}

func TestDeployHandler_AFailingCollectionNeverFailsTheDeployment(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	w.gcHistory(dep, 6)
	w.remote.exit("compose.gc", 1)

	if err := w.run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	w.want(dep.ID, deployments.StateSucceeded)
	if n := w.gcEventCount(); n != 1 {
		t.Errorf("deployment.gc_failed events = %d, want 1", n)
	}
}

func TestDeployHandler_AFailedDeploymentCollectsNothing(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()
	w.gcHistory(dep, 7)
	w.remote.exit("compose.pull", 1)

	if err := w.run(); err == nil {
		t.Fatal("the run succeeded with a failing pull")
	}

	w.want(dep.ID, deployments.StateFailed)
	if n := len(w.callsOf("compose.gc")); n != 0 {
		t.Errorf("compose.gc ran %d times after a failed deployment", n)
	}
}
