package database

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestResourceLockedSeesOnlyLocksOnThatResource(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		who := f.identity(ctx, q, domain.ActorHuman, "alice")
		jobID := f.ids.NewID()
		noErr(t, insertRow(ctx, q.(*Tx), "jobs", override(override(override(baselines()["jobs"],
			"id", jobID.String()), "actor_id", who.ID.String()), "resource_id", jobID.String())))
		node := domain.ResourceRef{Type: domain.ResourceNode, ID: f.ids.NewID()}
		if locked := must(ResourceLocked(ctx, q, node)); locked {
			t.Fatal("unlocked resource reported as locked")
		}
		noErr(t, insertRow(ctx, q.(*Tx), "resource_locks", map[string]any{
			"resource_type": "node", "resource_id": node.ID.String(), "job_id": jobID.String(),
			"mode": "exclusive", "acquired_at": 1,
		}))
		if !must(ResourceLocked(ctx, q, node)) {
			t.Fatal("locked resource reported as free")
		}
		other := domain.ResourceRef{Type: domain.ResourceService, ID: node.ID}
		if must(ResourceLocked(ctx, q, other)) {
			t.Fatal("lock on a node leaked to a service with the same id")
		}
	})
}

func TestUpdateEnvironmentSpecIsRevisionGuarded(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		env := must(CreateEnvironment(ctx, q, domain.Environment{
			ID: f.ids.NewID(), Name: "prod", RiskLevel: domain.EnvironmentDevelopment,
		}))
		env.RiskLevel, env.ApprovalsRequired, env.RequireProvenance = domain.EnvironmentProduction, 2, true

		got := must(UpdateEnvironmentSpec(ctx, q, env, env.SpecRevision))
		if got.SpecRevision != env.SpecRevision+1 || got.RiskLevel != domain.EnvironmentProduction ||
			got.ApprovalsRequired != 2 || !got.RequireProvenance || got.Name != "prod" {
			t.Fatalf("updated = %+v", got)
		}

		_, err := UpdateEnvironmentSpec(ctx, q, env, env.SpecRevision) // stale
		wantError(t, err, smerr.CodeConflict, "")
		if again := must(GetEnvironment(ctx, q, env.ID)); again.SpecRevision != got.SpecRevision {
			t.Fatalf("stale update changed the revision to %d", again.SpecRevision)
		}

		missing := env
		missing.ID = f.ids.NewID()
		_, err = UpdateEnvironmentSpec(ctx, q, missing, 1)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestPruneObservationsKeepsTheNewestPerResourceAndKind(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		record := func(kind string, at time.Time) domain.ID {
			id := f.ids.NewID()
			noErr(t, RecordObservation(ctx, q, Observation{
				ID: id, ResourceType: domain.ResourceNode, ResourceID: n.ID, Kind: kind, Value: 1, ObservedAt: at,
			}))
			return id
		}
		hour := time.Hour
		oldMetrics := record("metrics", testEpoch.Add(-3*hour))
		midMetrics := record("metrics", testEpoch.Add(-2*hour))
		supersededMetrics := record("metrics", testEpoch.Add(-hour))
		onlyProbe := record("probe", testEpoch.Add(-5*hour)) // the only one of its kind
		recent := record("metrics", testEpoch)

		removed := must(PruneObservations(ctx, q, testEpoch.Add(-30*time.Minute)))
		if removed != 3 {
			t.Fatalf("removed = %d, want 3", removed)
		}
		left := map[domain.ID]bool{}
		for _, id := range []domain.ID{oldMetrics, midMetrics, supersededMetrics, onlyProbe, recent} {
			var n int
			noErr(t, q.QueryRowContext(ctx, `SELECT count(*) FROM observations WHERE id = ?`, id).Scan(&n))
			left[id] = n == 1
		}
		if left[oldMetrics] || left[midMetrics] || left[supersededMetrics] || !left[onlyProbe] || !left[recent] {
			t.Fatalf("surviving observations = %v", left)
		}
		if again := must(PruneObservations(ctx, q, testEpoch.Add(-30*time.Minute))); again != 0 {
			t.Fatalf("second prune removed %d", again)
		}
	})
}

func TestSetNodeSystemIsAnObservation(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		noErr(t, SetNodeSystem(ctx, q, n.ID, "debian 13", "arm64"))

		got := must(GetNode(ctx, q, n.ID))
		if got.OS != "debian 13" || got.Arch != "arm64" || got.SpecRevision != n.SpecRevision {
			t.Fatalf("node = %+v, want os/arch set and revision %d", got, n.SpecRevision)
		}
		wantError(t, SetNodeSystem(ctx, q, f.ids.NewID(), "x", "y"), smerr.CodeNotFound, "")
	})
}
