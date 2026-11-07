package database_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
)

type noRevalidation struct{}

func (noRevalidation) Revalidate(context.Context, database.Querier, jobs.Job) error { return nil }

type noLocks struct{}

func (noLocks) PlanLocks(context.Context, database.Querier, jobs.Job) ([]domain.LockSpec, error) {
	return nil, nil
}

// After 000012 retires the settled jobs of a move, the startup reconciliation finds nothing to resolve or hold.
func TestStartupReconciliationIsCleanAfterMigration000012(t *testing.T) {
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.MigrateUpTo(ctx, db, 11); err != nil {
		t.Fatal(err)
	}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		for _, stmt := range []string{
			`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`,
			`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at, finished_at)
				VALUES ('job-move', 'app_target.move', 'app_target', 'target-1', 'id-1', 'session', 'succeeded', 'operational', 'resumable', 1, 1, 2)`,
			`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES ('app_target', 'target-1', 'job-move', 'exclusive', 1)`,
			`INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, completed_at, outcome)
				VALUES ('intent-1', 'job-move', 's', 1, 'completed', 'compose.down', 'app_target', 'target-1', 'marker-1', 9, 9, 'succeeded')`,
		} {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := jobs.NewStore(jobs.Config{
		DB: db, Clock: clock, IDs: domaintest.NewSequentialIDs(), Revalidator: noRevalidation{}, LockPlanner: noLocks{},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolutions, err := store.Reconcile(ctx, nil)
	if err != nil || len(resolutions) != 0 {
		t.Fatalf("Reconcile = %v, %v; want nothing to resolve", resolutions, err)
	}
	var locks int
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM resource_locks`).Scan(&locks); err != nil || locks != 0 {
		t.Fatalf("locks = %d, %v; want none", locks, err)
	}
}
