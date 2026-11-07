package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/migrations"
)

// A backup taken by the release before the app move was retired holds a database at schema 11. Restoring it
// migrates the staged copy to 12, so the migration's refusal of an unfinished move reaches the operator.

var epochFor11 = time.Unix(1_700_000_000, 0)

const retiredMoveGuidance = "finish the app move (or abandon it where it halted) with the previous SuperMgmt version before upgrading"

var migrationFileName = regexp.MustCompile(`^(\d{6})_.*\.up\.sql$`)

func migrateToVersion(t *testing.T, db *database.DB, version int) {
	t.Helper()
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries { // ReadDir is sorted by name, which is the version order
		match := migrationFileName.FindStringSubmatch(e.Name())
		if match == nil {
			continue
		}
		v, _ := strconv.Atoi(match[1])
		if v > version {
			continue
		}
		body, err := migrations.FS.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		err = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, 1)`, v)
			return err
		})
		if err != nil {
			t.Fatalf("migration %s: %v", e.Name(), err)
		}
	}
}

func execSQL(t *testing.T, db *database.DB, stmts ...string) {
	t.Helper()
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		for _, stmt := range stmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// schema11Archive archives a database at schema 11 holding one move in the given phase.
func schema11Archive(t *testing.T, phase string) (archive, keysDir string) {
	t.Helper()
	root := t.TempDir()
	clock, ids := domaintest.NewFakeClock(epochFor11), domaintest.NewSequentialIDs()
	db, err := database.Open(context.Background(), filepath.Join(root, "source.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	migrateToVersion(t, db, 11)
	execSQL(t, db,
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`,
		`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', 1, 1)`,
		`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
			VALUES ('node-1', 'prov-1', 'n1', 'n1', 'host', 'managed', 'unknown', 1, 1),
			       ('node-2', 'prov-1', 'n2', 'n2', 'host', 'managed', 'unknown', 1, 1)`,
		`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`,
		`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
			VALUES ('app-1', 'web', 'web', '{}', 'control-plane', 1, 1)`,
		`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
			VALUES ('target-1', 'app-1', 'env-1', 'node-2', 'web-prod', '{}', 1, 1)`,
		`INSERT INTO plans (id, action, actor_id, credential_kind, plan_json, plan_hash, finalized_at, created_at, expires_at)
			VALUES ('plan-1', 'app_target.move', 'id-1', 'session', '{}', 'sha256:1', 1, 1, 2)`,
		`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
			VALUES ('job-1', 'app_target.move', 'app_target', 'target-1', 'id-1', 'session', 'succeeded', 'operational', 'resumable', 1, 1)`,
		`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by, known_good,
			commit_sha, requested_json, credential_kind, created_at, updated_at)
			VALUES ('dep-1', 'deploy', 'app-1', 'target-1', 'env-1', 'node-1', 'succeeded', 'id-1', 1, 'abc', '{}', 'session', 1, 1)`,
		fmt.Sprintf(`INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id,
			stateful, phase, phase_started_at, created_by, created_at, updated_at)
			VALUES ('move-1', 'target-1', 'node-1', 'node-2', 'plan-1', 'job-1', 'dep-1', 0, '%s', 5, 'id-1', 4, 9)`, phase),
	)

	err = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.PutConfigSnapshot(ctx, tx, []byte("listen: local\n"), []byte("policy: v1\n"), clock.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	keysDir = filepath.Join(root, "keys")
	repo := app.NewSecretsRepo(db, clock)
	keys, err := secrets.OpenFileKeys(context.Background(), keysDir, repo, ids)
	if err != nil {
		t.Fatal(err)
	}
	created, err := backup.Create(context.Background(), backup.CreateOptions{
		Dir: filepath.Join(root, "backups"), Instance: "lab", SMVersion: "9.9.9", Clock: clock, Source: db, Keys: keys,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return created.Path, keysDir
}

func restoreInto(t *testing.T, archive, keysDir string) (dbPath string, err error) {
	t.Helper()
	root := t.TempDir()
	dataDir, targetKeys := filepath.Join(root, "data"), filepath.Join(root, "keys")
	for _, dir := range []string{dataDir, targetKeys} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(keysDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(targetKeys, e.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dbPath = filepath.Join(dataDir, "supermgmt.db")
	err = backup.Restore(context.Background(), backup.RestoreOptions{
		Archive: archive, DataDir: dataDir, KeysDir: targetKeys, DBPath: dbPath,
		Clock: domaintest.NewFakeClock(epochFor11), IDs: domaintest.NewSequentialIDs(),
	})
	return dbPath, err
}

func TestRestoringABackupWithOnlyTerminalMovesSucceedsAtSchema12(t *testing.T) {
	for _, phase := range []string{"done", "rolled_back"} {
		t.Run(phase, func(t *testing.T) {
			archive, keysDir := schema11Archive(t, phase)
			dbPath, err := restoreInto(t, archive, keysDir)
			if err != nil {
				t.Fatalf("Restore: %v", err)
			}
			db, err := database.OpenReadOnly(context.Background(), dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version, moveTables int
			if err := db.Querier().QueryRowContext(context.Background(), `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := db.Querier().QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_master WHERE name LIKE 'app_move%'`).Scan(&moveTables); err != nil {
				t.Fatal(err)
			}
			if version != 12 || moveTables != 0 {
				t.Errorf("schema version %d with %d move objects, want 12 and none", version, moveTables)
			}
		})
	}
}

func TestRestoringABackupWithAnOpenMoveFailsWithTheGuidance(t *testing.T) {
	archive, keysDir := schema11Archive(t, "started")
	dbPath, err := restoreInto(t, archive, keysDir)
	if err == nil || !strings.Contains(err.Error(), retiredMoveGuidance) {
		t.Fatalf("Restore error = %v, want the guidance %q", err, retiredMoveGuidance)
	}
	if _, statErr := os.Stat(dbPath); statErr == nil {
		t.Error("a refused restore left a database behind")
	}
}
