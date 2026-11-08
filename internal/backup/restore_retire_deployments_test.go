package backup_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/migrations"
)

// A backup taken by the release before deployments were retired holds a database at schema 13. Restoring it
// migrates the staged copy to 14, so the migration's refusal of an open deployment reaches the operator.

const restoreGuidance = "restore it with the previous SuperMgmt release, let the deployment finish (or cancel it), then take a new backup"

var migrationFile = regexp.MustCompile(`^(\d{6})_.*\.up\.sql$`)

func migrateThrough(t *testing.T, db *database.DB, version int) {
	t.Helper()
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		match := migrationFile.FindStringSubmatch(e.Name())
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

// schema13Archive archives a database at schema 13 holding one deployment in the given state.
func schema13Archive(t *testing.T, state string) (archive string, src *site) {
	t.Helper()
	clock, ids := domaintest.NewFakeClock(epoch), domaintest.NewSequentialIDs()
	root := filepath.Join(t.TempDir(), "source")
	src = &site{t: t, root: root, dataDir: filepath.Join(root, "data"), keysDir: filepath.Join(root, "keys"), clock: clock, ids: ids}
	src.dbPath = filepath.Join(src.dataDir, "supermgmt.db")
	if err := os.MkdirAll(src.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), src.dbPath, database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	src.db = db
	migrateThrough(t, db, 13)
	src.exec(`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`)
	src.exec(`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', 1, 1)`)
	src.exec(`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
		VALUES ('node-1', 'prov-1', 'n', 'n', 'host', 'managed', 'unknown', 1, 1)`)
	src.exec(`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`)
	src.exec(`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
		VALUES ('app-1', 'web', 'web', '{}', 'control-plane', 1, 1)`)
	src.exec(`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
		VALUES ('target-1', 'app-1', 'env-1', 'node-1', 'web-prod', '{}', 1, 1)`)
	src.exec(fmt.Sprintf(`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by,
		commit_sha, requested_json, credential_kind, created_at, updated_at)
		VALUES ('dep-1', 'deploy', 'app-1', 'target-1', 'env-1', 'node-1', '%s', 'id-1', 'c', '{}', 'session', 1, 1)`, state))

	repo := app.NewSecretsRepo(db, clock)
	keys, err := secrets.OpenFileKeys(context.Background(), src.keysDir, repo, ids)
	if err != nil {
		t.Fatal(err)
	}
	src.keys = keys
	return src.archive(), src
}

func TestRestoringABackupWithOnlyTerminalDeploymentsMigratesPastSchema14(t *testing.T) {
	for _, state := range []string{"succeeded", "failed", "rolled_back", "rollback_failed", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			archive, src := schema13Archive(t, state)
			tg := newTarget(t, src, archive)

			if err := backup.Restore(context.Background(), tg.options()); err != nil {
				t.Fatalf("Restore: %v", err)
			}

			db := openDB(t, tg.dbPath, tg.clock)
			if n := scalar[int](t, db, `SELECT count(*) FROM sqlite_master WHERE name IN ('deployments', 'apps', 'app_targets')`); n != 0 {
				t.Errorf("%d deployment tables survived the restore", n)
			}
			if n := scalar[int](t, db, `SELECT max(version) FROM schema_migrations`); n < 14 {
				t.Errorf("schema version %d, want at least 14", n)
			}
		})
	}
}

func TestRestoringABackupWithAnOpenDeploymentIsRefusedWithGuidanceAndChangesNothing(t *testing.T) {
	for _, state := range []string{"created", "waiting_ci", "awaiting_approval", "queued", "deploying", "interrupted"} {
		t.Run(state, func(t *testing.T) {
			archive, src := schema13Archive(t, state)
			tg := newTarget(t, src, archive)
			before := tg.tree()

			err := backup.Restore(context.Background(), tg.options())

			if err == nil || !strings.Contains(err.Error(), restoreGuidance) {
				t.Fatalf("Restore error = %v, want the guidance %q", err, restoreGuidance)
			}
			if after := tg.tree(); !sameTree(before, after) {
				t.Errorf("a refused restore changed the target: %v vs %v", keysOf(before), keysOf(after))
			}
		})
	}
}
