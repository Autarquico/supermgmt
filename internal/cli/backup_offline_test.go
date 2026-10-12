package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/migrations"
)

// previousSchemaSandbox is a stopped control plane left by the previous
// release: a database migrated to every embedded migration but the last, an
// instance, a master key and an activated configuration. It returns the schema
// version the database is at.
func previousSchemaSandbox(t *testing.T) (sandbox, int) {
	t.Helper()
	ctx := context.Background()
	s := newSandbox(t)
	if err := os.MkdirAll(filepath.Dir(s.dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	version := migrateAllButLast(t, s.dbPath)

	db, err := database.Open(ctx, s.dbPath, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		now := domain.SystemClock{}.Now()
		if err := database.CreateInstance(ctx, tx, database.Instance{ID: domain.UUIDv7Generator{}.NewID(), Name: "test", CreatedAt: now}); err != nil {
			return err
		}
		_, err := database.PutConfigSnapshot(ctx, tx, []byte("version: 1\n"), nil, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	repo := writableSecrets{ReadOnlySecrets: database.ReadOnlySecrets{Q: db.Reader()}, db: db}
	if _, err := secrets.OpenFileKeys(ctx, keysDirOf(t, s), repo, domain.UUIDv7Generator{}); err != nil {
		t.Fatal(err)
	}
	return s, version
}

// migrateAllButLast applies the embedded migrations except the newest, the way
// the previous release's binary left the database.
func migrateAllButLast(t *testing.T, path string) int {
	t.Helper()
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			files = append(files, e.Name())
		}
	}
	if len(files) < 2 {
		t.Skip("only one migration exists: there is no previous schema")
	}
	files = files[:len(files)-1] // the directory listing is sorted by name, which is by version
	ctx := context.Background()
	db, err := database.Open(ctx, path, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var version int
	for _, name := range files {
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if version, err = strconv.Atoi(name[:6]); err != nil {
			t.Fatal(err)
		}
		err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, 0)`, version)
			return err
		})
		if err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	return version
}

func createOffline(s sandbox, extra ...string) result {
	return s.runIn("", append([]string{"backup", "create", "--offline", "--json"}, extra...)...)
}

// archivePath is where the report's archive is. The report's own path is
// normalized for display, so the test derives the real one.
func archivePath(s sandbox, report offlineBackupReport) string {
	return filepath.Join(filepath.Dir(s.dbPath), "backups", report.Name)
}

func parseOfflineBackup(t *testing.T, r result) offlineBackupReport {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var report offlineBackupReport
	if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
		t.Fatalf("report %q: %v", r.stdout, err)
	}
	return report
}

func TestOfflineBackupOfThePreviousSchemaKeepsItAndRestores(t *testing.T) {
	s, previous := previousSchemaSandbox(t)
	before, err := os.ReadFile(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}

	report := parseOfflineBackup(t, createOffline(s))

	if report.SchemaVersion != previous {
		t.Errorf("archive schema = %d, want the database's %d: an offline backup never migrates", report.SchemaVersion, previous)
	}
	after, err := os.ReadFile(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the database file changed")
	}
	for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(s.dbPath + sidecar); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists next to the database: %v", sidecar, err)
		}
	}
	entries, err := backup.Archives{Dir: filepath.Dir(archivePath(s, report))}.List()
	if err != nil || len(entries) != 1 || entries[0].Manifest.SchemaVersion != previous || entries[0].Manifest.ConfigGeneration != 1 {
		t.Fatalf("catalog = %+v, %v; want one archive at schema %d", entries, err, previous)
	}
	if len(entries[0].Manifest.KEKIDs) != 1 {
		t.Errorf("archive needs keys %v, want the one master key", entries[0].Manifest.KEKIDs)
	}

	restore := s.runIn("", "backup", "restore", "--offline", archivePath(s, report))
	if restore.code != 0 {
		t.Fatalf("restoring the archive: exit %d: %s", restore.code, restore.stderr)
	}
}

func TestOfflineBackupBelongsToTheInvokingUserAndIsOwnerOnly(t *testing.T) {
	s, _ := previousSchemaSandbox(t)

	report := parseOfflineBackup(t, createOffline(s))

	info, err := os.Stat(archivePath(s, report))
	if err != nil {
		t.Fatal(err)
	}
	if uid := int(info.Sys().(*syscall.Stat_t).Uid); uid != os.Getuid() {
		t.Errorf("archive owned by uid %d, want the invoking user %d", uid, os.Getuid())
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("archive mode %04o, want 0600", info.Mode().Perm())
	}
}

func TestOfflineBackupRefusesWhileADaemonHoldsTheDatabase(t *testing.T) {
	s, _ := previousSchemaSandbox(t)
	lock, err := database.AcquireDatabaseLock(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()

	r := createOffline(s)

	if r.code != exitPrerequisite || !strings.Contains(r.stderr, "stop the service") {
		t.Errorf("exit %d, %q", r.code, r.stderr)
	}
}

func TestOfflineBackupNeedsAnInitializedDatabaseAndNeverCreatesOne(t *testing.T) {
	s := newSandbox(t)

	r := createOffline(s)

	if r.code != exitUsage {
		t.Errorf("exit %d, %q; want a usage error", r.code, r.stderr)
	}
	if _, err := os.Stat(s.dbPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a database was created: %v", err)
	}
}

func TestOfflineBackupNeverCreatesAMasterKey(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t) // a schema, but no instance, no key and no configuration

	r := createOffline(s)

	if r.code == 0 {
		t.Fatalf("a backup of an uninitialized database succeeded: %q", r.stdout)
	}
	if files := keyFilesIn(t, keysDirOf(t, s)); len(files) != 0 {
		t.Errorf("the offline backup created keys: %v", files)
	}
}
