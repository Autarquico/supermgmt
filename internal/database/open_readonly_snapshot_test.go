package database

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/migrations"
)

// previousSchemaDB creates a closed database migrated to every embedded
// migration but the last, with a configuration snapshot activated: what the
// previous release leaves behind. It returns the path and the schema version.
func previousSchemaDB(t *testing.T) (string, int) {
	t.Helper()
	ctx := context.Background()
	all, err := loadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Skip("only one migration exists: there is no previous schema")
	}
	path := filepath.Join(t.TempDir(), "sm.db")
	db, err := Open(ctx, path, Options{Clock: domaintest.NewFakeClock(testEpoch)})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all[:len(all)-1] {
		if err := db.apply(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := PutConfigSnapshot(ctx, db.writer, []byte("version: 1\n"), nil, testEpoch); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path, all[len(all)-2].version
}

func TestReadOnlySnapshotKeepsThePreviousSchemaAndLeavesTheSourceUntouched(t *testing.T) {
	ctx := context.Background()
	path, previous := previousSchemaDB(t)
	dir := filepath.Dir(path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore := dirEntries(t, dir)

	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "copy.db")
	snap, err := ro.SnapshotTo(ctx, copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}

	if snap.SchemaVersion != previous {
		t.Errorf("snapshot schema = %d, want the source's %d: a snapshot must never migrate", snap.SchemaVersion, previous)
	}
	if snap.Config.Generation != 1 || string(snap.Config.Config) != "version: 1\n" {
		t.Errorf("snapshot config = generation %d, %q", snap.Config.Generation, snap.Config.Config)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !slices.Equal(entriesBefore, dirEntries(t, dir)) {
		t.Errorf("the source changed: entries %v -> %v", entriesBefore, dirEntries(t, dir))
	}
	if left := dirEntries(t, filepath.Dir(copyPath)); !slices.Equal(left, []string{"copy.db"}) {
		t.Errorf("the copy left %v, want one self-contained file", left)
	}
	reopened, err := Open(ctx, copyPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if version, err := reopened.schemaVersion(ctx); err != nil || version != previous {
		t.Errorf("the copy is at schema %d (%v), want %d", version, err, previous)
	}
}

func TestReadOnlySnapshotRefusesAnExistingDestination(t *testing.T) {
	ctx := context.Background()
	ro, err := OpenReadOnly(ctx, closedMigratedDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	existing := filepath.Join(t.TempDir(), "existing.db")
	if err := os.WriteFile(existing, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ro.SnapshotTo(ctx, existing); err == nil {
		t.Fatal("snapshot over a non-database file succeeded")
	}
}
