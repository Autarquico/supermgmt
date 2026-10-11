package database

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

func closedMigratedDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sm.db")
	db, err := Open(context.Background(), path, Options{Clock: domaintest.NewFakeClock(testEpoch)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := PutSetting(context.Background(), db.writer, Setting{Key: "active_kek_id", Value: []byte(`"x"`), UpdatedAt: testEpoch}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestOpenReadOnlyReadsWithoutLeavingFiles(t *testing.T) {
	path := closedMigratedDB(t)
	before := dirEntries(t, filepath.Dir(path))

	ro, err := OpenReadOnly(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := ReadOnlySecrets{Q: ro.Querier()}.Setting(context.Background(), "active_kek_id")
	if err != nil || !found || value != `"x"` {
		t.Fatalf("Setting = %q, %v, %v", value, found, err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	if after := dirEntries(t, filepath.Dir(path)); !slices.Equal(before, after) {
		t.Fatalf("directory changed: %v -> %v", before, after)
	}
}

func TestOpenReadOnlyRefusesWrites(t *testing.T) {
	ro, err := OpenReadOnly(context.Background(), closedMigratedDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := PutSetting(context.Background(), ro.Querier(), Setting{Key: "k", Value: []byte(`1`), UpdatedAt: testEpoch}); err == nil {
		t.Fatal("a write through the read-only database succeeded")
	}
}

func TestOpenReadOnlyDoesNotCreateAMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if ro, err := OpenReadOnly(context.Background(), path); err == nil {
		_ = ro.Close()
		t.Fatal("opened a database that does not exist")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("OpenReadOnly created the file")
	}
}

func TestOpenReadOnlyRefusesPendingWAL(t *testing.T) {
	path := closedMigratedDB(t)
	if err := os.WriteFile(path+"-wal", []byte("unmerged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ro, err := OpenReadOnly(context.Background(), path); err == nil {
		_ = ro.Close()
		t.Fatal("opened a database with unmerged WAL content")
	}
}

func TestReadOnlySecretsRefusesWrites(t *testing.T) {
	ro, err := OpenReadOnly(context.Background(), closedMigratedDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := (ReadOnlySecrets{Q: ro.Querier()}).PutSettings(context.Background(), map[string]string{"a": "1"}); err == nil {
		t.Fatal("PutSettings succeeded")
	}
}

func TestReadOnlyHasSchema(t *testing.T) {
	ro, err := OpenReadOnly(context.Background(), closedMigratedDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if has, err := ro.HasSchema(context.Background()); err != nil || !has {
		t.Fatalf("HasSchema = %v, %v; want true", has, err)
	}

	empty := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bare, err := OpenReadOnly(context.Background(), empty)
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	if has, err := bare.HasSchema(context.Background()); err != nil || has {
		t.Fatalf("HasSchema of an empty file = %v, %v; want false", has, err)
	}
}
