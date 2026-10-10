package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
)

func TestMigrationsCleanDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sm.db")
	db, err := database.Open(ctx, path, database.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	applied := count(t, db, `SELECT COUNT(*) FROM schema_migrations`)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("re-Migrate: %v", err)
	}

	if again := count(t, db, `SELECT COUNT(*) FROM schema_migrations`); again != applied || applied == 0 {
		t.Errorf("schema_migrations rows = %d then %d, want equal and non-zero", applied, again)
	}
	var verdict string
	if err := db.Reader().QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&verdict); err != nil || verdict != "ok" {
		t.Errorf("integrity_check = %q, %v; want ok", verdict, err)
	}
}

func count(t *testing.T, db *database.DB, query string) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}
