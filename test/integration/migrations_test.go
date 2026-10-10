package integration

import (
	"context"
	_ "embed"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/migrations"
)

//go:embed testdata/m1_seed.sql
var m1Seed string

const m1SeedIdentity = "01970000-0000-7000-8000-000000000010"

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

// TestMigrationsM1ToM2KeepsData builds a database exactly as an M1 binary left
// it (migrations 000001 and 000002 plus data), then migrates it with the
// current binary: the M1 rows must survive and the M2 tables must be usable.
func TestMigrationsM1ToM2KeepsData(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedM1(t, db)
	if v := count(t, db, `SELECT MAX(version) FROM schema_migrations`); v != 2 {
		t.Fatalf("seeded schema version = %d, want 2", v)
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if v := count(t, db, `SELECT MAX(version) FROM schema_migrations`); v != 3 {
		t.Errorf("schema version = %d, want 3", v)
	}
	for table, want := range map[string]int{
		"instances": 1, "identities": 2, "providers": 1, "nodes": 1, "jobs": 1, "secrets": 1,
		"settings": 1, "interactive_sessions": 1, "idempotency_records": 1,
	} {
		if got := count(t, db, `SELECT COUNT(*) FROM `+table); got != want {
			t.Errorf("%s rows after migration = %d, want %d", table, got, want)
		}
	}
	if got := count(t, db, `SELECT COUNT(*) FROM nodes WHERE metadata_json = '{"note":"kept"}'`); got != 1 {
		t.Errorf("node metadata was altered by the migration")
	}
	for _, table := range []string{"sessions", "api_tokens", "bootstrap_codes", "oidc_replay", "join_tokens"} {
		if got := count(t, db, `SELECT COUNT(*) FROM `+table); got != 0 {
			t.Errorf("new table %s has %d rows, want 0", table, got)
		}
	}
	assertIntegrity(t, db)

	created := time.UnixMilli(2000)
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.CreateAuthSession(ctx, tx, database.AuthSession{
			ID: "01970000-0000-7000-8000-000000000070", IdentityID: m1SeedIdentity, TokenHash: "h",
			Origin: database.OriginOIDC, CreatedAt: created, ExpiresAt: created.Add(time.Hour),
		})
	})
	if err != nil {
		t.Errorf("session for a migrated identity: %v", err)
	}
}

func seedM1(t *testing.T, db *database.DB) {
	t.Helper()
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		for _, name := range []string{"000001_initial.up.sql", "000002_m1.up.sql"} {
			body, err := migrations.FS.ReadFile(name)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (1, 1000), (2, 1000)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, m1Seed)
		return err
	})
	if err != nil {
		t.Fatalf("seed M1 database: %v", err)
	}
}

func assertIntegrity(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := context.Background()
	var verdict string
	if err := db.Reader().QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&verdict); err != nil || verdict != "ok" {
		t.Errorf("integrity_check = %q, %v; want ok", verdict, err)
	}
	rows, err := db.Reader().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Error("foreign_key_check reports violations after migration")
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
