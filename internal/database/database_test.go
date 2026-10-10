package database

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

var testEpoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "sm.db"), Options{Clock: domaintest.NewFakeClock(testEpoch)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func migratedTest(t *testing.T) *DB {
	t.Helper()
	db := openTest(t)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func scalar[T any](t *testing.T, q Querier, query string, args ...any) T {
	t.Helper()
	var v T
	if err := q.QueryRowContext(context.Background(), query, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

func TestPragmasSurviveConnectionReplacement(t *testing.T) {
	db := openTest(t)
	db.writer.SetMaxIdleConns(0) // every statement now runs on a brand-new connection
	db.reader.SetMaxIdleConns(0)

	cases := []struct {
		name   string
		q      Querier
		pragma string
		want   int64
	}{
		{"writer foreign_keys", db.writer, "foreign_keys", 1},
		{"writer synchronous FULL", db.writer, "synchronous", 2},
		{"writer busy_timeout", db.writer, "busy_timeout", 5000},
		{"reader foreign_keys", db.reader, "foreign_keys", 1},
		{"reader query_only", db.reader, "query_only", 1},
		{"reader busy_timeout", db.reader, "busy_timeout", 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for range 3 {
				if got := scalar[int64](t, tc.q, "PRAGMA "+tc.pragma); got != tc.want {
					t.Fatalf("PRAGMA %s = %d, want %d", tc.pragma, got, tc.want)
				}
			}
		})
	}
	if mode := scalar[string](t, db.writer, "PRAGMA journal_mode"); mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
}

func TestReaderRejectsWrites(t *testing.T) {
	db := migratedTest(t)
	_, err := db.Reader().ExecContext(context.Background(),
		`INSERT INTO roles (id, name) VALUES ('01970000-0000-7000-8000-0000000000ff', 'rogue')`)
	if err == nil {
		t.Fatal("write through the reader pool succeeded")
	}
}

func TestMigrateCleanAndIdempotent(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	for range 2 {
		if err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
	}
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM schema_migrations`); n != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1", n)
	}
	if got := scalar[string](t, db.Reader(), `PRAGMA integrity_check`); got != "ok" {
		t.Fatalf("integrity_check = %q", got)
	}
	rows, err := db.Reader().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reported violations")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateSeedsDefaultRoles(t *testing.T) {
	db := migratedTest(t)
	rows, err := db.Reader().QueryContext(context.Background(), `SELECT name FROM roles ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"viewer", "operator", "deployer", "admin"}
	if len(got) != len(want) {
		t.Fatalf("roles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roles = %v, want %v", got, want)
		}
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (999999, 0)`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var tooNew *SchemaTooNewError
	if err := db.Migrate(ctx); !errors.As(err, &tooNew) {
		t.Fatalf("Migrate on newer schema = %v, want *SchemaTooNewError", err)
	}
	if tooNew.DatabaseVersion != 999999 {
		t.Fatalf("DatabaseVersion = %d", tooNew.DatabaseVersion)
	}
}

func TestWithWriteTxCommitsOnNil(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO roles (id, name) VALUES ('01970000-0000-7000-8000-0000000000a1', 'extra')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM roles WHERE name = 'extra'`); n != 1 {
		t.Fatalf("committed rows = %d, want 1", n)
	}
}

func TestWithWriteTxRollsBackOnError(t *testing.T) {
	db := migratedTest(t)
	boom := errors.New("boom")
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles (id, name) VALUES ('01970000-0000-7000-8000-0000000000a2', 'ghost')`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM roles WHERE name = 'ghost'`); n != 0 {
		t.Fatalf("rolled-back rows visible: %d", n)
	}
}

func TestWithWriteTxRollsBackAndRepanics(t *testing.T) {
	db := migratedTest(t)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic was swallowed")
			}
		}()
		_ = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
			_, _ = tx.ExecContext(ctx, `INSERT INTO roles (id, name) VALUES ('01970000-0000-7000-8000-0000000000a3', 'phantom')`)
			panic("kaboom")
		})
	}()
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM roles WHERE name = 'phantom'`); n != 0 {
		t.Fatalf("rows from a panicked transaction visible: %d", n)
	}
	// The writer connection must have been returned to the pool.
	if err := db.WithWriteTx(context.Background(), func(context.Context, *Tx) error { return nil }); err != nil {
		t.Fatalf("writer unusable after panic: %v", err)
	}
}

func TestNestedWriteTxIsAnErrorNotADeadlock(t *testing.T) {
	db := migratedTest(t)
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, _ *Tx) error {
		return db.WithWriteTx(ctx, func(context.Context, *Tx) error { return nil })
	})
	if !errors.Is(err, ErrNestedWriteTx) {
		t.Fatalf("err = %v, want ErrNestedWriteTx", err)
	}
}

func TestConcurrentWritersSerialize(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	if err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE counter (n INTEGER NOT NULL) STRICT; INSERT INTO counter VALUES (0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	const writers, increments = 8, 25
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range increments {
				err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
					var n int
					if err := tx.QueryRowContext(ctx, `SELECT n FROM counter`).Scan(&n); err != nil {
						return err
					}
					_, err := tx.ExecContext(ctx, `UPDATE counter SET n = ?`, n+1)
					return err
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("writer failed: %v", err)
	}
	if n := scalar[int](t, db.Reader(), `SELECT n FROM counter`); n != writers*increments {
		t.Fatalf("counter = %d, want %d (lost updates)", n, writers*increments)
	}
}
