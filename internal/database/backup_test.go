package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func openCopy(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSnapshotIsConsistentWhileWritersCommit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// Both rows commit together; a snapshot must never hold one without the other.
			err := f.db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
				for _, side := range []string{"a", "b"} {
					key := fmt.Sprintf("pair.%s.%d", side, i)
					if err := PutSetting(ctx, tx, Setting{Key: key, Value: []byte(`1`), UpdatedAt: testEpoch}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Errorf("writer: %v", err)
				return
			}
		}
	}()

	for n := range 8 {
		path := filepath.Join(t.TempDir(), "snapshot.db")
		snap, err := f.db.SnapshotTo(ctx, path)
		if err != nil {
			t.Fatalf("SnapshotTo #%d: %v", n, err)
		}
		if snap.SchemaVersion < 1 {
			t.Errorf("schema version = %d", snap.SchemaVersion)
		}
		copyDB := openCopy(t, path)
		a := scalar[int](t, copyDB, `SELECT count(*) FROM settings WHERE key LIKE 'pair.a.%'`)
		b := scalar[int](t, copyDB, `SELECT count(*) FROM settings WHERE key LIKE 'pair.b.%'`)
		if a != b {
			t.Fatalf("snapshot #%d holds %d a-rows and %d b-rows: torn copy", n, a, b)
		}
		if check := scalar[string](t, copyDB, `PRAGMA integrity_check`); check != "ok" {
			t.Fatalf("integrity_check = %q", check)
		}
	}
	close(stop)
	writers.Wait()
}

func TestSnapshotLeavesOneSelfContainedFile(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.db")

	if _, err := f.db.SnapshotTo(context.Background(), path); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "snapshot.db" {
		t.Errorf("snapshot directory = %v, want only snapshot.db", entries)
	}
}

func TestSnapshotCarriesTheActivatedConfiguration(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	none, err := f.db.SnapshotTo(ctx, filepath.Join(t.TempDir(), "none.db"))
	if err != nil || none.Config.Generation != 0 {
		t.Fatalf("before any activation: %+v, %v; want generation 0", none, err)
	}

	f.tx(func(ctx context.Context, q Querier) {
		must(PutConfigSnapshot(ctx, q, []byte("a: 1\n"), []byte("p: 1\n"), testEpoch))
	})
	snap, err := f.db.SnapshotTo(ctx, filepath.Join(t.TempDir(), "some.db"))
	if err != nil {
		t.Fatal(err)
	}
	if snap.Config.Generation != 1 || string(snap.Config.Config) != "a: 1\n" || string(snap.Config.Policy) != "p: 1\n" {
		t.Errorf("snapshot config = %+v", snap.Config)
	}
}

func TestSnapshotIntoAMissingDirectoryFails(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "missing-dir", "x.db")

	if _, err := f.db.SnapshotTo(context.Background(), path); err == nil {
		t.Fatal("SnapshotTo into a missing directory succeeded")
	}
}
