package database

import (
	"context"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func snapshotOf(kind ExecutionSnapshotKind, content string) ExecutionSnapshot {
	return ExecutionSnapshot{Hash: ExecutionSnapshotHash([]byte(content)), Kind: kind, Content: []byte(content), CreatedAt: testEpoch}
}

func TestSnapshotRoundTrip(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	want := snapshotOf(SnapshotComposeModel, `{"services":{}}`)

	if err := PutExecutionSnapshot(ctx, db.writer, want); err != nil {
		t.Fatalf("PutExecutionSnapshot: %v", err)
	}
	got, err := GetExecutionSnapshot(ctx, db.Reader(), want.Hash)
	if err != nil {
		t.Fatalf("GetExecutionSnapshot: %v", err)
	}
	if got.Kind != want.Kind || string(got.Content) != string(want.Content) || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPutSnapshotIsInsertIfAbsent(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	first := snapshotOf(SnapshotHealth, "[]")
	again := first
	again.CreatedAt = testEpoch.AddDate(0, 0, 1)

	for _, s := range []ExecutionSnapshot{first, again} {
		if err := PutExecutionSnapshot(ctx, db.writer, s); err != nil {
			t.Fatalf("PutExecutionSnapshot: %v", err)
		}
	}
	got, _ := GetExecutionSnapshot(ctx, db.Reader(), first.Hash)
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at = %v, want the first write's %v", got.CreatedAt, first.CreatedAt)
	}
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM execution_snapshots`); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

func TestPutSnapshotRejectsAHashThatIsNotTheContents(t *testing.T) {
	db := migratedTest(t)
	s := snapshotOf(SnapshotManifest, "a")
	s.Content = []byte("b")
	wantError(t, PutExecutionSnapshot(context.Background(), db.writer, s), smerr.CodeInvalidArgument, "")
}

func TestPutSnapshotRejectsAKindChange(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	if err := PutExecutionSnapshot(ctx, db.writer, snapshotOf(SnapshotHealth, "same")); err != nil {
		t.Fatal(err)
	}
	wantError(t, PutExecutionSnapshot(ctx, db.writer, snapshotOf(SnapshotExceptions, "same")), smerr.CodeConflict, "")
}

func TestGetSnapshotMissingIsNotFound(t *testing.T) {
	db := migratedTest(t)
	_, err := GetExecutionSnapshot(context.Background(), db.Reader(), "sha256:00")
	wantError(t, err, smerr.CodeNotFound, "")
}

func TestGetSnapshotDetectsCorruptedContent(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	// Bypass the immutability trigger the way disk corruption would: write a row whose hash is wrong.
	if _, err := db.writer.ExecContext(ctx,
		`INSERT INTO execution_snapshots (hash, kind, content, created_at) VALUES ('sha256:bad', 'manifest', 'x', 1)`); err != nil {
		t.Fatal(err)
	}
	_, err := GetExecutionSnapshot(ctx, db.Reader(), "sha256:bad")
	wantError(t, err, smerr.CodeDeploymentFailed, smerr.ReasonStagingFailed)
}
