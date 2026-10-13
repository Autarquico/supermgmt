package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ExecutionSnapshotKind names what an execution snapshot freezes (ADR-0007).
type ExecutionSnapshotKind string

const (
	SnapshotComposeModel     ExecutionSnapshotKind = "compose_model"
	SnapshotHealth           ExecutionSnapshotKind = "health"
	SnapshotDeploymentPolicy ExecutionSnapshotKind = "deployment_policy"
	SnapshotExceptions       ExecutionSnapshotKind = "exceptions"
	SnapshotManifest         ExecutionSnapshotKind = "manifest"
)

// ExecutionSnapshot is an immutable, content-addressed execution snapshot. Hash is
// ExecutionSnapshotHash(Content): the value a plan binds in its content fields.
type ExecutionSnapshot struct {
	Hash      string
	Kind      ExecutionSnapshotKind
	Content   []byte
	CreatedAt time.Time
}

// ExecutionSnapshotHash returns the "sha256:<hex>" address of content.
func ExecutionSnapshotHash(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PutExecutionSnapshot stores s unless a snapshot with the same hash already exists
// (insert-if-absent). The hash must be ExecutionSnapshotHash(s.Content), else
// INVALID_ARGUMENT. Re-storing the same hash under another kind is a CONFLICT.
func PutExecutionSnapshot(ctx context.Context, q Querier, s ExecutionSnapshot) error {
	if s.Hash != ExecutionSnapshotHash(s.Content) {
		return smerr.New(smerr.CodeInvalidArgument, "", "snapshot hash does not match its content")
	}
	res, err := q.ExecContext(ctx, `
		INSERT INTO execution_snapshots (hash, kind, content, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (hash) DO NOTHING`,
		s.Hash, string(s.Kind), string(s.Content), millis(s.CreatedAt))
	if err != nil {
		return fmt.Errorf("insert snapshot: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	stored, err := GetExecutionSnapshot(ctx, q, s.Hash)
	if err != nil {
		return err
	}
	if stored.Kind != s.Kind {
		return smerr.New(smerr.CodeConflict, "", "snapshot already stored with a different kind")
	}
	return nil
}

// GetExecutionSnapshot returns the snapshot, NOT_FOUND when absent, or DEPLOYMENT_FAILED
// (STAGING_FAILED) when the stored content no longer hashes to its address.
func GetExecutionSnapshot(ctx context.Context, q Querier, hash string) (ExecutionSnapshot, error) {
	var (
		s       ExecutionSnapshot
		kind    string
		content string
		created int64
	)
	err := q.QueryRowContext(ctx,
		`SELECT hash, kind, content, created_at FROM execution_snapshots WHERE hash = ?`, hash).
		Scan(&s.Hash, &kind, &content, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutionSnapshot{}, notFound("snapshot")
	}
	if err != nil {
		return ExecutionSnapshot{}, fmt.Errorf("read snapshot: %w", err)
	}
	s.Kind, s.Content, s.CreatedAt = ExecutionSnapshotKind(kind), []byte(content), domain.FromUnixMillis(created)
	if ExecutionSnapshotHash(s.Content) != s.Hash {
		return ExecutionSnapshot{}, smerr.FromReason(smerr.ReasonStagingFailed, "snapshot content does not match its hash")
	}
	return s, nil
}
