package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// IdempotencyRecord is the committed answer to one mutating request (spec §23,
// ADR-0014). RequestHash is the request identity; ResponseJSON holds the exact
// wire envelope bytes, which a replay returns unchanged.
type IdempotencyRecord struct {
	IdentityID   domain.ID
	Key          string
	Method       string
	Path         string
	RequestHash  string
	StatusCode   int
	ResponseJSON []byte
	JobID        *domain.ID
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// InsertIdempotencyRecord stores r in the caller's write transaction, next to
// the mutation it answers. A second record for the same (identity, key) is CONFLICT.
func InsertIdempotencyRecord(ctx context.Context, q Querier, r IdempotencyRecord) error {
	_, err := q.ExecContext(ctx, `
		INSERT INTO idempotency_records (identity_id, key, method, path, request_hash, status_code,
		                                 response_json, job_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.IdentityID, r.Key, r.Method, r.Path, r.RequestHash, r.StatusCode, string(r.ResponseJSON),
		nullID(r.JobID), millis(r.CreatedAt), millis(r.ExpiresAt))
	if err != nil {
		return conflictIfDuplicate(err, "idempotency record")
	}
	return nil
}

// GetIdempotencyRecord returns the record or NOT_FOUND. Expired records still
// match until SweepIdempotencyRecords removes them: callers compare ExpiresAt.
func GetIdempotencyRecord(ctx context.Context, q Querier, identity domain.ID, key string) (IdempotencyRecord, error) {
	var (
		r                    IdempotencyRecord
		response             string
		job                  sql.NullString
		createdMs, expiresMs int64
	)
	err := q.QueryRowContext(ctx, `
		SELECT identity_id, key, method, path, request_hash, status_code, response_json, job_id, created_at, expires_at
		FROM idempotency_records WHERE identity_id = ? AND key = ?`, identity, key).
		Scan(&r.IdentityID, &r.Key, &r.Method, &r.Path, &r.RequestHash, &r.StatusCode, &response, &job,
			&createdMs, &expiresMs)
	if err != nil {
		return IdempotencyRecord{}, getErr(err, "idempotency record")
	}
	r.ResponseJSON, r.JobID = []byte(response), idOf(job)
	r.CreatedAt, r.ExpiresAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(expiresMs)
	return r, nil
}

// SweepIdempotencyRecords deletes the records that expired at or before now and
// returns how many it removed.
func SweepIdempotencyRecords(ctx context.Context, q Querier, now time.Time) (int64, error) {
	res, err := q.ExecContext(ctx, `DELETE FROM idempotency_records WHERE expires_at <= ?`, millis(now))
	if err != nil {
		return 0, fmt.Errorf("sweep idempotency records: %w", err)
	}
	return res.RowsAffected()
}
