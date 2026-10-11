package database

import (
	"context"
	"time"
)

// SweepOrphanStagedSecrets deletes staged secret versions created at or before
// cutoff that no unfinished job refers to. A staged version is referenced by
// the staged_id of its job's payload; when that job ended without activating
// or discarding it (a crash between the two), nothing ever will. Callers pass
// a cutoff a little in the past so a version staged a moment ago, whose job is
// not enqueued yet, survives. It returns how many versions were deleted.
func SweepOrphanStagedSecrets(ctx context.Context, q Querier, cutoff time.Time) (int64, error) {
	return affected(ctx, q, "staged secrets", `
		DELETE FROM secrets
		WHERE version < 0 AND created_at <= ?
		  AND NOT EXISTS (
		      SELECT 1 FROM jobs
		      WHERE jobs.state NOT IN ('succeeded', 'failed', 'cancelled')
		        AND json_extract(jobs.payload_json, '$.staged_id') = secrets.id)`,
		millis(cutoff))
}
