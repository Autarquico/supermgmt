package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const (
	restoreSource = "restore"
	restoreAction = "backup.restore"
)

// neutralized counts what phase C changed in the staged database.
type neutralized struct {
	undispatchedFailed int64
	interrupted        int64
	approvalsDeleted   int64
	locksDeleted       int64
	credentialsRevoked int64
	codesInvalidated   int64
}

// neutralize is phase C on the staged database, in ONE transaction (spec
// §29.2 step 4, ADR-0020). Nothing in it can dispatch work: jobs that never
// reached a target fail, jobs that may have reached one become interrupted
// with a lease generation past every intent's so the reconciler's quiescence
// rule (jobs.Store.quiescent) can act, credentials die, and the hold is set.
func neutralize(ctx context.Context, db *database.DB, clock domain.Clock, ids domain.IDGenerator) error {
	return db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		now := clock.Now()
		counts, err := neutralizeJobs(ctx, tx, now)
		if err != nil {
			return err
		}
		if err := neutralizeAccess(ctx, tx, now, &counts); err != nil {
			return err
		}
		if err := database.SetRestoreHold(ctx, tx, true, now); err != nil {
			return fmt.Errorf("set the restore hold: %w", err)
		}
		return emitRestored(ctx, tx, clock, ids, counts)
	})
}

func neutralizeJobs(ctx context.Context, tx *database.Tx, now time.Time) (neutralized, error) {
	var counts neutralized
	nowMs := now.UnixMilli()
	steps := []struct {
		into  *int64
		query string
		args  []any
	}{
		// Approvals die with the non-terminal jobs they were for; read the
		// states before the next steps change them.
		{&counts.approvalsDeleted, `DELETE FROM job_approvals WHERE job_id IN
			(SELECT id FROM jobs WHERE state IN ('awaiting_approval', 'queued', 'running', 'interrupted'))`, nil},
		// May have reached a target: running, interrupted, and non-retryable
		// jobs that already recorded an intent. The new generation is past the
		// job's own and every intent's, and the lease is already expired.
		{&counts.interrupted, `UPDATE jobs SET state = 'interrupted', lease_owner = NULL, lease_until = ?,
			lease_generation = max(lease_generation, COALESCE((SELECT max(i.lease_generation) FROM operation_intents i WHERE i.job_id = jobs.id), 0)) + 1
			WHERE state IN ('running', 'interrupted')
			   OR (state IN ('awaiting_approval', 'queued') AND retry_class = 'non_retryable'
			       AND EXISTS (SELECT 1 FROM operation_intents i WHERE i.job_id = jobs.id))`, []any{nowMs}},
		// Never mutated a target.
		{&counts.undispatchedFailed, `UPDATE jobs SET state = 'failed', error_json = ?, finished_at = ?,
			lease_owner = NULL, lease_until = NULL, heartbeat_at = NULL
			WHERE state IN ('awaiting_approval', 'queued')`, nil},
		// Locks belong to claimed jobs; only interrupted ones keep theirs.
		{&counts.locksDeleted, `DELETE FROM resource_locks WHERE job_id NOT IN (SELECT id FROM jobs WHERE state = 'interrupted')`, nil},
	}
	failure, err := json.Marshal(jobs.Failure{
		Code:    smerr.CodeFor(smerr.ReasonRestoredUndispatched),
		Reason:  smerr.ReasonRestoredUndispatched,
		Message: "the control plane was restored from a backup before this job started; submit it again",
	})
	if err != nil {
		return counts, fmt.Errorf("encode job failure: %w", err)
	}
	steps[2].args = []any{string(failure), nowMs}
	for _, s := range steps {
		res, err := tx.ExecContext(ctx, s.query, s.args...)
		if err != nil {
			return counts, fmt.Errorf("neutralize jobs: %w", err)
		}
		if *s.into, err = res.RowsAffected(); err != nil {
			return counts, fmt.Errorf("neutralize jobs: %w", err)
		}
	}
	return counts, nil
}

func neutralizeAccess(ctx context.Context, tx *database.Tx, now time.Time, counts *neutralized) error {
	var err error
	if counts.credentialsRevoked, err = database.RevokeAllCredentials(ctx, tx, now); err != nil {
		return fmt.Errorf("revoke credentials: %w", err)
	}
	if counts.codesInvalidated, err = database.InvalidatePendingCodes(ctx, tx, now); err != nil {
		return fmt.Errorf("invalidate bootstrap codes and join tokens: %w", err)
	}
	return nil
}

func emitRestored(ctx context.Context, tx *database.Tx, clock domain.Clock, ids domain.IDGenerator, c neutralized) error {
	instance := ""
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT id FROM instances LIMIT 1), '')`).Scan(&instance); err != nil {
		return fmt.Errorf("read instance id: %w", err)
	}
	emitter := audit.Emitter{Clock: clock, IDs: ids, Source: restoreSource}
	_, err := emitter.Emit(ctx, database.EventsIn(tx), domain.Event{
		ActorType:    domain.ActorSystem,
		ActorID:      restoreSource,
		Action:       restoreAction,
		ResourceType: domain.ResourceInstance,
		ResourceID:   domain.ID(instance),
		Severity:     domain.SeverityWarning,
		Result:       domain.ResultSucceeded,
		Data: map[string]any{
			"restore_hold":             true,
			"jobs_failed_undispatched": c.undispatchedFailed,
			"jobs_interrupted":         c.interrupted,
			"approvals_deleted":        c.approvalsDeleted,
			"locks_deleted":            c.locksDeleted,
			"credentials_revoked":      c.credentialsRevoked,
			"codes_invalidated":        c.codesInvalidated,
		},
	})
	return err
}
