package jobs

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// fenced runs fn in a write transaction whose first statement is the fence.
func (s *Store) fenced(ctx context.Context, lease Lease, fn func(ctx context.Context, tx *database.Tx) error) error {
	return s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
}

// Heartbeat extends the lease. A worker whose lease already expired gets
// ErrLeaseLost and must stop rather than renew (spec §20.4).
func (s *Store) Heartbeat(ctx context.Context, lease Lease) error {
	return s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		now := s.clock.Now()
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET lease_until = ?, heartbeat_at = ? WHERE id = ?`,
			domain.UnixMillis(now.Add(s.leaseTTL)), domain.UnixMillis(now), lease.JobID)
		if err != nil {
			return fmt.Errorf("heartbeat job %s: %w", lease.JobID, err)
		}
		return nil
	})
}

// Succeed finishes the job as succeeded and releases its locks.
func (s *Store) Succeed(ctx context.Context, lease Lease) error {
	return s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		_, err := s.move(ctx, tx, move{id: lease.JobID, from: domain.JobRunning, to: domain.JobSucceeded, actor: systemActor})
		return err
	})
}

// Fail ends the attempt after runErr. An idempotent job with attempts left goes
// back to queued with exponential backoff; every other job becomes failed.
// Resumable jobs are never retried here, only by the reconciler (spec §20.4).
func (s *Store) Fail(ctx context.Context, lease Lease, runErr error) error {
	return s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		job, err := s.Get(ctx, tx, lease.JobID)
		if err != nil {
			return err
		}
		failure := FailureOf(runErr)
		if job.RetryClass == domain.RetryIdempotent && job.Attempts < job.MaxAttempts {
			return s.requeue(ctx, tx, job, domain.JobRunning, failure)
		}
		_, err = s.move(ctx, tx, move{id: job.ID, from: domain.JobRunning, to: domain.JobFailed, actor: systemActor, failure: &failure})
		return err
	})
}

// FailTerminal ends the job as failed regardless of its retry class (panics,
// unknown job types).
func (s *Store) FailTerminal(ctx context.Context, lease Lease, runErr error) error {
	return s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		failure := FailureOf(runErr)
		_, err := s.move(ctx, tx, move{id: lease.JobID, from: domain.JobRunning, to: domain.JobFailed, actor: systemActor, failure: &failure})
		return err
	})
}

// Interrupt moves the job running -> interrupted on the worker's own initiative,
// because its handler cannot tell how a dispatched operation ended
// (ErrOutcomeUnknown). Like Takeover, it bumps the lease generation and expires
// the lease, so no later write by this worker passes the fence and the
// reconciler may treat the job as quiescent once each dispatched intent has
// proof or is past deadline_at + reconcile_grace. Locks are kept.
func (s *Store) Interrupt(ctx context.Context, lease Lease, cause error) error {
	return s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		_, err := s.move(ctx, tx, move{
			id: lease.JobID, from: domain.JobRunning, to: domain.JobInterrupted, actor: systemActor,
			assign: []assignment{
				{"lease_generation = lease_generation + 1", nil},
				{"lease_until = ?", []any{domain.UnixMillis(s.clock.Now())}},
			},
			data: map[string]any{"reason": "outcome unknown", "cause": audit.ScrubString(cause.Error())},
		})
		return err
	})
}

// requeue puts job back in the queue after the backoff for its attempts so far.
func (s *Store) requeue(ctx context.Context, q database.Querier, job Job, from domain.JobState, cause Failure) error {
	delay := s.backoffAfter(job.Attempts)
	_, err := s.move(ctx, q, move{
		id: job.ID, from: from, to: domain.JobQueued, actor: systemActor,
		assign:  []assignment{{"scheduled_at = ?", []any{domain.UnixMillis(s.clock.Now().Add(delay))}}},
		failure: &cause,
		data:    map[string]any{"retry_in_ms": delay.Milliseconds()},
	})
	return err
}

// requeueNow puts job back in the queue to run immediately (reconciler resume).
func (s *Store) requeueNow(ctx context.Context, q database.Querier, job Job, from domain.JobState, reason string) error {
	_, err := s.move(ctx, q, move{
		id: job.ID, from: from, to: domain.JobQueued, actor: systemActor,
		assign: []assignment{{"scheduled_at = ?", []any{domain.UnixMillis(s.clock.Now())}}},
		data:   map[string]any{"reason": reason},
	})
	return err
}
