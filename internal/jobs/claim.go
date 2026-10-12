package jobs

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"

	"modernc.org/sqlite"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// errClaimRejected aborts the claim transaction after a revalidation failure so
// that nothing it read or wrote survives; the rejection travels in claimOutcome.
var errClaimRejected = errors.New("claim rejected")

type rejection struct {
	job  Job
	err  *smerr.Error
	mode ClaimMode
}

type claimOutcome struct {
	claimed  *Claimed
	rejected *rejection
}

// Claim hands the oldest runnable job to owner (spec §20.4). It returns false
// when nothing can run: no due job, every due job blocked by locks, or the
// restore hold is on.
//
// A job that fails revalidation is moved out of queued in a second transaction
// and the search continues with the next candidate.
func (s *Store) Claim(ctx context.Context, owner string) (Claimed, bool, error) {
	if s.restoreHold.Load() {
		return Claimed{}, false, nil
	}
	for {
		out, err := s.claimOnce(ctx, owner)
		if err != nil {
			return Claimed{}, false, err
		}
		if out.claimed != nil {
			return *out.claimed, true, nil
		}
		if out.rejected == nil {
			return Claimed{}, false, nil
		}
		if err := s.applyRejection(ctx, *out.rejected); err != nil {
			return Claimed{}, false, err
		}
	}
}

// claimOnce is the single IMMEDIATE transaction of a claim attempt.
func (s *Store) claimOnce(ctx context.Context, owner string) (claimOutcome, error) {
	var out claimOutcome
	err := s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		candidates, err := s.dueJobs(ctx, tx)
		if err != nil {
			return err
		}
		var blocked []domain.ID
		for _, job := range candidates {
			claimed, rej, wasBlocked, err := s.tryClaim(ctx, tx, job, owner)
			switch {
			case err != nil:
				return err
			case rej != nil:
				out.rejected = rej
				return errClaimRejected
			case wasBlocked:
				blocked = append(blocked, job.ID)
			case claimed != nil:
				out.claimed = claimed
				return s.deferBlocked(ctx, tx, blocked)
			}
		}
		return s.deferBlocked(ctx, tx, blocked)
	})
	if errors.Is(err, errClaimRejected) {
		return out, nil
	}
	if err != nil {
		return claimOutcome{}, fmt.Errorf("claim: %w", err)
	}
	return out, nil
}

func (s *Store) dueJobs(ctx context.Context, q database.Querier) ([]Job, error) {
	return queryJobs(ctx, q, `SELECT `+jobColumns+` FROM jobs
		WHERE state = 'queued' AND scheduled_at <= ? ORDER BY scheduled_at, created_at, id`,
		domain.UnixMillis(s.clock.Now()))
}

// deferBlocked pushes lock-blocked jobs back by one backoff step so they are
// not retried on every poll (spec §20.4 step 2).
func (s *Store) deferBlocked(ctx context.Context, q database.Querier, ids []domain.ID) error {
	until := domain.UnixMillis(s.clock.Now().Add(s.backoffAfter(1)))
	for _, id := range ids {
		if _, err := q.ExecContext(ctx, `UPDATE jobs SET scheduled_at = ? WHERE id = ? AND state = 'queued'`, until, id); err != nil {
			return fmt.Errorf("defer blocked job %s: %w", id, err)
		}
	}
	return nil
}

// tryClaim reports blocked=true when locks held by other jobs conflict, so the
// next candidate should be tried.
func (s *Store) tryClaim(ctx context.Context, tx *database.Tx, job Job, owner string) (claimed *Claimed, rej *rejection, blocked bool, err error) {
	mode, rej, err := s.revalidateForClaim(ctx, tx, job)
	if err != nil || rej != nil {
		return nil, rej, false, err
	}
	specs, err := s.planner.PlanLocks(ctx, tx, job)
	if err != nil {
		_, rej, err := rejectClaim(job, mode, err)
		return nil, rej, false, err
	}
	locks, lockErr := newLockSet(specs)
	if lockErr != nil {
		return nil, &rejection{job: job, err: lockErr, mode: mode}, false, nil
	}
	free, err := locks.free(ctx, tx, job.ID)
	if err != nil || !free {
		return nil, nil, !free, err
	}
	now := s.clock.Now()
	if err := locks.replace(ctx, tx, job.ID, now); err != nil {
		return nil, nil, false, err
	}
	running, err := s.move(ctx, tx, move{
		id: job.ID, from: domain.JobQueued, to: domain.JobRunning, actor: systemActor,
		assign: []assignment{
			{"lease_owner = ?", []any{owner}},
			{"lease_generation = lease_generation + 1", nil},
			{"lease_until = ?", []any{domain.UnixMillis(now.Add(s.leaseTTL))}},
			{"heartbeat_at = ?", []any{domain.UnixMillis(now)}},
			{"attempts = attempts + 1", nil},
			{"error_json = NULL", nil},
			{"started_at = ?", []any{domain.UnixMillis(now)}},
		},
		data: claimData(owner, locks, mode),
		mode: mode,
	})
	if err != nil {
		return nil, nil, false, err
	}
	return &Claimed{Job: running, Lease: s.leaseOf(running)}, nil, false, nil
}

func claimData(owner string, locks lockSet, mode ClaimMode) map[string]any {
	data := map[string]any{"owner": owner, "locks": locks.len()}
	if mode == ClaimRecovery {
		data["mode"] = "safety_recovery"
	}
	return data
}

// revalidateForClaim decides the claim mode and revalidates accordingly. A job
// whose type has no policy is always forward. Under a policy, a recovery
// record replaces the requester Revalidator with RevalidateRecovery; a forward
// rejection (never an infrastructure error) may be escalated to recovery
// inside this transaction, and the claim then proceeds as recovery.
func (s *Store) revalidateForClaim(ctx context.Context, tx *database.Tx, job Job) (ClaimMode, *rejection, error) {
	policy := s.policies[job.Type]
	if policy == nil {
		return rejectClaim(job, ClaimForward, s.revalidator.Revalidate(ctx, tx, job))
	}
	mode, err := policy.ClaimMode(ctx, tx, job)
	if err != nil {
		return rejectClaim(job, ClaimForward, err)
	}
	if mode == ClaimForward {
		cause := s.revalidator.Revalidate(ctx, tx, job)
		if cause == nil {
			return ClaimForward, nil, nil
		}
		rejected, err := asRejection(job, cause)
		if err != nil {
			return ClaimForward, nil, err
		}
		escalated, err := policy.EscalateToRecovery(ctx, tx, job, cause)
		if err != nil {
			return rejectClaim(job, ClaimForward, err)
		}
		if !escalated {
			return ClaimForward, rejected, nil
		}
	}
	return rejectClaim(job, ClaimRecovery, policy.RevalidateRecovery(ctx, tx, job))
}

// rejectClaim turns err, when not nil, into a rejection. Recovery never waits
// for approval, so an approval requirement under recovery is an internal error.
func rejectClaim(job Job, mode ClaimMode, err error) (ClaimMode, *rejection, error) {
	if err == nil {
		return mode, nil, nil
	}
	rej, err := asRejection(job, err)
	if rej != nil {
		rej.mode = mode
		if mode == ClaimRecovery && rej.err.Code == smerr.CodeApprovalRequired {
			rej.err = smerr.New(smerr.CodeInternal, "", "safety recovery cannot require approval")
		}
	}
	return mode, rej, err
}

// asRejection classifies an error from the Revalidator or LockPlanner. A typed
// error fails the job with its own code; a database, connection or context
// error (or one marked ErrInfrastructure) aborts the claim and the job stays
// queued; anything else is a per-job data problem and fails only that job, so
// a poison job cannot block the queue.
func asRejection(job Job, err error) (*rejection, error) {
	var typed *smerr.Error
	switch {
	case errors.As(err, &typed):
		return &rejection{job: job, err: typed}, nil
	case isInfrastructure(err):
		return nil, fmt.Errorf("revalidate job %s: %w", job.ID, err)
	}
	return &rejection{job: job, err: smerr.Wrap(err, smerr.CodeInternal, "", "job cannot be prepared for execution")}, nil
}

func isInfrastructure(err error) bool {
	var sqliteErr *sqlite.Error
	return errors.Is(err, ErrInfrastructure) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, sql.ErrConnDone) || errors.Is(err, sql.ErrTxDone) || errors.Is(err, driver.ErrBadConn) ||
		errors.As(err, &sqliteErr)
}

// applyRejection is the second transaction of a failed claim: queued -> failed,
// or queued -> awaiting_approval when only the approval quorum lapsed.
func (s *Store) applyRejection(ctx context.Context, r rejection) error {
	failure := FailureOf(r.err)
	m := move{id: r.job.ID, from: domain.JobQueued, to: domain.JobFailed, actor: systemActor, failure: &failure, mode: r.mode}
	if r.err.Code == smerr.CodeApprovalRequired {
		m.to, m.failure = domain.JobAwaitingApproval, nil
		m.data = map[string]any{"reason": string(r.err.Reason)}
	}
	err := s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := s.move(ctx, tx, m)
		return err
	})
	if smerr.CodeOf(err) == smerr.CodeConflict {
		return nil // the job left queued meanwhile; nothing to apply
	}
	return err
}

func (s *Store) leaseOf(j Job) Lease {
	return Lease{JobID: j.ID, Owner: j.LeaseOwner, Generation: j.LeaseGeneration, clock: s.clock}
}

// lockSet is the merged, validated set of locks one job needs.
type lockSet struct {
	entries []lockEntry
}

type lockEntry struct {
	resourceType, resourceID string
	mode                     domain.LockMode
}

// newLockSet splits each key at its first colon and merges duplicates, the
// exclusive mode winning.
func newLockSet(specs []domain.LockSpec) (lockSet, *smerr.Error) {
	var set lockSet
	index := map[string]int{}
	for _, spec := range specs {
		kind, rest, ok := strings.Cut(spec.Key, ":")
		if !ok || kind == "" || rest == "" || !spec.Mode.Valid() {
			return lockSet{}, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("invalid lock spec %q (%s)", spec.Key, spec.Mode))
		}
		if i, seen := index[spec.Key]; seen {
			if spec.Mode == domain.LockExclusive {
				set.entries[i].mode = domain.LockExclusive
			}
			continue
		}
		index[spec.Key] = len(set.entries)
		set.entries = append(set.entries, lockEntry{kind, rest, spec.Mode})
	}
	return set, nil
}

func (l lockSet) len() int { return len(l.entries) }

// free reports whether no other job holds a conflicting lock: exclusive
// conflicts with any holder, shared only with an exclusive one (spec §20.5).
// Holders include running and interrupted jobs, which keep their locks.
func (l lockSet) free(ctx context.Context, q database.Querier, job domain.ID) (bool, error) {
	for _, e := range l.entries {
		var conflicting int
		err := q.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM resource_locks
			WHERE resource_type = ? AND resource_id = ? AND job_id <> ? AND (? = 'exclusive' OR mode = 'exclusive')`,
			e.resourceType, e.resourceID, job, e.mode).Scan(&conflicting)
		if err != nil {
			return false, fmt.Errorf("check lock %s:%s: %w", e.resourceType, e.resourceID, err)
		}
		if conflicting > 0 {
			return false, nil
		}
	}
	return true, nil
}

// replace makes the job's lock rows exactly this set: a job requeued after a
// retry still holds its previous rows (§20.5), which may differ from the new plan.
func (l lockSet) replace(ctx context.Context, q database.Querier, job domain.ID, now time.Time) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM resource_locks WHERE job_id = ?`, job); err != nil {
		return fmt.Errorf("reset locks of job %s: %w", job, err)
	}
	for _, e := range l.entries {
		_, err := q.ExecContext(ctx, `
			INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES (?, ?, ?, ?, ?)`,
			e.resourceType, e.resourceID, job, e.mode, now.UnixMilli())
		if err != nil {
			return fmt.Errorf("acquire lock %s:%s: %w", e.resourceType, e.resourceID, err)
		}
	}
	return nil
}
