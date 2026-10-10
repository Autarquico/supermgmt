package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// errClaimRejected aborts the claim transaction after a revalidation failure so
// that nothing it read or wrote survives; the rejection travels in claimOutcome.
var errClaimRejected = errors.New("claim rejected")

type rejection struct {
	job Job
	err *smerr.Error
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
		for _, job := range candidates {
			claimed, rej, err := s.tryClaim(ctx, tx, job, owner)
			switch {
			case err != nil:
				return err
			case rej != nil:
				out.rejected = rej
				return errClaimRejected
			case claimed != nil:
				out.claimed = claimed
				return nil
			}
		}
		return nil
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

// tryClaim returns (nil, nil, nil) when the job is blocked by locks and the
// next candidate should be tried.
func (s *Store) tryClaim(ctx context.Context, tx *database.Tx, job Job, owner string) (*Claimed, *rejection, error) {
	if err := s.revalidator.Revalidate(ctx, tx, job); err != nil {
		rej, err := asRejection(job, err)
		return nil, rej, err
	}
	specs, err := s.planner.PlanLocks(ctx, tx, job)
	if err != nil {
		rej, err := asRejection(job, err)
		return nil, rej, err
	}
	locks, err := newLockSet(specs)
	if err != nil {
		return nil, nil, err
	}
	free, err := locks.free(ctx, tx, job.ID)
	if err != nil || !free {
		return nil, nil, err
	}
	if err := locks.acquire(ctx, tx, job.ID, s.clock.Now()); err != nil {
		return nil, nil, err
	}
	running, err := s.move(ctx, tx, move{
		id: job.ID, from: domain.JobQueued, to: domain.JobRunning, actor: systemActor,
		assign: []assignment{
			{"lease_owner = ?", []any{owner}},
			{"lease_generation = lease_generation + 1", nil},
			{"lease_until = ?", []any{domain.UnixMillis(s.clock.Now().Add(s.leaseTTL))}},
			{"heartbeat_at = ?", []any{domain.UnixMillis(s.clock.Now())}},
			{"attempts = attempts + 1", nil},
			{"error_json = NULL", nil},
			{"started_at = ?", []any{domain.UnixMillis(s.clock.Now())}},
		},
		data: map[string]any{"owner": owner, "locks": locks.len()},
	})
	if err != nil {
		return nil, nil, err
	}
	return &Claimed{Job: running, Lease: s.leaseOf(running)}, nil, nil
}

// asRejection classifies a revalidation or lock-planning error: a typed error
// fails the job, anything else aborts the claim as an infrastructure failure.
func asRejection(job Job, err error) (*rejection, error) {
	var typed *smerr.Error
	if errors.As(err, &typed) {
		return &rejection{job: job, err: typed}, nil
	}
	return nil, fmt.Errorf("revalidate job %s: %w", job.ID, err)
}

// applyRejection is the second transaction of a failed claim: queued -> failed,
// or queued -> awaiting_approval when only the approval quorum lapsed.
func (s *Store) applyRejection(ctx context.Context, r rejection) error {
	failure := FailureOf(r.err)
	m := move{id: r.job.ID, from: domain.JobQueued, to: domain.JobFailed, actor: systemActor, failure: &failure}
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
func newLockSet(specs []domain.LockSpec) (lockSet, error) {
	var set lockSet
	index := map[string]int{}
	for _, spec := range specs {
		kind, rest, ok := strings.Cut(spec.Key, ":")
		if !ok || kind == "" || rest == "" || !spec.Mode.Valid() {
			return lockSet{}, fmt.Errorf("invalid lock spec %q (%s)", spec.Key, spec.Mode)
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

func (l lockSet) acquire(ctx context.Context, q database.Querier, job domain.ID, now time.Time) error {
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
