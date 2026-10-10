package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Takeover interrupts every running job whose lease has expired (spec §20.4).
// The lease generation is bumped in the same transaction, so every later write
// by the old worker fails its fence. Locks are kept. It returns the interrupted
// jobs.
//
// The expiry test is lease_until <= now, the exact complement of the fence's
// lease_until > now, so there is no instant at which both sides may write.
func (s *Store) Takeover(ctx context.Context, reconcilerID string) ([]domain.ID, error) {
	var taken []domain.ID
	err := s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		expired, err := queryJobs(ctx, tx, `SELECT `+jobColumns+` FROM jobs
			WHERE state = 'running' AND lease_until <= ? ORDER BY id`, domain.UnixMillis(s.clock.Now()))
		if err != nil {
			return err
		}
		for _, job := range expired {
			_, err := s.move(ctx, tx, move{
				id: job.ID, from: domain.JobRunning, to: domain.JobInterrupted, actor: systemActor,
				assign: []assignment{
					{"lease_generation = lease_generation + 1", nil},
					{"lease_owner = ?", []any{"reconciler:" + reconcilerID}},
				},
				data: map[string]any{"previous_owner": job.LeaseOwner},
			})
			if err != nil {
				return err
			}
			taken = append(taken, job.ID)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("takeover: %w", err)
	}
	return taken, nil
}

// Evidence is what an adapter observed about one dispatched operation. Only a
// completion signal with exit status 0 counts (spec §20.4).
type Evidence struct {
	Done       bool `json:"done"`
	ExitStatus int  `json:"exit_status"`
}

// Success reports whether the operation provably completed with exit status 0.
func (e Evidence) Success() bool { return e.Done && e.ExitStatus == 0 }

// EvidenceSource collects completion evidence for a dispatched, uncompleted
// intent. Concrete adapters (SSH, Docker, systemd, Proxmox) arrive with their
// milestones. Collect runs outside any transaction; an error counts as no evidence.
type EvidenceSource interface {
	Collect(ctx context.Context, intent Intent) (Evidence, error)
}

// ReconcileAction is what the reconciler did with an interrupted job.
type ReconcileAction string

const (
	ReconcileRequeued  ReconcileAction = "requeued"
	ReconcileSucceeded ReconcileAction = "succeeded"
	ReconcileFailed    ReconcileAction = "failed"
	// ReconcileHeld means evidence is missing: the job stays interrupted with
	// its locks, for human resolution. Nothing is ever redispatched.
	ReconcileHeld ReconcileAction = "held"
)

// Resolution reports one reconciled job.
type Resolution struct {
	JobID  domain.ID
	Action ReconcileAction
}

// Reconcile examines every quiescent interrupted job (spec §20.4). src may be
// nil, which means no evidence is ever available. Per-job failures do not stop
// the pass; they are returned joined, next to the resolutions that did happen.
func (s *Store) Reconcile(ctx context.Context, src EvidenceSource) ([]Resolution, error) {
	interrupted, err := s.List(ctx, s.db.Reader(), ListFilter{States: []domain.JobState{domain.JobInterrupted}, Limit: 1 << 20})
	if err != nil {
		return nil, fmt.Errorf("reconcile: %w", err)
	}
	var (
		resolutions []Resolution
		errs        []error
	)
	for _, job := range interrupted {
		res, err := s.reconcileJob(ctx, job, src)
		if err != nil {
			errs = append(errs, fmt.Errorf("job %s: %w", job.ID, err))
			continue
		}
		if res != nil {
			resolutions = append(resolutions, *res)
		}
	}
	return resolutions, errors.Join(errs...)
}

func (s *Store) reconcileJob(ctx context.Context, job Job, src EvidenceSource) (*Resolution, error) {
	intents, err := s.Intents(ctx, s.db.Reader(), job.ID)
	if err != nil {
		return nil, err
	}
	if !quiescent(job, intents, s.clock.Now()) {
		return nil, nil
	}
	evidence := collectEvidence(ctx, src, intents)

	var res *Resolution
	err = s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		fresh, err := s.Get(ctx, tx, job.ID)
		if err != nil {
			return err
		}
		if fresh.State != domain.JobInterrupted || fresh.LeaseGeneration != job.LeaseGeneration {
			return nil // resolved or taken over meanwhile
		}
		current, err := s.Intents(ctx, tx, job.ID)
		if err != nil {
			return err
		}
		res, err = s.applyVerdict(ctx, tx, fresh, current, evidence)
		return err
	})
	return res, err
}

// quiescent holds when no worker can still write for the job: its lease has
// expired and the generation was bumped past every intent's.
func quiescent(job Job, intents []Intent, now time.Time) bool {
	if job.LeaseUntil == nil || job.LeaseUntil.After(now) {
		return false
	}
	for _, in := range intents {
		if in.LeaseGeneration >= job.LeaseGeneration {
			return false
		}
	}
	return true
}

func collectEvidence(ctx context.Context, src EvidenceSource, intents []Intent) map[domain.ID]Evidence {
	found := map[domain.ID]Evidence{}
	if src == nil {
		return found
	}
	for _, in := range intents {
		if !pending(in) {
			continue
		}
		if ev, err := src.Collect(ctx, in); err == nil {
			found[in.ID] = ev
		}
	}
	return found
}

// pending is a dispatched operation nobody has completed.
func pending(in Intent) bool { return in.State == IntentRecorded && in.Dispatched() }

type verdict struct {
	action  ReconcileAction
	reason  string
	failure *Failure
}

// decide is the reconciliation table of spec §20.4 as a pure function. It never
// returns an action that would dispatch an operation again.
func decide(job Job, intents []Intent, evidence map[domain.ID]Evidence) verdict {
	for _, in := range intents {
		if pending(in) && !evidence[in.ID].Success() {
			return verdict{action: ReconcileHeld, reason: "no completion evidence for intent " + in.ID.String()}
		}
	}
	switch job.RetryClass {
	case domain.RetryIdempotent:
		if job.Attempts >= job.MaxAttempts {
			return failed("job interrupted and its attempts are exhausted")
		}
		return verdict{action: ReconcileRequeued, reason: "idempotent job requeued"}
	case domain.RetryResumable:
		return verdict{action: ReconcileRequeued, reason: "resumable job resumes from its completed intents"}
	case domain.RetryNonRetryable:
		return decideNonRetryable(intents)
	}
	return verdict{action: ReconcileHeld, reason: "unknown retry class"}
}

func decideNonRetryable(intents []Intent) verdict {
	if len(intents) == 0 {
		return failed("job interrupted before any operation was dispatched")
	}
	for _, in := range intents {
		if in.State == IntentRecorded && !pending(in) {
			return failed("job interrupted before dispatching intent " + in.ID.String())
		}
		if in.State == IntentCompleted && in.Outcome != OutcomeSucceeded {
			return failed("recorded operation " + in.Operation + " failed")
		}
	}
	return verdict{action: ReconcileSucceeded, reason: "every recorded operation completed"}
}

func failed(msg string) verdict {
	return verdict{action: ReconcileFailed, reason: msg, failure: &Failure{Code: smerr.CodeInternal, Message: msg}}
}

func (s *Store) applyVerdict(ctx context.Context, tx *database.Tx, job Job, intents []Intent, evidence map[domain.ID]Evidence) (*Resolution, error) {
	v := decide(job, intents, evidence)
	res := &Resolution{JobID: job.ID, Action: v.action}
	if v.action == ReconcileHeld {
		return res, s.emit(ctx, tx, systemActor, "job.reconcile_held", job.ID,
			eventOutcome{domain.SeverityWarning, domain.ResultPending}, map[string]any{"reason": v.reason})
	}
	if err := s.completeProven(ctx, tx, job, intents, evidence); err != nil {
		return nil, err
	}
	if v.action == ReconcileRequeued {
		return res, s.requeueNow(ctx, tx, job, domain.JobInterrupted, v.reason)
	}
	to := domain.JobSucceeded
	if v.action == ReconcileFailed {
		to = domain.JobFailed
	}
	_, err := s.move(ctx, tx, move{
		id: job.ID, from: domain.JobInterrupted, to: to, actor: systemActor, failure: v.failure,
		data: map[string]any{"reason": v.reason},
	})
	return res, err
}

// completeProven closes the intents whose completion the evidence proved.
func (s *Store) completeProven(ctx context.Context, q database.Querier, job Job, intents []Intent, evidence map[domain.ID]Evidence) error {
	for _, in := range intents {
		if !pending(in) {
			continue
		}
		raw, err := json.Marshal(evidence[in.ID])
		if err != nil {
			return fmt.Errorf("encode evidence: %w", err)
		}
		if err := s.completeIntent(ctx, q, job.ID, in.ID, OutcomeSucceeded, raw); err != nil {
			return err
		}
	}
	return nil
}
