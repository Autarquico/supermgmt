package jobs

import (
	"context"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ResolveOutcome is the verdict a human gives an interrupted job (spec §20.4).
type ResolveOutcome string

const (
	ResolveSucceeded      ResolveOutcome = "succeeded"
	ResolveFailed         ResolveOutcome = "failed"
	ResolveRollbackFailed ResolveOutcome = "rollback_failed"
)

// ResolveRequest asks to settle one interrupted job by hand.
type ResolveRequest struct {
	JobID    domain.ID
	PlanHash string
	Outcome  ResolveOutcome
	Note     string
	// AssumeQuiescent skips the quiescence check; the caller requires it when
	// the node cannot be reached, and it is recorded in the job's event.
	AssumeQuiescent bool
	By              domain.Actor
}

// Resolve settles an interrupted job as the human said and releases its locks.
// It runs inside the caller's write transaction, never re-executes anything and
// closes the dispatched intents with the same verdict. Authorization is the
// caller's: this only enforces the state, the plan hash the human saw and
// quiescence (no worker or remote process of ours can still be writing).
func (s *Store) Resolve(ctx context.Context, q database.Querier, r ResolveRequest) (Job, error) {
	to, failure, err := resolution(r.Outcome, r.Note)
	if err != nil {
		return Job{}, err
	}
	job, err := s.Get(ctx, q, r.JobID)
	if err != nil {
		return Job{}, err
	}
	if job.State != domain.JobInterrupted {
		return Job{}, invalidTransition(job.State, to)
	}
	if job.PlanHash != r.PlanHash {
		return Job{}, smerr.FromReason(smerr.ReasonPlanStale, "plan hash does not match the job's plan")
	}
	intents, err := s.Intents(ctx, q, job.ID)
	if err != nil {
		return Job{}, err
	}
	if !r.AssumeQuiescent && !s.quiescent(job, intents, s.clock.Now()) {
		return Job{}, smerr.New(smerr.CodeConflict, "", "job is not quiescent: a worker or a remote process may still be running")
	}
	if err := s.closeDispatched(ctx, q, intents, r.Outcome); err != nil {
		return Job{}, err
	}
	return s.move(ctx, q, move{
		id: job.ID, from: domain.JobInterrupted, to: to, actor: r.By, failure: failure,
		data: map[string]any{
			"resolved_by_human": true,
			"outcome":           string(r.Outcome),
			"note":              audit.ScrubString(r.Note),
			"assume_quiescent":  r.AssumeQuiescent,
		},
	})
}

// resolution maps a human outcome to the job state and, for failures, its reason.
func resolution(o ResolveOutcome, note string) (domain.JobState, *Failure, error) {
	switch o {
	case ResolveSucceeded:
		return domain.JobSucceeded, nil, nil
	case ResolveFailed:
		return domain.JobFailed, &Failure{Code: smerr.CodeInternal, Message: "resolved as failed by an operator: " + note}, nil
	case ResolveRollbackFailed:
		return domain.JobFailed, &Failure{Code: smerr.CodeRollbackFailed, Message: "resolved as rollback failed by an operator: " + note}, nil
	}
	return "", nil, smerr.New(smerr.CodeInvalidArgument, "", "outcome must be succeeded, failed or rollback_failed")
}

// closeDispatched completes every dispatched intent that is still recorded, so
// the job detail does not show operations in flight on a finished job.
func (s *Store) closeDispatched(ctx context.Context, q database.Querier, intents []Intent, o ResolveOutcome) error {
	outcome := OutcomeFailed
	if o == ResolveSucceeded {
		outcome = OutcomeSucceeded
	}
	for _, in := range intents {
		if in.State != IntentRecorded || !in.Dispatched() {
			continue
		}
		if err := s.completeIntent(ctx, q, in.JobID, in.ID, outcome, nil); err != nil {
			return err
		}
	}
	return nil
}
