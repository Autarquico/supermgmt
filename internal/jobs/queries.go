package jobs

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Detail is a job with its operation intents, whose pre-state and evidence
// show what the reconciler saw (spec §20.4).
type Detail struct {
	Job     Job
	Intents []Intent
}

// Detail returns the job and its intents, or NOT_FOUND. Run on one Querier
// (a transaction, or the reader pool) they come from one call site, not one
// snapshot: use a transaction when the pair must be consistent.
func (s *Store) Detail(ctx context.Context, q database.Querier, id domain.ID) (Detail, error) {
	job, err := s.Get(ctx, q, id)
	if err != nil {
		return Detail{}, err
	}
	intents, err := s.Intents(ctx, q, id)
	if err != nil {
		return Detail{}, err
	}
	return Detail{Job: job, Intents: intents}, nil
}

// ExpirePlans fails every job still awaiting approval whose plan has expired
// (PLAN_EXPIRED, spec §23) and returns their ids. Jobs that already passed
// approval are not touched here: claim-time revalidation rejects an expired
// plan (spec §20.4).
func (s *Store) ExpirePlans(ctx context.Context) ([]domain.ID, error) {
	var expired []domain.ID
	err := s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		due, err := queryJobs(ctx, tx, `SELECT `+jobColumns+` FROM jobs
			WHERE state = 'awaiting_approval'
			  AND plan_id IN (SELECT id FROM plans WHERE expires_at <= ?)
			ORDER BY id`, domain.UnixMillis(s.clock.Now()))
		if err != nil {
			return err
		}
		failure := FailureOf(smerr.FromReason(smerr.ReasonPlanExpired, "plan expired"))
		for _, job := range due {
			if _, err := s.FailPending(ctx, tx, job.ID, failure, systemActor); err != nil {
				return err
			}
			expired = append(expired, job.ID)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("expire plans: %w", err)
	}
	return expired, nil
}
