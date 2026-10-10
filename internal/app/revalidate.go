package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// Revalidator implements jobs.Revalidator: inside the claim transaction it
// re-checks everything that may have changed since submission (spec §20.4).
type Revalidator struct{ core }

// NewRevalidator validates cfg.
func NewRevalidator(cfg Config) (*Revalidator, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	return &Revalidator{core: c}, nil
}

var _ jobs.Revalidator = (*Revalidator)(nil)

// Revalidate returns nil when the job may start. Every refusal is a typed
// error, so the job engine fails the job with it; APPROVAL_REQUIRED sends it
// back to awaiting_approval instead. The refusal is recorded by the engine as
// the job's failure event: this transaction is rolled back, so nothing is
// emitted from here.
//
// Checks run in the order of spec §20.4: plan inputs, plan expiry,
// credential, policy, quorum.
func (r *Revalidator) Revalidate(ctx context.Context, q database.Querier, job jobs.Job) error {
	if job.PlanID == nil {
		return smerr.New(smerr.CodeInternal, "", "job has no plan to revalidate")
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	if err != nil {
		return err
	}
	if rec.PlanHash != job.PlanHash {
		return planStale()
	}
	current, err := rebuild(ctx, q, rec)
	if err != nil {
		return err
	}
	if !r.cfg.Clock.Now().Before(rec.ExpiresAt) {
		return smerr.FromReason(smerr.ReasonPlanExpired, "plan expired")
	}
	if err := r.requireStillValid(ctx, credentialOf(job)); err != nil {
		return err
	}
	requester, err := loadActor(ctx, q, job.ActorID, credentialOf(job))
	if err != nil {
		return err
	}
	res := r.authorize(current.request(requester))
	if err := decisionError(res); err != nil {
		return err
	}
	if !res.ApprovalRequired {
		return nil
	}
	return r.requireQuorum(ctx, q, job, requester, res.Quorum, current)
}

// requireQuorum re-counts the approvals on the job's plan hash (spec §11.4).
func (r *Revalidator) requireQuorum(ctx context.Context, q database.Querier, job jobs.Job, requester domain.Actor, required int, b built) error {
	counted, err := r.countApprovals(ctx, q, job, requester, required, b)
	if err != nil {
		return err
	}
	switch {
	case counted.Rejected:
		return smerr.FromReason(smerr.ReasonRejected, "plan was rejected")
	case !counted.Satisfied:
		return smerr.New(smerr.CodeApprovalRequired, "", "approval quorum is no longer met")
	}
	return nil
}
