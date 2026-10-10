package app

import (
	"context"
	"errors"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// Governance acts on existing jobs: cancel and resolve (spec §11.4, §20.4).
type Governance struct {
	core
	jobs *jobs.Store
}

// NewGovernance validates cfg.
func NewGovernance(cfg Config, store *jobs.Store) (*Governance, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("app: job store is required")
	}
	return &Governance{core: c, jobs: store}, nil
}

// ResolveRequest is a human's verdict on an interrupted job (spec §20.4).
type ResolveRequest struct {
	JobID           domain.ID
	PlanHash        string
	Outcome         jobs.ResolveOutcome
	Note            string
	AssumeQuiescent bool
}

// Cancel cancels a job that has not started (action job.cancel). The plan hash
// is the one the caller saw; a different one is PLAN_STALE.
func (g *Governance) Cancel(ctx context.Context, by Caller, job domain.ID, planHash string) (jobs.Job, error) {
	return commit(ctx, g.core, by, func(ctx context.Context, tx *database.Tx) (jobs.Job, error) {
		actor, _, err := g.begin(ctx, tx, by, job, planHash, policy.ActionJobCancel)
		if err != nil {
			return jobs.Job{}, err
		}
		return g.jobs.Cancel(ctx, tx, job, actor)
	})
}

// Resolve settles an interrupted job as the human said and releases its locks
// (action job.resolve). It never re-executes anything. Resolving a job one
// requested is allowed only where self-approval is (local mode).
func (g *Governance) Resolve(ctx context.Context, by Caller, r ResolveRequest) (jobs.Job, error) {
	return commit(ctx, g.core, by, func(ctx context.Context, tx *database.Tx) (jobs.Job, error) {
		actor, stored, err := g.begin(ctx, tx, by, r.JobID, r.PlanHash, policy.ActionJobResolve)
		if err != nil {
			return jobs.Job{}, err
		}
		if stored.ActorID == actor.ID && !g.cfg.AllowSelfApproval {
			res := policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonSelfApproval}
			if err := g.auditDecision(ctx, tx, actor, policy.ActionJobResolve, jobRef(stored), res); err != nil {
				return jobs.Job{}, err
			}
			return jobs.Job{}, reject(decisionError(res))
		}
		return g.jobs.Resolve(ctx, tx, jobs.ResolveRequest{
			JobID: r.JobID, PlanHash: r.PlanHash, Outcome: r.Outcome, Note: r.Note,
			AssumeQuiescent: r.AssumeQuiescent, By: actor,
		})
	})
}

// begin identifies the caller, loads the job, checks the plan hash and applies
// the governance policy to the job's target and sub-actions.
func (g *Governance) begin(ctx context.Context, tx *database.Tx, by Caller, id domain.ID, planHash, action string) (domain.Actor, jobs.Job, error) {
	actor, err := g.beginRequest(ctx, tx, by)
	if err != nil {
		return domain.Actor{}, jobs.Job{}, err
	}
	job, err := g.jobs.Get(ctx, tx, id)
	if err != nil {
		return domain.Actor{}, jobs.Job{}, err
	}
	if job.PlanID == nil {
		return domain.Actor{}, jobs.Job{}, smerr.New(smerr.CodeInvalidArgument, "", "job has no plan")
	}
	if job.PlanHash != planHash {
		return domain.Actor{}, jobs.Job{}, smerr.FromReason(smerr.ReasonPlanStale, "plan hash does not match the job's plan")
	}
	rec, err := database.GetPlan(ctx, tx, *job.PlanID)
	if err != nil {
		return domain.Actor{}, jobs.Job{}, err
	}
	current, err := rebuildCurrent(ctx, tx, rec)
	if err != nil {
		return domain.Actor{}, jobs.Job{}, err
	}
	res := g.authorizeGovernance(actor, action, current)
	if res.Decision != policy.DecisionAllow {
		if err := g.auditDecision(ctx, tx, actor, action, jobRef(job), res); err != nil {
			return domain.Actor{}, jobs.Job{}, err
		}
		return domain.Actor{}, jobs.Job{}, reject(decisionError(res))
	}
	return actor, job, nil
}
