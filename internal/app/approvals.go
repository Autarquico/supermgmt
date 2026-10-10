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

var systemActor = domain.Actor{Type: domain.ActorSystem}

// Approvals records approver decisions on submitted plans (spec §11.4).
type Approvals struct {
	core
	jobs *jobs.Store
}

// NewApprovals validates cfg. The store must have been built with this
// package's Revalidator and LockPlanner.
func NewApprovals(cfg Config, store *jobs.Store) (*Approvals, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("app: job store is required")
	}
	return &Approvals{core: c, jobs: store}, nil
}

// DecisionRequest names the job and the plan hash the approver saw.
type DecisionRequest struct {
	JobID    domain.ID
	PlanHash string
	Reason   string
}

// Approve records an approval. When the quorum is met the job moves from
// awaiting_approval to queued; otherwise it is returned unchanged.
func (a *Approvals) Approve(ctx context.Context, by Caller, req DecisionRequest) (jobs.Job, error) {
	return a.decide(ctx, by, req, domain.DecisionApprove)
}

// Reject records a rejection, which is final for the plan hash: the job fails
// with REJECTED. It is accepted while the job is awaiting_approval or queued.
func (a *Approvals) Reject(ctx context.Context, by Caller, req DecisionRequest) (jobs.Job, error) {
	return a.decide(ctx, by, req, domain.DecisionReject)
}

func (a *Approvals) decide(ctx context.Context, by Caller, req DecisionRequest, decision domain.ApprovalDecision) (jobs.Job, error) {
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (jobs.Job, error) {
		job, rec, err := a.pendingJob(ctx, tx, req, decision)
		if err != nil {
			return jobs.Job{}, err
		}
		approver, err := loadCaller(ctx, tx, by)
		if err != nil {
			return jobs.Job{}, err
		}
		if err := a.requireActive(ctx, by.Credential); err != nil {
			return jobs.Job{}, err
		}
		current, err := rebuildCurrent(ctx, tx, rec)
		if err != nil {
			return jobs.Job{}, err
		}
		if err := a.authorizeDecision(ctx, tx, approver, job, decision, current); err != nil {
			return jobs.Job{}, err
		}
		if !a.cfg.Clock.Now().Before(rec.ExpiresAt) {
			return jobs.Job{}, a.expire(ctx, tx, job) // only an authorized approver may expire the plan
		}
		stored, err := database.RecordDecision(ctx, tx, database.Approval{
			ID:         a.cfg.IDs.NewID(),
			JobID:      job.ID,
			PlanHash:   job.PlanHash,
			ApproverID: approver.ID,
			Decision:   decision,
			Reason:     req.Reason,
			ExpiresAt:  a.cfg.Clock.Now().Add(a.cfg.ApprovalTTL),
		}, a.cfg.Clock.Now())
		if err != nil {
			return jobs.Job{}, err
		}
		if err := a.emit(ctx, tx, approver, governanceAction(decision), jobRef(job), domain.ResultSucceeded,
			map[string]any{"plan_hash": job.PlanHash, "approval_id": stored.ID.String(), "reason": req.Reason}); err != nil {
			return jobs.Job{}, err
		}
		return a.advance(ctx, tx, approver, job, decision, current)
	})
}

// pendingJob loads the job and its plan and checks everything that does not
// depend on who decides: the hash the approver saw and the job's state.
func (a *Approvals) pendingJob(ctx context.Context, q database.Querier, req DecisionRequest, decision domain.ApprovalDecision) (jobs.Job, database.PlanRecord, error) {
	job, err := a.jobs.Get(ctx, q, req.JobID)
	if err != nil {
		return jobs.Job{}, database.PlanRecord{}, err
	}
	if job.PlanID == nil {
		return jobs.Job{}, database.PlanRecord{}, smerr.New(smerr.CodeInvalidArgument, "", "job has no plan to decide on")
	}
	if job.PlanHash != req.PlanHash {
		return jobs.Job{}, database.PlanRecord{}, smerr.FromReason(smerr.ReasonPlanStale, "plan hash does not match the job's plan")
	}
	if !decidable(job.State, decision) {
		return jobs.Job{}, database.PlanRecord{}, smerr.FromReason(smerr.ReasonInvalidTransition,
			"job in state "+string(job.State)+" cannot take this decision")
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	return job, rec, err
}

// decidable: approvals only matter while awaiting_approval; a rejection is
// also accepted on a queued job (ADR-0013, spec §11.4).
func decidable(state domain.JobState, decision domain.ApprovalDecision) bool {
	return state == domain.JobAwaitingApproval || (decision == domain.DecisionReject && state == domain.JobQueued)
}

// expire fails a job whose plan expired, commits that, and reports it.
func (a *Approvals) expire(ctx context.Context, q database.Querier, job jobs.Job) error {
	expired := smerr.FromReason(smerr.ReasonPlanExpired, "plan expired")
	if _, err := a.jobs.FailPending(ctx, q, job.ID, jobs.FailureOf(expired), systemActor); err != nil {
		return err
	}
	return reject(expired)
}

// authorizeDecision applies governance policy (steps 1, 3-5, 7) to the plan's
// target as it is now, then the self-approval rule. A refusal is audited and
// rejects.
func (a *Approvals) authorizeDecision(ctx context.Context, q database.Querier, approver domain.Actor, job jobs.Job, decision domain.ApprovalDecision, b built) error {
	action := governanceAction(decision)
	res := a.authorizeGovernance(approver, action, b)
	if res.Decision == policy.DecisionAllow && decision == domain.DecisionApprove &&
		approver.ID == job.ActorID && !a.cfg.AllowSelfApproval {
		res = policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonSelfApproval}
	}
	if res.Decision == policy.DecisionAllow {
		return nil
	}
	if err := a.auditDecision(ctx, q, approver, action, jobRef(job), res); err != nil {
		return err
	}
	return reject(decisionError(res))
}

// advance applies the effect of a recorded decision on the job.
func (a *Approvals) advance(ctx context.Context, q database.Querier, approver domain.Actor, job jobs.Job, decision domain.ApprovalDecision, current built) (jobs.Job, error) {
	if decision == domain.DecisionReject {
		rejected := smerr.FromReason(smerr.ReasonRejected, "plan was rejected")
		return a.jobs.FailPending(ctx, q, job.ID, jobs.FailureOf(rejected), approver)
	}
	if job.State != domain.JobAwaitingApproval {
		return job, nil
	}
	satisfied, err := a.quorumMet(ctx, q, job, current)
	if err != nil || !satisfied {
		return job, err
	}
	return a.jobs.Approve(ctx, q, job.ID, approver)
}

// quorumMet re-evaluates the requester's policy for the quorum it demands and
// counts the approvals on the job's plan hash.
func (a *Approvals) quorumMet(ctx context.Context, q database.Querier, job jobs.Job, current built) (bool, error) {
	requester, err := loadActor(ctx, q, job.ActorID, credentialOf(job))
	if isTyped(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	res := a.authorize(current.request(requester))
	if decisionError(res) != nil {
		return false, nil // the decision stays recorded; claim revalidation fails the job
	}
	counted, err := a.countApprovals(ctx, q, job, requester, res.Quorum, current)
	return counted.Satisfied, err
}

func governanceAction(decision domain.ApprovalDecision) string {
	if decision == domain.DecisionReject {
		return policy.ActionApprovalReject
	}
	return policy.ActionApprovalGrant
}

func jobRef(job jobs.Job) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceJob, ID: job.ID}
}
