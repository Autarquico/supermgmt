package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// authorize evaluates req. The system actor is not subject to policy and holds
// no roles (spec §11.1): what it may do is fixed in code, so it is allowed here
// and never needs approval. Authenticating a system caller is the daemon's job.
func (c core) authorize(req policy.Request) policy.Result {
	if req.Actor.Type == domain.ActorSystem {
		return policy.Result{Decision: policy.DecisionAllow}
	}
	return c.cfg.Policy.Evaluate(req)
}

// authorizeGovernance evaluates a governance action. The system actor can never
// approve, reject or resolve (spec §11.4).
func (c core) authorizeGovernance(actor domain.Actor, action string, targets []policy.Target) policy.Result {
	if actor.Type == domain.ActorSystem {
		return policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonDefaultDeny}
	}
	return c.cfg.Policy.EvaluateGovernance(actor, action, targets, nil)
}

// decisionError turns a non-allow result into its typed error; nil when allowed.
func decisionError(res policy.Result) error {
	switch res.Decision {
	case policy.DecisionAllow:
		return nil
	case policy.DecisionCapabilityUnavailable:
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "target does not advertise the required capability")
	case policy.DecisionDeny:
		return smerr.FromReason(res.Reason, "action denied by policy")
	}
	return smerr.FromReason(smerr.ReasonDefaultDeny, "unrecognized policy decision")
}

// auditDecision records a DENY or CAPABILITY_UNAVAILABLE outcome (spec §11.3).
// Allowed results record nothing here.
func (c core) auditDecision(ctx context.Context, q database.Querier, actor domain.Actor, action string, target domain.ResourceRef, res policy.Result) error {
	if res.Decision == policy.DecisionAllow {
		return nil
	}
	return c.emit(ctx, q, actor, "policy."+string(res.Decision), target, domain.ResultDenied, map[string]any{
		"action": action,
		"reason": string(res.Reason),
	})
}

// countApprovals evaluates the stored decisions on the job's plan hash: only
// unexpired approvals from approvers who still hold approval.grant count, and
// any rejection blocks (spec §11.4).
func (c core) countApprovals(ctx context.Context, q database.Querier, job jobs.Job, requester domain.Actor, required int, targets []policy.Target) (policy.QuorumResult, error) {
	decisions, err := database.ListDecisions(ctx, q, job.ID, job.PlanHash)
	if err != nil {
		return policy.QuorumResult{}, err
	}
	records := make([]policy.ApprovalRecord, len(decisions))
	authorized := make(map[domain.ID]bool, len(decisions))
	for i, d := range decisions {
		records[i] = policy.ApprovalRecord{Approver: d.ApproverID, Decision: d.Decision, ExpiresAt: d.ExpiresAt}
		if _, known := authorized[d.ApproverID]; known {
			continue
		}
		if authorized[d.ApproverID], err = c.mayApprove(ctx, q, d.ApproverID, targets); err != nil {
			return policy.QuorumResult{}, err
		}
	}
	return policy.EvaluateQuorum(policy.QuorumInput{
		Now:               c.cfg.Clock.Now(),
		Required:          required,
		Records:           records,
		Requester:         requester,
		AllowSelfApproval: c.cfg.AllowSelfApproval,
		StillAuthorized:   func(approver domain.ID) bool { return authorized[approver] },
	}), nil
}

// mayApprove reports whether the identity is currently allowed approval.grant
// on every target. An identity that is gone or disabled is simply not allowed;
// only infrastructure failures are errors.
func (c core) mayApprove(ctx context.Context, q database.Querier, id domain.ID, targets []policy.Target) (bool, error) {
	actor, err := loadActor(ctx, q, id, domain.CredentialContext{})
	if isTyped(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	res := c.authorizeGovernance(actor, policy.ActionApprovalGrant, targets)
	return res.Decision == policy.DecisionAllow, nil
}
