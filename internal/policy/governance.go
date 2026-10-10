package policy

import (
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// EvaluateGovernance decides a governance action (approval.grant,
// approval.reject, job.cancel, job.resolve) per spec §11.4: steps 1, 3-5 and
// 7 over every target and sub-action of the plan, with no capability check,
// and never approval-gated. The approver must be allowed for all of them.
func (p *Policy) EvaluateGovernance(actor domain.Actor, action string, targets []Target, subActions []SubAction) Result {
	spec, ok := Lookup(action)
	switch {
	case !ok:
		return denied(smerr.ReasonUnknownAction)
	case spec.Mode != ModeGovernance, !evaluable(actor), len(targets) == 0:
		return denied(smerr.ReasonDefaultDeny)
	case actor.Type == domain.ActorMCP && isApprovalDecision(action):
		return denied(smerr.ReasonDefaultDeny)
	}
	all := append([]Target(nil), targets...)
	for _, sub := range subActions {
		subSpec, known := Lookup(sub.Action)
		if !known {
			return denied(smerr.ReasonUnknownAction)
		}
		if subSpec.Mode == ModeGovernance {
			return denied(smerr.ReasonDefaultDeny)
		}
		all = append(all, sub.Target)
	}
	results := make([]TargetResult, len(all))
	for i, t := range all {
		results[i] = p.decideGovernance(actor, action, t)
	}
	return combine(results)
}

func isApprovalDecision(action string) bool {
	return action == ActionApprovalGrant || action == ActionApprovalReject
}

func (p *Policy) decideGovernance(actor domain.Actor, action string, t Target) TargetResult {
	res := TargetResult{Ref: t.Ref, Action: action}
	matched := p.match(actor, action, t.Attrs)
	res.MatchedRules = matched.names()
	if reason := authorizationGap(matched); reason != "" {
		return res.deny(reason)
	}
	if !scopesPermit(actor, action) {
		return res.deny(smerr.ReasonScopeDenied)
	}
	res.Decision = DecisionAllow
	return res
}
