package policy

import (
	"slices"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Decision is the outcome of an evaluation.
type Decision string

const (
	DecisionAllow                 Decision = "allow"
	DecisionDeny                  Decision = "deny"
	DecisionCapabilityUnavailable Decision = "capability_unavailable"
)

// CapabilitySet is the set of capabilities advertised for a target (spec §7).
type CapabilitySet map[string]struct{}

// NewCapabilitySet builds a set from capability names.
func NewCapabilitySet(names ...string) CapabilitySet {
	set := make(CapabilitySet, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}

// Has reports whether name is advertised. A nil set advertises nothing.
func (c CapabilitySet) Has(name string) bool {
	_, ok := c[name]
	return ok
}

// Target is one resource an action applies to, with the attributes and
// capabilities the caller computed for it.
type Target struct {
	Ref          domain.ResourceRef
	Attrs        Attributes
	Capabilities CapabilitySet
}

// SubAction is an action a composite plan performs alongside its main
// action, on its own target (spec §11.3 "Composite plans").
type SubAction struct {
	Action string
	Params map[string]any
	Target Target
}

// Request is the input of Evaluate.
type Request struct {
	Actor      domain.Actor
	Action     string
	Params     map[string]any
	Targets    []Target
	SubActions []SubAction
}

// TargetResult is the verdict for one target or sub-action.
type TargetResult struct {
	Ref              domain.ResourceRef
	Action           string
	Decision         Decision
	Reason           smerr.Reason
	MatchedRules     []string
	ApprovalRequired bool
	Quorum           int
}

// Result is the combined verdict (spec §11.3 steps 9 and 10). ApprovalRequired
// and Quorum are only meaningful when Decision is allow.
type Result struct {
	Decision         Decision
	ApprovalRequired bool
	Quorum           int
	Reason           smerr.Reason
	PerTarget        []TargetResult
}

type unit struct {
	spec   ActionSpec
	risk   domain.RiskClass
	target Target
}

// Evaluate implements spec §11.3 steps 1-10. It fails closed: anything it
// cannot positively authorize is a deny.
func (p *Policy) Evaluate(req Request) Result {
	spec, ok := Lookup(req.Action)
	switch {
	case !ok:
		return denied(smerr.ReasonUnknownAction)
	case !evaluable(req.Actor):
		return denied(smerr.ReasonDefaultDeny)
	case spec.Mode == ModeGovernance:
		return p.EvaluateGovernance(req.Actor, req.Action, req.Targets, req.SubActions)
	case spec.Mode == ModeSubAction, len(req.Targets) == 0:
		return denied(smerr.ReasonDefaultDeny)
	}
	units, reason := planUnits(spec, req)
	if reason != "" {
		return denied(reason)
	}
	results := make([]TargetResult, len(units))
	for i, u := range units {
		results[i] = p.decide(req.Actor, u)
	}
	return combine(results)
}

// planUnits is step 1: the catalog entry and risk of the main action and of
// every sub-action, paired with their targets.
func planUnits(spec ActionSpec, req Request) ([]unit, smerr.Reason) {
	risk, err := spec.riskFor(req.Params)
	if err != nil {
		return nil, smerr.ReasonDefaultDeny
	}
	units := make([]unit, 0, len(req.Targets)+len(req.SubActions))
	for _, t := range req.Targets {
		units = append(units, unit{spec: spec, risk: risk, target: t})
	}
	for _, sub := range req.SubActions {
		subSpec, ok := Lookup(sub.Action)
		if !ok {
			return nil, smerr.ReasonUnknownAction
		}
		if subSpec.Mode == ModeGovernance {
			return nil, smerr.ReasonDefaultDeny
		}
		subRisk, err := subSpec.riskFor(sub.Params)
		if err != nil {
			return nil, smerr.ReasonDefaultDeny
		}
		units = append(units, unit{spec: subSpec, risk: subRisk, target: sub.Target})
	}
	return units, ""
}

// decide runs steps 2-8 for one target or sub-action.
func (p *Policy) decide(actor domain.Actor, u unit) TargetResult {
	res := TargetResult{Ref: u.target.Ref, Action: u.spec.Name}
	if u.spec.Capability != "" && !u.target.Capabilities.Has(u.spec.Capability) {
		res.Decision = DecisionCapabilityUnavailable
		return res
	}
	matched := p.match(actor, u.spec.Name, u.target.Attrs)
	res.MatchedRules = matched.names()
	if reason := authorizationGap(matched); reason != "" {
		return res.deny(reason)
	}
	if u.risk == domain.RiskDestructive && !slices.ContainsFunc(matched.allow, func(r Rule) bool { return r.AllowDestructive }) {
		return res.deny(smerr.ReasonDestructiveGate)
	}
	if !scopesPermit(actor, u.spec.Name) {
		return res.deny(smerr.ReasonScopeDenied)
	}
	if skipsApproval(u.spec, u.risk) {
		res.Decision = DecisionAllow
		return res
	}
	required := approvalRequired(actor, u.risk, u.target.Attrs, matched.allow)
	if required && u.spec.CredentialIssuing {
		return res.deny(smerr.ReasonApprovalNotSupported)
	}
	res.Decision = DecisionAllow
	res.ApprovalRequired = required
	res.Quorum = quorumFor(u.target.Attrs, matched.allow)
	return res
}

func (r TargetResult) deny(reason smerr.Reason) TargetResult {
	r.Decision = DecisionDeny
	r.Reason = reason
	return r
}

// authorizationGap covers steps 4 and 5: a matched deny wins, and without a
// matched allow the default is deny. It returns "" when the actor is allowed.
func authorizationGap(m matchedRules) smerr.Reason {
	switch {
	case len(m.deny) > 0:
		return smerr.ReasonDenyRule
	case len(m.allow) == 0:
		return smerr.ReasonDefaultDeny
	}
	return ""
}

// scopesPermit is step 7: a credential with scopes can only do what a scope
// also matches. A credential without scopes is not narrowed.
func scopesPermit(actor domain.Actor, action string) bool {
	scopes := actor.Credential.Scopes
	return len(scopes) == 0 || matchesAnyAction(scopes, action)
}

// skipsApproval: step 8 does not apply to read risk, queries or governance.
func skipsApproval(spec ActionSpec, risk domain.RiskClass) bool {
	return risk == domain.RiskRead || spec.Mode == ModeQuery || spec.Mode == ModeGovernance
}

// approvalRequired is step 8. An explicit require_approval: true always
// holds; the production rule can be waived only by an explicit
// require_approval: false for human or automation actors; the high-risk and
// MCP floors are not configurable.
func approvalRequired(actor domain.Actor, risk domain.RiskClass, attrs Attributes, allow []Rule) bool {
	if slices.ContainsFunc(allow, Rule.requiresApproval) {
		return true
	}
	if risk.AtLeast(domain.RiskHigh) {
		return true
	}
	if actor.Type == domain.ActorMCP && risk.AtLeast(domain.RiskOperational) {
		return true
	}
	production := risk.AtLeast(domain.RiskOperational) && attrs.EnvironmentRisk == domain.EnvironmentProduction
	return production && !productionWaived(actor, allow)
}

func productionWaived(actor domain.Actor, allow []Rule) bool {
	mayWaive := actor.Type == domain.ActorHuman || actor.Type == domain.ActorAutomation
	return mayWaive && slices.ContainsFunc(allow, Rule.optsOutOfApproval)
}

// quorumFor is max(1, environment.approvals_required, rule approvals), bounded to 1..5.
func quorumFor(attrs Attributes, allow []Rule) int {
	q := max(minApprovals, attrs.ApprovalsRequired)
	for _, r := range allow {
		q = max(q, r.quorum())
	}
	return min(q, maxApprovals)
}

// combine is steps 9 and 10. A deny outranks capability_unavailable; approval
// is the OR and quorum the maximum over every target and sub-action.
func combine(results []TargetResult) Result {
	out := Result{Decision: DecisionAllow, PerTarget: results}
	for _, want := range []Decision{DecisionDeny, DecisionCapabilityUnavailable} {
		if i := slices.IndexFunc(results, func(r TargetResult) bool { return r.Decision == want }); i >= 0 {
			out.Decision = want
			out.Reason = results[i].Reason
			return out
		}
	}
	for _, r := range results {
		out.ApprovalRequired = out.ApprovalRequired || r.ApprovalRequired
		out.Quorum = max(out.Quorum, r.Quorum)
	}
	return out
}

func denied(reason smerr.Reason) Result {
	return Result{Decision: DecisionDeny, Reason: reason}
}

// evaluable: the system actor is not subject to policy and holds no roles, so
// it never receives an authorization from here; unknown actor types are rejected.
func evaluable(actor domain.Actor) bool {
	return actor.Type.Valid() && actor.Type != domain.ActorSystem
}
