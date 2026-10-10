package policy

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

type govCase struct {
	name    string
	policy  *Policy
	actor   domain.Actor
	action  string
	targets []Target
	subs    []SubAction
	want    Decision
	reason  smerr.Reason
}

func runGovernanceCases(t *testing.T, cases []govCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy.EvaluateGovernance(tc.actor, tc.action, tc.targets, tc.subs)
			if got.Decision != tc.want || got.Reason != tc.reason {
				t.Fatalf("got {%s reason=%q}, want {%s reason=%q}", got.Decision, got.Reason, tc.want, tc.reason)
			}
			if got.ApprovalRequired || got.Quorum != 0 {
				t.Fatalf("governance is never approval-gated: %+v", got)
			}
		})
	}
}

func TestEvaluateGovernance(t *testing.T) {
	approver := `{name: ap, subjects: ['role:operator'], allow: ['approval.grant', 'approval.reject']}`
	stagingNode := nodeT(stagingAttrs)  // no capabilities advertised on purpose
	prodNode := nodeT(prodAttrs)        // governance needs no capability
	snapshotNode := nodeT(stagingAttrs) // sub-action target
	stagingOnly := `{name: ap, subjects: ['role:operator'], resources: ['environment:staging'], allow: ['approval.grant']}`
	runGovernanceCases(t, []govCase{
		{"governance/allowed_approver", pol(t, approver), human("operator"), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionAllow, ""},
		{"governance/reject_allowed_too", pol(t, approver), human("operator"), ActionApprovalReject, []Target{stagingNode}, nil, DecisionAllow, ""},
		{"governance/no_rule_means_default_deny", pol(t), human("operator"), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/wrong_role", pol(t, approver), human("viewer"), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/must_be_allowed_for_every_target", pol(t, stagingOnly), human("operator"), ActionApprovalGrant, []Target{stagingNode, prodNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{
			"governance/must_be_allowed_for_every_sub_action_target", pol(t, stagingOnly), human("operator"), ActionApprovalGrant,
			[]Target{stagingNode},
			[]SubAction{{Action: ActionSnapshotCreate, Target: prodNode}},
			DecisionDeny, smerr.ReasonDefaultDeny,
		},
		{
			"governance/allowed_for_all_sub_action_targets", pol(t, stagingOnly), human("operator"), ActionApprovalGrant,
			[]Target{stagingNode},
			[]SubAction{{Action: ActionSnapshotCreate, Target: snapshotNode}},
			DecisionAllow, "",
		},
		{"governance/deny_overrides", pol(t, approver, `{name: d, subjects: ['*'], deny: ['approval.grant']}`), human("operator"), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDenyRule},
		{
			"governance/no_capability_check_even_for_high_risk_sub_action", pol(t, approver), human("operator"), ActionApprovalGrant,
			[]Target{stagingNode},
			[]SubAction{{Action: "node.reboot", Target: nodeT(prodAttrs)}},
			DecisionAllow, "",
		},
		{
			"governance/never_approval_gated_in_production", pol(t, `{name: ap, subjects: ['*'], allow: ['approval.grant'], require_approval: true, approvals: 3}`),
			human(), ActionApprovalGrant,
			[]Target{prodNode},
			nil, DecisionAllow, "",
		},
		{"governance/mcp_can_never_grant", pol(t, allowAll), mcp(), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/mcp_can_never_reject", pol(t, allowAll), mcp(), ActionApprovalReject, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/system_can_never_grant", pol(t, allowAll), actor(domain.ActorSystem), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/system_can_never_reject", pol(t, allowAll), actor(domain.ActorSystem), ActionApprovalReject, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/automation_without_explicit_rule_is_denied", pol(t, approver), automation(), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/automation_with_explicit_rule_is_allowed", pol(t, `{name: ci, subjects: ['type:automation'], allow: ['approval.grant']}`), automation(), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionAllow, ""},
		{"governance/mcp_job_cancel_follows_the_rules", pol(t, `{name: m, subjects: ['type:mcp'], allow: ['job.cancel']}`), mcp(), ActionJobCancel, []Target{target(domain.ResourceJob, "j", Attributes{})}, nil, DecisionAllow, ""},
		{"governance/job_resolve_default_deny", pol(t), human("operator"), ActionJobResolve, []Target{target(domain.ResourceJob, "j", Attributes{})}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/scope_narrows", pol(t, approver), scoped(human("operator"), "approval.reject"), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonScopeDenied},
		{"governance/scope_permits", pol(t, approver), scoped(human("operator"), "approval.*"), ActionApprovalGrant, []Target{stagingNode}, nil, DecisionAllow, ""},
		{"governance/non_governance_action_is_refused", pol(t, allowAll), human(), "node.read", []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/unknown_action", pol(t, allowAll), human(), "approval.revoke", []Target{stagingNode}, nil, DecisionDeny, smerr.ReasonUnknownAction},
		{"governance/unknown_sub_action", pol(t, allowAll), human(), ActionApprovalGrant, []Target{stagingNode}, []SubAction{{Action: "node.explode"}}, DecisionDeny, smerr.ReasonUnknownAction},
		{"governance/governance_sub_action_is_refused", pol(t, allowAll), human(), ActionApprovalGrant, []Target{stagingNode}, []SubAction{{Action: ActionJobCancel}}, DecisionDeny, smerr.ReasonDefaultDeny},
		{"governance/no_targets", pol(t, allowAll), human(), ActionApprovalGrant, nil, nil, DecisionDeny, smerr.ReasonDefaultDeny},
	})
}

func TestEvaluate_RoutesGovernanceActionsToGovernanceRules(t *testing.T) {
	p := pol(t, allowAll)
	got := p.Evaluate(Request{Actor: mcp(), Action: ActionApprovalGrant, Targets: []Target{nodeT(Attributes{})}})
	if got.Decision != DecisionDeny {
		t.Fatalf("mcp approving through Evaluate must be denied, got %+v", got)
	}
	got = p.Evaluate(Request{Actor: human(), Action: ActionJobCancel, Targets: []Target{target(domain.ResourceJob, "j", prodAttrs)}})
	if got.Decision != DecisionAllow || got.ApprovalRequired {
		t.Fatalf("human cancel through Evaluate = %+v", got)
	}
}
