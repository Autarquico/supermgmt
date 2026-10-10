package policy

import (
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const allowAll = `{name: all, subjects: ['*'], allow: ['*']}`

// pol builds a policy from flow-style rule lines.
func pol(t *testing.T, rules ...string) *Policy {
	t.Helper()
	text := "version: 1\nrules:\n"
	for _, r := range rules {
		text += "  - " + r + "\n"
	}
	p, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("test policy does not parse: %v\n%s", err, text)
	}
	return p
}

func actor(typ domain.ActorType, roles ...string) domain.Actor {
	return domain.Actor{ID: domain.ID("actor-" + string(typ)), Type: typ, Roles: roles}
}

func human(roles ...string) domain.Actor      { return actor(domain.ActorHuman, roles...) }
func automation(roles ...string) domain.Actor { return actor(domain.ActorAutomation, roles...) }
func mcp(roles ...string) domain.Actor        { return actor(domain.ActorMCP, roles...) }

func scoped(a domain.Actor, scopes ...string) domain.Actor {
	a.Credential.Scopes = scopes
	return a
}

func target(typ domain.ResourceType, id string, attrs Attributes, caps ...string) Target {
	return Target{Ref: domain.ResourceRef{Type: typ, ID: domain.ID(id)}, Attrs: attrs, Capabilities: NewCapabilitySet(caps...)}
}

func nodeT(attrs Attributes, caps ...string) Target {
	return target(domain.ResourceNode, "node-1", attrs, caps...)
}

var (
	prodAttrs    = Attributes{Environment: "production", EnvironmentRisk: domain.EnvironmentProduction}
	stagingAttrs = Attributes{Environment: "staging", EnvironmentRisk: domain.EnvironmentStaging}
)

type evalCase struct {
	name     string
	policy   *Policy
	req      Request
	want     Decision
	reason   smerr.Reason
	approval bool
	quorum   int
}

func runEvalCases(t *testing.T, cases []evalCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy.Evaluate(tc.req)
			if got.Decision != tc.want || got.Reason != tc.reason ||
				got.ApprovalRequired != tc.approval || got.Quorum != tc.quorum {
				t.Fatalf("got {%s reason=%q approval=%v quorum=%d}, want {%s reason=%q approval=%v quorum=%d}",
					got.Decision, got.Reason, got.ApprovalRequired, got.Quorum,
					tc.want, tc.reason, tc.approval, tc.quorum)
			}
		})
	}
}

func TestEvaluate_Step1_Catalog(t *testing.T) {
	p := pol(t, allowAll)
	runEvalCases(t, []evalCase{
		{"step1/unknown_action", p, Request{Actor: human(), Action: "node.explode", Targets: []Target{nodeT(Attributes{})}}, DecisionDeny, smerr.ReasonUnknownAction, false, 0},
		{"step1/unknown_action_even_with_bare_wildcard", p, Request{Actor: human(), Action: "", Targets: []Target{nodeT(Attributes{})}}, DecisionDeny, smerr.ReasonUnknownAction, false, 0},
		{"step1/known_action", p, Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}}, DecisionAllow, "", false, 0},
		{"step1/sub_action_is_never_invoked_directly", p, Request{Actor: human(), Action: ActionNodeBackupTemplateRun, Targets: []Target{nodeT(Attributes{}, "node.exec.template")}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step1/invalid_parameter_is_denied", p, Request{Actor: human(), Action: ActionProxmoxVMPower, Params: map[string]any{"verb": "poweroff"}, Targets: []Target{nodeT(Attributes{}, "proxmox.vm.power")}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step1/missing_required_parameter_is_denied", p, Request{Actor: human(), Action: ActionProxmoxVMPower, Targets: []Target{nodeT(Attributes{}, "proxmox.vm.power")}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step1/no_targets_is_denied", p, Request{Actor: human(), Action: "node.read"}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step1/system_actor_is_never_authorized", p, Request{Actor: actor(domain.ActorSystem), Action: "node.read", Targets: []Target{nodeT(Attributes{})}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step1/invalid_actor_type_is_denied", p, Request{Actor: actor("robot"), Action: "node.read", Targets: []Target{nodeT(Attributes{})}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step1/unknown_sub_action_is_denied", p, Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}, SubActions: []SubAction{{Action: "node.explode"}}}, DecisionDeny, smerr.ReasonUnknownAction, false, 0},
		{"step1/governance_sub_action_is_denied", p, Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}, SubActions: []SubAction{{Action: ActionJobCancel}}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step1/invalid_sub_action_parameter_is_denied", p, Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}, SubActions: []SubAction{{Action: ActionProxmoxVMPower, Params: map[string]any{"verb": "x"}, Target: nodeT(Attributes{}, "proxmox.vm.power")}}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
	})
}

func TestEvaluate_Step2_Capability(t *testing.T) {
	p := pol(t, allowAll)
	noRules := pol(t)
	reboot := func(tg ...Target) Request { return Request{Actor: human(), Action: "node.reboot", Targets: tg} }
	runEvalCases(t, []evalCase{
		{"step2/capability_advertised", p, reboot(nodeT(Attributes{}, "node.reboot")), DecisionAllow, "", true, 1},
		{"step2/capability_missing", p, reboot(nodeT(Attributes{})), DecisionCapabilityUnavailable, "", false, 0},
		{"step2/other_capability_does_not_count", p, reboot(nodeT(Attributes{}, "node.shutdown")), DecisionCapabilityUnavailable, "", false, 0},
		{"step2/nil_capability_set", p, reboot(Target{Ref: domain.ResourceRef{Type: domain.ResourceNode, ID: "n"}}), DecisionCapabilityUnavailable, "", false, 0},
		{"step2/checked_before_policy", noRules, reboot(nodeT(Attributes{})), DecisionCapabilityUnavailable, "", false, 0},
		{"step2/no_capability_required", p, Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}}, DecisionAllow, "", false, 0},
		{"step2/one_target_lacking_capability", p, reboot(nodeT(Attributes{}, "node.reboot"), nodeT(Attributes{})), DecisionCapabilityUnavailable, "", false, 0},
		{
			"step2/deny_outranks_capability_unavailable", pol(t, `{name: r, subjects: ['*'], resources: ['node:ok'], allow: ['*']}`),
			reboot(nodeT(Attributes{Node: "ok"}), nodeT(Attributes{Node: "other"}, "node.reboot")), DecisionDeny, smerr.ReasonDefaultDeny, false, 0,
		},
	})
}

func TestEvaluate_Step3_Match(t *testing.T) {
	read := func(a domain.Actor, attrs Attributes) Request {
		return Request{Actor: a, Action: "node.read", Targets: []Target{nodeT(attrs)}}
	}
	id := human()
	runEvalCases(t, []evalCase{
		{"step3/subject_type_matches", pol(t, `{name: r, subjects: ['type:human'], allow: ['node.read']}`), read(human(), Attributes{}), DecisionAllow, "", false, 0},
		{"step3/subject_type_differs", pol(t, `{name: r, subjects: ['type:human'], allow: ['node.read']}`), read(mcp(), Attributes{}), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step3/subject_role_matches", pol(t, `{name: r, subjects: ['role:viewer'], allow: ['node.read']}`), read(human("viewer"), Attributes{}), DecisionAllow, "", false, 0},
		{"step3/subject_role_differs", pol(t, `{name: r, subjects: ['role:viewer'], allow: ['node.read']}`), read(human("operator"), Attributes{}), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{
			"step3/subject_identity_matches", pol(t, `{name: r, subjects: ['identity:0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88'], allow: ['node.read']}`),
			read(domain.Actor{ID: "0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88", Type: domain.ActorAutomation}, Attributes{}), DecisionAllow, "", false, 0,
		},
		{"step3/subject_identity_differs", pol(t, `{name: r, subjects: ['identity:0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88'], allow: ['node.read']}`), read(id, Attributes{}), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step3/subject_wildcard", pol(t, `{name: r, subjects: ['*'], allow: ['node.read']}`), read(mcp(), Attributes{}), DecisionAllow, "", false, 0},
		{"step3/resource_omitted_matches_all", pol(t, `{name: r, subjects: ['*'], allow: ['node.read']}`), read(human(), stagingAttrs), DecisionAllow, "", false, 0},
		{"step3/resource_environment", pol(t, `{name: r, subjects: ['*'], resources: ['environment:staging'], allow: ['node.read']}`), read(human(), stagingAttrs), DecisionAllow, "", false, 0},
		{"step3/resource_environment_differs", pol(t, `{name: r, subjects: ['*'], resources: ['environment:staging'], allow: ['node.read']}`), read(human(), prodAttrs), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step3/resource_tag", pol(t, `{name: r, subjects: ['*'], resources: ['tag:db'], allow: ['node.read']}`), read(human(), Attributes{Tags: []string{"web", "db"}}), DecisionAllow, "", false, 0},
		{"step3/resource_provider_node_app_are_ORed", pol(t, `{name: r, subjects: ['*'], resources: ['provider:x', 'node:n1', 'app:y'], allow: ['node.read']}`), read(human(), Attributes{Node: "n1"}), DecisionAllow, "", false, 0},
		{"step3/resource_none_of_the_entries_match", pol(t, `{name: r, subjects: ['*'], resources: ['provider:x', 'node:n1', 'app:y'], allow: ['node.read']}`), read(human(), Attributes{Node: "n2"}), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step3/resource_wildcard_entry", pol(t, `{name: r, subjects: ['*'], resources: ['*'], allow: ['node.read']}`), read(human(), Attributes{}), DecisionAllow, "", false, 0},
		{
			"step3/administrative_resource_matches_only_unscoped_rules", pol(t, `{name: r, subjects: ['*'], resources: ['environment:production'], allow: ['identity.read']}`),
			Request{Actor: human(), Action: "identity.read", Targets: []Target{target(domain.ResourceIdentity, "i", Attributes{})}},
			DecisionDeny, smerr.ReasonDefaultDeny, false, 0,
		},
		{
			"step3/administrative_resource_matches_unscoped_rule", pol(t, `{name: r, subjects: ['*'], allow: ['identity.read']}`),
			Request{Actor: human(), Action: "identity.read", Targets: []Target{target(domain.ResourceIdentity, "i", Attributes{})}},
			DecisionAllow, "", false, 0,
		},
		{"step3/wildcard_action_one_segment", pol(t, `{name: r, subjects: ['*'], allow: ['*.read']}`), read(human(), Attributes{}), DecisionAllow, "", false, 0},
		{
			"step3/wildcard_does_not_cross_segments", pol(t, `{name: r, subjects: ['*'], allow: ['*.read']}`),
			Request{Actor: human(), Action: "service.logs", Targets: []Target{target(domain.ResourceService, "s", Attributes{}, "service.logs")}},
			DecisionDeny, smerr.ReasonDefaultDeny, false, 0,
		},
		// Validation rejects "proxmox.*" (it matches no catalog action), so the engine boundary is exercised with an unvalidated rule.
		{
			"step3/wildcard_prefix_does_not_match_deeper_action", &Policy{rules: []Rule{{Name: "r", Subjects: []string{"*"}, Allow: []string{"proxmox.*"}}}},
			Request{Actor: human(), Action: ActionProxmoxVMPower, Params: map[string]any{"verb": "start"}, Targets: []Target{nodeT(Attributes{}, "proxmox.vm.power")}},
			DecisionDeny, smerr.ReasonDefaultDeny, false, 0,
		},
		{"step3/bare_wildcard_matches_any_action", pol(t, allowAll), read(human(), Attributes{}), DecisionAllow, "", false, 0},
	})
}

func TestEvaluate_Step4_DenyOverrides(t *testing.T) {
	read := func(attrs Attributes) Request {
		return Request{Actor: human("viewer"), Action: "node.read", Targets: []Target{nodeT(attrs)}}
	}
	runEvalCases(t, []evalCase{
		{
			"step4/deny_beats_allow_in_other_rule", pol(t,
				`{name: a, subjects: ['*'], allow: ['*']}`, `{name: d, subjects: ['role:viewer'], deny: ['node.read']}`),
			read(Attributes{}), DecisionDeny, smerr.ReasonDenyRule, false, 0,
		},
		{
			"step4/deny_beats_allow_in_same_rule", pol(t, `{name: a, subjects: ['*'], allow: ['*'], deny: ['node.read']}`),
			read(Attributes{}), DecisionDeny, smerr.ReasonDenyRule, false, 0,
		},
		{
			"step4/deny_order_is_irrelevant", pol(t,
				`{name: d, subjects: ['role:viewer'], deny: ['node.read']}`, `{name: a, subjects: ['*'], allow: ['*']}`),
			read(Attributes{}), DecisionDeny, smerr.ReasonDenyRule, false, 0,
		},
		{
			"step4/deny_for_other_subject_does_not_apply", pol(t,
				`{name: a, subjects: ['*'], allow: ['*']}`, `{name: d, subjects: ['role:admin'], deny: ['node.read']}`),
			read(Attributes{}), DecisionAllow, "", false, 0,
		},
		{
			"step4/deny_for_other_resource_does_not_apply", pol(t,
				`{name: a, subjects: ['*'], allow: ['*']}`, `{name: d, subjects: ['*'], resources: ['environment:production'], deny: ['node.read']}`),
			read(stagingAttrs), DecisionAllow, "", false, 0,
		},
		{
			"step4/deny_for_matching_resource_applies", pol(t,
				`{name: a, subjects: ['*'], allow: ['*']}`, `{name: d, subjects: ['*'], resources: ['environment:production'], deny: ['node.read']}`),
			read(prodAttrs), DecisionDeny, smerr.ReasonDenyRule, false, 0,
		},
		{
			"step4/deny_for_other_action_does_not_apply", pol(t,
				`{name: a, subjects: ['*'], allow: ['*']}`, `{name: d, subjects: ['*'], deny: ['node.shutdown']}`),
			read(Attributes{}), DecisionAllow, "", false, 0,
		},
		{
			"step4/deny_wildcard", pol(t,
				`{name: a, subjects: ['*'], allow: ['*']}`, `{name: d, subjects: ['*'], deny: ['*.read']}`),
			read(Attributes{}), DecisionDeny, smerr.ReasonDenyRule, false, 0,
		},
	})
}

func TestEvaluate_Step5_DefaultDeny(t *testing.T) {
	read := Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}}
	runEvalCases(t, []evalCase{
		{"step5/empty_policy_denies", pol(t), read, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step5/allow_for_another_action_denies", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot']}`), read, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{
			"step5/automation_has_nothing_by_default", func() *Policy { p, _ := Default(); return p }(),
			Request{Actor: automation(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}},
			DecisionDeny, smerr.ReasonDefaultDeny, false, 0,
		},
		{"step5/allow_present_allows", pol(t, `{name: r, subjects: ['*'], allow: ['node.read']}`), read, DecisionAllow, "", false, 0},
	})
}

func TestEvaluate_Step6_DestructiveGate(t *testing.T) {
	remove := func(a domain.Actor) Request {
		return Request{Actor: a, Action: "node.remove", Targets: []Target{nodeT(Attributes{})}}
	}
	runEvalCases(t, []evalCase{
		{"step6/destructive_without_flag_is_denied", pol(t, `{name: r, subjects: ['*'], allow: ['node.remove']}`), remove(human()), DecisionDeny, smerr.ReasonDestructiveGate, false, 0},
		{"step6/destructive_with_flag_is_allowed_and_needs_approval", pol(t, `{name: r, subjects: ['*'], allow: ['node.remove'], allow_destructive: true}`), remove(human()), DecisionAllow, "", true, 1},
		{
			"step6/flag_on_a_rule_that_does_not_match_the_action_does_not_count", pol(t,
				`{name: r, subjects: ['*'], allow: ['node.remove']}`, `{name: f, subjects: ['*'], allow: ['provider.delete'], allow_destructive: true}`),
			remove(human()), DecisionDeny, smerr.ReasonDestructiveGate, false, 0,
		},
		{
			"step6/flag_on_a_rule_for_another_subject_does_not_count", pol(t,
				`{name: r, subjects: ['*'], allow: ['node.remove']}`, `{name: f, subjects: ['role:admin'], allow: ['node.remove'], allow_destructive: true}`),
			remove(human("operator")), DecisionDeny, smerr.ReasonDestructiveGate, false, 0,
		},
		{
			"step6/flag_on_one_of_several_matching_rules_suffices", pol(t,
				`{name: r, subjects: ['*'], allow: ['node.remove']}`, `{name: f, subjects: ['*'], allow: ['node.*'], allow_destructive: true}`),
			remove(human()), DecisionAllow, "", true, 1,
		},
		{
			"step6/flag_is_irrelevant_for_non_destructive", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot']}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{}, "node.reboot")}},
			DecisionAllow, "", true, 1,
		},
		{
			"step6/destructive_sub_action_is_gated", pol(t, `{name: r, subjects: ['*'], allow: ['deployment.create', 'proxmox.snapshot.delete']}`),
			Request{
				Actor: human(), Action: "deployment.create", Targets: []Target{target(domain.ResourceAppTarget, "t", Attributes{}, "docker.compose.deploy")},
				SubActions: []SubAction{{Action: "proxmox.snapshot.delete", Target: nodeT(Attributes{}, "proxmox.snapshot.create")}},
			},
			DecisionDeny, smerr.ReasonDestructiveGate, false, 0,
		},
	})
}

func TestEvaluate_Step7_CredentialScopes(t *testing.T) {
	p := pol(t, allowAll)
	read := func(a domain.Actor, action string) Request {
		return Request{Actor: a, Action: action, Targets: []Target{nodeT(Attributes{})}}
	}
	runEvalCases(t, []evalCase{
		{"step7/no_scopes_do_not_narrow", p, read(human(), "node.read"), DecisionAllow, "", false, 0},
		{"step7/scope_covers_action", p, read(scoped(human(), "node.read"), "node.read"), DecisionAllow, "", false, 0},
		{"step7/scope_wildcard_covers_action", p, read(scoped(human(), "*.read"), "node.read"), DecisionAllow, "", false, 0},
		{"step7/action_outside_scopes_is_denied", p, read(scoped(human(), "service.read"), "node.read"), DecisionDeny, smerr.ReasonScopeDenied, false, 0},
		{"step7/any_one_scope_suffices", p, read(scoped(human(), "service.read", "node.read"), "node.read"), DecisionAllow, "", false, 0},
		{"step7/scopes_never_widen_policy", pol(t), read(scoped(human(), "*"), "node.read"), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{
			"step7/scope_checked_for_sub_actions_too", pol(t, allowAll),
			Request{
				Actor: scoped(human(), "deployment.create"), Action: "deployment.create", Targets: []Target{target(domain.ResourceAppTarget, "t", Attributes{}, "docker.compose.deploy")},
				SubActions: []SubAction{{Action: ActionSnapshotCreate, Target: nodeT(Attributes{}, "proxmox.snapshot.create")}},
			},
			DecisionDeny, smerr.ReasonScopeDenied, false, 0,
		},
	})
}

func TestEvaluate_Step8_Approval(t *testing.T) {
	restart := func(a domain.Actor, attrs Attributes) Request {
		return Request{Actor: a, Action: "service.restart", Targets: []Target{target(domain.ResourceService, "s", attrs, "service.restart")}}
	}
	optOut := `{name: o, subjects: ['*'], allow: ['service.restart'], require_approval: false}`
	plain := `{name: p, subjects: ['*'], allow: ['service.restart']}`
	runEvalCases(t, []evalCase{
		{
			"step8/read_never_needs_approval", pol(t, `{name: r, subjects: ['*'], allow: ['node.read'], require_approval: true, approvals: 3}`),
			Request{Actor: mcp(), Action: "node.read", Targets: []Target{nodeT(prodAttrs)}},
			DecisionAllow, "", false, 0,
		},
		{
			"step8/read_risk_job_skips_approval", pol(t, `{name: r, subjects: ['*'], allow: ['node.probe'], require_approval: true}`),
			Request{Actor: human(), Action: "node.probe", Targets: []Target{nodeT(prodAttrs, "node.read")}},
			DecisionAllow, "", false, 0,
		},
		{"step8/operational_outside_production_needs_none", pol(t, plain), restart(human(), stagingAttrs), DecisionAllow, "", false, 1},
		{"step8/rule_require_approval_true", pol(t, `{name: r, subjects: ['*'], allow: ['service.restart'], require_approval: true}`), restart(human(), stagingAttrs), DecisionAllow, "", true, 1},
		{"step8/rule_require_approval_true_beats_optout_in_other_rule", pol(t, optOut, `{name: r, subjects: ['*'], allow: ['service.restart'], require_approval: true}`), restart(human(), prodAttrs), DecisionAllow, "", true, 1},
		{"step8/production_operational_needs_approval", pol(t, plain), restart(human(), prodAttrs), DecisionAllow, "", true, 1},
		{"step8/production_optout_human", pol(t, optOut), restart(human(), prodAttrs), DecisionAllow, "", false, 1},
		{"step8/production_optout_automation", pol(t, optOut), restart(automation(), prodAttrs), DecisionAllow, "", false, 1},
		{"step8/production_optout_does_not_apply_to_mcp", pol(t, optOut), restart(mcp(), prodAttrs), DecisionAllow, "", true, 1},
		{
			"step8/production_optout_must_be_a_matched_rule", pol(t, plain, `{name: o, subjects: ['*'], resources: ['environment:staging'], allow: ['service.restart'], require_approval: false}`),
			restart(human(), prodAttrs), DecisionAllow, "", true, 1,
		},
		{
			"step8/production_optout_from_rule_for_another_subject_is_ignored", pol(t, plain, `{name: o, subjects: ['role:admin'], allow: ['service.restart'], require_approval: false}`),
			restart(human("operator"), prodAttrs), DecisionAllow, "", true, 1,
		},
		{"step8/unset_require_approval_does_not_opt_out", pol(t, plain, `{name: u, subjects: ['*'], allow: ['service.restart']}`), restart(human(), prodAttrs), DecisionAllow, "", true, 1},
		{
			"step8/high_floor_even_with_optout", pol(t, `{name: o, subjects: ['*'], allow: ['node.reboot'], require_approval: false}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(stagingAttrs, "node.reboot")}},
			DecisionAllow, "", true, 1,
		},
		{
			"step8/high_floor_in_production_even_with_optout", pol(t, `{name: o, subjects: ['*'], allow: ['node.reboot'], require_approval: false}`),
			Request{Actor: automation(), Action: "node.reboot", Targets: []Target{nodeT(prodAttrs, "node.reboot")}},
			DecisionAllow, "", true, 1,
		},
		{"step8/mcp_floor_operational_in_development", pol(t, optOut), restart(mcp(), Attributes{EnvironmentRisk: domain.EnvironmentDevelopment}), DecisionAllow, "", true, 1},
		{"step8/mcp_floor_ignores_optout_without_environment", pol(t, optOut), restart(mcp(), Attributes{}), DecisionAllow, "", true, 1},
		{"step8/human_operational_without_environment_needs_none", pol(t, plain), restart(human(), Attributes{}), DecisionAllow, "", false, 1},
		{
			"step8/param_derived_risk_start_is_operational", pol(t, `{name: r, subjects: ['*'], allow: ['proxmox.vm.power']}`),
			Request{Actor: human(), Action: ActionProxmoxVMPower, Params: map[string]any{"verb": "start"}, Targets: []Target{nodeT(stagingAttrs, "proxmox.vm.power")}},
			DecisionAllow, "", false, 1,
		},
		{
			"step8/param_derived_risk_stop_is_high", pol(t, `{name: r, subjects: ['*'], allow: ['proxmox.vm.power']}`),
			Request{Actor: human(), Action: ActionProxmoxVMPower, Params: map[string]any{"verb": "stop"}, Targets: []Target{nodeT(stagingAttrs, "proxmox.vm.power")}},
			DecisionAllow, "", true, 1,
		},
		{
			"step8/param_derived_risk_reboot_in_production_needs_approval", pol(t, `{name: r, subjects: ['*'], allow: ['proxmox.vm.power']}`),
			Request{Actor: human(), Action: ActionProxmoxVMPower, Params: map[string]any{"verb": "reboot"}, Targets: []Target{nodeT(prodAttrs, "proxmox.vm.power")}},
			DecisionAllow, "", true, 1,
		},
		{
			"step8/quorum_defaults_to_one", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot']}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{}, "node.reboot")}},
			DecisionAllow, "", true, 1,
		},
		{
			"step8/quorum_from_rule", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot'], approvals: 2}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{}, "node.reboot")}},
			DecisionAllow, "", true, 2,
		},
		{
			"step8/quorum_from_environment", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot']}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{ApprovalsRequired: 3}, "node.reboot")}},
			DecisionAllow, "", true, 3,
		},
		{
			"step8/quorum_is_max_of_environment_and_rules", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot'], approvals: 2}`, `{name: s, subjects: ['*'], allow: ['node.*'], approvals: 4}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{ApprovalsRequired: 3}, "node.reboot")}},
			DecisionAllow, "", true, 4,
		},
		{
			"step8/quorum_ignores_rules_that_do_not_match", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot']}`, `{name: s, subjects: ['role:admin'], allow: ['node.reboot'], approvals: 5}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{}, "node.reboot")}},
			DecisionAllow, "", true, 1,
		},
		{
			"step8/quorum_bounded_to_five", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot']}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{ApprovalsRequired: 9}, "node.reboot")}},
			DecisionAllow, "", true, 5,
		},
		{
			"step8/quorum_negative_environment_value_is_floored_to_one", pol(t, `{name: r, subjects: ['*'], allow: ['node.reboot']}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{ApprovalsRequired: -3}, "node.reboot")}},
			DecisionAllow, "", true, 1,
		},
	})
}

func TestEvaluate_Step8_CredentialIssuingIsNeverApprovalGated(t *testing.T) {
	issue := func(a domain.Actor) Request {
		return Request{Actor: a, Action: "token.create", Targets: []Target{target(domain.ResourceIdentity, "i", Attributes{})}}
	}
	boolPtr := func(b bool) *bool { return &b }
	// Validation rejects require_approval: true here, so the runtime guard is
	// exercised with a policy built around the validator.
	forced := &Policy{rules: []Rule{{Name: "r", Subjects: []string{"*"}, Allow: []string{"token.create"}, RequireApproval: boolPtr(true)}}}
	runEvalCases(t, []evalCase{
		{"step8/credential_issuing_human_is_allowed_without_approval", pol(t, `{name: r, subjects: ['*'], allow: ['token.create']}`), issue(human()), DecisionAllow, "", false, 1},
		{"step8/credential_issuing_with_forced_require_approval_is_denied", forced, issue(human()), DecisionDeny, smerr.ReasonApprovalNotSupported, false, 0},
		{"step8/credential_issuing_mcp_floor_is_denied", pol(t, `{name: r, subjects: ['*'], allow: ['token.create']}`), issue(mcp()), DecisionDeny, smerr.ReasonApprovalNotSupported, false, 0},
		{
			"step8/register_is_approval_gated_as_high", pol(t, `{name: r, subjects: ['*'], allow: ['mcp_client.register']}`),
			Request{Actor: human(), Action: "mcp_client.register", Targets: []Target{target(domain.ResourceIdentity, "i", Attributes{})}},
			DecisionAllow, "", true, 1,
		},
	})
}

func TestEvaluate_Step9_CompositePlans(t *testing.T) {
	deploy := target(domain.ResourceAppTarget, "t", stagingAttrs, "docker.compose.deploy")
	snapshot := SubAction{Action: ActionSnapshotCreate, Target: nodeT(stagingAttrs, "proxmox.snapshot.create")}
	template := SubAction{Action: ActionNodeBackupTemplateRun, Target: nodeT(stagingAttrs, "node.exec.template")}
	plan := func(a domain.Actor, subs ...SubAction) Request {
		return Request{Actor: a, Action: "deployment.create", Targets: []Target{deploy}, SubActions: subs}
	}
	const deployRule = `{name: d, subjects: ['*'], allow: ['deployment.create']}`
	runEvalCases(t, []evalCase{
		{"step9/main_only", pol(t, deployRule), plan(human()), DecisionAllow, "", false, 1},
		{"step9/all_allowed", pol(t, deployRule, `{name: s, subjects: ['*'], allow: ['proxmox.snapshot.create', 'node.backup_template.run']}`), plan(human(), snapshot, template), DecisionAllow, "", false, 1},
		{"step9/one_sub_action_denied_denies_the_plan", pol(t, deployRule, `{name: s, subjects: ['*'], allow: ['proxmox.snapshot.create']}`), plan(human(), snapshot, template), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step9/explicit_deny_on_sub_action_denies_the_plan", pol(t, allowAll, `{name: x, subjects: ['*'], deny: ['proxmox.snapshot.create']}`), plan(human(), snapshot), DecisionDeny, smerr.ReasonDenyRule, false, 0},
		{"step9/main_denied_while_sub_actions_allowed", pol(t, `{name: s, subjects: ['*'], allow: ['proxmox.snapshot.create']}`), plan(human(), snapshot), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"step9/sub_action_capability_missing", pol(t, allowAll), plan(human(), SubAction{Action: ActionSnapshotCreate, Target: nodeT(stagingAttrs)}), DecisionCapabilityUnavailable, "", false, 0},
		{"step9/approval_is_OR_over_sub_actions", pol(t, deployRule, `{name: s, subjects: ['*'], allow: ['proxmox.snapshot.create'], require_approval: true}`), plan(human(), snapshot), DecisionAllow, "", true, 1},
		{
			"step9/approval_from_sub_action_target_in_production", pol(t, deployRule, `{name: s, subjects: ['*'], allow: ['proxmox.snapshot.create']}`),
			plan(human(), SubAction{Action: ActionSnapshotCreate, Target: nodeT(prodAttrs, "proxmox.snapshot.create")}), DecisionAllow, "", true, 1,
		},
		{
			"step9/quorum_is_max_over_sub_actions", pol(t, deployRule, `{name: s, subjects: ['*'], allow: ['proxmox.snapshot.create'], approvals: 3}`, `{name: t, subjects: ['*'], allow: ['node.backup_template.run'], approvals: 2}`),
			plan(human(), snapshot, template), DecisionAllow, "", false, 3,
		},
		{
			"step9/quorum_is_max_over_targets", pol(t, `{name: d, subjects: ['*'], allow: ['node.reboot']}`),
			Request{Actor: human(), Action: "node.reboot", Targets: []Target{nodeT(Attributes{ApprovalsRequired: 2}, "node.reboot"), nodeT(Attributes{ApprovalsRequired: 4}, "node.reboot")}},
			DecisionAllow, "", true, 4,
		},
		{
			"step9/one_denied_target_denies_all", pol(t, `{name: d, subjects: ['*'], resources: ['environment:staging'], allow: ['node.read']}`),
			Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(stagingAttrs), nodeT(prodAttrs)}},
			DecisionDeny, smerr.ReasonDefaultDeny, false, 0,
		},
		{
			"step9/all_targets_allowed", pol(t, `{name: d, subjects: ['*'], allow: ['node.read']}`),
			Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(stagingAttrs), nodeT(prodAttrs)}},
			DecisionAllow, "", false, 0,
		},
	})
}

func TestEvaluate_Step10_PerTargetResult(t *testing.T) {
	p := pol(t,
		`{name: allow-staging, subjects: ['*'], resources: ['environment:staging'], allow: ['node.reboot']}`,
		`{name: deny-prod, subjects: ['*'], resources: ['environment:production'], deny: ['node.reboot']}`,
		`{name: unrelated, subjects: ['role:admin'], allow: ['node.reboot']}`)
	staging := target(domain.ResourceNode, "n-staging", stagingAttrs, "node.reboot")
	production := target(domain.ResourceNode, "n-prod", prodAttrs, "node.reboot")
	got := p.Evaluate(Request{Actor: human(), Action: "node.reboot", Targets: []Target{staging, production}})
	if got.Decision != DecisionDeny || len(got.PerTarget) != 2 {
		t.Fatalf("got %+v", got)
	}
	first, second := got.PerTarget[0], got.PerTarget[1]
	if first.Ref != staging.Ref || first.Decision != DecisionAllow || !first.ApprovalRequired || first.Quorum != 1 ||
		!slices.Equal(first.MatchedRules, []string{"allow-staging"}) {
		t.Errorf("staging result = %+v", first)
	}
	if second.Ref != production.Ref || second.Decision != DecisionDeny || second.Reason != smerr.ReasonDenyRule ||
		!slices.Equal(second.MatchedRules, []string{"deny-prod"}) {
		t.Errorf("production result = %+v", second)
	}
}

func TestEvaluate_DefaultPolicy_EndToEnd(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	restart := func(a domain.Actor, attrs Attributes) Request {
		return Request{Actor: a, Action: "service.restart", Targets: []Target{target(domain.ResourceService, "s", attrs, "service.restart")}}
	}
	runEvalCases(t, []evalCase{
		{"default/viewer_cannot_restart", p, restart(human("viewer"), Attributes{}), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"default/operator_restarts_in_staging", p, restart(human("operator"), stagingAttrs), DecisionAllow, "", false, 1},
		{"default/operator_restart_in_production_needs_approval", p, restart(human("operator"), prodAttrs), DecisionAllow, "", true, 1},
		{"default/admin_may_write_config_with_approval", p, Request{Actor: human("admin"), Action: "config.write", Targets: []Target{target(domain.ResourceInstance, "i", Attributes{})}}, DecisionAllow, "", true, 1},
		{"default/mcp_reads", p, Request{Actor: mcp(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}}, DecisionAllow, "", false, 0},
		{"default/mcp_cannot_restart", p, restart(mcp(), Attributes{}), DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"default/automation_gets_nothing", p, Request{Actor: automation(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}}, DecisionDeny, smerr.ReasonDefaultDeny, false, 0},
		{"default/plan_create_for_viewer", p, Request{Actor: human("viewer"), Action: "plan.create", Targets: []Target{nodeT(Attributes{})}}, DecisionAllow, "", false, 0},
		{"default/destructive_is_gated_for_admin", p, Request{Actor: human("admin"), Action: "node.remove", Targets: []Target{nodeT(Attributes{})}}, DecisionDeny, smerr.ReasonDestructiveGate, false, 0},
	})
}

func TestEvaluate_ReasonIsOneOfTheDeclaredReasons(t *testing.T) {
	p := pol(t)
	got := p.Evaluate(Request{Actor: human(), Action: "node.read", Targets: []Target{nodeT(Attributes{})}})
	if !slices.Contains(smerr.Reasons(), got.Reason) {
		t.Fatalf("reason %q is not declared", got.Reason)
	}
	if code := smerr.CodeFor(got.Reason); code != smerr.CodePolicyDenied {
		t.Fatalf("code = %s", code)
	}
}
