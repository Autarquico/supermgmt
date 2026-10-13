package app

import (
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

var (
	mcpActor   = domain.Actor{ID: "mcp-1", Type: domain.ActorMCP}
	humanActor = domain.Actor{ID: "human-1", Type: domain.ActorHuman}
)

func everythingAllowed(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte("version: 1\nrules:\n  - {name: all, subjects: ['type:mcp', 'type:human'], allow: ['*']}\n"))
	mustf(t, err, "Parse")
	return p
}

func gateCore(t *testing.T, writes bool) core {
	t.Helper()
	f := newFixture(t, func(c *Config) {
		c.MCPWritesEnabled = writes
		c.Policy = everythingAllowed(t)
	})
	c, err := newCore(f.cfg)
	mustf(t, err, "newCore")
	return c
}

func wantDenied(t *testing.T, res policy.Result, reason smerr.Reason, what string) {
	t.Helper()
	if res.Decision != policy.DecisionDeny || res.Reason != reason {
		t.Errorf("%s: got %s/%s, want deny/%s", what, res.Decision, res.Reason, reason)
	}
}

func TestMCPWritesOff_EveryNonQueryActionIsDenied(t *testing.T) {
	c := gateCore(t, false)
	for _, spec := range policy.Catalog() {
		res := c.authorize(policy.Request{Actor: mcpActor, Action: spec.Name})
		switch {
		case mcpForbids(spec.Name):
			wantDenied(t, res, smerr.ReasonMCPActionForbidden, spec.Name)
		case spec.Mode == policy.ModeQuery:
			if res.Reason == smerr.ReasonMCPWritesDisabled || res.Reason == smerr.ReasonMCPActionForbidden {
				t.Errorf("%s is a query but was gated: %s", spec.Name, res.Reason)
			}
		default:
			wantDenied(t, res, smerr.ReasonMCPWritesDisabled, spec.Name)
		}
	}
}

func TestMCPWritesOff_HumansAreUnaffected(t *testing.T) {
	c := gateCore(t, false)
	for _, spec := range policy.Catalog() {
		if _, gated := c.mcpGate(humanActor, spec.Name); gated {
			t.Errorf("%s: a human was gated", spec.Name)
		}
		if res := c.authorize(policy.Request{Actor: humanActor, Action: spec.Name}); res.Reason == smerr.ReasonMCPWritesDisabled {
			t.Errorf("%s: a human got %s", spec.Name, res.Reason)
		}
	}
}

func TestMCPForbiddenSet_HoldsWithWritesOnAndAWildcardGrant(t *testing.T) {
	c := gateCore(t, true)
	forbidden := []string{"token.create", "mcp_client.issue_token", "enrollment.create", "mcp_client.register", "mcp_client.delete", "identity.write", "role_binding.write"}
	for _, spec := range policy.Catalog() {
		if spec.CredentialIssuing && !slices.Contains(forbidden, spec.Name) {
			t.Errorf("credential action %s is not in the expectation: extend it deliberately", spec.Name)
		}
	}
	for _, action := range forbidden {
		wantDenied(t, c.authorize(policy.Request{Actor: mcpActor, Action: action}), smerr.ReasonMCPActionForbidden, action)
		wantDenied(t, c.authorize(policy.Request{
			Actor: mcpActor, Action: "plan.create", SubActions: []policy.SubAction{{Action: action}},
		}), smerr.ReasonMCPActionForbidden, "sub-action "+action)
	}
}

func TestMCPWritesOn_OrdinaryWritesGoToPolicy(t *testing.T) {
	c := gateCore(t, true)

	if res, gated := c.mcpGate(mcpActor, "node.reboot", "service.restart"); gated {
		t.Errorf("writes on: gated with %s", res.Reason)
	}
}

func TestMCPGovernance_IsGatedLikeEveryOtherWrite(t *testing.T) {
	target := []policy.Target{{Ref: domain.ResourceRef{Type: domain.ResourceNode, ID: "n"}}}
	off := gateCore(t, false)
	on := gateCore(t, true)

	wantDenied(t, off.authorizeGovernanceOn(mcpActor, policy.ActionJobCancel, target, nil), smerr.ReasonMCPWritesDisabled, "job.cancel, writes off")
	if res := on.authorizeGovernanceOn(mcpActor, policy.ActionJobCancel, target, nil); res.Reason == smerr.ReasonMCPWritesDisabled {
		t.Errorf("writes on: job.cancel still gated")
	}
	for _, c := range []core{off, on} {
		wantDenied(t, c.authorizeGovernanceOn(mcpActor, policy.ActionApprovalGrant, target, nil), smerr.ReasonDefaultDeny, "approval.grant stays never-approve")
	}
}
