package app

import (
	"slices"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

// mcpForbiddenActions are denied to an mcp actor on top of every action that
// issues a credential: an MCP bearer must never mint or reshape an identity
// whose lifecycle is independent of its source client (ADR-0032), nor open an
// interactive node session (no exec tools in V1, spec §24), nor resolve an
// interrupted job, which is human judgment over ambiguous evidence (§20.4),
// nor delete a snapshot, which is unrecoverable.
var mcpForbiddenActions = []string{"mcp_client.register", "mcp_client.delete", "identity.write", "role_binding.write", "node.connect", "job.resolve", "proxmox.snapshot.delete"}

// mcpUnplannableUntilNodeTools are job actions an MCP client cannot plan yet:
// node setup is added with the node tools.
var mcpUnplannableUntilNodeTools = []string{policy.ActionNodeSetup, policy.ActionSudoersWrite, policy.ActionLogBrokerInstall}

// mcpGate is the check that runs before policy for an mcp actor: the forbidden
// set holds whatever the policy grants, and while writes are disabled only
// queries pass. It reports false when policy may decide.
func (c core) mcpGate(actor domain.Actor, actions ...string) (policy.Result, bool) {
	if actor.Type != domain.ActorMCP {
		return policy.Result{}, false
	}
	if slices.ContainsFunc(actions, mcpForbids) {
		return policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonMCPActionForbidden}, true
	}
	if c.cfg.MCPWritesEnabled || !slices.ContainsFunc(actions, isNotQuery) {
		return policy.Result{}, false
	}
	return policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonMCPWritesDisabled}, true
}

// PlannableByMCP lists the actions an MCP client may ask to plan: the job
// actions the gate does not forbid and that are not destructive. It is the
// gate's own predicate, so a listing cannot promise what the gate refuses.
func PlannableByMCP() []policy.ActionSpec {
	var out []policy.ActionSpec
	for _, spec := range policy.Catalog() {
		if spec.Mode == policy.ModeJob && spec.Risk != domain.RiskDestructive &&
			!mcpForbids(spec.Name) && !slices.Contains(mcpUnplannableUntilNodeTools, spec.Name) {
			out = append(out, spec)
		}
	}
	return out
}

func mcpForbids(action string) bool {
	spec, known := policy.Lookup(action)
	return slices.Contains(mcpForbiddenActions, action) || (known && spec.CredentialIssuing)
}

// isNotQuery is true for an unknown action too: with writes off, anything the
// catalog cannot vouch for as a read is refused.
func isNotQuery(action string) bool {
	spec, known := policy.Lookup(action)
	return !known || spec.Mode != policy.ModeQuery
}

func actionsOf(req policy.Request) []string {
	actions := []string{req.Action}
	for _, sub := range req.SubActions {
		actions = append(actions, sub.Action)
	}
	return actions
}
