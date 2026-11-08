package app

import (
	"context"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

// mcpForbiddenActions are denied to an mcp actor on top of every action that
// issues a credential: an MCP bearer must never mint or reshape an identity
// whose lifecycle is independent of its source client (ADR-0032), nor open an
// interactive node session (no exec tools in V1, spec §24), nor resolve an
// interrupted job, which is human judgment over ambiguous evidence (§20.4),
// nor delete a snapshot, which is unrecoverable.
var mcpForbiddenActions = []string{"mcp_client.register", "mcp_client.delete", "identity.write", "role_binding.write", "node.connect", "job.resolve", "proxmox.snapshot.delete"}

// mcpUnlisted are job actions infra_list_actions does not describe: their parameters have restricted values
// (requireMCPSafeSetup) that a listing of the catalog cannot express, so the listing omits them;
// requireMCPSafeSetup still applies to any path that plans them.
var mcpUnlisted = []string{policy.ActionNodeSetup, policy.ActionSudoersWrite, policy.ActionLogBrokerInstall}

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
			!mcpForbids(spec.Name) && !slices.Contains(mcpUnlisted, spec.Name) {
			out = append(out, spec)
		}
	}
	return out
}

// requireMCPSafeSetup refuses, before any plan exists, the node.setup parameters an mcp actor may not plan:
// values that grant root-equivalent access, write as root, issue a credential or install a root-run binary.
// It reads no node state, so it may run before policy. It must see the parameters that will be stored, so it
// runs after the defaults are filled. A person planning the same is unaffected.
func requireMCPSafeSetup(actor domain.Actor, req PlanRequest) error {
	if actor.Type != domain.ActorMCP || req.Action != policy.ActionNodeSetup {
		return nil
	}
	if refused := unsafeSetupParam(req.Parameters); refused != "" {
		return invalidArgument("node.setup parameter %s is not available to an MCP client; a person must plan it", refused)
	}
	return nil
}

// requireMCPFreshNode refuses a node.setup by an mcp actor on a node that already has a setup or runs behind a
// tunnel, since a re-run replaces its grants and docker access. It reads node state, so it runs only for a client
// the policy let see the node, and again when the job runs, the last decision point: a setup recorded after the
// plan was made must not be overwritten by it.
func requireMCPFreshNode(ctx context.Context, q database.Querier, actor domain.Actor, action string, nodeID domain.ID) error {
	if actor.Type != domain.ActorMCP || action != policy.ActionNodeSetup {
		return nil
	}
	node, err := database.GetNode(ctx, q, nodeID)
	if err != nil {
		return err
	}
	meta, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return err
	}
	if meta != nil || node.Endpoint.Transport == domain.TransportCloudflare {
		return invalidArgument("node %q already has a setup or a tunnel, and a re-run replaces its grants and docker access: a person re-runs it with `sm nodes setup`", node.Name)
	}
	return nil
}

func unsafeSetupParam(params map[string]any) string {
	switch {
	case params[policy.ParamDockerAccess] != nil && params[policy.ParamDockerAccess] != "false":
		return policy.ParamDockerAccess
	case hasGrants(params[policy.ParamGrants]):
		return policy.ParamGrants
	case params[policy.ParamDeployRoot] != nil && params[policy.ParamDeployRoot] != "":
		return policy.ParamDeployRoot
	case params[policy.ParamProxmox] == "true":
		return policy.ParamProxmox
	case params[policy.ParamLogsMode] == string(runtimes.LogsBroker):
		return policy.ParamLogsMode
	}
	return ""
}

func hasGrants(raw any) bool {
	switch list := raw.(type) {
	case nil:
		return false
	case []string:
		return len(list) > 0
	case []any:
		return len(list) > 0
	}
	return true // any other shape is refused rather than guessed at
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
