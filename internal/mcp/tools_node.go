package mcp

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// The node tools: adding a node pins the host key the daemon scanned, so the model never names a key, a
// fingerprint or a credential file; setting a node up asks only for what grants no root-equivalent access.

type addNodeInput struct {
	Name               string `json:"name" jsonschema:"name of the new node"`
	Host               string `json:"host" jsonschema:"DNS name or IP address of the SSH endpoint"`
	Port               int    `json:"port,omitempty" jsonschema:"SSH port, default 22"`
	User               string `json:"user,omitempty" jsonschema:"automation user the control plane creates and uses, default supermgmt"`
	AdminUser          string `json:"admin_user" jsonschema:"existing account used once, by the setup, to prepare the node"`
	AdminCredentialRef string `json:"admin_credential_ref,omitempty" jsonschema:"secret://<name> holding the admin_user SSH private key. A person stores it first with: sm secrets import --name <name>; you cannot create or list secrets, so ask the user for the name. Required on a server instance; omit it on a local instance to use the SSH agent"`
}

type setupNodeInput struct {
	Node   string `json:"node" jsonschema:"node id or exact node name"`
	Tunnel bool   `json:"tunnel,omitempty" jsonschema:"also move the node behind a Cloudflare Tunnel (needs Cloudflare configured); a node already behind a tunnel is refused, a person re-runs its setup"`
}

func addNodeTools(s *sdk.Server, api API) {
	actionTool(s, "infra_add_node",
		"Add a node reached over SSH. The daemon scans the host key of host:port and requests the add pinned to that key; you cannot pass a key, a fingerprint or a credential file. A request from an MCP client always waits for a person, who sees the host, the users, the credential references and the key's SHA-256 fingerprint and approves it; no node exists until then. Ask the user to review it with `sm approvals --plan` or the TUI; once approved, set it up with infra_setup_node. The default policy does not grant this; it needs a policy rule for type:mcp for node.add. Note it makes the daemon dial the host you name.",
		func(ctx context.Context, in addNodeInput) (WriteResult, error) { return addNode(ctx, api, in) })
	actionTool(s, "infra_setup_node",
		"Plan and submit the setup of a node (id or exact name) with safe parameters only: no Docker access, no service grants, journal logs. The resulting node can be probed and its logs read, but has no service verbs (start, stop, restart) until a person runs `sm nodes setup <node> --unit <unit>`. Only a node without a setup and not behind a tunnel is accepted: re-running setup replaces grants and docker access, so a person does it. A request from an MCP client always waits for a person. The default policy does not grant this; it needs a policy rule for type:mcp granting node.setup and sudoers.write.",
		func(ctx context.Context, in setupNodeInput) (WriteResult, error) { return setupNode(ctx, api, in) })
}

func addNode(ctx context.Context, api API, in addNodeInput) (WriteResult, error) {
	key, err := api.ScanHostKey(ctx, wire.ScanHostKeyRequest{Host: in.Host, Port: in.Port})
	if err != nil {
		return scanFailure(err)
	}
	res, err := api.AddSSHNode(ctx, wire.AddSSHNodeRequest{
		Name: in.Name, Host: in.Host, Port: in.Port, User: in.User, AdminUser: in.AdminUser,
		HostPublicKey: key.AuthorizedKey, AdminCredentialRef: in.AdminCredentialRef,
	})
	if err != nil {
		return WriteResult{}, err
	}
	if res.Pending == nil {
		return WriteResult{Status: WriteDone, Summary: fmt.Sprintf("node %s added", operatorLine(in.Name)), Risk: string(domain.RiskOperational)}, nil
	}
	return submissionResult(*res.Pending), nil
}

// scanFailure reports a policy refusal of the scan as a denied write, naming the reason; any other failure
// surfaces as the tool error.
func scanFailure(err error) (WriteResult, error) {
	var api *smerr.Error
	if errors.As(err, &api) && api.Code == smerr.CodePolicyDenied {
		return WriteResult{
			Status:  WriteDenied,
			Summary: fmt.Sprintf("policy denied node.add: %s", api.Reason),
			Risk:    string(domain.RiskOperational),
		}, nil
	}
	return WriteResult{}, err
}

func setupNode(ctx context.Context, api API, in setupNodeInput) (WriteResult, error) {
	params := map[string]any{"docker_access": "false", "logs_mode": "journal-group"}
	if in.Tunnel {
		params["tunnel"] = "true"
	}
	return planAndSubmit(ctx, api, "node.setup", planTarget{Type: string(domain.ResourceNode), Ref: in.Node}, params)
}
