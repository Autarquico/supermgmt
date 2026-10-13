package mcp

import (
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverName = "supermgmt"

// NewServer builds the MCP server of SuperMgmt: the read tools and
// infra_plan_action always, the write tools only when o.WriteTools is set.
// A write tool that is not registered is unknown to tools/list and to
// tools/call alike.
func NewServer(api API, o Options) *sdk.Server {
	server := sdk.NewServer(
		&sdk.Implementation{Name: serverName, Version: o.Version},
		&sdk.ServerOptions{Logger: o.Log},
	)
	addReadTools(server, api)
	addPlanTool(server, api, o.WriteTools)
	if o.WriteTools {
		addWriteTools(server, api)
	}
	return server
}
