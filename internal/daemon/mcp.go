package daemon

import (
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
)

// mcpClients is the service behind /mcp/clients. Remote clients are
// registered against mcp.oauth.issuer, and only when remote MCP is on.
func (b *builder) mcpClients() (*app.MCPClientService, error) {
	opts := app.MCPClientsOptions{Tokens: auth.Minter{}, Mode: b.cfg.Instance.Mode, TokenOverHTTPS: b.cfg.MCP.TokenOverHTTPS}
	if b.mcpRemoteOn() {
		opts.RemoteIssuer = b.cfg.MCP.OAuth.Issuer
	}
	return app.NewMCPClients(b.app, b.jobs, opts)
}

// mcpSocketResolver admits the token of a local MCP client on the Unix
// socket (ADR-0032); with mcp.enabled false it refuses every one.
func (b *builder) mcpSocketResolver() auth.Resolver {
	return auth.MCPResolver{DB: b.db, Clock: b.o.Clock, Enabled: b.cfg.MCP.Enabled}
}

// mcpHTTPSResolver admits, on the HTTPS listener, the token of a local MCP
// client registered over_https (ADR-0044). It is nil unless
// mcp.token_over_https and mcp.enabled are both on, so otherwise the listener
// refuses an "smm_" token on its prefix without looking anything up.
func (b *builder) mcpHTTPSResolver() auth.Resolver {
	if !b.cfg.MCP.Enabled || !b.cfg.MCP.TokenOverHTTPS {
		return nil
	}
	return auth.MCPResolver{DB: b.db, Clock: b.o.Clock, Enabled: true, OverHTTPS: true}
}

// mcpRemoteOn is whether /mcp is served: remote MCP needs MCP itself.
func (b *builder) mcpRemoteOn() bool { return b.cfg.MCP.Enabled && b.cfg.MCP.RemoteEnabled }
