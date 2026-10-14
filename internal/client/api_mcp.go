package client

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- MCP clients (spec §24, ADR-0032) -------------------------------------

func (c *Client) ListMCPClients(ctx context.Context) (wire.Page[wire.MCPClient], error) {
	return call[wire.Page[wire.MCPClient]](ctx, c, get(wire.PathMCPClients, nil))
}

func (c *Client) RegisterMCPClient(ctx context.Context, r wire.RegisterMCPClientRequest) (wire.Direct[wire.MCPClient], error) {
	return call[wire.Direct[wire.MCPClient]](ctx, c, post(wire.PathMCPClients, r))
}

// IssueMCPToken is a credential route: it carries no Idempotency-Key, so a
// retried request is never replayed as a second token.
func (c *Client) IssueMCPToken(ctx context.Context, id domain.ID, r wire.IssueMCPTokenRequest) (wire.MCPTokenIssued, error) {
	return call[wire.MCPTokenIssued](ctx, c, postUnkeyed(wire.Path(wire.PathMCPClientToken, string(id)), r))
}

func (c *Client) DeleteMCPClient(ctx context.Context, id domain.ID) (wire.Direct[wire.MCPClient], error) {
	return call[wire.Direct[wire.MCPClient]](ctx, c, request{method: http.MethodDelete, path: wire.Path(wire.PathMCPClient, string(id))})
}
