package api

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
)

// ExemptMCP stands for the remote MCP endpoint and its two well-known
// documents (ADR-0033). They are mounted verbatim outside /api/v1 (Options.
// MCPRemote), so they are not in Routes() and not in the OpenAPI document.
const ExemptMCP = "exempt:mcp"

// mcpClients registers the MCP client routes (spec §11.1, §23; ADR-0032).
// Without the service they are not served.
func (rs *routeSet) mcpClients() {
	s := rs.s
	if s.svc.MCPClients == nil {
		return
	}
	rs.read(wire.PathMCPClients, "identity.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.MCPClient], error) {
		if _, err := wire.ParsePageQuery(in.r.URL.Query()); err != nil {
			return wire.Page[wire.MCPClient]{}, err
		}
		clients, err := s.svc.MCPClients.List(ctx, by)
		return wire.Page[wire.MCPClient]{Items: nonNil(clients)}, err
	}))
	rs.routes = append(rs.routes, route{
		method: http.MethodPost, pattern: wire.PathMCPClients, action: "mcp_client.register", keyed: true,
		do: mutation(s, s.registerMCPClient, mcpClientOutcome),
	})
	rs.routes = append(rs.routes, route{
		method: http.MethodPost, pattern: wire.PathMCPClientToken, action: "mcp_client.issue_token", credential: true,
		do: s.issueMCPToken,
	})
	rs.routes = append(rs.routes, route{
		method: http.MethodDelete, pattern: wire.PathMCPClient, action: "mcp_client.delete", keyed: true,
		do: mutation(s, func(ctx context.Context, by app.Caller, in input) (app.DirectResult[wire.MCPClient], error) {
			id, err := in.id("id")
			if err != nil {
				return app.DirectResult[wire.MCPClient]{}, err
			}
			return s.svc.MCPClients.Delete(ctx, by, id)
		}, mcpClientOutcome),
	})
}

// mcpClientOutcome answers 200 when the change was applied and 202 when it
// became a job awaiting approval; both are stored under the Idempotency-Key.
var mcpClientOutcome = direct(http.StatusOK, same[wire.MCPClient])

func (s *Server) registerMCPClient(ctx context.Context, by app.Caller, in input) (app.DirectResult[wire.MCPClient], error) {
	req, err := decode[wire.RegisterMCPClientRequest](in)
	if err != nil {
		return app.DirectResult[wire.MCPClient]{}, err
	}
	return s.svc.MCPClients.Register(ctx, by, req)
}

// issueMCPToken answers with the client's token once. Like every credential
// route it refuses an Idempotency-Key (admit) and stores no answer.
func (s *Server) issueMCPToken(w http.ResponseWriter, r *http.Request) error {
	in, err := readInput(r)
	if err != nil {
		return err
	}
	id, err := in.id("id")
	if err != nil {
		return err
	}
	req, err := decode[wire.IssueMCPTokenRequest](in)
	if err != nil {
		return err
	}
	issued, err := s.svc.MCPClients.IssueToken(r.Context(), scopeOf(r.Context()).caller, id, req)
	if err != nil {
		return err
	}
	s.writeData(w, r, http.StatusCreated, issued)
	return nil
}
