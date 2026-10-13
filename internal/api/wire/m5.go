package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- MCP clients (spec §11.1, §11.2, §24; ADR-0032) --------------------------

// MCPOrigin says how an MCP client authenticates: a local client presents the
// one token issued for it on the daemon socket; a remote client presents
// OAuth access tokens from the configured authorization server.
type MCPOrigin string

const (
	MCPOriginLocal  MCPOrigin = "local"
	MCPOriginRemote MCPOrigin = "remote"
)

// MCPClientState moves only forward: pending_token -> active when a local
// client's token is issued (remote clients start active), and any -> deleted.
type MCPClientState string

const (
	MCPClientPendingToken MCPClientState = "pending_token"
	MCPClientActive       MCPClientState = "active"
	MCPClientDeleted      MCPClientState = "deleted"
)

// MCPClient is an element of GET /mcp/clients. It never carries a token or a
// token hash. Subject and ClientID are the OAuth identity of a remote client
// (its issuer is mcp.oauth.issuer); both are empty for a local client.
// ApprovedAt starts the 24-hour window in which a local client's token may be
// issued.
type MCPClient struct {
	ID             domain.ID      `json:"id"`
	IdentityID     domain.ID      `json:"identity_id"`
	Name           string         `json:"name"`
	Origin         MCPOrigin      `json:"origin"`
	State          MCPClientState `json:"state"`
	Subject        string         `json:"subject,omitempty"`
	ClientID       string         `json:"client_id,omitempty"`
	RequestedBy    domain.ID      `json:"requested_by"`
	ApprovedAt     time.Time      `json:"approved_at"`
	TokenIssuedAt  *time.Time     `json:"token_issued_at"`
	TokenExpiresAt *time.Time     `json:"token_expires_at"`
	CreatedAt      time.Time      `json:"created_at"`
}

// RegisterMCPClientRequest is POST /mcp/clients (mcp_client.register). A
// remote registration names the OAuth subject and client_id; a local one
// names neither.
type RegisterMCPClientRequest struct {
	Name     string    `json:"name"`
	Origin   MCPOrigin `json:"origin"`
	Subject  string    `json:"subject,omitempty"`
	ClientID string    `json:"client_id,omitempty"`
}

// IssueMCPTokenRequest is POST /mcp/clients/{id}/token
// (mcp_client.issue_token). ExpiresAt is mandatory and at most 365 days
// ahead, like an API token's.
type IssueMCPTokenRequest struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// MCPTokenIssued is the one response that carries a local MCP client's token.
type MCPTokenIssued struct {
	Client MCPClient `json:"client"`
	Token  string    `json:"token"`
}
