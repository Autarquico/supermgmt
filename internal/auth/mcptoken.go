package auth

import (
	"context"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const mcpSocketSource = "mcp_socket"

// MCPResolver authenticates the "smm_" token a local MCP client presents on
// the admin socket (spec §11.1, ADR-0032). It never accepts another token
// kind, and refuses everything while MCP is disabled. Nothing is cached.
type MCPResolver struct {
	DB *database.DB
	// Clock defaults to the system clock.
	Clock   domain.Clock
	Enabled bool
}

var _ Resolver = MCPResolver{}

func (r MCPResolver) Resolve(ctx context.Context, bearer string) (app.Caller, error) {
	if !r.Enabled {
		return app.Caller{}, smerr.New(smerr.CodeUnauthenticated, "", "mcp is disabled")
	}
	client, err := r.lookup(ctx, bearer)
	if err != nil {
		return app.Caller{}, err
	}
	state, err := CredentialStatus{DB: r.DB, Clock: r.Clock}.Status(ctx, domain.CredentialContext{Kind: domain.CredentialMCPToken, ID: client.ID.String()})
	if err != nil {
		return app.Caller{}, err
	}
	if err := credentialError(state); err != nil {
		return app.Caller{}, err
	}
	now := clockOrSystem(r.Clock).Now()
	r.recordUse(ctx, client, now)
	expires := *client.TokenExpiresAt
	return app.Caller{
		ID:         client.IdentityID,
		Credential: domain.CredentialContext{Kind: domain.CredentialMCPToken, ID: client.ID.String(), ExpiresAt: &expires},
		Source:     mcpSocketSource,
	}, nil
}

func (r MCPResolver) lookup(ctx context.Context, bearer string) (database.MCPClient, error) {
	kind, hash, err := Hash(bearer)
	if err != nil {
		return database.MCPClient{}, err
	}
	if kind != KindMCP {
		return database.MCPClient{}, smerr.New(smerr.CodeUnauthenticated, "", "this token kind cannot authenticate an mcp client")
	}
	client, err := database.GetMCPClientByTokenHash(ctx, r.DB.Reader(), hash)
	if err != nil {
		return database.MCPClient{}, unknownCredential(err)
	}
	return client, nil
}

// recordUse stamps last_used_at at most once per lastUsedGranularity. It is
// bookkeeping: a failed write must not fail an authenticated request.
func (r MCPResolver) recordUse(ctx context.Context, client database.MCPClient, now time.Time) {
	if client.LastUsedAt != nil && now.Sub(*client.LastUsedAt) < lastUsedGranularity {
		return
	}
	_ = r.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.TouchMCPClient(ctx, tx, client.ID, now)
	})
}
