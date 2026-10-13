package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// MCP client rows (spec §11.1, ADR-0032) hold the state of a registered MCP
// client and, for a local client, the SHA-256 of its single token. Hashing,
// the issuance window and the identity side effects belong to internal/auth
// and internal/app; this file only persists and looks rows up.

// MCPTokenMaxLifetime is the longest an MCP token may live; the schema
// enforces the same bound with a CHECK.
const MCPTokenMaxLifetime = 365 * 24 * time.Hour

type MCPClientOrigin string

const (
	MCPOriginLocal  MCPClientOrigin = "local"
	MCPOriginRemote MCPClientOrigin = "remote"
)

type MCPClientState string

const (
	MCPClientPendingToken MCPClientState = "pending_token"
	MCPClientActive       MCPClientState = "active"
	MCPClientDeleted      MCPClientState = "deleted"
)

// MCPClient is a registered MCP client. The token hash is deliberately not
// part of it: look the row up by hash, never read the hash from the row.
type MCPClient struct {
	ID                domain.ID
	IdentityID        domain.ID
	Name              string
	Origin            MCPClientOrigin
	State             MCPClientState
	RequestedBy       domain.ID
	RegistrationJobID *domain.ID
	ApprovedAt        time.Time
	TokenIssuedAt     *time.Time
	TokenExpiresAt    *time.Time
	RevokedAt         *time.Time
	LastUsedAt        *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time
}

const mcpClientColumns = `id, identity_id, name, origin, state, requested_by, registration_job_id, approved_at,
	token_issued_at, token_expires_at, revoked_at, last_used_at, created_at, updated_at, deleted_at`

func scanMCPClient(row scanner) (MCPClient, error) {
	var (
		c                                MCPClient
		job                              sql.NullString
		approvedMs, createdMs, updatedMs int64
		issuedMs, expiresMs, revokedMs   sql.NullInt64
		lastUsedMs, deletedMs            sql.NullInt64
	)
	err := row.Scan(&c.ID, &c.IdentityID, &c.Name, &c.Origin, &c.State, &c.RequestedBy, &job, &approvedMs,
		&issuedMs, &expiresMs, &revokedMs, &lastUsedMs, &createdMs, &updatedMs, &deletedMs)
	if err != nil {
		return MCPClient{}, err
	}
	c.RegistrationJobID = idOf(job)
	c.ApprovedAt = domain.FromUnixMillis(approvedMs)
	c.CreatedAt, c.UpdatedAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(updatedMs)
	c.TokenIssuedAt, c.TokenExpiresAt = timeOf(issuedMs), timeOf(expiresMs)
	c.RevokedAt, c.LastUsedAt, c.DeletedAt = timeOf(revokedMs), timeOf(lastUsedMs), timeOf(deletedMs)
	return c, nil
}

// CreateMCPClient stores c without a token. A second live client for the same
// identity or with the same name is CONFLICT; the identity must be an mcp one.
func CreateMCPClient(ctx context.Context, q Querier, c MCPClient) error {
	_, err := q.ExecContext(ctx, `
		INSERT INTO mcp_clients (id, identity_id, name, origin, state, requested_by, registration_job_id,
		                         approved_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.IdentityID, c.Name, c.Origin, c.State, c.RequestedBy, nullID(c.RegistrationJobID),
		millis(c.ApprovedAt), millis(c.CreatedAt), millis(c.UpdatedAt))
	if err != nil {
		return conflictIfDuplicate(err, "mcp client")
	}
	return nil
}

// GetMCPClient returns the client or NOT_FOUND. State, expiry and revocation are the caller's to judge.
func GetMCPClient(ctx context.Context, q Querier, id domain.ID) (MCPClient, error) {
	c, err := scanMCPClient(q.QueryRowContext(ctx, `SELECT `+mcpClientColumns+` FROM mcp_clients WHERE id = ?`, id))
	return c, getErr(err, "mcp client")
}

// GetMCPClientByTokenHash returns the client holding that token hash or NOT_FOUND.
func GetMCPClientByTokenHash(ctx context.Context, q Querier, tokenHash string) (MCPClient, error) {
	c, err := scanMCPClient(q.QueryRowContext(ctx,
		`SELECT `+mcpClientColumns+` FROM mcp_clients WHERE token_hash = ?`, tokenHash))
	return c, getErr(err, "mcp client")
}

// GetLiveMCPClientByIdentity returns the identity's client that is not deleted, or NOT_FOUND.
func GetLiveMCPClientByIdentity(ctx context.Context, q Querier, identity domain.ID) (MCPClient, error) {
	c, err := scanMCPClient(q.QueryRowContext(ctx,
		`SELECT `+mcpClientColumns+` FROM mcp_clients WHERE identity_id = ? AND state <> 'deleted'`, identity))
	return c, getErr(err, "mcp client")
}

// ListMCPClients returns every client, deleted ones included, oldest first.
func ListMCPClients(ctx context.Context, q Querier) ([]MCPClient, error) {
	return list(ctx, q, "mcp clients",
		`SELECT `+mcpClientColumns+` FROM mcp_clients ORDER BY created_at, id`, scanMCPClient)
}

// IssueMCPToken stores the hash of the client's one token and moves it to
// active, atomically. It succeeds for exactly one caller: a client that is not
// pending_token is CONFLICT/INVALID_TRANSITION, a missing one NOT_FOUND, an
// expiry that is not after issuedAt or is beyond MCPTokenMaxLifetime
// INVALID_ARGUMENT.
func IssueMCPToken(ctx context.Context, q Querier, id domain.ID, tokenHash string, issuedAt, expiresAt time.Time) (MCPClient, error) {
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MCPTokenMaxLifetime {
		return MCPClient{}, smerr.New(smerr.CodeInvalidArgument, "", "mcp token expiry must be within 365 days after issuance")
	}
	c, err := scanMCPClient(q.QueryRowContext(ctx, `
		UPDATE mcp_clients SET token_hash = ?, token_issued_at = ?, token_expires_at = ?, state = 'active', updated_at = ?
		WHERE id = ? AND state = 'pending_token' AND token_hash IS NULL
		RETURNING `+mcpClientColumns, tokenHash, millis(issuedAt), millis(expiresAt), millis(issuedAt), id))
	if !errors.Is(err, sql.ErrNoRows) {
		return c, getErr(err, "mcp client")
	}
	if _, err := GetMCPClient(ctx, q, id); err != nil {
		return MCPClient{}, err
	}
	return MCPClient{}, smerr.New(smerr.CodeConflict, smerr.ReasonInvalidTransition, "mcp client is not waiting for its token")
}

// DeleteMCPClient marks the client deleted and revokes its token, keeping the
// row as history. The first call wins and reports true; a later call changes
// nothing and reports false. A missing client is NOT_FOUND.
func DeleteMCPClient(ctx context.Context, q Querier, id domain.ID, at time.Time) (bool, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE mcp_clients SET state = 'deleted', deleted_at = ?, revoked_at = COALESCE(revoked_at, ?), updated_at = ?
		WHERE id = ? AND state <> 'deleted'`, millis(at), millis(at), millis(at), id)
	if err != nil {
		return false, fmt.Errorf("delete mcp client: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("delete mcp client: %w", err)
	}
	if n == 1 {
		return true, nil
	}
	_, err = GetMCPClient(ctx, q, id)
	return false, err
}

// TouchMCPClient records the client's last use.
func TouchMCPClient(ctx context.Context, q Querier, id domain.ID, at time.Time) error {
	return touch(ctx, q, "mcp_clients", id, at)
}

// ---- OAuth access tokens ---------------------------------------------------

// OAuthAccessToken is the record of an access token an authorization server
// issued for a remote MCP client, keyed by the SHA-256 of the token so that
// revocation, expiry at claim and audit work like other credentials. The
// token itself is never stored.
type OAuthAccessToken struct {
	ID          domain.ID
	MCPClientID domain.ID
	TokenHash   string
	Issuer      string
	JTI         string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	FirstSeenAt time.Time
	LastUsedAt  *time.Time
}

const oauthColumns = `id, mcp_client_id, token_hash, issuer, jti, issued_at, expires_at, revoked_at, first_seen_at, last_used_at`

func scanOAuthAccessToken(row scanner) (OAuthAccessToken, error) {
	var (
		t                                OAuthAccessToken
		issuedMs, expiresMs, firstSeenMs int64
		revokedMs, lastUsedMs            sql.NullInt64
	)
	err := row.Scan(&t.ID, &t.MCPClientID, &t.TokenHash, &t.Issuer, &t.JTI, &issuedMs, &expiresMs, &revokedMs, &firstSeenMs, &lastUsedMs)
	if err != nil {
		return OAuthAccessToken{}, err
	}
	t.IssuedAt, t.ExpiresAt = domain.FromUnixMillis(issuedMs), domain.FromUnixMillis(expiresMs)
	t.FirstSeenAt = domain.FromUnixMillis(firstSeenMs)
	t.RevokedAt, t.LastUsedAt = timeOf(revokedMs), timeOf(lastUsedMs)
	return t, nil
}

// RecordOAuthAccessToken stores a token the first time it is seen and returns
// the stored row. A token seen before by the same client is returned with its
// last use stamped (t.FirstSeenAt is "now" for this call). A hash that is
// revoked, or that belongs to another client, is CONFLICT: a revoked hash never
// comes back and a hash is never re-attached.
func RecordOAuthAccessToken(ctx context.Context, q Querier, t OAuthAccessToken) (OAuthAccessToken, error) {
	_, err := q.ExecContext(ctx, `
		INSERT INTO oauth_access_tokens (id, mcp_client_id, token_hash, issuer, jti, issued_at, expires_at, first_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (token_hash) DO NOTHING`,
		t.ID, t.MCPClientID, t.TokenHash, t.Issuer, t.JTI, millis(t.IssuedAt), millis(t.ExpiresAt), millis(t.FirstSeenAt))
	if err != nil {
		return OAuthAccessToken{}, conflictIfDuplicate(err, "oauth access token")
	}
	stored, err := GetOAuthAccessTokenByHash(ctx, q, t.TokenHash)
	if err != nil {
		return OAuthAccessToken{}, err
	}
	switch {
	case stored.MCPClientID != t.MCPClientID:
		return OAuthAccessToken{}, smerr.New(smerr.CodeConflict, "", "oauth access token belongs to another client")
	case stored.RevokedAt != nil:
		return OAuthAccessToken{}, smerr.New(smerr.CodeConflict, "", "oauth access token is revoked")
	}
	if err := touch(ctx, q, "oauth_access_tokens", stored.ID, t.FirstSeenAt); err != nil {
		return OAuthAccessToken{}, err
	}
	return GetOAuthAccessToken(ctx, q, stored.ID)
}

// GetOAuthAccessToken returns the token record or NOT_FOUND.
func GetOAuthAccessToken(ctx context.Context, q Querier, id domain.ID) (OAuthAccessToken, error) {
	t, err := scanOAuthAccessToken(q.QueryRowContext(ctx,
		`SELECT `+oauthColumns+` FROM oauth_access_tokens WHERE id = ?`, id))
	return t, getErr(err, "oauth access token")
}

// GetOAuthAccessTokenByHash returns the token record with that hash or NOT_FOUND.
func GetOAuthAccessTokenByHash(ctx context.Context, q Querier, tokenHash string) (OAuthAccessToken, error) {
	t, err := scanOAuthAccessToken(q.QueryRowContext(ctx,
		`SELECT `+oauthColumns+` FROM oauth_access_tokens WHERE token_hash = ?`, tokenHash))
	return t, getErr(err, "oauth access token")
}

// RevokeOAuthTokensOfClient revokes every access token of the client that is
// not revoked yet and returns how many.
func RevokeOAuthTokensOfClient(ctx context.Context, q Querier, client domain.ID, at time.Time) (int64, error) {
	return affected(ctx, q, "oauth_access_tokens",
		`UPDATE oauth_access_tokens SET revoked_at = ? WHERE mcp_client_id = ? AND revoked_at IS NULL`, millis(at), client)
}
