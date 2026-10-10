package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Credential rows (spec §11, ADR-0017) hold SHA-256 hashes of the bearer
// secrets, never the secrets themselves. Hashing and expiry policy belong to
// internal/auth; this file only persists and looks rows up by hash.

// APITokenMaxLifetime is the longest an API token may live (spec §11.3). The
// schema enforces the same bound with a CHECK.
const APITokenMaxLifetime = 365 * 24 * time.Hour

type SessionOrigin string

const (
	OriginOIDC      SessionOrigin = "oidc"
	OriginBootstrap SessionOrigin = "bootstrap"
)

func AllSessionOrigins() []SessionOrigin { return []SessionOrigin{OriginOIDC, OriginBootstrap} }

// revoke stamps revoked_at on a row that is not revoked yet. The first call
// wins and reports true; a later call changes nothing and reports false.
// A missing row is NOT_FOUND. table is always a package constant.
func revoke(ctx context.Context, q Querier, table, what string, id domain.ID, at time.Time) (bool, error) {
	res, err := q.ExecContext(ctx,
		`UPDATE `+table+` SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, millis(at), id)
	if err != nil {
		return false, fmt.Errorf("revoke %s: %w", what, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoke %s: %w", what, err)
	}
	if n == 1 {
		return true, nil
	}
	var exists int
	err = q.QueryRowContext(ctx, `SELECT 1 FROM `+table+` WHERE id = ?`, id).Scan(&exists)
	return false, getErr(err, what)
}

// touch records the last use of a credential row.
func touch(ctx context.Context, q Querier, table string, id domain.ID, at time.Time) error {
	if _, err := q.ExecContext(ctx, `UPDATE `+table+` SET last_used_at = ? WHERE id = ?`, millis(at), id); err != nil {
		return fmt.Errorf("touch %s: %w", table, err)
	}
	return nil
}

// ---- sessions --------------------------------------------------------------

// AuthSession is a bearer session of a signed-in identity (ADR-0017). It is
// not an InteractiveSession, which is an SSH handoff.
type AuthSession struct {
	ID         domain.ID
	IdentityID domain.ID
	TokenHash  string
	Client     string
	Origin     SessionOrigin
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

const authSessionColumns = `id, identity_id, token_hash, client, origin, created_at, expires_at, revoked_at, last_used_at`

func scanAuthSession(row scanner) (AuthSession, error) {
	var (
		s                     AuthSession
		createdMs, expiresMs  int64
		revokedMs, lastUsedMs sql.NullInt64
	)
	err := row.Scan(&s.ID, &s.IdentityID, &s.TokenHash, &s.Client, &s.Origin, &createdMs, &expiresMs, &revokedMs, &lastUsedMs)
	if err != nil {
		return AuthSession{}, err
	}
	s.CreatedAt, s.ExpiresAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(expiresMs)
	s.RevokedAt, s.LastUsedAt = timeOf(revokedMs), timeOf(lastUsedMs)
	return s, nil
}

// CreateAuthSession stores s; revocation and last-use fields are ignored.
// A duplicate id or token hash is CONFLICT.
func CreateAuthSession(ctx context.Context, q Querier, s AuthSession) error {
	if !slices.Contains(AllSessionOrigins(), s.Origin) {
		return smerr.New(smerr.CodeInvalidArgument, "", "unknown session origin")
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO sessions (id, identity_id, token_hash, client, origin, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.IdentityID, s.TokenHash, s.Client, s.Origin, millis(s.CreatedAt), millis(s.ExpiresAt))
	if err != nil {
		return conflictIfDuplicate(err, "session")
	}
	return nil
}

// GetAuthSession returns the session or NOT_FOUND. It does not judge expiry or
// revocation; the caller compares the timestamps with its clock.
func GetAuthSession(ctx context.Context, q Querier, id domain.ID) (AuthSession, error) {
	s, err := scanAuthSession(q.QueryRowContext(ctx, `SELECT `+authSessionColumns+` FROM sessions WHERE id = ?`, id))
	return s, getErr(err, "session")
}

// GetAuthSessionByHash returns the session with that token hash or NOT_FOUND.
func GetAuthSessionByHash(ctx context.Context, q Querier, tokenHash string) (AuthSession, error) {
	s, err := scanAuthSession(q.QueryRowContext(ctx, `SELECT `+authSessionColumns+` FROM sessions WHERE token_hash = ?`, tokenHash))
	return s, getErr(err, "session")
}

// TouchAuthSession records the session's last use.
func TouchAuthSession(ctx context.Context, q Querier, id domain.ID, at time.Time) error {
	return touch(ctx, q, "sessions", id, at)
}

// RevokeAuthSession revokes the session; see revoke for the first-wins rule.
func RevokeAuthSession(ctx context.Context, q Querier, id domain.ID, at time.Time) (bool, error) {
	return revoke(ctx, q, "sessions", "session", id, at)
}

// ---- API tokens ------------------------------------------------------------

// APIToken is a long-lived, scope-narrowed credential of an identity.
type APIToken struct {
	ID         domain.ID
	IdentityID domain.ID
	Name       string
	TokenHash  string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

const apiColumns = `id, identity_id, name, token_hash, scopes_json, created_at, expires_at, revoked_at, last_used_at`

func scanAPIToken(row scanner) (APIToken, error) {
	var (
		t                     APIToken
		scopes                string
		createdMs, expiresMs  int64
		revokedMs, lastUsedMs sql.NullInt64
	)
	err := row.Scan(&t.ID, &t.IdentityID, &t.Name, &t.TokenHash, &scopes, &createdMs, &expiresMs, &revokedMs, &lastUsedMs)
	if err != nil {
		return APIToken{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &t.Scopes); err != nil {
		return APIToken{}, fmt.Errorf("decode token scopes: %w", err)
	}
	t.CreatedAt, t.ExpiresAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(expiresMs)
	t.RevokedAt, t.LastUsedAt = timeOf(revokedMs), timeOf(lastUsedMs)
	return t, nil
}

// CreateAPIToken stores t. A name already used by the identity (revoked or
// not) or a duplicate hash is CONFLICT; an expiry beyond APITokenMaxLifetime
// or at or before creation is INVALID_ARGUMENT.
func CreateAPIToken(ctx context.Context, q Querier, t APIToken) error {
	if !t.ExpiresAt.After(t.CreatedAt) || t.ExpiresAt.Sub(t.CreatedAt) > APITokenMaxLifetime {
		return smerr.New(smerr.CodeInvalidArgument, "", "token expiry must be within 365 days after creation")
	}
	scopes, err := json.Marshal(append([]string{}, t.Scopes...))
	if err != nil {
		return fmt.Errorf("encode token scopes: %w", err)
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO api_tokens (id, identity_id, name, token_hash, scopes_json, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.IdentityID, t.Name, t.TokenHash, string(scopes), millis(t.CreatedAt), millis(t.ExpiresAt))
	if err != nil {
		return conflictIfDuplicate(err, "api token")
	}
	return nil
}

// GetAPIToken returns the token or NOT_FOUND. Expiry and revocation are the caller's to judge.
func GetAPIToken(ctx context.Context, q Querier, id domain.ID) (APIToken, error) {
	t, err := scanAPIToken(q.QueryRowContext(ctx, `SELECT `+apiColumns+` FROM api_tokens WHERE id = ?`, id))
	return t, getErr(err, "api token")
}

// GetAPITokenByHash returns the token with that hash or NOT_FOUND.
func GetAPITokenByHash(ctx context.Context, q Querier, tokenHash string) (APIToken, error) {
	t, err := scanAPIToken(q.QueryRowContext(ctx, `SELECT `+apiColumns+` FROM api_tokens WHERE token_hash = ?`, tokenHash))
	return t, getErr(err, "api token")
}

// ListAPITokens returns every token of the identity, revoked ones included, oldest first.
func ListAPITokens(ctx context.Context, q Querier, identity domain.ID) ([]APIToken, error) {
	return list(ctx, q, "api tokens",
		`SELECT `+apiColumns+` FROM api_tokens WHERE identity_id = ? ORDER BY created_at, id`,
		scanAPIToken, identity)
}

// TouchAPIToken records the token's last use.
func TouchAPIToken(ctx context.Context, q Querier, id domain.ID, at time.Time) error {
	return touch(ctx, q, "api_tokens", id, at)
}

// RevokeAPIToken revokes the token; see revoke for the first-wins rule.
func RevokeAPIToken(ctx context.Context, q Querier, id domain.ID, at time.Time) (bool, error) {
	return revoke(ctx, q, "api_tokens", "api token", id, at)
}

// ---- bootstrap codes -------------------------------------------------------

// BootstrapCode is the one-time code that makes the first admin (spec §11.5).
type BootstrapCode struct {
	ID            domain.ID
	CodeHash      string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	ConsumedBy    *domain.ID
	InvalidatedAt *time.Time
}

const bootstrapColumns = `id, code_hash, created_at, expires_at, consumed_at, consumed_by, invalidated_at`

func scanBootstrapCode(row scanner) (BootstrapCode, error) {
	var (
		c                         BootstrapCode
		createdMs, expiresMs      int64
		consumedMs, invalidatedMs sql.NullInt64
		consumedBy                sql.NullString
	)
	err := row.Scan(&c.ID, &c.CodeHash, &createdMs, &expiresMs, &consumedMs, &consumedBy, &invalidatedMs)
	if err != nil {
		return BootstrapCode{}, err
	}
	c.CreatedAt, c.ExpiresAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(expiresMs)
	c.ConsumedAt, c.ConsumedBy, c.InvalidatedAt = timeOf(consumedMs), idOf(consumedBy), timeOf(invalidatedMs)
	return c, nil
}

// IssueBootstrapCode invalidates every code that is still pending and stores
// c as the only usable one (spec §11.5: a new code invalidates the previous).
// Call it inside one write transaction.
func IssueBootstrapCode(ctx context.Context, q Querier, c BootstrapCode) error {
	if _, err := invalidatePending(ctx, q, "bootstrap_codes", c.CreatedAt); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO bootstrap_codes (id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		c.ID, c.CodeHash, millis(c.CreatedAt), millis(c.ExpiresAt))
	if err != nil {
		return conflictIfDuplicate(err, "bootstrap code")
	}
	return nil
}

// ConsumeBootstrapCode marks the code with that hash consumed by identity and
// returns it. A code that is unknown, expired, already consumed or invalidated
// is NOT_FOUND, deliberately without saying which. The identity must exist.
func ConsumeBootstrapCode(ctx context.Context, q Querier, codeHash string, by domain.ID, at time.Time) (BootstrapCode, error) {
	c, err := scanBootstrapCode(q.QueryRowContext(ctx, `
		UPDATE bootstrap_codes SET consumed_at = ?, consumed_by = ?
		WHERE code_hash = ? AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
		RETURNING `+bootstrapColumns, millis(at), by, codeHash, millis(at)))
	return c, getErr(err, "bootstrap code")
}

// GetBootstrapCode returns the code by id or NOT_FOUND.
func GetBootstrapCode(ctx context.Context, q Querier, id domain.ID) (BootstrapCode, error) {
	c, err := scanBootstrapCode(q.QueryRowContext(ctx, `SELECT `+bootstrapColumns+` FROM bootstrap_codes WHERE id = ?`, id))
	return c, getErr(err, "bootstrap code")
}

// invalidatePending stamps invalidated_at on every unconsumed, not yet invalidated row.
func invalidatePending(ctx context.Context, q Querier, table string, at time.Time) (int64, error) {
	return affected(ctx, q, table, `UPDATE `+table+` SET invalidated_at = ?
		WHERE consumed_at IS NULL AND invalidated_at IS NULL`, millis(at))
}

func affected(ctx context.Context, q Querier, what, statement string, args ...any) (int64, error) {
	res, err := q.ExecContext(ctx, statement, args...)
	if err != nil {
		return 0, fmt.Errorf("update %s: %w", what, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("update %s: %w", what, err)
	}
	return n, nil
}

// ---- OIDC replay -----------------------------------------------------------

// ClaimOIDCJTI records an ID-token jti and reports whether it was new. A jti
// seen before from the same issuer reports false: the token is a replay.
// expiresAt is when the record may be swept, normally the token's own expiry.
func ClaimOIDCJTI(ctx context.Context, q Querier, issuer, jti string, expiresAt time.Time) (bool, error) {
	n, err := affected(ctx, q, "oidc_replay", `
		INSERT INTO oidc_replay (issuer, jti, expires_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`,
		issuer, jti, millis(expiresAt))
	return n == 1, err
}

// ---- bulk operations -------------------------------------------------------

// RevokeAllCredentials revokes every session and API token that is still
// active, as a restore does (spec §29.2, ADR-0020), and returns how many.
func RevokeAllCredentials(ctx context.Context, q Querier, at time.Time) (int64, error) {
	var total int64
	for _, table := range []string{"sessions", "api_tokens"} {
		n, err := affected(ctx, q, table, `UPDATE `+table+` SET revoked_at = ? WHERE revoked_at IS NULL`, millis(at))
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// InvalidatePendingCodes invalidates every unconsumed bootstrap code and join
// token, as a restore does, and returns how many.
func InvalidatePendingCodes(ctx context.Context, q Querier, at time.Time) (int64, error) {
	var total int64
	for _, table := range []string{"bootstrap_codes", "join_tokens"} {
		n, err := invalidatePending(ctx, q, table, at)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// AuthSwept counts the rows SweepAuth removed.
type AuthSwept struct {
	Sessions, APITokens, BootstrapCodes, JoinTokens, OIDCReplays int64
}

// SweepAuth deletes sessions, API tokens, bootstrap codes, join tokens and
// OIDC replay records that expired at or before cutoff. Callers pass a cutoff
// a little in the past so a recently expired credential still reads as
// "expired" rather than "unknown". Revoked rows go with their expiry.
func SweepAuth(ctx context.Context, q Querier, cutoff time.Time) (AuthSwept, error) {
	var out AuthSwept
	targets := []struct {
		table   string
		counter *int64
	}{
		{"sessions", &out.Sessions},
		{"api_tokens", &out.APITokens},
		{"bootstrap_codes", &out.BootstrapCodes},
		{"join_tokens", &out.JoinTokens},
		{"oidc_replay", &out.OIDCReplays},
	}
	for _, t := range targets {
		n, err := affected(ctx, q, t.table, `DELETE FROM `+t.table+` WHERE expires_at <= ?`, millis(cutoff))
		if err != nil {
			return AuthSwept{}, err
		}
		*t.counter = n
	}
	return out, nil
}
