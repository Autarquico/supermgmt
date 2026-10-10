package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// JoinTokenMaxLifetime is the longest a join token may live (ADR-0022).
const JoinTokenMaxLifetime = 24 * time.Hour

// Keys under which an enrolled node's metadata records its enrollment
// (ADR-0022). FindEnrolledNode reads them back for the lost-response replay.
const (
	JoinMetaTokenID       = "join_token_id"
	JoinMetaRequestDigest = "join_request_digest"
)

// JoinConstraints limit what a join token may enroll.
type JoinConstraints struct {
	Tags        []string `json:"tags,omitempty"`
	MaxNodes    int      `json:"max_nodes"`
	SourceCIDRs []string `json:"source_cidrs,omitempty"`
}

// JoinToken is a single-purpose enrollment credential (spec §13, ADR-0022).
type JoinToken struct {
	ID            domain.ID
	TokenHash     string
	CreatedBy     domain.ID
	Constraints   JoinConstraints
	Uses          int
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	InvalidatedAt *time.Time
}

const joinColumns = `id, token_hash, created_by, constraints_json, uses, created_at, expires_at, consumed_at, invalidated_at`

func scanJoinToken(row scanner) (JoinToken, error) {
	var (
		t                         JoinToken
		constraints               string
		createdMs, expiresMs      int64
		consumedMs, invalidatedMs sql.NullInt64
	)
	err := row.Scan(&t.ID, &t.TokenHash, &t.CreatedBy, &constraints, &t.Uses, &createdMs, &expiresMs, &consumedMs, &invalidatedMs)
	if err != nil {
		return JoinToken{}, err
	}
	if err := json.Unmarshal([]byte(constraints), &t.Constraints); err != nil {
		return JoinToken{}, fmt.Errorf("decode join constraints: %w", err)
	}
	t.CreatedAt, t.ExpiresAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(expiresMs)
	t.ConsumedAt, t.InvalidatedAt = timeOf(consumedMs), timeOf(invalidatedMs)
	return t, nil
}

// CreateJoinToken stores t. MaxNodes must be at least 1 and the lifetime
// positive and at most JoinTokenMaxLifetime, else INVALID_ARGUMENT.
func CreateJoinToken(ctx context.Context, q Querier, t JoinToken) error {
	lifetime := t.ExpiresAt.Sub(t.CreatedAt)
	if lifetime <= 0 || lifetime > JoinTokenMaxLifetime {
		return smerr.New(smerr.CodeInvalidArgument, "", "join token lifetime must be within 24 hours")
	}
	if t.Constraints.MaxNodes < 1 {
		return smerr.New(smerr.CodeInvalidArgument, "", "join token must allow at least one node")
	}
	constraints, err := json.Marshal(t.Constraints)
	if err != nil {
		return fmt.Errorf("encode join constraints: %w", err)
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO join_tokens (id, token_hash, created_by, constraints_json, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.TokenHash, t.CreatedBy, string(constraints), millis(t.CreatedAt), millis(t.ExpiresAt))
	if err != nil {
		return conflictIfDuplicate(err, "join token")
	}
	return nil
}

// GetJoinToken returns the token or NOT_FOUND. Expiry is the caller's to judge.
func GetJoinToken(ctx context.Context, q Querier, id domain.ID) (JoinToken, error) {
	t, err := scanJoinToken(q.QueryRowContext(ctx, `SELECT `+joinColumns+` FROM join_tokens WHERE id = ?`, id))
	return t, getErr(err, "join token")
}

// GetJoinTokenByHash returns the token with that hash or NOT_FOUND.
func GetJoinTokenByHash(ctx context.Context, q Querier, tokenHash string) (JoinToken, error) {
	t, err := scanJoinToken(q.QueryRowContext(ctx, `SELECT `+joinColumns+` FROM join_tokens WHERE token_hash = ?`, tokenHash))
	return t, getErr(err, "join token")
}

// UseJoinToken takes one enrollment slot atomically and returns the token as
// updated; consumed_at is stamped when the last slot goes. A token that is
// expired, invalidated or out of slots is CONFLICT; an unknown id is NOT_FOUND.
func UseJoinToken(ctx context.Context, q Querier, id domain.ID, at time.Time) (JoinToken, error) {
	const maxNodes = `coalesce(json_extract(constraints_json, '$.max_nodes'), 1)`
	t, err := scanJoinToken(q.QueryRowContext(ctx, `
		UPDATE join_tokens SET uses = uses + 1,
		    consumed_at = CASE WHEN uses + 1 >= `+maxNodes+` THEN ? ELSE consumed_at END
		WHERE id = ? AND invalidated_at IS NULL AND expires_at > ? AND uses < `+maxNodes+`
		RETURNING `+joinColumns, millis(at), id, millis(at)))
	if err == nil {
		return t, nil
	}
	if _, lookupErr := GetJoinToken(ctx, q, id); lookupErr != nil {
		return JoinToken{}, lookupErr
	}
	return JoinToken{}, smerr.New(smerr.CodeConflict, "", "join token is expired, invalidated or exhausted")
}

// JoinRequestDigest identifies an enrollment request: SHA-256 over the host
// public key, a zero byte and the hostname, hex encoded (ADR-0022).
func JoinRequestDigest(hostPublicKey, hostname string) string {
	sum := sha256.Sum256([]byte(hostPublicKey + "\x00" + hostname))
	return hex.EncodeToString(sum[:])
}

// FindEnrolledNode returns the node whose enrollment recorded digest, for a
// retry after a lost response. A non-empty tokenID restricts the match to
// nodes enrolled with that token; empty accepts any token. NOT_FOUND if none.
func FindEnrolledNode(ctx context.Context, q Querier, tokenID domain.ID, digest string) (domain.ID, error) {
	var id domain.ID
	err := q.QueryRowContext(ctx, `
		SELECT id FROM nodes
		WHERE json_extract(metadata_json, '$.`+JoinMetaRequestDigest+`') = ?
		  AND (? = '' OR json_extract(metadata_json, '$.`+JoinMetaTokenID+`') = ?)
		ORDER BY created_at, id LIMIT 1`, digest, tokenID, tokenID).Scan(&id)
	return id, getErr(err, "enrolled node")
}
