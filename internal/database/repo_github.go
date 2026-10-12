package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- artifacts -------------------------------------------------------------

// Artifact is a verified OCI image bound to a commit. Rows are immutable (trigger).
type Artifact struct {
	ID               domain.ID
	AppID            domain.ID
	Type             string
	ImmutableRef     string
	Digest           string
	CommitSHA        string
	SourceRunID      *int64
	SourceRunAttempt *int64
	ProvenanceJSON   []byte
	ProvenanceMethod string
	CreatedAt        time.Time
}

const artifactColumns = `id, app_id, type, immutable_ref, digest, commit_sha, source_run_id,
	source_run_attempt, provenance_json, provenance_method, created_at`

func scanArtifact(row scanner) (Artifact, error) {
	var (
		a            Artifact
		runID, runAt sql.NullInt64
		provenance   string
		createdAt    int64
	)
	err := row.Scan(&a.ID, &a.AppID, &a.Type, &a.ImmutableRef, &a.Digest, &a.CommitSHA, &runID, &runAt,
		&provenance, &a.ProvenanceMethod, &createdAt)
	if err != nil {
		return Artifact{}, err
	}
	a.SourceRunID, a.SourceRunAttempt = githubInt64Of(runID), githubInt64Of(runAt)
	a.ProvenanceJSON, a.CreatedAt = []byte(provenance), domain.FromUnixMillis(createdAt)
	return a, nil
}

// CreateArtifact stores a. The type defaults to oci_image.
func CreateArtifact(ctx context.Context, q Querier, a Artifact) (Artifact, error) {
	if a.Type == "" {
		a.Type = "oci_image"
	}
	_, err := q.ExecContext(ctx, `INSERT INTO artifacts (`+artifactColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AppID, a.Type, a.ImmutableRef, a.Digest, a.CommitSHA, githubNullInt(a.SourceRunID),
		githubNullInt(a.SourceRunAttempt), appsJSONOrEmptyObject(a.ProvenanceJSON), a.ProvenanceMethod, millis(a.CreatedAt))
	if err != nil {
		return Artifact{}, conflictIfDuplicate(err, "artifact")
	}
	return a, nil
}

// GetArtifact returns the artifact or NOT_FOUND.
func GetArtifact(ctx context.Context, q Querier, id domain.ID) (Artifact, error) {
	a, err := scanArtifact(q.QueryRowContext(ctx, `SELECT `+artifactColumns+` FROM artifacts WHERE id = ?`, id))
	return appsFoundOrErr(a, err, "artifact")
}

// FindArtifact returns the newest artifact of the app with this digest and commit, or NOT_FOUND.
func FindArtifact(ctx context.Context, q Querier, appID domain.ID, digest, commitSHA string) (Artifact, error) {
	a, err := scanArtifact(q.QueryRowContext(ctx, `SELECT `+artifactColumns+`
		FROM artifacts WHERE app_id = ? AND digest = ? AND commit_sha = ?
		ORDER BY created_at DESC, id DESC LIMIT 1`, appID, digest, commitSHA))
	return appsFoundOrErr(a, err, "artifact")
}

// ---- artifact checks -------------------------------------------------------

// ArtifactCheck is the evidence of one CI check run behind an artifact (spec §18).
// AppID is the GitHub App id that produced the check run.
type ArtifactCheck struct {
	ArtifactID   domain.ID
	CheckName    string
	AppID        int64
	WorkflowPath string
	RunID        *int64
	RunAttempt   *int64
	Conclusion   string
	CompletedAt  *time.Time
}

// PutArtifactCheck stores c; one check name per artifact, a second is CONFLICT.
func PutArtifactCheck(ctx context.Context, q Querier, c ArtifactCheck) error {
	_, err := q.ExecContext(ctx, `
		INSERT INTO artifact_checks (artifact_id, check_name, app_id, workflow_path, run_id, run_attempt,
		                             conclusion, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ArtifactID, c.CheckName, c.AppID, c.WorkflowPath, githubNullInt(c.RunID), githubNullInt(c.RunAttempt),
		c.Conclusion, nullMillis(c.CompletedAt))
	if err != nil {
		return conflictIfDuplicate(err, "artifact check")
	}
	return nil
}

// ListArtifactChecks returns the checks of an artifact ordered by name.
func ListArtifactChecks(ctx context.Context, q Querier, artifactID domain.ID) ([]ArtifactCheck, error) {
	return appsListRows(ctx, q, "artifact checks", func(row scanner) (ArtifactCheck, error) {
		var (
			c            ArtifactCheck
			runID, runAt sql.NullInt64
			completed    sql.NullInt64
		)
		err := row.Scan(&c.ArtifactID, &c.CheckName, &c.AppID, &c.WorkflowPath, &runID, &runAt, &c.Conclusion, &completed)
		c.RunID, c.RunAttempt, c.CompletedAt = githubInt64Of(runID), githubInt64Of(runAt), timeOf(completed)
		return c, err
	}, `SELECT artifact_id, check_name, app_id, workflow_path, run_id, run_attempt, conclusion, completed_at
		FROM artifact_checks WHERE artifact_id = ? ORDER BY check_name`, artifactID)
}

// ---- GitHub Actions OIDC credentials ---------------------------------------

// GithubOIDCCredential is the durable status record of one verified Actions OIDC token
// (ADR-0028). It never holds the token; ClaimsJSON holds the non-secret §18 claims.
type GithubOIDCCredential struct {
	ID           string
	IdentityID   domain.ID
	RepositoryID int64
	ClaimsJSON   []byte
	IssuedAt     time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time
}

// GithubOIDCCredentialID is the credential id of a token: sha256(issuer|jti), hex.
func GithubOIDCCredentialID(issuer, jti string) string {
	sum := sha256.Sum256([]byte(issuer + "|" + jti))
	return hex.EncodeToString(sum[:])
}

const githubOIDCColumns = `id, identity_id, repository_id, claims_json, issued_at, expires_at, revoked_at, created_at`

// InsertGithubOIDCCredential stores c; a credential id already stored is CONFLICT.
func InsertGithubOIDCCredential(ctx context.Context, q Querier, c GithubOIDCCredential) error {
	_, err := q.ExecContext(ctx, `INSERT INTO github_oidc_credentials (`+githubOIDCColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.IdentityID, c.RepositoryID, appsJSONOrEmptyObject(c.ClaimsJSON), millis(c.IssuedAt),
		millis(c.ExpiresAt), nullMillis(c.RevokedAt), millis(c.CreatedAt))
	if err != nil {
		return conflictIfDuplicate(err, "github oidc credential")
	}
	return nil
}

// GetGithubOIDCCredential returns the credential or NOT_FOUND.
func GetGithubOIDCCredential(ctx context.Context, q Querier, id string) (GithubOIDCCredential, error) {
	var (
		c                        GithubOIDCCredential
		claims                   string
		issued, expires, created int64
		revoked                  sql.NullInt64
	)
	err := q.QueryRowContext(ctx, `SELECT `+githubOIDCColumns+` FROM github_oidc_credentials WHERE id = ?`, id).
		Scan(&c.ID, &c.IdentityID, &c.RepositoryID, &claims, &issued, &expires, &revoked, &created)
	if err != nil {
		return appsFoundOrErr(c, err, "github oidc credential")
	}
	c.ClaimsJSON, c.RevokedAt = []byte(claims), timeOf(revoked)
	c.IssuedAt, c.ExpiresAt, c.CreatedAt = domain.FromUnixMillis(issued), domain.FromUnixMillis(expires), domain.FromUnixMillis(created)
	return c, nil
}

// RevokeGithubOIDCCredentialsByIdentity revokes every open credential of the identity at `at`
// and returns how many it revoked. Already revoked credentials keep their original time.
func RevokeGithubOIDCCredentialsByIdentity(ctx context.Context, q Querier, identityID domain.ID, at time.Time) (int64, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE github_oidc_credentials SET revoked_at = ? WHERE identity_id = ? AND revoked_at IS NULL`,
		millis(at), identityID)
	if err != nil {
		return 0, fmt.Errorf("revoke github oidc credentials: %w", err)
	}
	return res.RowsAffected()
}

// ---- webhook deliveries ----------------------------------------------------

// WebhookDelivery is one received webhook, kept for deduplication by delivery id.
type WebhookDelivery struct {
	ID             domain.ID
	Provider       string
	DeliveryID     string
	ReceivedAt     time.Time
	SignatureValid bool
	EventType      string
}

// RecordWebhookDelivery stores d unless the provider already delivered that delivery id. It
// reports whether d was new: false means a redelivery the caller must not process again.
func RecordWebhookDelivery(ctx context.Context, q Querier, d WebhookDelivery) (bool, error) {
	res, err := q.ExecContext(ctx, `
		INSERT INTO webhook_deliveries (id, provider, delivery_id, received_at, signature_valid, event_type)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (provider, delivery_id) DO NOTHING`,
		d.ID, d.Provider, d.DeliveryID, millis(d.ReceivedAt), d.SignatureValid, d.EventType)
	if err != nil {
		return false, fmt.Errorf("insert webhook delivery: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// MarkWebhookDeliveryProcessed records the outcome of processing a delivery, or NOT_FOUND.
func MarkWebhookDeliveryProcessed(ctx context.Context, q Querier, provider, deliveryID string, at time.Time, result string) error {
	return updateOne(ctx, q, "webhook delivery", `
		UPDATE webhook_deliveries SET processed_at = ?, result = ? WHERE provider = ? AND delivery_id = ?`,
		millis(at), result, provider, deliveryID)
}

// ---- helpers ---------------------------------------------------------------

func githubNullInt(n *int64) sql.NullInt64 {
	if n == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *n, Valid: true}
}

func githubInt64Of(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}
