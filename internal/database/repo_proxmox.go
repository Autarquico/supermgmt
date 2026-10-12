package database

import (
	"context"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// UpdateProviderSpec writes the configured fields of a provider (endpoint,
// credential reference, config) and bumps spec_revision, provided the stored
// revision still equals expectedRev; otherwise it returns CONFLICT. The
// observed fields (status, last_sync_at) are never written here.
func UpdateProviderSpec(ctx context.Context, q Querier, p domain.Provider, expectedRev int64) (domain.Provider, error) {
	config, err := encodeJSON(p.Config)
	if err != nil {
		return domain.Provider{}, err
	}
	res, err := q.ExecContext(ctx, `
		UPDATE providers SET endpoint = ?, credential_ref = ?, config_json = ?, updated_at = ?,
		                     spec_revision = spec_revision + 1
		WHERE id = ? AND spec_revision = ?`,
		p.Endpoint, p.CredentialRef, config, millis(p.UpdatedAt), p.ID, expectedRev)
	if err != nil {
		return domain.Provider{}, conflictIfDuplicate(err, "provider")
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return domain.Provider{}, err
	}
	if affected == 0 {
		return domain.Provider{}, staleOrMissing(ctx, q, "providers", p.ID, expectedRev)
	}
	return GetProvider(ctx, q, p.ID)
}

// SetProviderStatus records the observed status of a provider. A non-nil
// syncedAt also records when its last successful sync happened; nil leaves
// last_sync_at as it is. It never changes spec_revision.
func SetProviderStatus(ctx context.Context, q Querier, id domain.ID, status string, syncedAt *time.Time) error {
	return updateOne(ctx, q, "provider", `
		UPDATE providers SET status = ?, last_sync_at = COALESCE(?, last_sync_at) WHERE id = ?`,
		status, nullMillis(syncedAt), id)
}

// MarkProviderRemoved records that a provider left the configuration: it sets
// the observed status and bumps spec_revision, so every plan that took the
// provider as an input is stale from now on.
func MarkProviderRemoved(ctx context.Context, q Querier, id domain.ID, status string) error {
	return updateOne(ctx, q, "provider", `
		UPDATE providers SET status = ?, spec_revision = spec_revision + 1 WHERE id = ?`,
		status, id)
}

// SetNodeMetadata replaces the observed metadata of a node. It never changes
// spec_revision.
func SetNodeMetadata(ctx context.Context, q Querier, id domain.ID, metadata map[string]any) error {
	encoded, err := encodeJSON(metadata)
	if err != nil {
		return err
	}
	return updateOne(ctx, q, "node", `UPDATE nodes SET metadata_json = ? WHERE id = ?`, encoded, id)
}
