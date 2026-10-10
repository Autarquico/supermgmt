package database

import (
	"context"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ResourceLocked reports whether any job holds a lock on the resource itself
// (spec §23: updates to a locked resource are CONFLICT, RESOURCE_LOCKED).
func ResourceLocked(ctx context.Context, q Querier, ref domain.ResourceRef) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM resource_locks WHERE resource_type = ? AND resource_id = ?`, ref.Type, ref.ID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check locks on %s %s: %w", ref.Type, ref.ID, err)
	}
	return n > 0, nil
}

// UpdateEnvironmentSpec rewrites the configured fields of e (risk level and
// config) and bumps spec_revision, provided the stored revision still equals
// expectedRev; otherwise CONFLICT (or NOT_FOUND). The name is never changed.
func UpdateEnvironmentSpec(ctx context.Context, q Querier, e domain.Environment, expectedRev int64) (domain.Environment, error) {
	config, err := encodeJSON(environmentConfig{e.RequireProvenance, e.ApprovalsRequired, e.AllowAutomaticRollback})
	if err != nil {
		return domain.Environment{}, err
	}
	res, err := q.ExecContext(ctx, `
		UPDATE environments SET risk_level = ?, config_json = ?, spec_revision = spec_revision + 1
		WHERE id = ? AND spec_revision = ?`, e.RiskLevel, config, e.ID, expectedRev)
	if err != nil {
		return domain.Environment{}, fmt.Errorf("update environment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return domain.Environment{}, fmt.Errorf("update environment: %w", err)
	}
	if n == 0 {
		return domain.Environment{}, staleOrMissing(ctx, q, "environments", e.ID, expectedRev)
	}
	return GetEnvironment(ctx, q, e.ID)
}

// PruneObservations deletes observations older than cutoff, except the newest
// one of every (resource, kind): views always show the latest, however old.
func PruneObservations(ctx context.Context, q Querier, cutoff time.Time) (int64, error) {
	res, err := q.ExecContext(ctx, `
		DELETE FROM observations
		WHERE observed_at < ?
		  AND id NOT IN (
		    SELECT id FROM (
		      SELECT id, ROW_NUMBER() OVER (
		        PARTITION BY resource_type, resource_id, kind ORDER BY observed_at DESC, id DESC) AS rank
		      FROM observations)
		    WHERE rank = 1)`, millis(cutoff))
	if err != nil {
		return 0, fmt.Errorf("prune observations: %w", err)
	}
	return res.RowsAffected()
}

// SetNodeSystem records the observed operating system and architecture. It
// never touches spec_revision.
func SetNodeSystem(ctx context.Context, q Querier, id domain.ID, os, arch string) error {
	return updateOne(ctx, q, "node", `UPDATE nodes SET os = ?, arch = ? WHERE id = ?`, os, arch, id)
}
