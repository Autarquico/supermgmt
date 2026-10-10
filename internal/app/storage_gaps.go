package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The statements below belong in internal/database, which this task does not
// own. They are kept in one place so moving them is mechanical. Each one is a
// single statement over a table the app already reads through that package.

// resourceLocked reports whether any job holds a lock on the resource itself
// (spec §23: updates to a locked resource are CONFLICT, RESOURCE_LOCKED).
func resourceLocked(ctx context.Context, q database.Querier, ref domain.ResourceRef) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM resource_locks WHERE resource_type = ? AND resource_id = ?`, ref.Type, ref.ID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check locks on %s %s: %w", ref.Type, ref.ID, err)
	}
	return n > 0, nil
}

// environmentConfig mirrors the config_json that database.CreateEnvironment writes.
type environmentConfig struct {
	RequireProvenance      bool `json:"require_provenance"`
	ApprovalsRequired      int  `json:"approvals_required"`
	AllowAutomaticRollback bool `json:"allow_automatic_rollback"`
}

// updateEnvironment rewrites a configured environment and bumps its
// spec_revision (spec §6.4), provided it still has expectedRevision.
func updateEnvironment(ctx context.Context, q database.Querier, e domain.Environment, expectedRevision int64) error {
	config, err := json.Marshal(environmentConfig{e.RequireProvenance, e.ApprovalsRequired, e.AllowAutomaticRollback})
	if err != nil {
		return fmt.Errorf("encode environment config: %w", err)
	}
	res, err := q.ExecContext(ctx,
		`UPDATE environments SET risk_level = ?, config_json = ?, spec_revision = spec_revision + 1
		 WHERE id = ? AND spec_revision = ?`, e.RiskLevel, string(config), e.ID, expectedRevision)
	if err != nil {
		return fmt.Errorf("update environment: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return staleRevision("environment", expectedRevision, expectedRevision)
	}
	return nil
}

// pruneObservations deletes observations older than cutoff, except the newest
// one of every (resource, kind): views always show the latest, however old.
func pruneObservations(ctx context.Context, q database.Querier, cutoff time.Time) (int64, error) {
	res, err := q.ExecContext(ctx, `
		DELETE FROM observations
		WHERE observed_at < ?
		  AND id NOT IN (
		    SELECT id FROM (
		      SELECT id, ROW_NUMBER() OVER (
		        PARTITION BY resource_type, resource_id, kind ORDER BY observed_at DESC, id DESC) AS rank
		      FROM observations)
		    WHERE rank = 1)`, cutoff.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("prune observations: %w", err)
	}
	return res.RowsAffected()
}
