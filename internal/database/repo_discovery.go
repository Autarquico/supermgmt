package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// StatusGone is the status of a runtime or service that an earlier discovery
// reported and the latest one no longer does. The row is kept, so its id is
// stable if the thing reappears.
const StatusGone = "gone"

// UpsertRuntime stores the observed runtime r, keyed by (node, type, native id).
// A known runtime keeps its id; version, status, metadata and last_seen_at are
// refreshed. The returned runtime carries the stored id.
func UpsertRuntime(ctx context.Context, q Querier, r domain.Runtime) (domain.Runtime, error) {
	metadata, err := encodeJSON(r.Metadata)
	if err != nil {
		return domain.Runtime{}, err
	}
	row := q.QueryRowContext(ctx, `
		INSERT INTO runtimes (`+runtimeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (node_id, type, native_id) DO UPDATE SET
			version = excluded.version, status = excluded.status,
			metadata_json = excluded.metadata_json, last_seen_at = excluded.last_seen_at
		RETURNING `+runtimeColumns,
		r.ID, r.NodeID, r.Type, r.NativeID, r.Version, r.Status, metadata, nullMillis(r.LastSeenAt))
	stored, err := scanRuntime(row)
	if err != nil {
		return domain.Runtime{}, fmt.Errorf("upsert runtime: %w", err)
	}
	return stored, nil
}

// UpsertService stores the observed service s, keyed by (runtime, native id).
// A known service keeps its id and spec_revision: name, kind, status, health,
// metadata and last_seen_at are observations. s.Kind must be a domain.ServiceKind.
func UpsertService(ctx context.Context, q Querier, s domain.Service) (domain.Service, error) {
	if !domain.ServiceKind(s.Kind).Valid() {
		return domain.Service{}, smerr.New(smerr.CodeInvalidArgument, "", "unknown service kind")
	}
	metadata, err := encodeJSON(s.Metadata)
	if err != nil {
		return domain.Service{}, err
	}
	row := q.QueryRowContext(ctx, `
		INSERT INTO services (`+serviceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (runtime_id, native_id) DO UPDATE SET
			name = excluded.name, kind = excluded.kind, status = excluded.status, health = excluded.health,
			metadata_json = excluded.metadata_json, last_seen_at = excluded.last_seen_at
		RETURNING `+serviceColumns,
		s.ID, s.RuntimeID, s.NodeID, s.NativeID, s.Name, s.Kind, s.Status, s.Health, metadata,
		initialRevision, nullMillis(s.LastSeenAt))
	stored, err := scanService(row)
	if err != nil {
		return domain.Service{}, fmt.Errorf("upsert service: %w", err)
	}
	return stored, nil
}

// RetireMissingServices marks as gone every service of runtime whose native id
// is not in seen. It returns the retired services.
func RetireMissingServices(ctx context.Context, q Querier, runtime domain.ID, seen []string) ([]domain.Service, error) {
	notSeen, args := notIn("native_id", seen)
	return list(ctx, q, "retired services", `
		UPDATE services SET status = ?, health = ''
		WHERE runtime_id = ? AND status <> ? `+notSeen+` RETURNING `+serviceColumns,
		scanService, append([]any{StatusGone, runtime, StatusGone}, args...)...)
}

// RuntimeKey identifies a runtime within its node.
type RuntimeKey struct {
	Type     string
	NativeID string
}

// RetireMissingRuntimes marks as gone every runtime of node that is not in seen,
// together with all of its services. It returns the retired runtimes.
func RetireMissingRuntimes(ctx context.Context, q Querier, node domain.ID, seen []RuntimeKey) ([]domain.Runtime, error) {
	current, err := ListRuntimes(ctx, q, node)
	if err != nil {
		return nil, err
	}
	present := make(map[RuntimeKey]bool, len(seen))
	for _, k := range seen {
		present[k] = true
	}
	var retired []domain.Runtime
	for _, r := range current {
		if present[RuntimeKey{r.Type, r.NativeID}] || r.Status == StatusGone {
			continue
		}
		if _, err := q.ExecContext(ctx, `UPDATE runtimes SET status = ? WHERE id = ?`, StatusGone, r.ID); err != nil {
			return nil, fmt.Errorf("retire runtime: %w", err)
		}
		if _, err := RetireMissingServices(ctx, q, r.ID, nil); err != nil {
			return nil, err
		}
		r.Status = StatusGone
		retired = append(retired, r)
	}
	return retired, nil
}

// notIn builds "AND col NOT IN (?, ...)" for values, or nothing when values is empty.
func notIn(column string, values []string) (string, []any) {
	if len(values) == 0 {
		return "", nil
	}
	args := make([]any, len(values))
	for i, v := range values {
		args[i] = v
	}
	return "AND " + column + " NOT IN (?" + strings.Repeat(", ?", len(values)-1) + ")", args
}

// GetNodeCapability returns one capability of a node, or NOT_FOUND.
func GetNodeCapability(ctx context.Context, q Querier, node domain.ID, capability string) (NodeCapability, error) {
	var (
		c         NodeCapability
		metadata  string
		checkedMs int64
	)
	err := q.QueryRowContext(ctx, `
		SELECT capability, available, metadata_json, checked_at
		FROM node_capabilities WHERE node_id = ? AND capability = ?`, node, capability).
		Scan(&c.Capability, &c.Available, &metadata, &checkedMs)
	if err != nil {
		return NodeCapability{}, getErr(err, "node capability")
	}
	if c.Metadata, err = decodeMap(metadata); err != nil {
		return NodeCapability{}, err
	}
	c.CheckedAt = domain.FromUnixMillis(checkedMs)
	return c, nil
}

// LatestObservations returns, for every resource of the type that has one, the
// newest observation of the kind. Value is a json.RawMessage. Expired
// observations are returned too: the caller shows them as stale (spec §27).
func LatestObservations(ctx context.Context, q Querier, resource domain.ResourceType, kind string) (map[domain.ID]Observation, error) {
	rows, err := list(ctx, q, "latest observations", `
		SELECT id, resource_type, resource_id, kind, value_json, observed_at, expires_at FROM (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY resource_id ORDER BY observed_at DESC, id DESC) AS rank
			FROM observations WHERE resource_type = ? AND kind = ?)
		WHERE rank = 1`, scanObservation, resource, kind)
	if err != nil {
		return nil, err
	}
	out := make(map[domain.ID]Observation, len(rows))
	for _, o := range rows {
		out[o.ResourceID] = o
	}
	return out, nil
}

// LatestObservation returns the newest observation of the kind for one
// resource, or NOT_FOUND. Value is a json.RawMessage.
func LatestObservation(ctx context.Context, q Querier, resource domain.ResourceRef, kind string) (Observation, error) {
	o, err := scanObservation(q.QueryRowContext(ctx, `
		SELECT id, resource_type, resource_id, kind, value_json, observed_at, expires_at
		FROM observations WHERE resource_type = ? AND resource_id = ? AND kind = ?
		ORDER BY observed_at DESC, id DESC LIMIT 1`, resource.Type, resource.ID, kind))
	return o, getErr(err, "observation")
}

func scanObservation(row scanner) (Observation, error) {
	var (
		o          Observation
		value      string
		observedMs int64
		expires    sql.NullInt64
	)
	if err := row.Scan(&o.ID, &o.ResourceType, &o.ResourceID, &o.Kind, &value, &observedMs, &expires); err != nil {
		return Observation{}, err
	}
	o.Value, o.ObservedAt, o.ExpiresAt = json.RawMessage(value), domain.FromUnixMillis(observedMs), timeOf(expires)
	return o, nil
}
