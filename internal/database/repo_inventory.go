package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Every Create* below stores spec_revision = 1; the returned entity carries it.
// Only the Update*Spec functions change a revision (spec §6.4).
const initialRevision = 1

// ---- environments ----------------------------------------------------------

type environmentConfig struct {
	RequireProvenance      bool `json:"require_provenance"`
	ApprovalsRequired      int  `json:"approvals_required"`
	AllowAutomaticRollback bool `json:"allow_automatic_rollback"`
}

func CreateEnvironment(ctx context.Context, q Querier, e domain.Environment) (domain.Environment, error) {
	config, err := encodeJSON(environmentConfig{e.RequireProvenance, e.ApprovalsRequired, e.AllowAutomaticRollback})
	if err != nil {
		return domain.Environment{}, err
	}
	_, err = q.ExecContext(ctx,
		`INSERT INTO environments (id, name, risk_level, config_json, spec_revision) VALUES (?, ?, ?, ?, ?)`,
		e.ID, e.Name, e.RiskLevel, config, initialRevision)
	if err != nil {
		return domain.Environment{}, conflictIfDuplicate(err, "environment")
	}
	e.SpecRevision = initialRevision
	return e, nil
}

const environmentColumns = `id, name, risk_level, config_json, spec_revision`

func scanEnvironment(row scanner) (domain.Environment, error) {
	var (
		e      domain.Environment
		config string
	)
	if err := row.Scan(&e.ID, &e.Name, &e.RiskLevel, &config, &e.SpecRevision); err != nil {
		return domain.Environment{}, err
	}
	var c environmentConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return domain.Environment{}, fmt.Errorf("decode environment config: %w", err)
	}
	e.RequireProvenance, e.ApprovalsRequired, e.AllowAutomaticRollback =
		c.RequireProvenance, c.ApprovalsRequired, c.AllowAutomaticRollback
	return e, nil
}

func GetEnvironment(ctx context.Context, q Querier, id domain.ID) (domain.Environment, error) {
	e, err := scanEnvironment(q.QueryRowContext(ctx,
		`SELECT `+environmentColumns+` FROM environments WHERE id = ?`, id))
	return e, getErr(err, "environment")
}

func ListEnvironments(ctx context.Context, q Querier) ([]domain.Environment, error) {
	return list(ctx, q, "environments", `SELECT `+environmentColumns+` FROM environments ORDER BY name`,
		scanEnvironment)
}

// ---- providers -------------------------------------------------------------

const providerColumns = `id, type, name, origin, endpoint, credential_ref, config_json, status,
	spec_revision, last_sync_at, created_at, updated_at`

func CreateProvider(ctx context.Context, q Querier, p domain.Provider) (domain.Provider, error) {
	config, err := encodeJSON(p.Config)
	if err != nil {
		return domain.Provider{}, err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO providers (`+providerColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Type, p.Name, p.Origin, p.Endpoint, p.CredentialRef, config, p.Status,
		initialRevision, nullMillis(p.LastSyncAt), millis(p.CreatedAt), millis(p.UpdatedAt))
	if err != nil {
		return domain.Provider{}, conflictIfDuplicate(err, "provider")
	}
	p.SpecRevision = initialRevision
	return p, nil
}

func scanProvider(row scanner) (domain.Provider, error) {
	var (
		p                        domain.Provider
		config                   string
		lastSync                 sql.NullInt64
		createdAtMs, updatedAtMs int64
	)
	if err := row.Scan(&p.ID, &p.Type, &p.Name, &p.Origin, &p.Endpoint, &p.CredentialRef, &config,
		&p.Status, &p.SpecRevision, &lastSync, &createdAtMs, &updatedAtMs); err != nil {
		return domain.Provider{}, err
	}
	var err error
	if p.Config, err = decodeMap(config); err != nil {
		return domain.Provider{}, err
	}
	p.LastSyncAt = timeOf(lastSync)
	p.CreatedAt, p.UpdatedAt = domain.FromUnixMillis(createdAtMs), domain.FromUnixMillis(updatedAtMs)
	return p, nil
}

func GetProvider(ctx context.Context, q Querier, id domain.ID) (domain.Provider, error) {
	p, err := scanProvider(q.QueryRowContext(ctx, `SELECT `+providerColumns+` FROM providers WHERE id = ?`, id))
	return p, getErr(err, "provider")
}

func ListProviders(ctx context.Context, q Querier) ([]domain.Provider, error) {
	return list(ctx, q, "providers", `SELECT `+providerColumns+` FROM providers ORDER BY name`, scanProvider)
}

// ---- nodes -----------------------------------------------------------------

type endpointRecord struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	User               string `json:"user"`
	AdminUser          string `json:"admin_user"`
	AdminCredentialRef string `json:"admin_credential_ref"`
	HostPublicKey      string `json:"host_public_key"`
}

const nodeColumns = `id, provider_id, native_id, name, kind, environment_id, management_state, reachability,
	endpoint_json, credential_ref, os, arch, metadata_json, spec_revision, created_at, updated_at, last_seen_at`

func scanNode(row scanner) (domain.Node, error) {
	var (
		n                    domain.Node
		environment          sql.NullString
		endpoint, metadata   string
		createdMs, updatedMs int64
		lastSeen             sql.NullInt64
	)
	if err := row.Scan(&n.ID, &n.ProviderID, &n.NativeID, &n.Name, &n.Kind, &environment,
		&n.ManagementState, &n.Reachability, &endpoint, &n.CredentialRef, &n.OS, &n.Arch, &metadata,
		&n.SpecRevision, &createdMs, &updatedMs, &lastSeen); err != nil {
		return domain.Node{}, err
	}
	var rec endpointRecord
	if err := json.Unmarshal([]byte(endpoint), &rec); err != nil {
		return domain.Node{}, fmt.Errorf("decode node endpoint: %w", err)
	}
	var err error
	if n.Metadata, err = decodeMap(metadata); err != nil {
		return domain.Node{}, err
	}
	n.Endpoint = domain.NodeEndpoint(rec)
	n.EnvironmentID = idOf(environment)
	n.CreatedAt, n.UpdatedAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(updatedMs)
	n.LastSeenAt = timeOf(lastSeen)
	return n, nil
}

// CreateNode stores n and its tags.
func CreateNode(ctx context.Context, q Querier, n domain.Node) (domain.Node, error) {
	endpoint, err := encodeJSON(endpointRecord(n.Endpoint))
	if err != nil {
		return domain.Node{}, err
	}
	metadata, err := encodeJSON(n.Metadata)
	if err != nil {
		return domain.Node{}, err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO nodes (`+nodeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.ProviderID, n.NativeID, n.Name, n.Kind, nullID(n.EnvironmentID), n.ManagementState,
		n.Reachability, endpoint, n.CredentialRef, n.OS, n.Arch, metadata, initialRevision,
		millis(n.CreatedAt), millis(n.UpdatedAt), nullMillis(n.LastSeenAt))
	if err != nil {
		return domain.Node{}, conflictIfDuplicate(err, "node")
	}
	if err := insertTags(ctx, q, n.ID, n.Tags); err != nil {
		return domain.Node{}, err
	}
	return GetNode(ctx, q, n.ID)
}

func insertTags(ctx context.Context, q Querier, node domain.ID, tags []string) error {
	for _, tag := range tags {
		if _, err := q.ExecContext(ctx,
			`INSERT OR IGNORE INTO node_tags (node_id, tag) VALUES (?, ?)`, node, tag); err != nil {
			return fmt.Errorf("insert node tag: %w", err)
		}
	}
	return nil
}

func GetNode(ctx context.Context, q Querier, id domain.ID) (domain.Node, error) {
	n, err := scanNode(q.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id))
	if err != nil {
		return domain.Node{}, getErr(err, "node")
	}
	tags, err := tagsOf(ctx, q, `WHERE node_id = ?`, id)
	if err != nil {
		return domain.Node{}, err
	}
	n.Tags = tags[n.ID]
	return n, nil
}

// ListNodes returns every node ordered by name, tags included.
func ListNodes(ctx context.Context, q Querier) ([]domain.Node, error) {
	nodes, err := list(ctx, q, "nodes", `SELECT `+nodeColumns+` FROM nodes ORDER BY name, id`, scanNode)
	if err != nil {
		return nil, err
	}
	tags, err := tagsOf(ctx, q, ``)
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		nodes[i].Tags = tags[nodes[i].ID]
	}
	return nodes, nil
}

func tagsOf(ctx context.Context, q Querier, where string, args ...any) (map[domain.ID][]string, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT node_id, tag FROM node_tags `+where+` ORDER BY node_id, tag`, args...)
	if err != nil {
		return nil, fmt.Errorf("list node tags: %w", err)
	}
	defer rows.Close()
	tags := map[domain.ID][]string{}
	for rows.Next() {
		var (
			node domain.ID
			tag  string
		)
		if err := rows.Scan(&node, &tag); err != nil {
			return nil, fmt.Errorf("scan node tag: %w", err)
		}
		tags[node] = append(tags[node], tag)
	}
	return tags, rows.Err()
}

// UpdateNodeSpec writes the CONFIGURED fields of n (name, kind, environment,
// management state, endpoint, credential reference, tags) and bumps
// spec_revision, provided the stored revision still equals expectedRev;
// otherwise it returns CONFLICT. Observed fields (reachability, os, arch,
// metadata, last_seen_at) are never written here. n.UpdatedAt stamps the row.
func UpdateNodeSpec(ctx context.Context, q Querier, n domain.Node, expectedRev int64) (domain.Node, error) {
	endpoint, err := encodeJSON(endpointRecord(n.Endpoint))
	if err != nil {
		return domain.Node{}, err
	}
	res, err := q.ExecContext(ctx, `
		UPDATE nodes SET name = ?, kind = ?, environment_id = ?, management_state = ?, endpoint_json = ?,
		                 credential_ref = ?, updated_at = ?, spec_revision = spec_revision + 1
		WHERE id = ? AND spec_revision = ?`,
		n.Name, n.Kind, nullID(n.EnvironmentID), n.ManagementState, endpoint,
		n.CredentialRef, millis(n.UpdatedAt), n.ID, expectedRev)
	if err != nil {
		return domain.Node{}, conflictIfDuplicate(err, "node")
	}
	if affected, err := res.RowsAffected(); err != nil {
		return domain.Node{}, fmt.Errorf("update node: %w", err)
	} else if affected == 0 {
		return domain.Node{}, staleOrMissing(ctx, q, "nodes", n.ID, expectedRev)
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM node_tags WHERE node_id = ?`, n.ID); err != nil {
		return domain.Node{}, fmt.Errorf("replace node tags: %w", err)
	}
	if err := insertTags(ctx, q, n.ID, n.Tags); err != nil {
		return domain.Node{}, err
	}
	return GetNode(ctx, q, n.ID)
}

// staleOrMissing explains a zero-row guarded update: NOT_FOUND or revision CONFLICT.
func staleOrMissing(ctx context.Context, q Querier, table string, id domain.ID, expectedRev int64) error {
	var current int64
	err := q.QueryRowContext(ctx, `SELECT spec_revision FROM `+table+` WHERE id = ?`, id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return notFound(table)
	}
	if err != nil {
		return fmt.Errorf("read %s revision: %w", table, err)
	}
	e := smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"%s changed concurrently: expected spec_revision %d, found %d", table, expectedRev, current))
	e.Details = map[string]any{"expected_spec_revision": expectedRev, "current_spec_revision": current}
	return e
}

// ---- node observations (never touch spec_revision) -------------------------

// SetNodeReachability records the observed reachability.
func SetNodeReachability(ctx context.Context, q Querier, id domain.ID, r domain.Reachability) error {
	return updateOne(ctx, q, "node", `UPDATE nodes SET reachability = ? WHERE id = ?`, r, id)
}

// TouchLastSeen records when a node was last observed.
func TouchLastSeen(ctx context.Context, q Querier, id domain.ID, at time.Time) error {
	return updateOne(ctx, q, "node", `UPDATE nodes SET last_seen_at = ? WHERE id = ?`, millis(at), id)
}

// NodeCapability is a discovered capability of a node (observed state).
type NodeCapability struct {
	Capability string
	Available  bool
	Metadata   map[string]any
	CheckedAt  time.Time
}

// SetNodeCapability upserts a discovered capability.
func SetNodeCapability(ctx context.Context, q Querier, node domain.ID, c NodeCapability) error {
	metadata, err := encodeJSON(c.Metadata)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO node_capabilities (node_id, capability, available, metadata_json, checked_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (node_id, capability) DO UPDATE SET
			available = excluded.available, metadata_json = excluded.metadata_json,
			checked_at = excluded.checked_at`,
		node, c.Capability, c.Available, metadata, millis(c.CheckedAt))
	if err != nil {
		return fmt.Errorf("set node capability: %w", err)
	}
	return nil
}

func ListNodeCapabilities(ctx context.Context, q Querier, node domain.ID) ([]NodeCapability, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT capability, available, metadata_json, checked_at
		FROM node_capabilities WHERE node_id = ? ORDER BY capability`, node)
	if err != nil {
		return nil, fmt.Errorf("list node capabilities: %w", err)
	}
	defer rows.Close()
	var caps []NodeCapability
	for rows.Next() {
		var (
			c         NodeCapability
			metadata  string
			checkedMs int64
		)
		if err := rows.Scan(&c.Capability, &c.Available, &metadata, &checkedMs); err != nil {
			return nil, fmt.Errorf("scan node capability: %w", err)
		}
		if c.Metadata, err = decodeMap(metadata); err != nil {
			return nil, err
		}
		c.CheckedAt = domain.FromUnixMillis(checkedMs)
		caps = append(caps, c)
	}
	return caps, rows.Err()
}

// Observation is one observed fact about a resource (spec §6.4).
type Observation struct {
	ID           domain.ID
	ResourceType domain.ResourceType
	ResourceID   domain.ID
	Kind         string
	Value        any
	ObservedAt   time.Time
	ExpiresAt    *time.Time
}

// RecordObservation appends an observation. It never changes any spec_revision.
func RecordObservation(ctx context.Context, q Querier, o Observation) error {
	value, err := encodeJSON(o.Value)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO observations (id, resource_type, resource_id, kind, value_json, observed_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.ResourceType, o.ResourceID, o.Kind, value, millis(o.ObservedAt), nullMillis(o.ExpiresAt))
	if err != nil {
		return conflictIfDuplicate(err, "observation")
	}
	return nil
}

// ---- runtimes and services -------------------------------------------------

const runtimeColumns = `id, node_id, type, native_id, version, status, metadata_json, last_seen_at`

func CreateRuntime(ctx context.Context, q Querier, r domain.Runtime) error {
	metadata, err := encodeJSON(r.Metadata)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO runtimes (`+runtimeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.NodeID, r.Type, r.NativeID, r.Version, r.Status, metadata, nullMillis(r.LastSeenAt))
	if err != nil {
		return conflictIfDuplicate(err, "runtime")
	}
	return nil
}

func scanRuntime(row scanner) (domain.Runtime, error) {
	var (
		r        domain.Runtime
		metadata string
		lastSeen sql.NullInt64
	)
	if err := row.Scan(&r.ID, &r.NodeID, &r.Type, &r.NativeID, &r.Version, &r.Status, &metadata, &lastSeen); err != nil {
		return domain.Runtime{}, err
	}
	var err error
	if r.Metadata, err = decodeMap(metadata); err != nil {
		return domain.Runtime{}, err
	}
	r.LastSeenAt = timeOf(lastSeen)
	return r, nil
}

func GetRuntime(ctx context.Context, q Querier, id domain.ID) (domain.Runtime, error) {
	r, err := scanRuntime(q.QueryRowContext(ctx, `SELECT `+runtimeColumns+` FROM runtimes WHERE id = ?`, id))
	return r, getErr(err, "runtime")
}

func ListRuntimes(ctx context.Context, q Querier, node domain.ID) ([]domain.Runtime, error) {
	return list(ctx, q, "runtimes",
		`SELECT `+runtimeColumns+` FROM runtimes WHERE node_id = ? ORDER BY type, native_id`, scanRuntime, node)
}

const serviceColumns = `id, runtime_id, node_id, native_id, name, kind, status, health, metadata_json,
	spec_revision, last_seen_at`

func CreateService(ctx context.Context, q Querier, s domain.Service) (domain.Service, error) {
	metadata, err := encodeJSON(s.Metadata)
	if err != nil {
		return domain.Service{}, err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO services (`+serviceColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.RuntimeID, s.NodeID, s.NativeID, s.Name, s.Kind, s.Status, s.Health, metadata,
		initialRevision, nullMillis(s.LastSeenAt))
	if err != nil {
		return domain.Service{}, conflictIfDuplicate(err, "service")
	}
	s.SpecRevision = initialRevision
	return s, nil
}

func scanService(row scanner) (domain.Service, error) {
	var (
		s        domain.Service
		metadata string
		lastSeen sql.NullInt64
	)
	if err := row.Scan(&s.ID, &s.RuntimeID, &s.NodeID, &s.NativeID, &s.Name, &s.Kind, &s.Status, &s.Health,
		&metadata, &s.SpecRevision, &lastSeen); err != nil {
		return domain.Service{}, err
	}
	var err error
	if s.Metadata, err = decodeMap(metadata); err != nil {
		return domain.Service{}, err
	}
	s.LastSeenAt = timeOf(lastSeen)
	return s, nil
}

func GetService(ctx context.Context, q Querier, id domain.ID) (domain.Service, error) {
	s, err := scanService(q.QueryRowContext(ctx, `SELECT `+serviceColumns+` FROM services WHERE id = ?`, id))
	return s, getErr(err, "service")
}

func ListServices(ctx context.Context, q Querier, node domain.ID) ([]domain.Service, error) {
	return list(ctx, q, "services",
		`SELECT `+serviceColumns+` FROM services WHERE node_id = ? ORDER BY name, id`, scanService, node)
}

// ---- shared helpers --------------------------------------------------------

// getErr maps sql.ErrNoRows to NOT_FOUND and wraps everything else.
func getErr(err error, what string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return notFound(what)
	default:
		return fmt.Errorf("get %s: %w", what, err)
	}
}

func list[T any](ctx context.Context, q Querier, what, query string, scan func(scanner) (T, error), args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", what, err)
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", what, err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list %s: %w", what, err)
	}
	return out, nil
}

// updateOne runs a single-row UPDATE and reports NOT_FOUND when nothing matched.
func updateOne(ctx context.Context, q Querier, what, query string, args ...any) error {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update %s: %w", what, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update %s: %w", what, err)
	}
	if affected == 0 {
		return notFound(what)
	}
	return nil
}
