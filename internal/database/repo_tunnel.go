package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// TunnelOperationKind is what a tunnel operation does to a node.
type TunnelOperationKind string

const (
	TunnelEnable  TunnelOperationKind = "enable"
	TunnelDisable TunnelOperationKind = "disable"
)

// TunnelPhase is a step of the tunnel state machine (ADR-0037). The record only stores the phase;
// the order in which phases are walked belongs to the application.
type TunnelPhase string

const (
	PhaseStarted        TunnelPhase = "started"
	PhaseTokenReady     TunnelPhase = "token_ready"
	PhaseTunnelCreated  TunnelPhase = "tunnel_created"
	PhaseIngressSet     TunnelPhase = "ingress_set"
	PhaseAccessReady    TunnelPhase = "access_ready"
	PhaseDNSCreated     TunnelPhase = "dns_created"
	PhaseInstalled      TunnelPhase = "installed"
	PhaseVerified       TunnelPhase = "verified"
	PhaseCommitted      TunnelPhase = "committed"
	PhaseDirectVerified TunnelPhase = "direct_verified"
	PhaseSwitched       TunnelPhase = "switched"
	PhaseServiceRemoved TunnelPhase = "service_removed"
	PhaseRouteClosed    TunnelPhase = "route_closed"
	PhaseAccessRemoved  TunnelPhase = "access_removed"
	PhaseTunnelDeleted  TunnelPhase = "tunnel_deleted"
	PhaseDone           TunnelPhase = "done"
	PhaseFailed         TunnelPhase = "failed"
	PhaseConflict       TunnelPhase = "conflict"
)

// Finished reports whether the phase ends an operation and releases the node.
func (p TunnelPhase) Finished() bool { return p == PhaseCommitted || p == PhaseDone }

// Halted reports whether the operation stopped and waits for an operator or a reconcile.
func (p TunnelPhase) Halted() bool { return p == PhaseFailed || p == PhaseConflict }

// TunnelObjects are the Cloudflare object IDs an operation created. Empty means not created yet.
type TunnelObjects struct {
	TunnelID    string
	DNSRecordID string
	AccessAppID string
}

// TunnelOperation is the per-node operation record.
type TunnelOperation struct {
	ID             domain.ID
	NodeID         domain.ID
	Generation     int64
	Kind           TunnelOperationKind
	Phase          TunnelPhase
	HaltedPhase    TunnelPhase // the phase held when Phase is failed or conflict
	PhaseStartedAt time.Time
	AccountID      string
	Zone           string
	InstanceID     string
	Hostname       string
	Objects        TunnelObjects
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const tunnelOperationColumns = `id, node_id, generation, operation, phase, halted_phase, phase_started_at,
	account_id, zone, instance_id, hostname, tunnel_id, dns_record_id, access_app_id, last_error, created_at, updated_at`

func scanTunnelOperation(s scanner) (TunnelOperation, error) {
	var (
		op                          TunnelOperation
		halted                      sql.NullString
		startedMs, createdMs, updMs int64
	)
	err := s.Scan(&op.ID, &op.NodeID, &op.Generation, &op.Kind, &op.Phase, &halted, &startedMs,
		&op.AccountID, &op.Zone, &op.InstanceID, &op.Hostname,
		&op.Objects.TunnelID, &op.Objects.DNSRecordID, &op.Objects.AccessAppID,
		&op.LastError, &createdMs, &updMs)
	if err != nil {
		return TunnelOperation{}, err
	}
	op.HaltedPhase = TunnelPhase(halted.String)
	op.PhaseStartedAt = domain.FromUnixMillis(startedMs)
	op.CreatedAt = domain.FromUnixMillis(createdMs)
	op.UpdatedAt = domain.FromUnixMillis(updMs)
	return op, nil
}

// CreateTunnelOperation records the start of an operation for op.NodeID. The generation is assigned
// here (one above the node's highest) and the phase is always started; only ID, NodeID, Kind,
// AccountID, Zone, InstanceID, Hostname and CreatedAt of op are used. A node that still has an
// unfinished operation yields CONFLICT.
func CreateTunnelOperation(ctx context.Context, q Querier, op TunnelOperation) (TunnelOperation, error) {
	_, err := q.ExecContext(ctx, `
		INSERT INTO tunnel_operations (id, node_id, generation, operation, phase, phase_started_at,
			account_id, zone, instance_id, hostname, created_at, updated_at)
		VALUES (?, ?, (SELECT COALESCE(MAX(generation), 0) + 1 FROM tunnel_operations WHERE node_id = ?),
			?, 'started', ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.NodeID, op.NodeID, op.Kind, millis(op.CreatedAt),
		op.AccountID, op.Zone, op.InstanceID, op.Hostname, millis(op.CreatedAt), millis(op.CreatedAt))
	if err != nil {
		return TunnelOperation{}, conflictIfDuplicate(err, "active tunnel operation for node")
	}
	return GetTunnelOperation(ctx, q, op.ID)
}

// GetTunnelOperation returns the record, or NOT_FOUND.
func GetTunnelOperation(ctx context.Context, q Querier, id domain.ID) (TunnelOperation, error) {
	op, err := scanTunnelOperation(q.QueryRowContext(ctx,
		`SELECT `+tunnelOperationColumns+` FROM tunnel_operations WHERE id = ?`, id))
	if err != nil {
		return TunnelOperation{}, getErr(err, "tunnel operation")
	}
	return op, nil
}

// ActiveTunnelOperation returns the node's unfinished operation (including halted ones), or NOT_FOUND.
func ActiveTunnelOperation(ctx context.Context, q Querier, nodeID domain.ID) (TunnelOperation, error) {
	op, err := scanTunnelOperation(q.QueryRowContext(ctx,
		`SELECT `+tunnelOperationColumns+` FROM tunnel_operations
		 WHERE node_id = ? AND phase NOT IN ('committed', 'done')`, nodeID))
	if err != nil {
		return TunnelOperation{}, getErr(err, "tunnel operation")
	}
	return op, nil
}

// ListActiveTunnelOperations returns every unfinished operation, oldest first, for reconciliation
// after a takeover or a restore.
func ListActiveTunnelOperations(ctx context.Context, q Querier) ([]TunnelOperation, error) {
	return list(ctx, q, "tunnel operations",
		`SELECT `+tunnelOperationColumns+` FROM tunnel_operations
		 WHERE phase NOT IN ('committed', 'done') ORDER BY created_at, id`,
		scanTunnelOperation)
}

// ListTunnelOperations returns every operation of the node, newest generation first.
func ListTunnelOperations(ctx context.Context, q Querier, nodeID domain.ID) ([]TunnelOperation, error) {
	return list(ctx, q, "tunnel operations",
		`SELECT `+tunnelOperationColumns+` FROM tunnel_operations WHERE node_id = ? ORDER BY generation DESC`,
		scanTunnelOperation, nodeID)
}

// AdvanceTunnelPhase moves the operation to next, recording any non-empty object IDs in the same
// statement, but only while the stored generation and phase still equal the expectation. A halted
// operation resumes through here with expected set to failed or conflict. Otherwise it returns
// CONFLICT (or NOT_FOUND) and changes nothing.
func AdvanceTunnelPhase(ctx context.Context, q Querier, id domain.ID, generation int64,
	expected, next TunnelPhase, objects TunnelObjects, now time.Time,
) (TunnelOperation, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_operations SET phase = ?, halted_phase = NULL, phase_started_at = ?, updated_at = ?,
			last_error = '',
			tunnel_id = COALESCE(NULLIF(?, ''), tunnel_id),
			dns_record_id = COALESCE(NULLIF(?, ''), dns_record_id),
			access_app_id = COALESCE(NULLIF(?, ''), access_app_id)
		WHERE id = ? AND generation = ? AND phase = ?`,
		next, millis(now), millis(now), objects.TunnelID, objects.DNSRecordID, objects.AccessAppID,
		id, generation, expected)
	if err != nil {
		return TunnelOperation{}, fmt.Errorf("advance tunnel operation: %w", err)
	}
	if err := requireTunnelRow(ctx, q, res, id, generation, expected); err != nil {
		return TunnelOperation{}, err
	}
	return GetTunnelOperation(ctx, q, id)
}

// ResumeHaltedTunnelOperation moves a halted operation back to the phase it
// held, keeping phase_started_at: the objects an earlier attempt of that phase
// created stay adoptable. It fails like AdvanceTunnelPhase when the stored
// generation or halted phase differ.
func ResumeHaltedTunnelOperation(ctx context.Context, q Querier, id domain.ID, generation int64,
	halted TunnelPhase, now time.Time,
) (TunnelOperation, error) {
	if !halted.Halted() {
		return TunnelOperation{}, smerr.New(smerr.CodeInvalidArgument, "", "only a failed or conflict operation can be resumed")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_operations SET phase = halted_phase, halted_phase = NULL, last_error = '', updated_at = ?
		WHERE id = ? AND generation = ? AND phase = ? AND halted_phase IS NOT NULL`,
		millis(now), id, generation, halted)
	if err != nil {
		return TunnelOperation{}, fmt.Errorf("resume tunnel operation: %w", err)
	}
	if err := requireTunnelRow(ctx, q, res, id, generation, halted); err != nil {
		return TunnelOperation{}, err
	}
	return GetTunnelOperation(ctx, q, id)
}

// HaltTunnelOperation marks the operation failed or conflict, keeping the phase it was in as
// HaltedPhase, under the same expectation as AdvanceTunnelPhase. lastError must already be sanitized.
func HaltTunnelOperation(ctx context.Context, q Querier, id domain.ID, generation int64,
	expected, halt TunnelPhase, lastError string, now time.Time,
) (TunnelOperation, error) {
	if !halt.Halted() || expected.Halted() {
		return TunnelOperation{}, smerr.New(smerr.CodeInvalidArgument, "", "halt phase must be failed or conflict, from a running phase")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_operations SET phase = ?, halted_phase = phase, last_error = ?, updated_at = ?
		WHERE id = ? AND generation = ? AND phase = ?`,
		halt, lastError, millis(now), id, generation, expected)
	if err != nil {
		return TunnelOperation{}, fmt.Errorf("halt tunnel operation: %w", err)
	}
	if err := requireTunnelRow(ctx, q, res, id, generation, expected); err != nil {
		return TunnelOperation{}, err
	}
	return GetTunnelOperation(ctx, q, id)
}

func requireTunnelRow(ctx context.Context, q Querier, res sql.Result, id domain.ID, generation int64, expected TunnelPhase) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("tunnel operation: %w", err)
	}
	if n > 0 {
		return nil
	}
	current, err := GetTunnelOperation(ctx, q, id)
	if err != nil {
		return err
	}
	e := smerr.New(smerr.CodeConflict, "", "tunnel operation changed concurrently")
	e.Details = map[string]any{
		"expected_generation": generation, "current_generation": current.Generation,
		"expected_phase": string(expected), "current_phase": string(current.Phase),
	}
	return e
}

// ---- instance-wide Cloudflare state ----------------------------------------

// RotationPhase is where a service-token rotation stands.
type RotationPhase string

const (
	RotationIdle          RotationPhase = "idle"
	RotationCreated       RotationPhase = "created"
	RotationPolicyUpdated RotationPhase = "policy_updated"
	RotationRetiring      RotationPhase = "retiring"
)

// CloudflareToken identifies one Access service token. The secret is never stored here.
type CloudflareToken struct {
	ID        string
	Name      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CloudflareState is the single instance-wide row. Revision is 0 until stored.
type CloudflareState struct {
	Revision        int64
	AccountID       string
	Token           CloudflareToken
	Rotation        RotationPhase
	Pending         *CloudflareToken // the new token while Rotation is not idle
	ServicePolicyID string
	OwnersPolicyID  string
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// GetCloudflareState returns the state, or NOT_FOUND before the service token is first initialised.
func GetCloudflareState(ctx context.Context, q Querier) (CloudflareState, error) {
	var (
		s                                        CloudflareState
		tokCreated, tokExpires, created, updated int64
		pendCreated, pendExpires                 sql.NullInt64
		pending                                  CloudflareToken
	)
	err := q.QueryRowContext(ctx, `
		SELECT revision, account_id, service_token_id, service_token_name, service_token_created_at,
			service_token_expires_at, rotation_phase, pending_token_id, pending_token_name,
			pending_token_created_at, pending_token_expires_at, service_policy_id, owners_policy_id,
			last_error, created_at, updated_at
		FROM cloudflare_state WHERE id = 1`).Scan(&s.Revision, &s.AccountID, &s.Token.ID, &s.Token.Name,
		&tokCreated, &tokExpires, &s.Rotation, &pending.ID, &pending.Name, &pendCreated, &pendExpires,
		&s.ServicePolicyID, &s.OwnersPolicyID, &s.LastError, &created, &updated)
	if err != nil {
		return CloudflareState{}, getErr(err, "cloudflare state")
	}
	s.Token.CreatedAt, s.Token.ExpiresAt = domain.FromUnixMillis(tokCreated), domain.FromUnixMillis(tokExpires)
	if pending.ID != "" {
		pending.CreatedAt, pending.ExpiresAt = domain.FromUnixMillis(pendCreated.Int64), domain.FromUnixMillis(pendExpires.Int64)
		s.Pending = &pending
	}
	s.CreatedAt, s.UpdatedAt = domain.FromUnixMillis(created), domain.FromUnixMillis(updated)
	return s, nil
}

// SaveCloudflareState writes s (stamped now) provided the stored revision equals expectedRevision;
// 0 means no row exists yet. Otherwise CONFLICT and nothing changes. The new revision is
// expectedRevision+1; CreatedAt of an existing row is kept.
func SaveCloudflareState(ctx context.Context, q Querier, s CloudflareState, expectedRevision int64, now time.Time) (CloudflareState, error) {
	var (
		pending                  CloudflareToken
		pendCreated, pendExpires sql.NullInt64
	)
	if s.Pending != nil {
		pending = *s.Pending
		pendCreated = sql.NullInt64{Int64: millis(pending.CreatedAt), Valid: true}
		pendExpires = sql.NullInt64{Int64: millis(pending.ExpiresAt), Valid: true}
	}
	rotation := s.Rotation
	if rotation == "" {
		rotation = RotationIdle
	}
	res, err := q.ExecContext(ctx, `
		INSERT INTO cloudflare_state (id, revision, account_id, service_token_id, service_token_name,
			service_token_created_at, service_token_expires_at, rotation_phase, pending_token_id,
			pending_token_name, pending_token_created_at, pending_token_expires_at, service_policy_id,
			owners_policy_id, last_error, created_at, updated_at)
		SELECT 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE ? = 0 OR EXISTS (SELECT 1 FROM cloudflare_state)
		ON CONFLICT (id) DO UPDATE SET revision = excluded.revision, account_id = excluded.account_id,
			service_token_id = excluded.service_token_id, service_token_name = excluded.service_token_name,
			service_token_created_at = excluded.service_token_created_at,
			service_token_expires_at = excluded.service_token_expires_at,
			rotation_phase = excluded.rotation_phase, pending_token_id = excluded.pending_token_id,
			pending_token_name = excluded.pending_token_name,
			pending_token_created_at = excluded.pending_token_created_at,
			pending_token_expires_at = excluded.pending_token_expires_at,
			service_policy_id = excluded.service_policy_id, owners_policy_id = excluded.owners_policy_id,
			last_error = excluded.last_error, updated_at = excluded.updated_at
		WHERE cloudflare_state.revision = ?`,
		expectedRevision+1, s.AccountID, s.Token.ID, s.Token.Name, millis(s.Token.CreatedAt), millis(s.Token.ExpiresAt),
		rotation, pending.ID, pending.Name, pendCreated, pendExpires, s.ServicePolicyID, s.OwnersPolicyID,
		s.LastError, millis(now), millis(now), expectedRevision, expectedRevision)
	if err != nil {
		return CloudflareState{}, fmt.Errorf("save cloudflare state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return CloudflareState{}, fmt.Errorf("save cloudflare state: %w", err)
	}
	if n == 0 {
		return CloudflareState{}, smerr.New(smerr.CodeConflict, "", "cloudflare state changed concurrently")
	}
	return GetCloudflareState(ctx, q)
}
