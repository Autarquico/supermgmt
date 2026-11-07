package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// NodeRoutePhase is a step of an node route's state machine (ADR-0040). A halted route is in NodeRouteFailed or
// NodeRouteConflict and keeps the phase it held in HaltedPhase.
type NodeRoutePhase string

const (
	NodeRouteAdmitted       NodeRoutePhase = "admitted"
	NodeRouteProvisioning   NodeRoutePhase = "provisioning"
	NodeRouteIngressReady   NodeRoutePhase = "ingress_ready"
	NodeRouteAccessReady    NodeRoutePhase = "access_ready"
	NodeRouteActive         NodeRoutePhase = "active"
	NodeRouteRemoving       NodeRoutePhase = "removing"
	NodeRouteDNSRemoved     NodeRoutePhase = "dns_removed"
	NodeRouteIngressRemoved NodeRoutePhase = "ingress_removed"
	NodeRouteRemoved        NodeRoutePhase = "removed"
	NodeRouteFailed         NodeRoutePhase = "failed"
	NodeRouteConflict       NodeRoutePhase = "conflict"
)

// Halted reports whether the route stopped and waits for an operator or a reconcile.
func (p NodeRoutePhase) Halted() bool { return p == NodeRouteFailed || p == NodeRouteConflict }

// NodeRouteObjects are the Cloudflare object IDs a route created. Empty means not created yet.
type NodeRouteObjects struct {
	DNSRecordID string
	AccessAppID string
}

// NodeRoute is the record of one hostname published through a node's tunnel to one of its ports.
type NodeRoute struct {
	ID               domain.ID
	NodeID           domain.ID
	Hostname         string // canonical: lowercase
	Port             int
	Access           string // public | owners
	Phase            NodeRoutePhase
	HaltedPhase      NodeRoutePhase // the phase held when Phase is failed or conflict
	PhaseStartedAt   time.Time
	AccountID        string
	Zone             string
	InstanceID       string
	TunnelID         string
	TunnelGeneration int64
	Objects          NodeRouteObjects
	PlanID           *domain.ID // the plan whose admission wrote the row
	LastError        string
	CreatedBy        domain.ID
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// NodeRouteFilter narrows ListNodeRoutes. Zero fields match everything; removed routes are left out unless
// IncludeRemoved is set.
type NodeRouteFilter struct {
	NodeID         domain.ID
	IncludeRemoved bool
}

const nodeRouteColumns = `id, node_id, hostname, port, access, phase, halted_phase,
	phase_started_at, account_id, zone, instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id,
	plan_id, last_error, created_by, created_at, updated_at`

func scanNodeRoute(s scanner) (NodeRoute, error) {
	var (
		r                           NodeRoute
		halted, planID              sql.NullString
		startedMs, createdMs, updMs int64
	)
	err := s.Scan(&r.ID, &r.NodeID, &r.Hostname, &r.Port, &r.Access, &r.Phase, &halted,
		&startedMs, &r.AccountID, &r.Zone, &r.InstanceID, &r.TunnelID, &r.TunnelGeneration,
		&r.Objects.DNSRecordID, &r.Objects.AccessAppID, &planID, &r.LastError, &r.CreatedBy, &createdMs, &updMs)
	if err != nil {
		return NodeRoute{}, err
	}
	r.HaltedPhase = NodeRoutePhase(halted.String)
	if planID.Valid {
		id := domain.ID(planID.String)
		r.PlanID = &id
	}
	r.PhaseStartedAt = domain.FromUnixMillis(startedMs)
	r.CreatedAt = domain.FromUnixMillis(createdMs)
	r.UpdatedAt = domain.FromUnixMillis(updMs)
	return r, nil
}

// InsertNodeRoute records an accepted route. The phase is always admitted; every field of r but Phase,
// HaltedPhase, PhaseStartedAt, Objects, LastError and UpdatedAt is used. A nil PlanID stores NULL. A hostname or node port that has a live route
// yields CONFLICT.
func InsertNodeRoute(ctx context.Context, q Querier, r NodeRoute) (NodeRoute, error) {
	_, err := q.ExecContext(ctx, `
		INSERT INTO node_routes (id, node_id, hostname, port, access, phase, phase_started_at,
			account_id, zone, instance_id, tunnel_id, tunnel_generation, plan_id, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'admitted', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.NodeID, r.Hostname, r.Port, r.Access, millis(r.CreatedAt),
		r.AccountID, r.Zone, r.InstanceID, r.TunnelID, r.TunnelGeneration, r.PlanID, r.CreatedBy, millis(r.CreatedAt), millis(r.CreatedAt))
	if err != nil {
		return NodeRoute{}, conflictIfDuplicate(err, "live node route for hostname or port")
	}
	return GetNodeRoute(ctx, q, r.ID)
}

// GetNodeRoute returns the route, or NOT_FOUND.
func GetNodeRoute(ctx context.Context, q Querier, id domain.ID) (NodeRoute, error) {
	r, err := scanNodeRoute(q.QueryRowContext(ctx, `SELECT `+nodeRouteColumns+` FROM node_routes WHERE id = ?`, id))
	if err != nil {
		return NodeRoute{}, getErr(err, "node route")
	}
	return r, nil
}

// GetNodeRouteByPlan returns the route that the admission of the plan wrote, in any phase, or NOT_FOUND.
func GetNodeRouteByPlan(ctx context.Context, q Querier, planID domain.ID) (NodeRoute, error) {
	r, err := scanNodeRoute(q.QueryRowContext(ctx, `SELECT `+nodeRouteColumns+` FROM node_routes WHERE plan_id = ?`, planID))
	if err != nil {
		return NodeRoute{}, getErr(err, "node route")
	}
	return r, nil
}

// GetLiveNodeRouteByHostname returns the hostname's route that is not removed (halted ones included), or NOT_FOUND.
func GetLiveNodeRouteByHostname(ctx context.Context, q Querier, hostname string) (NodeRoute, error) {
	r, err := scanNodeRoute(q.QueryRowContext(ctx,
		`SELECT `+nodeRouteColumns+` FROM node_routes WHERE hostname = ? AND phase <> 'removed'`, hostname))
	if err != nil {
		return NodeRoute{}, getErr(err, "node route")
	}
	return r, nil
}

// GetLiveNodeRouteByNodePort returns the route that publishes the node's port and is not removed (halted ones
// included), or NOT_FOUND.
func GetLiveNodeRouteByNodePort(ctx context.Context, q Querier, nodeID domain.ID, port int) (NodeRoute, error) {
	r, err := scanNodeRoute(q.QueryRowContext(ctx,
		`SELECT `+nodeRouteColumns+` FROM node_routes WHERE node_id = ? AND port = ? AND phase <> 'removed'`, nodeID, port))
	if err != nil {
		return NodeRoute{}, getErr(err, "node route")
	}
	return r, nil
}

// ListNodeRoutes returns the routes matching the filter, oldest first.
func ListNodeRoutes(ctx context.Context, q Querier, f NodeRouteFilter) ([]NodeRoute, error) {
	var (
		where []string
		args  []any
	)
	if f.NodeID != "" {
		where, args = append(where, "node_id = ?"), append(args, f.NodeID)
	}
	if !f.IncludeRemoved {
		where = append(where, "phase <> 'removed'")
	}
	query := `SELECT ` + nodeRouteColumns + ` FROM node_routes`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	return list(ctx, q, "node routes", query+` ORDER BY created_at, id`, scanNodeRoute, args...)
}

// CountLiveNodeRoutesByNode counts the node's routes that are not removed, halted ones included.
func CountLiveNodeRoutesByNode(ctx context.Context, q Querier, nodeID domain.ID) (int, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM node_routes WHERE node_id = ? AND phase <> 'removed'`, nodeID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count node routes: %w", err)
	}
	return n, nil
}

// AdvanceNodeRoutePhase moves the route from to next, recording any non-empty object IDs in the same
// statement, but only while the stored phase still equals from. Otherwise CONFLICT (or NOT_FOUND) and nothing changes.
func AdvanceNodeRoutePhase(ctx context.Context, q Querier, id domain.ID,
	from, to NodeRoutePhase, objects NodeRouteObjects, now time.Time,
) (NodeRoute, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE node_routes SET phase = ?, halted_phase = NULL, phase_started_at = ?, updated_at = ?, last_error = '',
			dns_record_id = COALESCE(NULLIF(?, ''), dns_record_id),
			access_app_id = COALESCE(NULLIF(?, ''), access_app_id)
		WHERE id = ? AND phase = ?`,
		to, millis(now), millis(now), objects.DNSRecordID, objects.AccessAppID, id, from)
	return finishNodeRouteUpdate(ctx, q, res, err, "advance", id, from)
}

// HaltNodeRoute marks the route failed or conflict, keeping its phase as HaltedPhase, under the same
// expectation as AdvanceNodeRoutePhase. lastError must already be sanitized.
func HaltNodeRoute(ctx context.Context, q Querier, id domain.ID,
	from, halt NodeRoutePhase, lastError string, now time.Time,
) (NodeRoute, error) {
	if !halt.Halted() || from.Halted() || from == NodeRouteRemoved {
		return NodeRoute{}, smerr.New(smerr.CodeInvalidArgument, "", "halt phase must be failed or conflict, from a running phase")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE node_routes SET phase = ?, halted_phase = phase, last_error = ?, updated_at = ?
		WHERE id = ? AND phase = ?`, halt, lastError, millis(now), id, from)
	return finishNodeRouteUpdate(ctx, q, res, err, "halt", id, from)
}

// ResumeHaltedNodeRoute moves a halted route back to the phase it held, keeping phase_started_at: the objects
// an earlier attempt of that phase created stay adoptable. It fails like AdvanceNodeRoutePhase when the stored
// phase differs from halted.
func ResumeHaltedNodeRoute(ctx context.Context, q Querier, id domain.ID, halted NodeRoutePhase, now time.Time) (NodeRoute, error) {
	if !halted.Halted() {
		return NodeRoute{}, smerr.New(smerr.CodeInvalidArgument, "", "only a failed or conflict route can be resumed")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE node_routes SET phase = halted_phase, halted_phase = NULL, last_error = '', updated_at = ?
		WHERE id = ? AND phase = ? AND halted_phase IS NOT NULL`, millis(now), id, halted)
	return finishNodeRouteUpdate(ctx, q, res, err, "resume", id, halted)
}

// MarkNodeRouteRemoving starts the removal from the phase the route is in (a halted one included). The
// objects are then taken down step by step with AdvanceNodeRoutePhase. A removed route yields INVALID_ARGUMENT.
func MarkNodeRouteRemoving(ctx context.Context, q Querier, id domain.ID, from NodeRoutePhase, now time.Time) (NodeRoute, error) {
	if from == NodeRouteRemoved {
		return NodeRoute{}, smerr.New(smerr.CodeInvalidArgument, "", "a removed route has nothing to remove")
	}
	return AdvanceNodeRoutePhase(ctx, q, id, from, NodeRouteRemoving, NodeRouteObjects{}, now)
}

func finishNodeRouteUpdate(ctx context.Context, q Querier, res sql.Result, err error, verb string, id domain.ID, expected NodeRoutePhase) (NodeRoute, error) {
	if err != nil {
		return NodeRoute{}, fmt.Errorf("%s node route: %w", verb, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return NodeRoute{}, fmt.Errorf("node route: %w", err)
	}
	current, getErr := GetNodeRoute(ctx, q, id)
	if n > 0 {
		return current, getErr
	}
	if getErr != nil {
		return NodeRoute{}, getErr
	}
	e := smerr.New(smerr.CodeConflict, "", "node route changed concurrently")
	e.Details = map[string]any{"expected_phase": string(expected), "current_phase": string(current.Phase)}
	return NodeRoute{}, e
}
