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

// AppRoutePhase is a step of an app route's state machine (ADR-0040). A halted route is in AppRouteFailed or
// AppRouteConflict and keeps the phase it held in HaltedPhase.
type AppRoutePhase string

const (
	AppRouteWaiting        AppRoutePhase = "waiting"
	AppRouteProvisioning   AppRoutePhase = "provisioning"
	AppRouteIngressReady   AppRoutePhase = "ingress_ready"
	AppRouteAccessReady    AppRoutePhase = "access_ready"
	AppRouteActive         AppRoutePhase = "active"
	AppRouteRemoving       AppRoutePhase = "removing"
	AppRouteDNSRemoved     AppRoutePhase = "dns_removed"
	AppRouteIngressRemoved AppRoutePhase = "ingress_removed"
	AppRouteRemoved        AppRoutePhase = "removed"
	AppRouteFailed         AppRoutePhase = "failed"
	AppRouteConflict       AppRoutePhase = "conflict"
)

// Halted reports whether the route stopped and waits for an operator or a reconcile.
func (p AppRoutePhase) Halted() bool { return p == AppRouteFailed || p == AppRouteConflict }

// AppRouteObjects are the Cloudflare object IDs a route created. Empty means not created yet.
type AppRouteObjects struct {
	DNSRecordID string
	AccessAppID string
}

// AppRoute is the record of one hostname exposed from an app target through its node's tunnel.
type AppRoute struct {
	ID               domain.ID
	AppTargetID      domain.ID
	NodeID           domain.ID
	Hostname         string // canonical: lowercase
	Service          string
	Port             int
	Access           string // public | owners
	Phase            AppRoutePhase
	HaltedPhase      AppRoutePhase // the phase held when Phase is failed or conflict
	PhaseStartedAt   time.Time
	AccountID        string
	Zone             string
	InstanceID       string
	TunnelID         string
	TunnelGeneration int64
	Objects          AppRouteObjects
	PlanID           *domain.ID // the plan whose admission wrote the row
	LastError        string
	CreatedBy        domain.ID
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// AppRouteFilter narrows ListAppRoutes. Zero fields match everything; removed routes are left out unless
// IncludeRemoved is set.
type AppRouteFilter struct {
	TargetID       domain.ID
	NodeID         domain.ID
	IncludeRemoved bool
}

const appRouteColumns = `id, app_target_id, node_id, hostname, service, port, access, phase, halted_phase,
	phase_started_at, account_id, zone, instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id,
	plan_id, last_error, created_by, created_at, updated_at`

func scanAppRoute(s scanner) (AppRoute, error) {
	var (
		r                           AppRoute
		halted, planID              sql.NullString
		startedMs, createdMs, updMs int64
	)
	err := s.Scan(&r.ID, &r.AppTargetID, &r.NodeID, &r.Hostname, &r.Service, &r.Port, &r.Access, &r.Phase, &halted,
		&startedMs, &r.AccountID, &r.Zone, &r.InstanceID, &r.TunnelID, &r.TunnelGeneration,
		&r.Objects.DNSRecordID, &r.Objects.AccessAppID, &planID, &r.LastError, &r.CreatedBy, &createdMs, &updMs)
	if err != nil {
		return AppRoute{}, err
	}
	r.HaltedPhase = AppRoutePhase(halted.String)
	if planID.Valid {
		id := domain.ID(planID.String)
		r.PlanID = &id
	}
	r.PhaseStartedAt = domain.FromUnixMillis(startedMs)
	r.CreatedAt = domain.FromUnixMillis(createdMs)
	r.UpdatedAt = domain.FromUnixMillis(updMs)
	return r, nil
}

// InsertAppRoute records an accepted route. The phase is always waiting; every field of r but Phase,
// HaltedPhase, PhaseStartedAt, Objects, LastError and UpdatedAt is used. A nil PlanID stores NULL. A hostname that has a live route
// yields CONFLICT. The node must be the target's node.
func InsertAppRoute(ctx context.Context, q Querier, r AppRoute) (AppRoute, error) {
	_, err := q.ExecContext(ctx, `
		INSERT INTO app_routes (id, app_target_id, node_id, hostname, service, port, access, phase, phase_started_at,
			account_id, zone, instance_id, tunnel_id, tunnel_generation, plan_id, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.AppTargetID, r.NodeID, r.Hostname, r.Service, r.Port, r.Access, millis(r.CreatedAt),
		r.AccountID, r.Zone, r.InstanceID, r.TunnelID, r.TunnelGeneration, r.PlanID, r.CreatedBy, millis(r.CreatedAt), millis(r.CreatedAt))
	if err != nil {
		return AppRoute{}, conflictIfDuplicate(err, "live app route for hostname")
	}
	return GetAppRoute(ctx, q, r.ID)
}

// GetAppRoute returns the route, or NOT_FOUND.
func GetAppRoute(ctx context.Context, q Querier, id domain.ID) (AppRoute, error) {
	r, err := scanAppRoute(q.QueryRowContext(ctx, `SELECT `+appRouteColumns+` FROM app_routes WHERE id = ?`, id))
	if err != nil {
		return AppRoute{}, getErr(err, "app route")
	}
	return r, nil
}

// GetAppRouteByPlan returns the route that the admission of the plan wrote, in any phase, or NOT_FOUND.
func GetAppRouteByPlan(ctx context.Context, q Querier, planID domain.ID) (AppRoute, error) {
	r, err := scanAppRoute(q.QueryRowContext(ctx, `SELECT `+appRouteColumns+` FROM app_routes WHERE plan_id = ?`, planID))
	if err != nil {
		return AppRoute{}, getErr(err, "app route")
	}
	return r, nil
}

// GetLiveAppRouteByHostname returns the hostname's route that is not removed (halted ones included), or NOT_FOUND.
func GetLiveAppRouteByHostname(ctx context.Context, q Querier, hostname string) (AppRoute, error) {
	r, err := scanAppRoute(q.QueryRowContext(ctx,
		`SELECT `+appRouteColumns+` FROM app_routes WHERE hostname = ? AND phase <> 'removed'`, hostname))
	if err != nil {
		return AppRoute{}, getErr(err, "app route")
	}
	return r, nil
}

// ListAppRoutes returns the routes matching the filter, oldest first.
func ListAppRoutes(ctx context.Context, q Querier, f AppRouteFilter) ([]AppRoute, error) {
	var (
		where []string
		args  []any
	)
	if f.TargetID != "" {
		where, args = append(where, "app_target_id = ?"), append(args, f.TargetID)
	}
	if f.NodeID != "" {
		where, args = append(where, "node_id = ?"), append(args, f.NodeID)
	}
	if !f.IncludeRemoved {
		where = append(where, "phase <> 'removed'")
	}
	query := `SELECT ` + appRouteColumns + ` FROM app_routes`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	return list(ctx, q, "app routes", query+` ORDER BY created_at, id`, scanAppRoute, args...)
}

// CountLiveAppRoutesByNode counts the node's routes that are not removed, halted and waiting ones included.
func CountLiveAppRoutesByNode(ctx context.Context, q Querier, nodeID domain.ID) (int, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_routes WHERE node_id = ? AND phase <> 'removed'`, nodeID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count app routes: %w", err)
	}
	return n, nil
}

// ListWaitingAppRoutes returns the target's routes still waiting for a version that publishes their port.
func ListWaitingAppRoutes(ctx context.Context, q Querier, targetID domain.ID) ([]AppRoute, error) {
	return list(ctx, q, "app routes",
		`SELECT `+appRouteColumns+` FROM app_routes WHERE app_target_id = ? AND phase = 'waiting' ORDER BY created_at, id`,
		scanAppRoute, targetID)
}

// AdvanceAppRoutePhase moves the route from to next, recording any non-empty object IDs in the same
// statement, but only while the stored phase still equals from. Otherwise CONFLICT (or NOT_FOUND) and nothing changes.
func AdvanceAppRoutePhase(ctx context.Context, q Querier, id domain.ID,
	from, to AppRoutePhase, objects AppRouteObjects, now time.Time,
) (AppRoute, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE app_routes SET phase = ?, halted_phase = NULL, phase_started_at = ?, updated_at = ?, last_error = '',
			dns_record_id = COALESCE(NULLIF(?, ''), dns_record_id),
			access_app_id = COALESCE(NULLIF(?, ''), access_app_id)
		WHERE id = ? AND phase = ?`,
		to, millis(now), millis(now), objects.DNSRecordID, objects.AccessAppID, id, from)
	return finishAppRouteUpdate(ctx, q, res, err, "advance", id, from)
}

// HaltAppRoute marks the route failed or conflict, keeping its phase as HaltedPhase, under the same
// expectation as AdvanceAppRoutePhase. lastError must already be sanitized.
func HaltAppRoute(ctx context.Context, q Querier, id domain.ID,
	from, halt AppRoutePhase, lastError string, now time.Time,
) (AppRoute, error) {
	if !halt.Halted() || from.Halted() || from == AppRouteRemoved {
		return AppRoute{}, smerr.New(smerr.CodeInvalidArgument, "", "halt phase must be failed or conflict, from a running phase")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE app_routes SET phase = ?, halted_phase = phase, last_error = ?, updated_at = ?
		WHERE id = ? AND phase = ?`, halt, lastError, millis(now), id, from)
	return finishAppRouteUpdate(ctx, q, res, err, "halt", id, from)
}

// ResumeHaltedAppRoute moves a halted route back to the phase it held, keeping phase_started_at: the objects
// an earlier attempt of that phase created stay adoptable. It fails like AdvanceAppRoutePhase when the stored
// phase differs from halted.
func ResumeHaltedAppRoute(ctx context.Context, q Querier, id domain.ID, halted AppRoutePhase, now time.Time) (AppRoute, error) {
	if !halted.Halted() {
		return AppRoute{}, smerr.New(smerr.CodeInvalidArgument, "", "only a failed or conflict route can be resumed")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE app_routes SET phase = halted_phase, halted_phase = NULL, last_error = '', updated_at = ?
		WHERE id = ? AND phase = ? AND halted_phase IS NOT NULL`, millis(now), id, halted)
	return finishAppRouteUpdate(ctx, q, res, err, "resume", id, halted)
}

// MarkAppRouteRemoving starts the removal from the phase the route is in (a halted one included). The
// objects are then taken down step by step with AdvanceAppRoutePhase. A removed route yields INVALID_ARGUMENT.
func MarkAppRouteRemoving(ctx context.Context, q Querier, id domain.ID, from AppRoutePhase, now time.Time) (AppRoute, error) {
	if from == AppRouteRemoved {
		return AppRoute{}, smerr.New(smerr.CodeInvalidArgument, "", "a removed route has nothing to remove")
	}
	return AdvanceAppRoutePhase(ctx, q, id, from, AppRouteRemoving, AppRouteObjects{}, now)
}

func finishAppRouteUpdate(ctx context.Context, q Querier, res sql.Result, err error, verb string, id domain.ID, expected AppRoutePhase) (AppRoute, error) {
	if err != nil {
		return AppRoute{}, fmt.Errorf("%s app route: %w", verb, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return AppRoute{}, fmt.Errorf("app route: %w", err)
	}
	current, getErr := GetAppRoute(ctx, q, id)
	if n > 0 {
		return current, getErr
	}
	if getErr != nil {
		return AppRoute{}, getErr
	}
	e := smerr.New(smerr.CodeConflict, "", "app route changed concurrently")
	e.Details = map[string]any{"expected_phase": string(expected), "current_phase": string(current.Phase)}
	return AppRoute{}, e
}
