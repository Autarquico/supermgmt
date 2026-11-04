package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// AppMovePhase is a step of an app move's state machine (ADR-0041). A halted move is in AppMoveFailed or
// AppMoveConflict and keeps the phase it held in HaltedPhase.
type AppMovePhase string

const (
	AppMovePreflight    AppMovePhase = "preflight"
	AppMoveStaged       AppMovePhase = "staged"
	AppMoveSourceStop   AppMovePhase = "source_stopped" // stateful only
	AppMoveDataCopied   AppMovePhase = "data_copied"    // stateful only
	AppMoveStarted      AppMovePhase = "started"
	AppMoveVerified     AppMovePhase = "verified"
	AppMoveCommitted    AppMovePhase = "committed"
	AppMoveSourceParked AppMovePhase = "source_parked"
	AppMoveDone         AppMovePhase = "done"

	// A routed move (ADR-0042) only: B's ingress carries the routes, then their records point at B, and the commit
	// runs from routes_switched; after it A's ingress is cleaned. Compensation undoes the routes before anything else.
	AppMoveRoutesDestIncluded  AppMovePhase = "routes_dest_included"
	AppMoveRoutesSwitched      AppMovePhase = "routes_switched"
	AppMoveRoutesSourceCleaned AppMovePhase = "routes_source_cleaned"

	AppMoveCompensatingRoutesRestored  AppMovePhase = "compensating_routes_restored"
	AppMoveCompensatingRoutesWithdrawn AppMovePhase = "compensating_routes_withdrawn"
	AppMoveCompensatingBStopped        AppMovePhase = "compensating_b_stopped"
	AppMoveCompensatingSourceStarted   AppMovePhase = "compensating_source_started"
	AppMoveCompensatingSourceVerified  AppMovePhase = "compensating_source_verified"
	AppMoveCompensatingBRemoved        AppMovePhase = "compensating_b_removed"
	AppMoveRolledBack                  AppMovePhase = "rolled_back"
	AppMoveFailed                      AppMovePhase = "failed"
	AppMoveConflict                    AppMovePhase = "conflict"
)

// Halted reports whether the move stopped and waits for an operator or a reconcile.
func (p AppMovePhase) Halted() bool { return p == AppMoveFailed || p == AppMoveConflict }

// Finished reports whether the move is over: done or rolled back. Every other phase, halted ones included, is open.
func (p AppMovePhase) Finished() bool { return p == AppMoveDone || p == AppMoveRolledBack }

// AppMoveVolumeState is the progress of one volume's copy.
type AppMoveVolumeState string

const (
	AppMoveVolumePending   AppMoveVolumeState = "pending"
	AppMoveVolumeImporting AppMoveVolumeState = "importing"
	AppMoveVolumeImported  AppMoveVolumeState = "imported"
	AppMoveVolumeVerified  AppMoveVolumeState = "verified"
)

// AppMove is the record of one move of an app target from its source node (A) to a destination node (B).
type AppMove struct {
	ID                    domain.ID
	AppTargetID           domain.ID
	SourceNodeID          domain.ID
	DestNodeID            domain.ID
	PlanID                domain.ID
	JobID                 domain.ID
	KnownGoodDeploymentID domain.ID
	DestDeploymentID      *domain.ID // B's deployment; nil until staged
	Stateful              bool
	BStartedAt            *time.Time // nil until B starts for the first time
	Phase                 AppMovePhase
	HaltedPhase           AppMovePhase // the phase held when Phase is failed or conflict
	PhaseStartedAt        time.Time
	LastError             string
	CommittedRevision     int64 // the target revision the commit wrote; 0 before the commit
	CreatedBy             domain.ID
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// AppMoveVolume is one entry of a move's volume map.
type AppMoveVolume struct {
	MoveID           domain.ID
	VolumeName       string // <project>_<volume>
	Service          string // the service whose container exports and imports the volume
	MountTarget      string
	OtherServices    []string
	Attempt          int
	State            AppMoveVolumeState
	SourceBytes      int64
	DestBytes        int64
	SourceDigest     string
	DestDigest       string
	CreatedByMove    bool       // evidence that this move created the volume on B
	ImportDeadlineAt *time.Time // while importing: when the import is proven stopped
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

const appMoveColumns = `id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id,
	dest_deployment_id, stateful, COALESCE(b_started_at, 0), phase, halted_phase, phase_started_at, last_error,
	COALESCE(committed_revision, 0), created_by, created_at, updated_at`

func scanAppMove(s scanner) (AppMove, error) {
	var (
		m                                                     AppMove
		dest, halted                                          sql.NullString
		stateful                                              int
		bStartedMs, startedMs, createdMs, updMs, committedRev int64
	)
	err := s.Scan(&m.ID, &m.AppTargetID, &m.SourceNodeID, &m.DestNodeID, &m.PlanID, &m.JobID, &m.KnownGoodDeploymentID,
		&dest, &stateful, &bStartedMs, &m.Phase, &halted, &startedMs, &m.LastError, &committedRev, &m.CreatedBy,
		&createdMs, &updMs)
	if err != nil {
		return AppMove{}, err
	}
	m.DestDeploymentID = idOf(dest)
	m.Stateful = stateful == 1
	if bStartedMs != 0 {
		t := domain.FromUnixMillis(bStartedMs)
		m.BStartedAt = &t
	}
	m.HaltedPhase = AppMovePhase(halted.String)
	m.PhaseStartedAt = domain.FromUnixMillis(startedMs)
	m.CommittedRevision = committedRev
	m.CreatedAt, m.UpdatedAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(updMs)
	return m, nil
}

const appMoveVolumeColumns = `move_id, volume_name, service, mount_target, other_services_json, attempt, state,
	source_bytes, dest_bytes, source_digest, dest_digest, created_by_move, COALESCE(import_deadline_at, 0),
	created_at, updated_at`

func scanAppMoveVolume(s scanner) (AppMoveVolume, error) {
	var (
		v                                AppMoveVolume
		others                           string
		createdByMove                    int
		deadlineMs, createdMs, updatedMs int64
	)
	err := s.Scan(&v.MoveID, &v.VolumeName, &v.Service, &v.MountTarget, &others, &v.Attempt, &v.State,
		&v.SourceBytes, &v.DestBytes, &v.SourceDigest, &v.DestDigest, &createdByMove, &deadlineMs, &createdMs, &updatedMs)
	if err != nil {
		return AppMoveVolume{}, err
	}
	if err := json.Unmarshal([]byte(others), &v.OtherServices); err != nil {
		return AppMoveVolume{}, fmt.Errorf("decode other services: %w", err)
	}
	v.CreatedByMove = createdByMove == 1
	if deadlineMs != 0 {
		t := domain.FromUnixMillis(deadlineMs)
		v.ImportDeadlineAt = &t
	}
	v.CreatedAt, v.UpdatedAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(updatedMs)
	return v, nil
}

// InsertAppMove records a planned move at preflight together with its volume map, in the caller's transaction.
// Every field of m but Phase, HaltedPhase, PhaseStartedAt, BStartedAt, DestDeploymentID, LastError,
// CommittedRevision and UpdatedAt is used; the volumes start pending, attempt 1, with SourceBytes as the
// planned size. A target that already has an open move yields CONFLICT.
func InsertAppMove(ctx context.Context, q Querier, m AppMove, volumes []AppMoveVolume) (AppMove, error) {
	_, err := q.ExecContext(ctx, `
		INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id,
			stateful, phase, phase_started_at, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'preflight', ?, ?, ?, ?)`,
		m.ID, m.AppTargetID, m.SourceNodeID, m.DestNodeID, m.PlanID, m.JobID, m.KnownGoodDeploymentID,
		boolInt(m.Stateful), millis(m.CreatedAt), m.CreatedBy, millis(m.CreatedAt), millis(m.CreatedAt))
	if err != nil {
		return AppMove{}, conflictIfDuplicate(err, "open app move for the target")
	}
	for _, v := range volumes {
		others, err := json.Marshal(nonNil(v.OtherServices))
		if err != nil {
			return AppMove{}, fmt.Errorf("encode other services: %w", err)
		}
		_, err = q.ExecContext(ctx, `
			INSERT INTO app_move_volumes (move_id, volume_name, service, mount_target, other_services_json, source_bytes,
				created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			m.ID, v.VolumeName, v.Service, v.MountTarget, string(others), v.SourceBytes, millis(m.CreatedAt), millis(m.CreatedAt))
		if err != nil {
			return AppMove{}, conflictIfDuplicate(err, "app move volume")
		}
	}
	return GetAppMove(ctx, q, m.ID)
}

// GetAppMove returns the move, or NOT_FOUND.
func GetAppMove(ctx context.Context, q Querier, id domain.ID) (AppMove, error) {
	m, err := scanAppMove(q.QueryRowContext(ctx, `SELECT `+appMoveColumns+` FROM app_moves WHERE id = ?`, id))
	if err != nil {
		return AppMove{}, getErr(err, "app move")
	}
	return m, nil
}

// GetOpenAppMoveByTarget returns the target's move that is not done or rolled back (halted ones included), or NOT_FOUND.
func GetOpenAppMoveByTarget(ctx context.Context, q Querier, targetID domain.ID) (AppMove, error) {
	m, err := scanAppMove(q.QueryRowContext(ctx,
		`SELECT `+appMoveColumns+` FROM app_moves WHERE app_target_id = ? AND phase NOT IN ('done', 'rolled_back')`, targetID))
	if err != nil {
		return AppMove{}, getErr(err, "open app move")
	}
	return m, nil
}

// neverRanMove selects (as alias m) an open move that no worker will ever run: still at preflight with no
// deployment on B, and its job ended without having been claimed (plan rejected or expired, job cancelled). It holds
// nothing on any node, so it blocks nothing.
const neverRanMove = `(m.phase = 'preflight' AND m.dest_deployment_id IS NULL AND EXISTS (
	SELECT 1 FROM jobs j WHERE j.id = m.job_id AND j.started_at IS NULL AND j.state IN ('succeeded', 'failed', 'cancelled')))`

// GetLiveAppMoveByTarget is GetOpenAppMoveByTarget without a move that never ran: the one that blocks the target.
func GetLiveAppMoveByTarget(ctx context.Context, q Querier, targetID domain.ID) (AppMove, error) {
	m, err := scanAppMove(q.QueryRowContext(ctx,
		`SELECT `+appMoveColumns+` FROM app_moves m WHERE m.app_target_id = ? AND m.phase NOT IN ('done', 'rolled_back') AND NOT `+neverRanMove, targetID))
	if err != nil {
		return AppMove{}, getErr(err, "open app move")
	}
	return m, nil
}

// ListAppMovesByTarget returns every move of the target, newest first.
func ListAppMovesByTarget(ctx context.Context, q Querier, targetID domain.ID) ([]AppMove, error) {
	return list(ctx, q, "app moves",
		`SELECT `+appMoveColumns+` FROM app_moves WHERE app_target_id = ? ORDER BY created_at DESC, id DESC`,
		scanAppMove, targetID)
}

// OpenMoveDestinations returns the destination node of every open move whose target uses the Compose project:
// those nodes will host the project, so a new target there must be refused.
func OpenMoveDestinations(ctx context.Context, q Querier, project string) ([]domain.ID, error) {
	return list(ctx, q, "open move destinations", `
		SELECT DISTINCT m.dest_node_id FROM app_moves m JOIN app_targets t ON t.id = m.app_target_id
		WHERE t.compose_project = ? AND m.phase NOT IN ('done', 'rolled_back') AND NOT `+neverRanMove+` ORDER BY m.dest_node_id`,
		func(s scanner) (domain.ID, error) {
			var id domain.ID
			return id, s.Scan(&id)
		}, project)
}

// RebindAppMoveJob hands an open move to the plan and job of a resuming request, provided the stored job is
// still from. Otherwise CONFLICT (or NOT_FOUND) and nothing changes.
func RebindAppMoveJob(ctx context.Context, q Querier, id, from, planID, jobID domain.ID, now time.Time) (AppMove, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE app_moves SET plan_id = ?, job_id = ?, updated_at = ?
		WHERE id = ? AND job_id = ? AND phase NOT IN ('done', 'rolled_back')`,
		planID, jobID, millis(now), id, from)
	return finishAppMoveUpdate(ctx, q, res, err, "rebind", id, "")
}

// BindAppMoveDestDeployment records B's deployment once. Binding the same deployment again is a no-op; another one
// yields CONFLICT. The deployment must be a move deployment of the move's target on its destination node.
func BindAppMoveDestDeployment(ctx context.Context, q Querier, id, deploymentID domain.ID, now time.Time) (AppMove, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE app_moves SET dest_deployment_id = ?, updated_at = ?
		WHERE id = ? AND phase NOT IN ('done', 'rolled_back')
		  AND (dest_deployment_id IS NULL OR dest_deployment_id = ?)
		  AND EXISTS (SELECT 1 FROM deployments d WHERE d.id = ? AND d.kind = 'move'
		              AND d.app_target_id = app_moves.app_target_id AND d.node_id = app_moves.dest_node_id)`,
		deploymentID, millis(now), id, deploymentID, deploymentID)
	return finishAppMoveUpdate(ctx, q, res, err, "bind destination deployment of", id, "")
}

// SetAppMoveBStartedAt records the first start of B. The first value stays: a repeated call returns the move unchanged.
// It must run before the start is dispatched.
func SetAppMoveBStartedAt(ctx context.Context, q Querier, id domain.ID, at time.Time) (AppMove, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE app_moves SET b_started_at = COALESCE(b_started_at, ?), updated_at = ?
		WHERE id = ? AND phase NOT IN ('done', 'rolled_back')`, millis(at), millis(at), id)
	return finishAppMoveUpdate(ctx, q, res, err, "record first start of", id, "")
}

// AdvanceAppMovePhase moves the move from one phase to another, but only while the stored phase still equals from.
// Otherwise CONFLICT (or NOT_FOUND) and nothing changes. Halting, resuming and the commit have their own functions,
// so neither phase may be failed, conflict or committed.
func AdvanceAppMovePhase(ctx context.Context, q Querier, id domain.ID, from, to AppMovePhase, now time.Time) (AppMove, error) {
	if from.Halted() || to.Halted() || to == AppMoveCommitted {
		return AppMove{}, smerr.New(smerr.CodeInvalidArgument, "", "halting, resuming and committing a move have their own operations")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE app_moves SET phase = ?, halted_phase = NULL, phase_started_at = ?, updated_at = ?, last_error = ''
		WHERE id = ? AND phase = ?`, to, millis(now), millis(now), id, from)
	return finishAppMoveUpdate(ctx, q, res, err, "advance", id, from)
}

// HaltAppMove marks the move failed or conflict, keeping its phase as HaltedPhase, under the same expectation as
// AdvanceAppMovePhase. lastError must already be sanitized.
func HaltAppMove(ctx context.Context, q Querier, id domain.ID, from, halt AppMovePhase, lastError string, now time.Time) (AppMove, error) {
	if !halt.Halted() || from.Halted() || from.Finished() {
		return AppMove{}, smerr.New(smerr.CodeInvalidArgument, "", "halt phase must be failed or conflict, from a running phase")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE app_moves SET phase = ?, halted_phase = phase, last_error = ?, updated_at = ?
		WHERE id = ? AND phase = ?`, halt, lastError, millis(now), id, from)
	return finishAppMoveUpdate(ctx, q, res, err, "halt", id, from)
}

// ResumeHaltedAppMove moves a halted move back to the phase it held, keeping phase_started_at. It fails like
// AdvanceAppMovePhase when the stored phase differs from halted.
func ResumeHaltedAppMove(ctx context.Context, q Querier, id domain.ID, halted AppMovePhase, now time.Time) (AppMove, error) {
	if !halted.Halted() {
		return AppMove{}, smerr.New(smerr.CodeInvalidArgument, "", "only a failed or conflict move can be resumed")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE app_moves SET phase = halted_phase, halted_phase = NULL, last_error = '', updated_at = ?
		WHERE id = ? AND phase = ? AND halted_phase IS NOT NULL`, millis(now), id, halted)
	return finishAppMoveUpdate(ctx, q, res, err, "resume", id, halted)
}

func finishAppMoveUpdate(ctx context.Context, q Querier, res sql.Result, err error, verb string, id domain.ID, expected AppMovePhase) (AppMove, error) {
	if err != nil {
		return AppMove{}, fmt.Errorf("%s app move: %w", verb, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return AppMove{}, fmt.Errorf("app move: %w", err)
	}
	current, getErr := GetAppMove(ctx, q, id)
	if n > 0 {
		return current, getErr
	}
	if getErr != nil {
		return AppMove{}, getErr
	}
	e := smerr.New(smerr.CodeConflict, "", "app move changed concurrently")
	e.Details = map[string]any{"current_phase": string(current.Phase)}
	if expected != "" {
		e.Details["expected_phase"] = string(expected)
	}
	return AppMove{}, e
}

// CommitAppMove is the move's commit, all or nothing. In one savepoint it
//   - points the target at the destination node, but only while its revision is expectedRevision and its node is
//     sourceNode (the revision then becomes expectedRevision+1);
//   - settles B's deployment as succeeded and known good, provided it is the move's deployment on destNode;
//   - writes the routes of a routed move to the destination (node, tunnel and generation as one tuple, fenced on
//     the frozen values) and their rows to committed;
//   - records the written revision and advances the move to committed, from routes_switched when it carries routes
//     and from verified when it does not.
//
// Every statement must change exactly one row. Any mismatch rolls the whole commit back and yields CONFLICT.
func CommitAppMove(ctx context.Context, q Querier, moveID, targetID domain.ID, expectedRevision int64,
	sourceNode, destNode, destDeploymentID domain.ID, now time.Time,
) (move AppMove, err error) {
	const savepoint = "app_move_commit"
	if _, err := q.ExecContext(ctx, "SAVEPOINT "+savepoint); err != nil {
		return AppMove{}, fmt.Errorf("commit app move: %w", err)
	}
	defer func() {
		stmt := "RELEASE " + savepoint
		if err != nil {
			stmt = "ROLLBACK TO " + savepoint + "; RELEASE " + savepoint
		}
		if _, relErr := q.ExecContext(ctx, stmt); relErr != nil && err == nil {
			move, err = AppMove{}, fmt.Errorf("commit app move: %w", relErr)
		}
	}()

	if err := requireOneRow(ctx, q, "the target no longer has the planned revision and source node", `
		UPDATE app_targets SET node_id = ?, spec_revision = spec_revision + 1, updated_at = ?
		WHERE id = ? AND spec_revision = ? AND node_id = ?`,
		destNode, millis(now), targetID, expectedRevision, sourceNode); err != nil {
		return AppMove{}, err
	}
	if err := settleMoveDeployment(ctx, q, targetID, destNode, destDeploymentID, now); err != nil {
		return AppMove{}, err
	}
	routes, err := commitAppMoveRoutes(ctx, q, moveID, targetID, now)
	if err != nil {
		return AppMove{}, err
	}
	fromPhase := AppMoveVerified
	if routes > 0 {
		fromPhase = AppMoveRoutesSwitched
	}
	if err := requireOneRow(ctx, q, "the move is not "+string(fromPhase)+" on its recorded nodes and deployment", `
		UPDATE app_moves SET phase = 'committed', halted_phase = NULL, phase_started_at = ?, updated_at = ?,
		       last_error = '', committed_revision = ?
		WHERE id = ? AND phase = ? AND app_target_id = ? AND source_node_id = ? AND dest_node_id = ?
		  AND dest_deployment_id = ?`,
		millis(now), millis(now), expectedRevision+1, moveID, fromPhase, targetID, sourceNode, destNode, destDeploymentID); err != nil {
		return AppMove{}, err
	}
	return GetAppMove(ctx, q, moveID)
}

func settleMoveDeployment(ctx context.Context, q Querier, targetID, destNode, deploymentID domain.ID, now time.Time) error {
	d, err := GetDeployment(ctx, q, deploymentID)
	if err != nil {
		return err
	}
	if d.Kind != deployments.KindMove || d.AppTargetID != targetID || d.NodeID != destNode {
		return smerr.New(smerr.CodeConflict, "", "the destination deployment is not a move deployment of the target on the destination node")
	}
	if err := TransitionDeployment(ctx, q, deploymentID, deployments.StateSucceeded, StateFailure{}, now); err != nil {
		return smerr.Wrap(err, smerr.CodeConflict, "", "the destination deployment cannot be settled as succeeded")
	}
	return MarkDeploymentKnownGood(ctx, q, deploymentID, now)
}

func requireOneRow(ctx context.Context, q Querier, mismatch, query string, args ...any) error {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		if isUniqueViolation(err) {
			return smerr.Wrap(err, smerr.CodeConflict, "", mismatch)
		}
		return fmt.Errorf("commit app move: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("commit app move: %w", err)
	} else if n != 1 {
		return smerr.New(smerr.CodeConflict, "", "app move commit: "+mismatch)
	}
	return nil
}

// ---- volumes ---------------------------------------------------------------

// GetAppMoveVolume returns one volume of the move, or NOT_FOUND.
func GetAppMoveVolume(ctx context.Context, q Querier, moveID domain.ID, volume string) (AppMoveVolume, error) {
	v, err := scanAppMoveVolume(q.QueryRowContext(ctx,
		`SELECT `+appMoveVolumeColumns+` FROM app_move_volumes WHERE move_id = ? AND volume_name = ?`, moveID, volume))
	if err != nil {
		return AppMoveVolume{}, getErr(err, "app move volume")
	}
	return v, nil
}

// ListAppMoveVolumes returns the move's volume map in volume name order.
func ListAppMoveVolumes(ctx context.Context, q Querier, moveID domain.ID) ([]AppMoveVolume, error) {
	return list(ctx, q, "app move volumes",
		`SELECT `+appMoveVolumeColumns+` FROM app_move_volumes WHERE move_id = ? ORDER BY volume_name`,
		scanAppMoveVolume, moveID)
}

// MarkAppMoveVolumesCreatedByMove records, before compose create is dispatched, that the move's volumes are its own
// to remove on B. It returns how many rows changed; marking again changes none.
func MarkAppMoveVolumesCreatedByMove(ctx context.Context, q Querier, moveID domain.ID, now time.Time) (int, error) {
	if _, err := GetAppMove(ctx, q, moveID); err != nil {
		return 0, err
	}
	res, err := q.ExecContext(ctx, `
		UPDATE app_move_volumes SET created_by_move = 1, updated_at = ?
		WHERE move_id = ? AND created_by_move = 0
		  AND EXISTS (SELECT 1 FROM app_moves m WHERE m.id = ? AND m.phase NOT IN ('done', 'rolled_back'))`,
		millis(now), moveID, moveID)
	if err != nil {
		return 0, fmt.Errorf("mark app move volumes: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// BeginAppMoveVolumeImport moves a pending volume to importing and records the deadline after which the import is
// proven stopped, fenced on the attempt. The deadline must be recorded before the import is dispatched.
func BeginAppMoveVolumeImport(ctx context.Context, q Querier, moveID domain.ID, volume string, attempt int,
	deadline, now time.Time,
) (AppMoveVolume, error) {
	return updateAppMoveVolume(ctx, q, moveID, volume, attempt, AppMoveVolumePending, `
		state = 'importing', import_deadline_at = ?, updated_at = ?`, millis(deadline), millis(now))
}

// CompleteAppMoveVolumeImport moves an importing volume to imported once both ends exited 0, recording what A
// exported.
func CompleteAppMoveVolumeImport(ctx context.Context, q Querier, moveID domain.ID, volume string, attempt int,
	sourceBytes int64, sourceDigest string, now time.Time,
) (AppMoveVolume, error) {
	if sourceDigest == "" || sourceBytes < 0 {
		return AppMoveVolume{}, smerr.New(smerr.CodeInvalidArgument, "", "an imported volume needs the digest and size of what was exported")
	}
	return updateAppMoveVolume(ctx, q, moveID, volume, attempt, AppMoveVolumeImporting, `
		state = 'imported', import_deadline_at = NULL, source_bytes = ?, source_digest = ?, updated_at = ?`,
		sourceBytes, sourceDigest, millis(now))
}

// VerifyAppMoveVolume moves an imported volume to verified, recording what B exported back. The digest must equal
// the one recorded for A; otherwise CONFLICT, details telling the state is unchanged, and the attempt has failed.
func VerifyAppMoveVolume(ctx context.Context, q Querier, moveID domain.ID, volume string, attempt int,
	destBytes int64, destDigest string, now time.Time,
) (AppMoveVolume, error) {
	if destDigest == "" || destBytes < 0 {
		return AppMoveVolume{}, smerr.New(smerr.CodeInvalidArgument, "", "a verified volume needs the digest and size of what B holds")
	}
	return updateAppMoveVolumeWhere(ctx, q, moveID, volume, attempt, AppMoveVolumeImported, `
		state = 'verified', dest_bytes = ?, dest_digest = ?, updated_at = ?`,
		[]any{destBytes, destDigest, millis(now)}, ` AND source_digest = ?`, destDigest)
}

// ResetAppMoveVolume replaces a failed attempt: an importing or imported volume goes back to pending under the
// next attempt, with nothing measured. The caller proves the import stopped (its deadline plus the kill margin)
// before calling; the volume on B is then removed and recreated empty.
func ResetAppMoveVolume(ctx context.Context, q Querier, moveID domain.ID, volume string, attempt int,
	from AppMoveVolumeState, now time.Time,
) (AppMoveVolume, error) {
	if from != AppMoveVolumeImporting && from != AppMoveVolumeImported {
		return AppMoveVolume{}, smerr.New(smerr.CodeInvalidArgument, "", "only an importing or imported volume can be replaced")
	}
	return updateAppMoveVolume(ctx, q, moveID, volume, attempt, from, `
		state = 'pending', attempt = attempt + 1, import_deadline_at = NULL, dest_bytes = 0, source_digest = '',
		dest_digest = '', updated_at = ?`, millis(now))
}

// updateAppMoveVolume applies set to the volume while it is still at attempt and in state from. Otherwise CONFLICT
// (or NOT_FOUND) with the stored attempt and state, and nothing changes.
func updateAppMoveVolume(ctx context.Context, q Querier, moveID domain.ID, volume string, attempt int,
	from AppMoveVolumeState, set string, setArgs ...any,
) (AppMoveVolume, error) {
	return updateAppMoveVolumeWhere(ctx, q, moveID, volume, attempt, from, set, setArgs, "")
}

func updateAppMoveVolumeWhere(ctx context.Context, q Querier, moveID domain.ID, volume string, attempt int,
	from AppMoveVolumeState, set string, setArgs []any, extraWhere string, extraArgs ...any,
) (AppMoveVolume, error) {
	args := slices.Concat(setArgs, []any{moveID, volume, attempt, from}, extraArgs)
	res, err := q.ExecContext(ctx, `UPDATE app_move_volumes SET `+set+
		` WHERE move_id = ? AND volume_name = ? AND attempt = ? AND state = ?`+extraWhere, args...)
	if err != nil {
		return AppMoveVolume{}, fmt.Errorf("update app move volume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return AppMoveVolume{}, fmt.Errorf("app move volume: %w", err)
	}
	current, getErr := GetAppMoveVolume(ctx, q, moveID, volume)
	if n > 0 {
		return current, getErr
	}
	if getErr != nil {
		return AppMoveVolume{}, getErr
	}
	e := smerr.New(smerr.CodeConflict, "", "app move volume changed concurrently or does not match")
	e.Details = map[string]any{
		"expected_attempt": attempt, "current_attempt": current.Attempt,
		"expected_state": string(from), "current_state": string(current.State),
	}
	return AppMoveVolume{}, e
}

// AppMoveRestartSteps returns the steps of the restart-policy commands of the move that were dispatched, across every
// job that worked on it: what the move changed on a node's containers.
func AppMoveRestartSteps(ctx context.Context, q Querier, moveID domain.ID) (map[string]bool, error) {
	steps, err := list(ctx, q, "move restart steps", `
		SELECT step FROM operation_intents
		WHERE operation = 'docker.update_restart' AND dispatched_at IS NOT NULL AND json_extract(pre_state_json, '$.move') = ?`,
		func(s scanner) (string, error) {
			var step string
			return step, s.Scan(&step)
		}, moveID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(steps))
	for _, step := range steps {
		out[step] = true
	}
	return out, nil
}
