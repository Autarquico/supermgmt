package database

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

type (
	SessionTool   string
	SessionState  string
	SessionEnding string
)

const (
	ToolShell      SessionTool = "shell"
	ToolLazydocker SessionTool = "lazydocker"
	ToolBtop       SessionTool = "btop"
	ToolTmux       SessionTool = "tmux"

	SessionIssued    SessionState = "issued"
	SessionEnded     SessionState = "ended"
	SessionAbandoned SessionState = "abandoned"

	EndedExited       SessionEnding = "exited"
	EndedLaunchFailed SessionEnding = "launch_failed"
	EndedAbandoned    SessionEnding = "abandoned"
)

func AllSessionTools() []SessionTool {
	return []SessionTool{ToolShell, ToolLazydocker, ToolBtop, ToolTmux}
}

func AllSessionStates() []SessionState {
	return []SessionState{SessionIssued, SessionEnded, SessionAbandoned}
}

func AllSessionEndings() []SessionEnding {
	return []SessionEnding{EndedExited, EndedLaunchFailed, EndedAbandoned}
}

// InteractiveSession records one SSH handoff from issue to end (spec §8.4).
type InteractiveSession struct {
	ID         domain.ID
	IdentityID domain.ID
	NodeID     domain.ID
	Tool       SessionTool
	State      SessionState
	ExitCode   *int
	EndReason  SessionEnding
	CreatedAt  time.Time
	EndedAt    *time.Time
}

const sessionColumns = `id, identity_id, node_id, tool, state, exit_code, end_reason, created_at, ended_at`

// CreateInteractiveSession stores a session in state issued; the state, end
// fields and exit code of s are ignored.
func CreateInteractiveSession(ctx context.Context, q Querier, s InteractiveSession) (InteractiveSession, error) {
	if !slices.Contains(AllSessionTools(), s.Tool) {
		return InteractiveSession{}, smerr.New(smerr.CodeInvalidArgument, "", "unknown interactive session tool")
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO interactive_sessions (id, identity_id, node_id, tool, state, created_at)
		VALUES (?, ?, ?, ?, 'issued', ?)`,
		s.ID, s.IdentityID, s.NodeID, s.Tool, millis(s.CreatedAt))
	if err != nil {
		return InteractiveSession{}, conflictIfDuplicate(err, "interactive session")
	}
	return GetInteractiveSession(ctx, q, s.ID)
}

func scanSession(row scanner) (InteractiveSession, error) {
	var (
		s         InteractiveSession
		exitCode  sql.NullInt64
		endReason sql.NullString
		createdMs int64
		endedMs   sql.NullInt64
	)
	err := row.Scan(&s.ID, &s.IdentityID, &s.NodeID, &s.Tool, &s.State, &exitCode, &endReason, &createdMs, &endedMs)
	if err != nil {
		return InteractiveSession{}, err
	}
	if exitCode.Valid {
		code := int(exitCode.Int64)
		s.ExitCode = &code
	}
	s.EndReason = SessionEnding(endReason.String)
	s.CreatedAt, s.EndedAt = domain.FromUnixMillis(createdMs), timeOf(endedMs)
	return s, nil
}

// GetInteractiveSession returns the session or NOT_FOUND.
func GetInteractiveSession(ctx context.Context, q Querier, id domain.ID) (InteractiveSession, error) {
	s, err := scanSession(q.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM interactive_sessions WHERE id = ?`, id))
	return s, getErr(err, "interactive session")
}

// SessionEnd describes how a handoff ended. ExitCode is nil when no process ran.
type SessionEnd struct {
	Reason   SessionEnding
	ExitCode *int
	At       time.Time
}

// EndInteractiveSession ends an issued session that belongs to identity and
// node. The first end wins: it returns the stored session and first = true.
// A later call changes nothing and returns the already ended session with
// first = false. A session of another identity or node is NOT_FOUND.
func EndInteractiveSession(ctx context.Context, q Querier, id, identity, node domain.ID, end SessionEnd) (s InteractiveSession, first bool, err error) {
	if end.Reason != EndedExited && end.Reason != EndedLaunchFailed {
		return InteractiveSession{}, false, smerr.New(smerr.CodeInvalidArgument, "", "session end reason must be exited or launch_failed")
	}
	var code sql.NullInt64
	if end.ExitCode != nil {
		code = sql.NullInt64{Int64: int64(*end.ExitCode), Valid: true}
	}
	res, err := q.ExecContext(ctx, `
		UPDATE interactive_sessions SET state = 'ended', exit_code = ?, end_reason = ?, ended_at = ?
		WHERE id = ? AND identity_id = ? AND node_id = ? AND state = 'issued'`,
		code, end.Reason, millis(end.At), id, identity, node)
	if err != nil {
		return InteractiveSession{}, false, fmt.Errorf("end interactive session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return InteractiveSession{}, false, fmt.Errorf("end interactive session: %w", err)
	}
	s, err = GetInteractiveSession(ctx, q, id)
	if err != nil {
		return InteractiveSession{}, false, err
	}
	if s.IdentityID != identity || s.NodeID != node {
		return InteractiveSession{}, false, notFound("interactive session")
	}
	return s, n == 1, nil
}

// AbandonStaleSessions marks every session still issued at or before cutoff as
// abandoned, stamped at, and returns their ids for auditing.
func AbandonStaleSessions(ctx context.Context, q Querier, cutoff, at time.Time) ([]domain.ID, error) {
	return list(ctx, q, "abandoned sessions", `
		UPDATE interactive_sessions SET state = 'abandoned', end_reason = 'abandoned', ended_at = ?
		WHERE state = 'issued' AND created_at <= ? RETURNING id`,
		func(row scanner) (domain.ID, error) {
			var id domain.ID
			return id, row.Scan(&id)
		}, millis(at), millis(cutoff))
}
