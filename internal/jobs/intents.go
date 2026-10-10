package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// IntentState is operation_intents.state: recorded -> completed.
type IntentState string

const (
	IntentRecorded  IntentState = "recorded"
	IntentCompleted IntentState = "completed"
)

// Outcomes recorded when an intent completes.
const (
	OutcomeSucceeded = "succeeded"
	OutcomeFailed    = "failed"
)

// Intent is a durable record of a remote operation, committed before dispatch
// so a crash leaves proof of what may have been started (spec §20.4).
type Intent struct {
	ID              domain.ID
	JobID           domain.ID
	Step            string
	LeaseGeneration int64
	State           IntentState
	Operation       string
	TargetType      string
	TargetID        string
	Marker          string
	PreState        json.RawMessage
	DeadlineAt      time.Time
	DispatchedAt    *time.Time
	CompletedAt     *time.Time
	Outcome         string
	Evidence        json.RawMessage
}

// Dispatched reports whether the operation may have started on the target.
func (i Intent) Dispatched() bool { return i.DispatchedAt != nil }

// NewIntent describes an operation about to be dispatched. Marker is the unique
// node-side marker name; it defaults to the intent id.
type NewIntent struct {
	Step       string
	Operation  string
	TargetType string
	TargetID   string
	Marker     string
	PreState   json.RawMessage
	DeadlineAt time.Time
}

// RecordIntent durably records an intent under the lease, before dispatch.
func (s *Store) RecordIntent(ctx context.Context, lease Lease, ni NewIntent) (Intent, error) {
	if ni.Step == "" || ni.Operation == "" || ni.TargetType == "" || ni.TargetID == "" || ni.DeadlineAt.IsZero() {
		return Intent{}, smerr.New(smerr.CodeInvalidArgument, "", "intent needs step, operation, target and deadline")
	}
	var intent Intent
	err := s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		id := s.ids.NewID()
		marker := ni.Marker
		if marker == "" {
			marker = id.String()
		}
		taken, err := markerTaken(ctx, tx, marker)
		if err != nil {
			return err
		}
		if taken {
			return smerr.New(smerr.CodeConflict, "", "intent marker already exists")
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type,
			                               target_id, marker, pre_state_json, deadline_at)
			VALUES (?, ?, ?, ?, 'recorded', ?, ?, ?, ?, ?, ?)`,
			id, lease.JobID, ni.Step, lease.Generation, ni.Operation, ni.TargetType, ni.TargetID, marker,
			nullText(string(ni.PreState)), domain.UnixMillis(ni.DeadlineAt))
		if err != nil {
			return fmt.Errorf("insert intent: %w", err)
		}
		intent, err = getIntent(ctx, tx, id)
		return err
	})
	return intent, err
}

func markerTaken(ctx context.Context, q database.Querier, marker string) (bool, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_intents WHERE marker = ?`, marker).Scan(&n); err != nil {
		return false, fmt.Errorf("check intent marker: %w", err)
	}
	return n > 0, nil
}

// MarkDispatched stamps the moment just before the operation is sent. From then
// on the reconciler treats the operation as possibly started.
func (s *Store) MarkDispatched(ctx context.Context, lease Lease, intent domain.ID) error {
	return s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		return s.updateIntent(ctx, tx, lease.JobID, intent, `UPDATE operation_intents SET dispatched_at = ?
			WHERE id = ? AND job_id = ? AND state = 'recorded' AND dispatched_at IS NULL`,
			domain.UnixMillis(s.clock.Now()))
	})
}

// CompleteIntent closes an intent with its outcome and completion evidence.
func (s *Store) CompleteIntent(ctx context.Context, lease Lease, intent domain.ID, outcome string, evidence json.RawMessage) error {
	if outcome != OutcomeSucceeded && outcome != OutcomeFailed {
		return smerr.New(smerr.CodeInvalidArgument, "", "intent outcome must be succeeded or failed")
	}
	return s.fenced(ctx, lease, func(ctx context.Context, tx *database.Tx) error {
		return s.completeIntent(ctx, tx, lease.JobID, intent, outcome, evidence)
	})
}

func (s *Store) completeIntent(ctx context.Context, q database.Querier, job, intent domain.ID, outcome string, evidence json.RawMessage) error {
	return s.updateIntent(ctx, q, job, intent, `UPDATE operation_intents
		SET state = 'completed', completed_at = ?, outcome = ?, evidence_json = ?
		WHERE id = ? AND job_id = ? AND state = 'recorded'`,
		domain.UnixMillis(s.clock.Now()), outcome, nullText(string(evidence)))
}

// updateIntent runs a single-row UPDATE whose trailing parameters are (intent, job).
func (s *Store) updateIntent(ctx context.Context, q database.Querier, job, intent domain.ID, query string, leading ...any) error {
	res, err := q.ExecContext(ctx, query, append(leading, intent, job)...)
	if err != nil {
		return fmt.Errorf("update intent %s: %w", intent, err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return smerr.New(smerr.CodeConflict, "", "intent is not in a state that allows this change")
	}
	return nil
}

// Intents lists a job's intents in recording order.
func (s *Store) Intents(ctx context.Context, q database.Querier, job domain.ID) ([]Intent, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+intentColumns+` FROM operation_intents WHERE job_id = ? ORDER BY id`, job)
	if err != nil {
		return nil, fmt.Errorf("list intents: %w", err)
	}
	defer rows.Close()
	var out []Intent
	for rows.Next() {
		in, err := scanIntent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan intent: %w", err)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

const intentColumns = `id, job_id, step, lease_generation, state, operation, target_type, target_id, marker,
	pre_state_json, deadline_at, dispatched_at, completed_at, outcome, evidence_json`

func getIntent(ctx context.Context, q database.Querier, id domain.ID) (Intent, error) {
	in, err := scanIntent(q.QueryRowContext(ctx, `SELECT `+intentColumns+` FROM operation_intents WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Intent{}, smerr.New(smerr.CodeNotFound, "", "intent not found")
	}
	return in, err
}

func scanIntent(row rowScanner) (Intent, error) {
	var (
		in                     Intent
		pre, outcome, evidence sql.NullString
		deadline               int64
		dispatched, completed  sql.NullInt64
	)
	err := row.Scan(&in.ID, &in.JobID, &in.Step, &in.LeaseGeneration, &in.State, &in.Operation, &in.TargetType,
		&in.TargetID, &in.Marker, &pre, &deadline, &dispatched, &completed, &outcome, &evidence)
	if err != nil {
		return Intent{}, err
	}
	if pre.Valid {
		in.PreState = json.RawMessage(pre.String)
	}
	if evidence.Valid {
		in.Evidence = json.RawMessage(evidence.String)
	}
	in.Outcome = outcome.String
	in.DeadlineAt = domain.FromUnixMillis(deadline)
	in.DispatchedAt, in.CompletedAt = timeOf(dispatched), timeOf(completed)
	return in, nil
}
