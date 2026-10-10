package database

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// EventWriter appends audit events through a Querier, so an event commits or
// rolls back with the transaction that caused it (ADR-0013). It implements
// audit.EventWriter.
type EventWriter struct{ q Querier }

// EventsIn binds an event writer to q.
func EventsIn(q Querier) EventWriter { return EventWriter{q: q} }

// AppendEvent stores e and returns it with its assigned Seq.
func (w EventWriter) AppendEvent(ctx context.Context, e domain.Event) (domain.Event, error) {
	data, err := encodeJSON(e.Data)
	if err != nil {
		return domain.Event{}, err
	}
	err = w.q.QueryRowContext(ctx, `
		INSERT INTO events (event_id, timestamp, actor_type, actor_id, source, action, resource_type,
		                    resource_id, correlation_id, severity, result, data_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING seq`,
		e.EventID, millis(e.Timestamp), e.ActorType, e.ActorID, e.Source, e.Action, e.ResourceType,
		e.ResourceID, e.CorrelationID, e.Severity, e.Result, data).Scan(&e.Seq)
	if err != nil {
		return domain.Event{}, conflictIfDuplicate(err, "event")
	}
	return e, nil
}

// ListEvents returns up to limit events with Seq > afterSeq, oldest first.
func ListEvents(ctx context.Context, q Querier, afterSeq int64, limit int) ([]domain.Event, error) {
	if limit <= 0 {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "event limit must be positive")
	}
	return list(ctx, q, "events", `
		SELECT seq, event_id, timestamp, actor_type, actor_id, source, action, resource_type,
		       resource_id, correlation_id, severity, result, data_json
		FROM events WHERE seq > ? ORDER BY seq LIMIT ?`, scanEvent, afterSeq, limit)
}

func scanEvent(row scanner) (domain.Event, error) {
	var (
		e    domain.Event
		ms   int64
		data string
	)
	if err := row.Scan(&e.Seq, &e.EventID, &ms, &e.ActorType, &e.ActorID, &e.Source, &e.Action,
		&e.ResourceType, &e.ResourceID, &e.CorrelationID, &e.Severity, &e.Result, &data); err != nil {
		return domain.Event{}, err
	}
	e.Timestamp = domain.FromUnixMillis(ms)
	var err error
	if e.Data, err = decodeMap(data); err != nil {
		return domain.Event{}, fmt.Errorf("event %d: %w", e.Seq, err)
	}
	return e, nil
}
