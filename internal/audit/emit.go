package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// EventWriter appends an event to the audit trail and returns it with the
// store-assigned Seq. The database layer implements it inside its writer
// transaction; this package never opens one.
type EventWriter interface {
	AppendEvent(ctx context.Context, e domain.Event) (domain.Event, error)
}

// Emitter completes, validates and redacts events before they are written.
type Emitter struct {
	Clock  domain.Clock
	IDs    domain.IDGenerator
	Source string // default Event.Source, e.g. "daemon"
}

// Emit writes e through w. The emitter always assigns EventID and Timestamp
// (callers cannot backdate the trail). CorrelationID is kept when set, else
// taken from ctx, else generated. Source defaults to the emitter's. Data is
// redacted on a copy; the caller's map is untouched.
func (em Emitter) Emit(ctx context.Context, w EventWriter, e domain.Event) (domain.Event, error) {
	if err := validateEvent(e); err != nil {
		return domain.Event{}, err
	}
	e.EventID = em.IDs.NewID()
	e.Timestamp = em.Clock.Now()
	if e.CorrelationID == "" {
		_, id := EnsureCorrelationID(ctx, em.IDs)
		e.CorrelationID = string(id)
	}
	if e.Source == "" {
		e.Source = em.Source
	}
	e.Data = RedactMap(e.Data)

	stored, err := w.AppendEvent(ctx, e)
	if err != nil {
		return domain.Event{}, fmt.Errorf("append audit event %s: %w", e.Action, err)
	}
	return stored, nil
}

func validateEvent(e domain.Event) error {
	var problems []string
	if e.Action == "" {
		problems = append(problems, "action is required")
	}
	if !e.ActorType.Valid() {
		problems = append(problems, fmt.Sprintf("invalid actor_type %q", e.ActorType))
	}
	if !e.ResourceType.Valid() {
		problems = append(problems, fmt.Sprintf("invalid resource_type %q", e.ResourceType))
	}
	if !e.Result.Valid() {
		problems = append(problems, fmt.Sprintf("invalid result %q", e.Result))
	}
	if !e.Severity.Valid() {
		problems = append(problems, fmt.Sprintf("invalid severity %q", e.Severity))
	}
	if len(problems) == 0 {
		return nil
	}
	return smerr.New(smerr.CodeInvalidArgument, "", "invalid audit event: "+strings.Join(problems, "; "))
}
