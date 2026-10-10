package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// memoryWriter is an in-memory EventWriter that assigns Seq like the store does.
type memoryWriter struct {
	events []domain.Event
	err    error
}

func (m *memoryWriter) AppendEvent(_ context.Context, e domain.Event) (domain.Event, error) {
	if m.err != nil {
		return domain.Event{}, m.err
	}
	e.Seq = int64(len(m.events) + 1)
	m.events = append(m.events, e)
	return e, nil
}

var epoch = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func newEmitter() Emitter {
	return Emitter{Clock: domaintest.NewFakeClock(epoch), IDs: domaintest.NewSequentialIDs(), Source: "daemon"}
}

func validEvent() domain.Event {
	return domain.Event{
		ActorType:    domain.ActorHuman,
		ActorID:      "00000000-0000-7000-8000-0000000000aa",
		Action:       "deployment.create",
		ResourceType: domain.ResourceEvent,
		Result:       domain.ResultSucceeded,
		Severity:     domain.SeverityInfo,
	}
}

func TestEmitFillsIdentityTimeSourceAndCorrelation(t *testing.T) {
	w := &memoryWriter{}

	got, err := newEmitter().Emit(context.Background(), w, validEvent())
	if err != nil {
		t.Fatal(err)
	}

	if got.EventID != "00000000-0001-7000-8000-000000000000" {
		t.Errorf("EventID = %s", got.EventID)
	}
	if !got.Timestamp.Equal(epoch) {
		t.Errorf("Timestamp = %v, want the clock's time", got.Timestamp)
	}
	if got.Source != "daemon" {
		t.Errorf("Source = %q, want the emitter default", got.Source)
	}
	if got.CorrelationID == "" || got.CorrelationID == string(got.EventID) {
		t.Errorf("CorrelationID = %q, want a generated id distinct from the event id", got.CorrelationID)
	}
	if got.Seq != 1 || len(w.events) != 1 {
		t.Errorf("Seq = %d, stored = %d: Emit must return the writer's event", got.Seq, len(w.events))
	}
}

func TestEmitUsesContextCorrelationID(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "corr-from-ctx")
	got, err := newEmitter().Emit(ctx, &memoryWriter{}, validEvent())
	if err != nil {
		t.Fatal(err)
	}
	if got.CorrelationID != "corr-from-ctx" {
		t.Errorf("CorrelationID = %q", got.CorrelationID)
	}
}

func TestEmitKeepsExplicitCorrelationIDAndSource(t *testing.T) {
	e := validEvent()
	e.CorrelationID, e.Source = "explicit", "tui"
	ctx := WithCorrelationID(context.Background(), "ignored")

	got, err := newEmitter().Emit(ctx, &memoryWriter{}, e)
	if err != nil {
		t.Fatal(err)
	}
	if got.CorrelationID != "explicit" || got.Source != "tui" {
		t.Errorf("CorrelationID = %q, Source = %q", got.CorrelationID, got.Source)
	}
}

func TestEmitAlwaysAssignsEventIDAndTimestamp(t *testing.T) {
	e := validEvent()
	e.EventID = "forged"
	e.Timestamp = epoch.Add(-24 * time.Hour)

	got, err := newEmitter().Emit(context.Background(), &memoryWriter{}, e)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventID == "forged" || !got.Timestamp.Equal(epoch) {
		t.Errorf("caller-supplied EventID/Timestamp survived: %s %v", got.EventID, got.Timestamp)
	}
}

func TestEmitRedactsDataOnACopy(t *testing.T) {
	e := validEvent()
	e.Data = map[string]any{"commit": "a84f2d1", "token": plaintext, "out": "Authorization: Bearer " + plaintext}
	w := &memoryWriter{}

	if _, err := newEmitter().Emit(context.Background(), w, e); err != nil {
		t.Fatal(err)
	}

	stored := w.events[0].Data
	if stored["commit"] != "a84f2d1" || stored["token"] != Redacted || stored["out"] != "Authorization: Bearer "+Redacted {
		t.Errorf("stored data = %v", stored)
	}
	if e.Data["token"] != plaintext {
		t.Error("Emit modified the caller's Data map")
	}
}

func TestEmitRejectsInvalidEvents(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(e *domain.Event)
		want   string
	}{
		{"missing action", func(e *domain.Event) { e.Action = "" }, "action is required"},
		{"missing actor type", func(e *domain.Event) { e.ActorType = "" }, "actor_type"},
		{"unknown actor type", func(e *domain.Event) { e.ActorType = "robot" }, "actor_type"},
		{"missing resource type", func(e *domain.Event) { e.ResourceType = "" }, "resource_type"},
		{"missing result", func(e *domain.Event) { e.Result = "" }, "result"},
		{"unknown result", func(e *domain.Event) { e.Result = "maybe" }, "result"},
		{"missing severity", func(e *domain.Event) { e.Severity = "" }, "severity"},
		{"unknown severity", func(e *domain.Event) { e.Severity = "fatal" }, "severity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEvent()
			tt.mutate(&e)
			w := &memoryWriter{}

			_, err := newEmitter().Emit(context.Background(), w, e)

			if smerr.CodeOf(err) != smerr.CodeInvalidArgument || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want INVALID_ARGUMENT mentioning %q", err, tt.want)
			}
			if len(w.events) != 0 {
				t.Error("an invalid event reached the writer")
			}
		})
	}
}

func TestEmitReportsEveryInvalidField(t *testing.T) {
	_, err := newEmitter().Emit(context.Background(), &memoryWriter{}, domain.Event{})
	if err == nil {
		t.Fatal("want error")
	}
	for _, field := range []string{"action", "actor_type", "resource_type", "result", "severity"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error %q does not mention %s", err, field)
		}
	}
}

func TestEmitWrapsWriterErrors(t *testing.T) {
	boom := errors.New("disk full")

	_, err := newEmitter().Emit(context.Background(), &memoryWriter{err: boom}, validEvent())

	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "deployment.create") {
		t.Errorf("err = %v, want the writer error wrapped with the action", err)
	}
}
