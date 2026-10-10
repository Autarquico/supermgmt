package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func sampleIntent(e *env) NewIntent {
	return NewIntent{
		Step: "compose_up", Operation: "compose.up", TargetType: "node", TargetID: "node-1",
		PreState: json.RawMessage(`{"containers":2}`), DeadlineAt: e.clock.Now().Add(time.Second),
	}
}

func TestIntentLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	job := e.enqueue()
	c := e.claim("w1")

	intent, err := e.store.RecordIntent(ctx, c.Lease, sampleIntent(e))
	if err != nil {
		t.Fatalf("RecordIntent: %v", err)
	}
	if intent.State != IntentRecorded || intent.Dispatched() || intent.Marker != intent.ID.String() ||
		intent.LeaseGeneration != c.Lease.Generation || string(intent.PreState) != `{"containers":2}` {
		t.Fatalf("recorded intent = %+v", intent)
	}

	if err := e.store.MarkDispatched(ctx, c.Lease, intent.ID); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if err := e.store.MarkDispatched(ctx, c.Lease, intent.ID); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("second MarkDispatched = %v, want CONFLICT", err)
	}

	evidence := json.RawMessage(`{"done":true,"exit_status":0}`)
	if err := e.store.CompleteIntent(ctx, c.Lease, intent.ID, OutcomeSucceeded, evidence); err != nil {
		t.Fatalf("CompleteIntent: %v", err)
	}
	if err := e.store.CompleteIntent(ctx, c.Lease, intent.ID, OutcomeSucceeded, evidence); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("second CompleteIntent = %v, want CONFLICT", err)
	}

	intents, err := e.store.Intents(ctx, e.db.Reader(), job.ID)
	if err != nil || len(intents) != 1 {
		t.Fatalf("Intents = %v, %v", intents, err)
	}
	got := intents[0]
	if got.State != IntentCompleted || got.Outcome != OutcomeSucceeded || got.CompletedAt == nil ||
		!got.Dispatched() || string(got.Evidence) != string(evidence) {
		t.Fatalf("completed intent = %+v", got)
	}
}

func TestIntentMarkerIsUnique(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	c := e.claim("w1")
	ni := sampleIntent(e)
	ni.Marker = "marker-1"
	if _, err := e.store.RecordIntent(context.Background(), c.Lease, ni); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.RecordIntent(context.Background(), c.Lease, ni); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("duplicate marker = %v, want CONFLICT", err)
	}
}

func TestIntentValidation(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	c := e.claim("w1")
	ni := sampleIntent(e)
	ni.Operation = ""
	if _, err := e.store.RecordIntent(context.Background(), c.Lease, ni); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Fatalf("RecordIntent without operation = %v, want INVALID_ARGUMENT", err)
	}
	intent, err := e.store.RecordIntent(context.Background(), c.Lease, sampleIntent(e))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CompleteIntent(context.Background(), c.Lease, intent.ID, "maybe", nil); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Fatalf("CompleteIntent with bad outcome = %v, want INVALID_ARGUMENT", err)
	}
}

func TestCompletedIntentCannotBeDispatched(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.enqueue()
	c := e.claim("w1")
	intent, err := e.store.RecordIntent(ctx, c.Lease, sampleIntent(e))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CompleteIntent(ctx, c.Lease, intent.ID, OutcomeFailed, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.store.MarkDispatched(ctx, c.Lease, intent.ID); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("MarkDispatched on completed intent = %v, want CONFLICT", err)
	}
}
