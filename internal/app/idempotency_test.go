package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// keyed returns the caller carrying an Idempotency-Key, and the number of
// times its Responder ran (once per executed mutation, never on a replay).
func (f *fixture) keyed(id domain.ID, key, hash string) (Caller, *atomic.Int32) {
	var runs atomic.Int32
	by := f.caller(id)
	by.Source = "api"
	by.Idempotency = &Idempotency{
		Key: key, Method: "POST", Path: "/api/v1/plans", RequestHash: hash,
		Respond: func(result any, _ error) (int, []byte) {
			n := runs.Add(1)
			created, _ := result.(CreatedPlan)
			return 201, fmt.Appendf(nil, `{"data":{"plan_hash":%q,"run":%d}}`, created.Record.PlanHash, n)
		},
	}
	return by, &runs
}

func asReplay(t *testing.T, err error) *Replay {
	t.Helper()
	var replay *Replay
	if !errors.As(err, &replay) {
		t.Fatalf("error = %v, want a replay", err)
	}
	return replay
}

func TestAReplayedRequestReturnsTheStoredBytesAndExecutesNothing(t *testing.T) {
	f := newFixture(t)
	first, runs := f.keyed(f.alice, "key-1", "hash-a")
	created, err := f.plans.Create(context.Background(), first, f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	again, _ := f.keyed(f.alice, "key-1", "hash-a")
	_, err = f.plans.Create(context.Background(), again, f.reboot())

	replay := asReplay(t, err)
	want := fmt.Sprintf(`{"data":{"plan_hash":%q,"run":1}}`, created.Record.PlanHash)
	if replay.Status != 201 || string(replay.Envelope) != want {
		t.Errorf("replay = %d %s, want 201 %s", replay.Status, replay.Envelope, want)
	}
	if runs.Load() != 1 || len(f.events("plan.create")) != 1 {
		t.Errorf("responder ran %d times, %d plans created; want 1 and 1", runs.Load(), len(f.events("plan.create")))
	}
}

func TestTheSameKeyWithADifferentRequestIsAMismatch(t *testing.T) {
	f := newFixture(t)
	first, _ := f.keyed(f.alice, "key-1", "hash-a")
	if _, err := f.plans.Create(context.Background(), first, f.reboot()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	other, _ := f.keyed(f.alice, "key-1", "hash-b")
	_, err := f.plans.Create(context.Background(), other, f.reboot())

	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Code != smerr.CodeConflict || typed.Reason != smerr.ReasonIdempotencyMismatch {
		t.Errorf("error = %v, want CONFLICT/IDEMPOTENCY_MISMATCH", err)
	}
}

func TestKeysAreScopedToTheIdentity(t *testing.T) {
	f := newFixture(t)
	alice, _ := f.keyed(f.alice, "shared", "hash-a")
	bob, bobRuns := f.keyed(f.bob, "shared", "hash-a")
	if _, err := f.plans.Create(context.Background(), alice, f.reboot()); err != nil {
		t.Fatalf("alice: %v", err)
	}

	_, err := f.plans.Create(context.Background(), bob, f.reboot())

	if err != nil || bobRuns.Load() != 1 {
		t.Errorf("bob's request with alice's key: err %v, ran %d times; want it to execute", err, bobRuns.Load())
	}
}

func TestARolledBackMutationLeavesNoRecord(t *testing.T) {
	f := newFixture(t)
	bad := f.reboot()
	bad.Action = "node.unknown"
	by, runs := f.keyed(f.alice, "key-1", "hash-a")
	if _, err := f.plans.Create(context.Background(), by, bad); err == nil {
		t.Fatal("want the unknown action to fail")
	}

	retry, retryRuns := f.keyed(f.alice, "key-1", "hash-a")
	_, err := f.plans.Create(context.Background(), retry, f.reboot())

	if err != nil || runs.Load() != 0 || retryRuns.Load() != 1 {
		t.Errorf("retry: err %v, responder runs %d then %d; want it to execute once after the failure", err, runs.Load(), retryRuns.Load())
	}
}

func TestARefusalLeavesItsAuditEventButNoRecord(t *testing.T) {
	f := newFixture(t)
	by, _ := f.keyed(f.dave, "key-1", "hash-a") // dave holds no role

	_, err := f.plans.Create(context.Background(), by, f.reboot())

	if smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Fatalf("error = %v, want POLICY_DENIED", err)
	}
	if len(f.events("policy.deny")) == 0 {
		t.Error("the refusal left no audit event")
	}
	_, err = database.GetIdempotencyRecord(context.Background(), f.db.Reader(), f.dave, "key-1")
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("a refused request stored a record: %v", err)
	}
}

func TestConcurrentDuplicatesExecuteOnce(t *testing.T) {
	f := newFixture(t)
	const callers = 8
	var executed atomic.Int32
	var wg sync.WaitGroup
	results := make([]error, callers)
	for i := range callers {
		wg.Go(func() {
			by, runs := f.keyed(f.alice, "key-1", "hash-a")
			_, results[i] = f.plans.Create(context.Background(), by, f.reboot())
			executed.Add(runs.Load())
		})
	}
	wg.Wait()

	replays := 0
	for _, err := range results {
		var replay *Replay
		switch {
		case errors.As(err, &replay):
			replays++
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if executed.Load() != 1 || replays != callers-1 || len(f.events("plan.create")) != 1 {
		t.Errorf("executed %d, replayed %d, plans %d; want 1, %d, 1", executed.Load(), replays, len(f.events("plan.create")), callers-1)
	}
}

func TestAnExpiredRecordIsExecutedAgain(t *testing.T) {
	f := newFixture(t)
	first, _ := f.keyed(f.alice, "key-1", "hash-a")
	if _, err := f.plans.Create(context.Background(), first, f.reboot()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.clock.Advance(idempotencyTTL + time.Minute)

	again, runs := f.keyed(f.alice, "key-1", "hash-a")
	_, err := f.plans.Create(context.Background(), again, f.reboot())

	if err != nil || runs.Load() != 1 || len(f.events("plan.create")) != 2 {
		t.Errorf("err %v, runs %d, plans %d; want a fresh execution", err, runs.Load(), len(f.events("plan.create")))
	}
}

func TestTheRecordPointsAtTheJobItCreated(t *testing.T) {
	f := newFixture(t)
	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	by, _ := f.keyed(f.alice, "submit-1", "hash-s")
	by.Idempotency.Respond = func(any, error) (int, []byte) { return 202, []byte(`{"data":{}}`) }

	sub, err := f.plans.Submit(context.Background(), by, created.Record.ID, created.Record.PlanHash)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	rec, err := database.GetIdempotencyRecord(context.Background(), f.db.Reader(), f.alice, "submit-1")
	if err != nil || rec.JobID == nil || *rec.JobID != sub.Job.ID {
		t.Errorf("record = %+v, %v; want it to point at job %s", rec, err, sub.Job.ID)
	}
}

func TestEventsCarryTheRequestSource(t *testing.T) {
	f := newFixture(t)
	by, _ := f.keyed(f.alice, "key-1", "hash-a")
	if _, err := f.plans.Create(context.Background(), by, f.reboot()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := f.events("plan.create")[0].Source; got != "api" {
		t.Errorf("event source = %q, want api", got)
	}
}
