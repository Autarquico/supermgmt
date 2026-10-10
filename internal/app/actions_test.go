package app

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// action is a node fixture with node.setup recorded on nginx.service and a
// service-action handler over a scripted adapter.
type action struct {
	*nodeFixture
	adapter *fakeAdapter
	handler actionHandler
	lease   jobs.Lease // of the job being run, renewed as time passes like the engine's heartbeat
	slept   time.Duration
}

func newAction(t *testing.T) *action {
	t.Helper()
	a := &action{nodeFixture: newNodeFixture(t), adapter: newFakeAdapter(domain.RuntimeSystemd)}
	a.grantSetup("nginx.service")
	a.dialer.as("supermgmt").exit("fake.restart", 0)
	core, err := newCore(a.cfg)
	mustf(t, err, "newCore")
	a.handler = actionHandler{
		core: core, store: a.store, conn: a.conn, adapters: fakeAdapters(a.adapter, newFakeAdapter(domain.RuntimeDocker)),
		settle: Settle{Sleep: func(ctx context.Context, d time.Duration) {
			a.clock.Advance(d)
			a.slept += d
			_ = a.store.Heartbeat(ctx, a.lease)
		}}.withDefaults(),
	}
	return a
}

// restartApproved submits a restart of nginx and approves it to quorum.
func (a *action) restartApproved() jobs.Job {
	a.t.Helper()
	sub, err := a.svcs.Act(context.Background(), a.caller(a.alice), a.service.ID, domain.VerbRestart)
	mustf(a.t, err, "Act")
	return a.approveToQuorum(sub.Job)
}

// run claims the queued job and runs the handler on it.
func (a *action) run() (jobs.Claimed, error) {
	a.t.Helper()
	claimed, ok := a.claim()
	if !ok {
		a.t.Fatal("no job to claim")
	}
	a.lease = claimed.Lease
	return claimed, a.handler.Run(context.Background(), claimed.Lease)
}

func (a *action) intents(job domain.ID) []jobs.Intent {
	a.t.Helper()
	intents, err := a.store.Intents(context.Background(), a.db.Reader(), job)
	mustf(a.t, err, "Intents")
	return intents
}

func TestActRefusesWhatSetupDidNotGrant(t *testing.T) {
	n := newNodeFixture(t)
	ctx, by := context.Background(), n.caller(n.alice)

	_, withoutSetup := n.svcs.Act(ctx, by, n.service.ID, domain.VerbRestart)
	n.grantSetup("other.service")
	_, otherUnit := n.svcs.Act(ctx, by, n.service.ID, domain.VerbRestart)

	if smerr.CodeOf(withoutSetup) != smerr.CodeCapabilityUnavailable {
		t.Errorf("without node.setup: %v, want CAPABILITY_UNAVAILABLE", withoutSetup)
	}
	wantError(t, otherUnit, smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible)
	if jobs, _ := n.store.List(ctx, n.db.Reader(), jobs.ListFilter{}); len(jobs) != 0 {
		t.Errorf("a refused action left %d jobs", len(jobs))
	}
}

func TestActInProductionWaitsForApprovalWithAPlan(t *testing.T) {
	n := newNodeFixture(t)
	n.grantSetup("nginx.service")

	sub, err := n.svcs.Act(context.Background(), n.caller(n.alice), n.service.ID, domain.VerbRestart)
	if err != nil {
		t.Fatalf("Act: %v", err)
	}
	job := sub.Job
	if job.Type != "service.restart" || job.State != domain.JobAwaitingApproval || job.RetryClass != domain.RetryNonRetryable ||
		job.PlanID == nil || job.PlanHash == "" || sub.Policy.Quorum != 2 || job.Resource.ID != n.service.ID {
		t.Errorf("job = %+v, policy %+v", job, sub.Policy)
	}
	if len(n.events("plan.create")) != 1 || len(n.events("plan.submit")) != 1 {
		t.Error("the plan and its submission must both be audited")
	}
}

func TestActIsDeniedForCallersWithoutThePermission(t *testing.T) {
	n := newNodeFixture(t)
	n.grantSetup("nginx.service")

	_, err := n.svcs.Act(context.Background(), n.caller(n.dave), n.service.ID, domain.VerbRestart)

	if smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Errorf("error = %v, want POLICY_DENIED", err)
	}
}

func TestActRejectsAnUnknownVerb(t *testing.T) {
	n := newNodeFixture(t)

	_, err := n.svcs.Act(context.Background(), n.caller(n.alice), n.service.ID, "reload")

	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("error = %v", err)
	}
}

func TestActIsIdempotentUnderTheSameKey(t *testing.T) {
	n := newNodeFixture(t)
	n.grantSetup("nginx.service")
	first, _ := n.keyed(n.alice, "restart-1", "hash")
	first.Idempotency.Respond = func(any, error) (int, []byte) { return 202, []byte(`{"data":"submitted"}`) }
	again, _ := n.keyed(n.alice, "restart-1", "hash")

	_, err := n.svcs.Act(context.Background(), first, n.service.ID, domain.VerbRestart)
	mustf(t, err, "first Act")
	_, err = n.svcs.Act(context.Background(), again, n.service.ID, domain.VerbRestart)

	_ = asReplay(t, err)
	if all, _ := n.store.List(context.Background(), n.db.Reader(), jobs.ListFilter{}); len(all) != 1 {
		t.Errorf("%d jobs after a replayed request, want 1", len(all))
	}
}

func TestTheHandlerRecordsTheIntentBeforeSendingAndSettlesOnEvidence(t *testing.T) {
	a := newAction(t)
	job := a.restartApproved()
	var seenAtSend jobs.Intent
	a.dialer.as("supermgmt").on("fake.restart", func(c templates.Command) (transport.Result, error) {
		intents, err := a.store.Intents(context.Background(), a.db.Reader(), job.ID)
		if err != nil || len(intents) != 1 {
			t.Errorf("at send time: %d intents, %v", len(intents), err)
			return transport.Result{}, nil
		}
		seenAtSend = intents[0]
		return transport.Result{}, nil
	})
	a.adapter.observe = func(int) (jobs.Evidence, error) { return complete(jobs.ClassComplete), nil }

	_, err := a.run()
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if seenAtSend.State != jobs.IntentRecorded || seenAtSend.DispatchedAt == nil || len(seenAtSend.PreState) == 0 || seenAtSend.Marker == "" {
		t.Errorf("intent at send time = %+v; it must be durable and dispatched before the command goes out", seenAtSend)
	}
	done := a.intents(job.ID)[0]
	if done.State != jobs.IntentCompleted || done.Outcome != jobs.OutcomeSucceeded || done.Operation != "service.restart" ||
		done.TargetType != "service" || done.TargetID != a.service.ID.String() {
		t.Errorf("intent after = %+v", done)
	}
	var ev jobs.Evidence
	if err := json.Unmarshal(done.Evidence, &ev); err != nil || ev.Classification != jobs.ClassComplete || len(ev.Fingerprint) == 0 {
		t.Errorf("evidence = %s, %v", done.Evidence, err)
	}
	if got := a.adapter.dispatches(); len(got) != 1 || !containsMarker(got[0].Line, done.Marker) {
		t.Errorf("dispatches = %+v; the command must carry the intent's marker %s", got, done.Marker)
	}
	if want := epoch.Add(templates.ActionDeadline); !done.DeadlineAt.Equal(want) {
		t.Errorf("deadline = %v, want %v (plan Q12: 2m)", done.DeadlineAt, want)
	}
}

func containsMarker(line, marker string) bool {
	return marker != "" && len(line) >= len(marker) && line[len(line)-len(marker):] == marker
}

func TestTheHandlerConnectsAsTheDedicatedUserWithThePinnedKey(t *testing.T) {
	a := newAction(t)
	a.restartApproved()
	a.adapter.observe = func(int) (jobs.Evidence, error) { return complete(jobs.ClassComplete), nil }

	_, err := a.run()

	mustf(t, err, "handler")
	targets := a.dialer.targets()
	last := targets[len(targets)-1]
	if last.User != "supermgmt" || last.CredentialRef != "secret://ssh/default@1" {
		t.Errorf("connected as %s with %s", last.User, last.CredentialRef)
	}
}

func TestTheHandlerWaitsForTheActionToSettle(t *testing.T) {
	a := newAction(t)
	a.restartApproved()
	a.adapter.observe = func(call int) (jobs.Evidence, error) {
		if call < 3 {
			return jobs.Evidence{}, errors.New("still settling")
		}
		return complete(jobs.ClassComplete), nil
	}

	_, err := a.run()

	if err != nil || a.adapter.observeCalls != 3 || a.slept != 2*time.Second {
		t.Errorf("err %v, %d observations, slept %v; want it to poll until evidence appears", err, a.adapter.observeCalls, a.slept)
	}
}

func (a *action) wantInterrupted(err error, job domain.ID) {
	a.t.Helper()
	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		a.t.Fatalf("error = %v, want one wrapping ErrOutcomeUnknown (the engine interrupts the job)", err)
	}
	if in := a.intents(job)[0]; in.State != jobs.IntentRecorded || in.DispatchedAt == nil {
		a.t.Errorf("intent = %+v; an unknown outcome leaves the dispatched intent recorded for the reconciler", in)
	}
}

func TestANonZeroExitIsObservedNotConcluded(t *testing.T) {
	a := newAction(t)
	job := a.restartApproved()
	a.dialer.as("supermgmt").exit("fake.restart", 3)
	a.adapter.observe = func(int) (jobs.Evidence, error) { return jobs.Evidence{}, errors.New("no evidence") }

	_, err := a.run()

	a.wantInterrupted(err, job.ID)
}

func TestANonZeroExitWithProofThatNothingChangedFailsTheJob(t *testing.T) {
	a := newAction(t)
	job := a.restartApproved()
	a.dialer.as("supermgmt").exit("fake.restart", 124) // timeout(1)
	a.adapter.observe = func(int) (jobs.Evidence, error) { return complete(jobs.ClassNotStarted), nil }

	_, err := a.run()

	if smerr.CodeOf(err) != smerr.CodeInternal || errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("error = %v, want a proven failure", err)
	}
	if in := a.intents(job.ID)[0]; in.Outcome != jobs.OutcomeFailed || len(in.Evidence) == 0 {
		t.Errorf("intent = %+v", in)
	}
}

func TestOnlyProvenNotStartedFailsAndAnythingElseIsUnknown(t *testing.T) {
	for _, class := range []jobs.Classification{jobs.ClassUnknown, jobs.ClassPartialStable} {
		a := newAction(t)
		job := a.restartApproved()
		a.adapter.observe = func(int) (jobs.Evidence, error) { return complete(class), nil }

		_, err := a.run()

		a.wantInterrupted(err, job.ID)
	}
	a := newAction(t)
	job := a.restartApproved()
	a.adapter.observe = func(int) (jobs.Evidence, error) {
		ev := complete(jobs.ClassNotStarted)
		ev.Done = false // classified, but nothing proves the platform finished
		return ev, nil
	}
	_, err := a.run()
	a.wantInterrupted(err, job.ID)
}

func TestAnUnobservableOutcomeInterruptsTheJobAndIsNeverRetried(t *testing.T) {
	a := newAction(t)
	job := a.restartApproved()
	a.adapter.observe = func(int) (jobs.Evidence, error) { return jobs.Evidence{}, errors.New("node went away") }

	_, err := a.run()

	a.wantInterrupted(err, job.ID)
	if got := len(a.adapter.dispatches()); got != 1 {
		t.Errorf("%d dispatches; the command must never be sent twice", got)
	}
	if smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
		t.Errorf("code = %s", smerr.CodeOf(err))
	}
}

func TestALostConnectionAfterDispatchIsSettledByEvidence(t *testing.T) {
	a := newAction(t)
	a.restartApproved()
	a.dialer.as("supermgmt").down("fake.restart", smerr.New(smerr.CodeNodeUnreachable, "", "connection reset"))
	a.adapter.observe = func(int) (jobs.Evidence, error) { return complete(jobs.ClassComplete), nil }

	_, err := a.run()
	if err != nil {
		t.Errorf("handler: %v; the action did complete, the evidence says so", err)
	}
}

func TestALostConnectionWaitsOutTheRemoteDeadlineBeforeGivingUp(t *testing.T) {
	a := newAction(t)
	a.restartApproved()
	a.dialer.as("supermgmt").down("fake.restart", smerr.New(smerr.CodeNodeUnreachable, "", "connection reset"))
	a.adapter.observe = func(int) (jobs.Evidence, error) { return jobs.Evidence{}, errors.New("unreachable") }

	_, err := a.run()

	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("error = %v", err)
	}
	if want := templates.ActionDeadline + templates.KillAfter; a.slept < want {
		t.Errorf("gave up after %v, before the remote command could have ended (%v)", a.slept, want)
	}
}

func TestTheHandlerSendsNothingWhenPreflightFails(t *testing.T) {
	a := newAction(t)
	job := a.restartApproved()
	a.adapter.preflightErr = smerr.FromReason(smerr.ReasonUnitNotEligible, "unit became writable by others")

	_, err := a.run()

	wantError(t, err, smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible)
	if len(a.intents(job.ID)) != 0 || len(a.adapter.dispatches()) != 0 {
		t.Error("a unit that fails the trust profile must not even get an intent")
	}
}

func TestTheHandlerRechecksTheGrantAtExecution(t *testing.T) {
	a := newAction(t)
	a.restartApproved()
	a.grantSetup("other.service") // setup re-run without nginx

	_, err := a.run()

	wantError(t, err, smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible)
	if len(a.adapter.dispatches()) != 0 {
		t.Error("an ungranted verb was dispatched")
	}
}
