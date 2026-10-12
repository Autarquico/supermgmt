package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const (
	ciWatchTimeout = time.Hour
	ciWatchInitial = 10 * time.Second
	ciWatchMax     = time.Minute
)

// ciWatchGitHub answers check-run queries from a table and counts them.
type ciWatchGitHub struct {
	mu    sync.Mutex
	runs  []github.CheckRun
	err   error
	calls int
}

func (g *ciWatchGitHub) For(context.Context, domain.ID) (github.Client, error) {
	return ciWatchClient{Client: nil, g: g}, nil
}

func (g *ciWatchGitHub) set(runs []github.CheckRun, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.runs, g.err = runs, err
}

func (g *ciWatchGitHub) used() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

type ciWatchClient struct {
	github.Client
	g *ciWatchGitHub
}

func (c ciWatchClient) CheckRuns(context.Context, github.Repo, string) ([]github.CheckRun, error) {
	c.g.mu.Lock()
	defer c.g.mu.Unlock()
	c.g.calls++
	return c.g.runs, c.g.err
}

const ciWatchSuite = 50

func (c ciWatchClient) WorkflowRun(_ context.Context, _ github.Repo, suite int64) (github.WorkflowRun, error) {
	if suite != ciWatchSuite {
		return github.WorkflowRun{}, github.ErrNoWorkflowRun
	}
	return github.WorkflowRun{
		ID: 700, RunAttempt: 2, Path: ".github/workflows/ci.yml", HeadBranch: "main", HeadSHA: depCommit, Event: "push",
	}, nil
}

// ciWatchRun is the run of the required check "test" in the given state.
func ciWatchRun(status, conclusion string) []github.CheckRun {
	return []github.CheckRun{{
		ID: 1, Name: "test", AppID: githubActionsAppID, Status: status, Conclusion: conclusion,
		HeadSHA: depCommit, SuiteID: ciWatchSuite,
	}}
}

// ciWatchFinalizer records what the watcher hands to finalization.
type ciWatchFinalizer struct {
	mu    sync.Mutex
	calls []ciWatchFinalized
	err   error
	done  chan struct{}
}

type ciWatchFinalized struct {
	id     domain.ID
	checks []github.CheckEvidence
}

func (f *ciWatchFinalizer) Finalize(_ context.Context, id domain.ID, checks []github.CheckEvidence) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ciWatchFinalized{id: id, checks: checks})
	if f.done != nil {
		select {
		case f.done <- struct{}{}:
		default:
		}
	}
	return f.err
}

func (f *ciWatchFinalizer) finalized() []ciWatchFinalized {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ciWatchFinalized(nil), f.calls...)
}

type ciWatchFixture struct {
	*depFixture
	gh        *ciWatchGitHub
	finalizer *ciWatchFinalizer
	watcher   *ciWatcher
	errs      []error
}

func newCIWatchFixture(t *testing.T, gated, server bool) *ciWatchFixture {
	t.Helper()
	f := &ciWatchFixture{depFixture: newDepFixture(t, gated), gh: &ciWatchGitHub{}, finalizer: &ciWatchFinalizer{}}
	f.gh.set(ciWatchRun("in_progress", ""), nil)
	var err error
	f.watcher, err = newCIWatcher(f.cfg, f.gh, f.finalizer,
		CIPolling{Initial: ciWatchInitial, Max: ciWatchMax, Timeout: ciWatchTimeout, Server: server},
		CIWatcherOptions{Tick: time.Hour, OnError: func(err error) { f.errs = append(f.errs, err) }})
	mustf(t, err, "newCIWatcher")
	return f
}

func (f *ciWatchFixture) poll() error { return f.watcher.pollDue(context.Background()) }

// untilNext moves the clock to the deployment's next scheduled check.
func (f *ciWatchFixture) untilNext(id domain.ID) {
	f.t.Helper()
	next := f.row(id).NextCICheck
	if next == nil {
		f.t.Fatal("deployment has no next check")
	}
	f.clock.Set(*next)
}

func wantCIFailure(t *testing.T, row database.Deployment, reason smerr.Reason) {
	t.Helper()
	if row.State != deployments.StateFailed || row.Failure.Code != string(smerr.CodeCINotPassed) || row.Failure.Reason != string(reason) {
		t.Fatalf("state %s code %s reason %s, want failed CI_NOT_PASSED/%s", row.State, row.Failure.Code, row.Failure.Reason, reason)
	}
}

// ---- polling ----------------------------------------------------------------------------------

func TestCIWatch_PassedChecksGoToFinalizationWithTheirEvidence(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()
	f.gh.set(ciWatchRun("completed", "success"), nil)

	mustf(t, f.poll(), "poll")

	calls := f.finalizer.finalized()
	if len(calls) != 1 || calls[0].id != created.ID {
		t.Fatalf("finalizations = %+v, want one for the deployment", calls)
	}
	ev := calls[0].checks
	if len(ev) != 1 || ev[0].CheckName != "test" || ev[0].RunID != 700 || ev[0].RunAttempt != 2 || ev[0].Conclusion != "success" {
		t.Errorf("evidence = %+v, want the passed check with its workflow run and attempt", ev)
	}
}

func TestCIWatch_PendingChecksBackOffFromTheInitialPollUpToTheMax(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()

	var gaps []time.Duration
	for range 6 {
		mustf(t, f.poll(), "poll")
		now := f.clock.Now()
		f.untilNext(created.ID)
		gaps = append(gaps, f.clock.Now().Sub(now))
	}

	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute, time.Minute}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("poll gaps = %v, want %v", gaps, want)
		}
	}
	if got := f.row(created.ID).State; got != deployments.StateWaitingCI {
		t.Errorf("state = %s, want waiting_ci while CI is pending", got)
	}
	if len(f.finalizer.finalized()) != 0 {
		t.Error("a pending CI must not finalize")
	}
}

func TestCIWatch_ServerModePollsOnlyAsABackstopAtTheMax(t *testing.T) {
	f := newCIWatchFixture(t, true, true)
	created := f.create()

	mustf(t, f.poll(), "poll")

	if next := f.row(created.ID).NextCICheck; next == nil || next.Sub(f.clock.Now()) != ciWatchMax {
		t.Errorf("next check %v, want now+ci_poll_max", next)
	}
}

func TestCIWatch_DoesNotLookBeforeTheCheckIsDue(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	f.create()
	mustf(t, f.poll(), "first poll")
	before := f.gh.used()

	f.clock.Advance(ciWatchInitial / 2)
	mustf(t, f.poll(), "early poll")

	if f.gh.used() != before {
		t.Errorf("GitHub asked %d times before the check was due", f.gh.used()-before)
	}
}

func TestCIWatch_AFailedCheckFailsTheDeploymentAtOnce(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()
	f.gh.set(ciWatchRun("completed", "failure"), nil)

	mustf(t, f.poll(), "poll")

	row := f.row(created.ID)
	wantCIFailure(t, row, smerr.ReasonCheckFailed)
	if row.FinishedAt == nil {
		t.Error("a failed deployment is finished")
	}
	events := f.events(eventDeploymentFailed)
	if len(events) != 1 || events[0].CorrelationID != created.ID.String() || events[0].Data["reason"] != string(smerr.ReasonCheckFailed) {
		t.Errorf("events = %+v, want one correlated deployment.failed", events)
	}
	if len(f.finalizer.finalized()) != 0 {
		t.Error("a failed CI must not finalize")
	}
}

func TestCIWatch_AMissingCheckWaitsForTheDeadlineThenFailsAsMissing(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()
	f.gh.set(nil, nil)

	mustf(t, f.poll(), "poll before the deadline")
	if got := f.row(created.ID).State; got != deployments.StateWaitingCI {
		t.Fatalf("state = %s, want waiting_ci: the check may not have started yet", got)
	}
	f.clock.Advance(ciWatchTimeout)
	mustf(t, f.poll(), "poll at the deadline")

	wantCIFailure(t, f.row(created.ID), smerr.ReasonCheckMissing)
}

func TestCIWatch_PendingChecksPastTheDeadlineFailAsATimeout(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()
	f.clock.Advance(ciWatchTimeout)

	mustf(t, f.poll(), "poll")

	wantCIFailure(t, f.row(created.ID), smerr.ReasonCITimeout)
}

func TestCIWatch_ChecksThatPassedAtTheDeadlineStillCount(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	f.create()
	f.clock.Advance(ciWatchTimeout)
	f.gh.set(ciWatchRun("completed", "success"), nil)

	mustf(t, f.poll(), "poll")

	if len(f.finalizer.finalized()) != 1 {
		t.Error("green CI at the deadline must finalize, not time out")
	}
}

func TestCIWatch_AGitHubFailureIsReportedAndRetriedUntilTheDeadline(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()
	f.gh.set(nil, errors.New("github is down"))

	err := f.poll()
	if err == nil {
		t.Fatal("poll hid a GitHub failure")
	}
	if row := f.row(created.ID); row.State != deployments.StateWaitingCI || row.NextCICheck == nil || !row.NextCICheck.After(f.clock.Now()) {
		t.Errorf("state %s next %v, want waiting_ci rescheduled", row.State, row.NextCICheck)
	}
	f.clock.Advance(ciWatchTimeout)
	_ = f.poll()

	wantCIFailure(t, f.row(created.ID), smerr.ReasonCITimeout)
}

func TestCIWatch_AFinalizationFaultKeepsTheDeploymentWaiting(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()
	f.gh.set(ciWatchRun("completed", "success"), nil)
	f.finalizer.err = errors.New("database is busy")

	if err := f.poll(); err == nil {
		t.Fatal("poll hid a finalization fault")
	}
	if got := f.row(created.ID).State; got != deployments.StateWaitingCI {
		t.Fatalf("state = %s, want waiting_ci", got)
	}
	f.finalizer.err = nil
	mustf(t, f.poll(), "retry")

	if len(f.finalizer.finalized()) != 2 {
		t.Errorf("finalizations = %d, want the retry to try again", len(f.finalizer.finalized()))
	}
}

func TestCIWatch_ACancelledDeploymentIsLeftAlone(t *testing.T) {
	f := newCIWatchFixture(t, true, false)
	created := f.create()
	_, err := f.deployments.Cancel(context.Background(), f.caller(f.deployer), created.ID)
	mustf(t, err, "Cancel")
	f.gh.set(ciWatchRun("completed", "success"), nil)

	mustf(t, f.poll(), "poll")

	if len(f.finalizer.finalized()) != 0 || f.gh.used() != 0 {
		t.Errorf("finalizations %d, GitHub calls %d; a cancelled deployment is not evaluated", len(f.finalizer.finalized()), f.gh.used())
	}
}

func TestCIWatch_DeploymentsWithoutAGateAreFinalizedWithoutEvidence(t *testing.T) {
	f := newCIWatchFixture(t, false, false)
	created := f.create()

	mustf(t, f.poll(), "poll")

	calls := f.finalizer.finalized()
	if len(calls) != 1 || calls[0].id != created.ID || calls[0].checks != nil {
		t.Errorf("finalizations = %+v, want one without evidence", calls)
	}
	if f.gh.used() != 0 {
		t.Error("an ungated deployment must not ask GitHub anything")
	}
}

// ---- webhook nudges ------------------------------------------------------------------------------

func TestCIWatch_ANudgeReEvaluatesOnlyTheDeploymentsOfThatCommit(t *testing.T) {
	f := newCIWatchFixture(t, true, true)
	f.create()
	f.create(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })
	f.gh.set(ciWatchRun("completed", "success"), nil)

	mustf(t, f.watcher.handleNudge(context.Background(), ciNudge{repositoryID: 4242, sha: depCommit}), "nudge")

	if f.gh.used() != 1 || len(f.finalizer.finalized()) != 1 {
		t.Errorf("GitHub calls %d finalizations %d, want exactly the nudged commit evaluated once", f.gh.used(), len(f.finalizer.finalized()))
	}
}

func TestCIWatch_ANudgeForAnotherRepositoryDoesNothing(t *testing.T) {
	f := newCIWatchFixture(t, true, true)
	f.create()

	mustf(t, f.watcher.handleNudge(context.Background(), ciNudge{repositoryID: 1, sha: depCommit}), "nudge")

	if f.gh.used() != 0 {
		t.Errorf("GitHub asked %d times for a repository the deployment does not use", f.gh.used())
	}
}

func TestCIWatch_ANudgeThatFindsCIPendingKeepsTheSchedule(t *testing.T) {
	f := newCIWatchFixture(t, true, true)
	created := f.create()
	mustf(t, f.poll(), "poll")
	scheduled := f.row(created.ID)

	f.clock.Advance(time.Second)
	mustf(t, f.watcher.handleNudge(context.Background(), ciNudge{repositoryID: 4242, sha: depCommit}), "nudge")

	after := f.row(created.ID)
	if !after.NextCICheck.Equal(*scheduled.NextCICheck) || !after.UpdatedAt.Equal(scheduled.UpdatedAt) {
		t.Errorf("schedule moved from %v to %v: a nudge must not advance the backoff", scheduled.NextCICheck, after.NextCICheck)
	}
}

func TestCIWatch_NudgeNeverBlocksWhenTheQueueIsFull(t *testing.T) {
	f := newCIWatchFixture(t, true, true)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for range 10 * ciNudgeBuffer {
			f.watcher.Nudge(4242, depCommit)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Nudge blocked on a full queue")
	}
	if len(f.watcher.nudges) != ciNudgeBuffer {
		t.Errorf("queued nudges = %d, want the buffer full", len(f.watcher.nudges))
	}
}

func TestCIWatch_RunEvaluatesANudgeAndStopsWithItsContext(t *testing.T) {
	f := newCIWatchFixture(t, true, true)
	f.create()
	f.finalizer.done = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- f.watcher.Run(ctx) }()
	waitForCIWatch(t, "the first pass", func() bool { return f.gh.used() == 1 })

	f.gh.set(ciWatchRun("completed", "success"), nil)
	f.watcher.Nudge(4242, depCommit)

	select {
	case <-f.finalizer.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the nudge did not reach finalization")
	}
	cancel()
	select {
	case err := <-stopped:
		mustf(t, err, "Run")
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

func waitForCIWatch(t *testing.T, what string, done func() bool) {
	t.Helper()
	for range 1000 {
		if done() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- polling configuration ----------------------------------------------------------------------

func TestCIPolling_DefaultsFollowTheConfigDefaults(t *testing.T) {
	got := CIPolling{}.withDefaults()

	if got.Initial != 15*time.Second || got.Max != 2*time.Minute || got.Timeout != 2*time.Hour {
		t.Errorf("defaults = %+v", got)
	}
	if clamped := (CIPolling{Initial: time.Minute, Max: time.Second}).withDefaults(); clamped.Max != time.Minute {
		t.Errorf("max = %v, want it never below the initial interval", clamped.Max)
	}
}
