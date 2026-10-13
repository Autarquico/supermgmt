package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func timelineFixture() (wire.Deployment, []wire.Event) {
	started := epoch.Add(-time.Hour)
	finished := started.Add(2 * time.Minute)
	plan := "sha256:" + strings.Repeat("9", 64)
	d := wire.Deployment{
		ID: m4DeployTwo, Kind: "deploy", AppID: m4AppShop, AppTargetID: m4TargetPrd,
		State: "failed", StateReason: "HEALTH_CHECK_FAILED", CommitSHA: strings.Repeat("2", 40),
		Images:   []wire.RequestedImage{{Service: "web", Digest: "sha256:" + strings.Repeat("c", 64)}},
		PlanHash: &plan, CreatedAt: started, FinishedAt: &finished,
		Steps: []wire.DeploymentStep{
			{Ordinal: 3, Name: "health", State: "failed", Attempt: 1, Error: &wire.StepError{Code: "HEALTH_FAILED", Reason: "TIMEOUT", Cause: "no 200 in 30s"}},
			{Ordinal: 1, Name: "preflight", State: "succeeded", Attempt: 1},
			{Ordinal: 2, Name: "compose_up", State: "succeeded", Attempt: 1},
			{Ordinal: 4, Name: "finalize", State: "skipped", Attempt: 0},
		},
	}
	events := []wire.Event{
		{Seq: 12, Timestamp: started.Add(90 * time.Second), Action: "deployment.step_failed", Result: "failure", CorrelationID: "corr-0000000b"},
		{Seq: 10, Timestamp: started, Action: "deployment.created", Result: "success", CorrelationID: "corr-0000000a"},
		{Seq: 11, Timestamp: started.Add(time.Minute), Action: "deployment.plan_frozen", Result: "success", CorrelationID: "corr-0000000a"},
	}
	return d, events
}

func newTimelineAPI() *deployFlowAPI {
	api := &deployFlowAPI{m4API: newM4API()}
	api.detail, api.events = timelineFixture()
	return api
}

// timelineRig drives the detail screen the way the Model will: it opens on the
// row the list holds, then loads.
type timelineRig struct {
	h      *harness
	screen timelineScreen
}

func openTimelineRig(t *testing.T, api API, rows int) *timelineRig {
	t.Helper()
	r := &timelineRig{h: newHarness(t, api, 80, rows)}
	listed, _ := timelineFixture()
	listed.Steps, listed.Images, listed.PlanHash = nil, nil, nil
	r.screen.open(listed)
	return r
}

func (r *timelineRig) loadAll() {
	r.h.t.Helper()
	r.h.drain(r.screen.loadDetail(r.h.m))
	r.h.drain(r.screen.loadEvents(r.h.m))
}

func (r *timelineRig) view() string {
	bw, bh := r.h.m.bodySize()
	return stripANSI(strings.Join(fitLines(r.screen.body(r.h.m, bw, bh), bw, bh), "\n"))
}

func loadedTimeline(t *testing.T, api *deployFlowAPI, rows int) *timelineRig {
	t.Helper()
	r := openTimelineRig(t, api, rows)
	r.loadAll()
	return r
}

func TestTimelineGolden(t *testing.T) {
	r := loadedTimeline(t, newTimelineAPI(), 24)
	bw, bh := r.h.m.bodySize()
	assertGolden(t, "m4_timeline", r.view(), bw, bh)
}

func TestTimelineOpensFromTheListRowBeforeTheDetailArrives(t *testing.T) {
	r := openTimelineRig(t, newTimelineAPI(), 24)
	view := r.view()
	for _, want := range []string{"DEPLOYMENT " + shortID(m4DeployTwo), "failed", "no steps yet"} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q before any load:\n%s", want, view)
		}
	}
}

func TestTimelineListsStepsInOrderWithTheirFailure(t *testing.T) {
	view := loadedTimeline(t, newTimelineAPI(), 24).view()
	last := -1
	for _, step := range []string{"preflight", "compose_up", "health", "finalize"} {
		at := strings.Index(view, step)
		if at < last {
			t.Errorf("step %s is out of order:\n%s", step, view)
		}
		last = at
	}
	for _, want := range []string{"HEALTH_FAILED/TIMEOUT (no 200 in 30s)", "HEALTH_CHECK_FAILED"} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q:\n%s", want, view)
		}
	}
}

func TestTimelineShowsEventsOldestFirstForThisDeployment(t *testing.T) {
	api := newTimelineAPI()
	view := loadedTimeline(t, api, 30).view()
	if api.eventQuery.ResourceType != domain.ResourceDeployment || api.eventQuery.ResourceID != m4DeployTwo {
		t.Errorf("events were queried with %+v, want this deployment's", api.eventQuery)
	}
	created, frozen, failed := strings.Index(view, "deployment.created"), strings.Index(view, "deployment.plan_frozen"), strings.Index(view, "deployment.step_failed")
	if created < 0 || created > frozen || frozen > failed {
		t.Errorf("events are not oldest first:\n%s", view)
	}
	if !strings.Contains(view, "0000000a") {
		t.Errorf("events should carry their correlation id:\n%s", view)
	}
}

func TestTimelineShowsTheNewestEventsWhenTheyDoNotAllFit(t *testing.T) {
	view := loadedTimeline(t, newTimelineAPI(), 24).view()
	if !strings.Contains(view, "deployment.step_failed") || strings.Contains(view, "deployment.created") {
		t.Errorf("a short screen should keep the newest events:\n%s", view)
	}
}

func TestTimelineKeepsWhatItHasWhenReloadFails(t *testing.T) {
	api := newTimelineAPI()
	r := loadedTimeline(t, api, 24)
	api.hook("GetDeployment", func(context.Context) error { return errors.New("daemon went away") })
	r.loadAll()
	view := r.view()
	if !strings.Contains(view, "[stale]") || !strings.Contains(view, "compose_up") {
		t.Errorf("a failed reload should keep the steps and say stale:\n%s", view)
	}
}

func TestTimelineFirstFailureIsAnError(t *testing.T) {
	api := newTimelineAPI()
	api.hook("GetDeployment", func(context.Context) error { return errors.New("denied") })
	r := openTimelineRig(t, api, 24)
	r.loadAll()
	if view := r.view(); !strings.Contains(view, "cannot load: denied") || strings.Contains(view, "[stale]") {
		t.Errorf("a first failure is an error, not stale data:\n%s", view)
	}
}

func TestTimelineIgnoresADetailThatArrivesForAnotherDeployment(t *testing.T) {
	api := newTimelineAPI()
	r := openTimelineRig(t, api, 24)
	cmd := r.screen.loadDetail(r.h.m)
	other, _ := timelineFixture()
	other.ID = m4DeployOne
	r.screen.open(other)
	r.h.drain(cmd)
	if r.screen.id != m4DeployOne || r.screen.d.ID != m4DeployOne {
		t.Errorf("a stale reply replaced the open deployment: id=%s d=%s", r.screen.id, r.screen.d.ID)
	}
}

func TestTimelineSaysWhenTheDaemonCannotServeIt(t *testing.T) {
	r := openTimelineRig(t, newFake(), 24)
	if cmd := r.screen.loadDetail(r.h.m); cmd != nil {
		t.Fatal("a client without DeployAPI must not issue a detail load")
	}
	if view := r.view(); !strings.Contains(view, unavailableDeploy) {
		t.Errorf("view does not say it is unavailable:\n%s", view)
	}
}

func TestTimelineWithoutStepsExplainsWhy(t *testing.T) {
	api := newTimelineAPI()
	api.detail = wire.Deployment{ID: m4DeployTwo, Kind: "deploy", State: "waiting_ci", CreatedAt: epoch}
	api.events = nil
	view := loadedTimeline(t, api, 24).view()
	for _, want := range []string{"no steps yet", "not finished", "no events recorded", "set once CI is verified"} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q:\n%s", want, view)
		}
	}
}
