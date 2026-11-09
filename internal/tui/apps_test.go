package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func openApps(t *testing.T, api API, w, h int) *harness {
	t.Helper()
	hs := newHarness(t, api, w, h)
	hs.start()
	hs.press("9")
	return hs
}

func openShop(t *testing.T, api API, w, h int) *harness {
	t.Helper()
	hs := openApps(t, api, w, h)
	hs.press("j", "enter") // blog comes first, then shop
	return hs
}

// Scenario 1.
func TestOverviewGroupsAppsAndListsOtherServices(t *testing.T) {
	h := openApps(t, newAppsFake(), 100, 28)
	v := h.view()
	contains(t, v, "web-1")
	contains(t, v, "shop (2)")
	contains(t, v, "blog (1)")
	contains(t, v, "other services")
	contains(t, v, "redis")
	contains(t, v, "sm-demo.service")
}

// Scenario 2.
func TestOverviewShowsHealthRestartsResourcesAndReadingTime(t *testing.T) {
	h := openApps(t, newAppsFake(), 100, 28)
	v := h.view()
	contains(t, v, "degraded")
	contains(t, v, "restarts 3")
	contains(t, v, "cpu 12% mem 410M/2.0G")
	contains(t, v, "12:00:03")
	contains(t, v, "errors 5")
	for _, line := range strings.Split(v, "\n") {
		if strings.Contains(line, "blog (1)") && strings.Contains(line, "errors") {
			t.Errorf("an app with no errors shows an error count: %q", line)
		}
	}
}

func TestOverviewLoadsAfterFirstPaintAndAsksForStatsAndErrors(t *testing.T) {
	api := newAppsFake()
	h := newHarness(t, api, 100, 28)
	h.start()
	if api.count("ListApps") != 0 {
		t.Fatal("the dashboard read the apps")
	}
	cmd := h.send(keyMsg("9"))
	contains(t, h.view(), "reading apps")
	contains(t, h.view(), "web-1") // the machines show before the apps arrive
	if api.count("ListApps") != 0 {
		t.Fatal("the apps were read before the first paint of the screen")
	}
	h.drain(cmd)
	if len(api.listed) != 1 || !api.listed[0].Stats || !api.listed[0].Errors {
		t.Errorf("ListApps queries = %+v, want one with stats and errors", api.listed)
	}
}

func TestOverviewDoesNotAskTheNodesEveryTick(t *testing.T) {
	api := newAppsFake()
	h := openApps(t, api, 100, 28)
	h.drain(h.send(tickMsg{}))
	if n := api.count("ListApps"); n != 1 {
		t.Errorf("ListApps ran %d times, want 1: a tick within the refresh window must not ask the nodes", n)
	}
	h.press("r")
	if n := api.count("ListApps"); n != 2 {
		t.Errorf("ListApps ran %d times after r, want 2", n)
	}
	for range 7 { // DefaultRefresh periods make up the refresh window
		h.drain(h.send(tickMsg{}))
	}
	if n := api.count("ListApps"); n != 3 {
		t.Errorf("ListApps ran %d times once the window passed, want 3", n)
	}
}

func TestAppsNeedTheDaemonToServeThem(t *testing.T) {
	h := openApps(t, newFake(), 100, 28)
	contains(t, h.view(), unavailableApps)
}

// Scenario 3.
func TestPanelShowsComponentsVolumesPortsAndRedactedConfig(t *testing.T) {
	h := openShop(t, newAppsFake(), 120, 40)
	v := h.view()
	contains(t, v, "shop on web-1")
	contains(t, v, "nginx:1.27")
	contains(t, v, "postgres:16")
	contains(t, v, "unhealthy")
	contains(t, v, "0.0.0.0:8080->80/tcp")
	contains(t, v, "volume shop_assets → /srv/assets (rw)")
	contains(t, v, "API_TOKEN=[REDACTED]")
	contains(t, v, "unless-stopped")
	contains(t, v, "now  ")
	h.press("j")
	contains(t, h.view(), "POSTGRES_PASSWORD=[REDACTED]")
}

func TestPanelScrollsToTheConfigurationBelowTheFold(t *testing.T) {
	h := openShop(t, newAppsFake(), 80, 24)
	lacks(t, h.view(), "API_TOKEN=[REDACTED]")
	h.press("pgdown")
	contains(t, h.view(), "API_TOKEN=[REDACTED]")
	h.press("pgup")
	lacks(t, h.view(), "API_TOKEN=[REDACTED]")
}

func TestPanelTrendIsMemoryOnlyAndKeptInMemory(t *testing.T) {
	api := newAppsFake()
	h := openShop(t, api, 120, 40)
	contains(t, h.view(), "collecting samples")
	api.mu.Lock()
	api.stats.SampledAt = api.stats.SampledAt.Add(5e9)
	api.stats.Total.MemUsedBytes = 600 << 20
	api.mu.Unlock()
	h.drain(h.send(tickMsg{}))
	if got := len(h.m.apps.trend); got != 2 {
		t.Fatalf("trend has %d samples, want 2", got)
	}
	contains(t, h.view(), "2 samples")
	h.drain(h.send(tickMsg{})) // the same sample answers again: not a new point
	if got := len(h.m.apps.trend); got != 2 {
		t.Errorf("trend has %d samples after a repeated sample, want 2", got)
	}
	h.press("esc", "enter")
	if got := len(h.m.apps.trend); got != 1 {
		t.Errorf("a reopened panel starts a new trend: %d samples, want 1", got)
	}
}

// Scenario 4.
func TestLogsFollowSearchAndStopOnLeaving(t *testing.T) {
	api := newAppsFake()
	h := openShop(t, api, 120, 30)
	h.press("l")
	contains(t, h.view(), "listening on :80")
	contains(t, h.view(), "paused")

	// Following polls with the opaque cursor and appends what arrives, showing a gap as a gap.
	api.polls = []wire.AppLogs{{Cursor: cursorTwo, Gap: true, CollectedAt: epoch, Lines: []string{"2026-10-10T12:00:09Z new line arrived"}}}
	h.press("f")
	contains(t, h.view(), "following")
	seq := h.m.apps.logs.seq
	h.drain(h.send(appLogsTickMsg{seq: seq}))
	if q := api.lastLogQuery(); q.Cursor != cursorOne || q.Component != "web" {
		t.Errorf("poll query = %+v, want the cursor of the first read", q)
	}
	v := h.view()
	contains(t, v, "new line arrived")
	contains(t, v, "gap: lines are missing here")
	if h.m.apps.logs.cursor != cursorTwo {
		t.Errorf("cursor = %q, want the one the poll returned", h.m.apps.logs.cursor)
	}

	// / searches here: it does not open the palette. The search says what window it covered.
	h.press("/")
	if h.m.prompt == nil || h.m.input.Prompt != "search " {
		t.Fatalf("/ did not open the search prompt: %+v", h.m.prompt)
	}
	h.typeText("timeout")
	h.press("enter")
	if q := api.lastLogQuery(); q.Search != "timeout" || q.Cursor != "" {
		t.Errorf("search query = %+v", q)
	}
	v = h.view()
	contains(t, v, `search "timeout": 1 match`)
	contains(t, v, "searched the last 2000 lines (11:00:00 to 12:00:03)")
	contains(t, v, "upstream timeout talking to db")
	if h.m.apps.logs.following {
		t.Error("a search left the follow on")
	}

	// esc clears the search first, then leaves.
	h.press("esc")
	if h.m.apps.logs.search != "" || h.m.screen != screenAppLogs {
		t.Fatalf("esc with a search: search %q screen %v", h.m.apps.logs.search, h.m.screen)
	}
	h.press("f")
	seq = h.m.apps.logs.seq
	h.press("esc")
	if h.m.screen != screenApp {
		t.Fatalf("esc did not leave the logs: %v", h.m.screen)
	}

	// Leaving stopped the polling: a late tick, and a poll that was in flight, do nothing.
	before := api.count("NodeAppLogs")
	if cmd := h.send(appLogsTickMsg{seq: seq}); cmd != nil {
		t.Error("a tick after leaving scheduled work")
	}
	if cmd := h.send(appLogsPolledMsg{seq: seq, rev: h.m.apps.logs.rev, logs: wire.AppLogs{Lines: []string{"late"}}}); cmd != nil {
		t.Error("a poll reply after leaving scheduled the next poll")
	}
	if n := api.count("NodeAppLogs"); n != before {
		t.Errorf("NodeAppLogs ran %d times after leaving, want %d", n, before)
	}
}

func TestPollRacingAReloadIsDropped(t *testing.T) {
	api := newAppsFake()
	h := openShop(t, api, 120, 30)
	h.press("l", "f")
	l := &h.m.apps.logs
	seq, rev := l.seq, l.rev
	h.press("r") // the lines are replaced while a poll is out
	h.send(appLogsPolledMsg{seq: seq, rev: rev, logs: wire.AppLogs{Cursor: cursorTwo, Lines: []string{"stale duplicate"}}})
	lacks(t, h.view(), "stale duplicate")
}

func TestSlashIsTheGlobalPaletteElsewhere(t *testing.T) {
	h := openShop(t, newAppsFake(), 100, 28)
	h.press("/")
	if h.m.prompt == nil || h.m.input.Prompt == "search " {
		t.Fatalf("the panel's / did not open the palette: %+v", h.m.prompt)
	}
}

func TestMatchSpansIgnoreCaseAndStayOnRunes(t *testing.T) {
	got := matchSpans("Timeout after TIMEOUT, é timeout", "timeout")
	want := [][2]int{{0, 7}, {14, 21}, {25, 32}}
	if len(got) != len(want) {
		t.Fatalf("spans = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("span %d = %v, want %v", i, got[i], want[i])
		}
	}
	if matchSpans("anything", "") != nil {
		t.Error("an empty term matched")
	}
}

// Scenario 5.
func TestRestartFromThePanelTargetsTheComponentAndNeedsApproval(t *testing.T) {
	api := newAppsFake()
	h := openShop(t, api, 100, 28)

	h.press("R")
	if len(api.planRequests) != 1 {
		t.Fatalf("plan requests = %d, want 1", len(api.planRequests))
	}
	req := api.planRequests[0]
	if req.Action != "service.restart" || len(req.Targets) != 1 || req.Targets[0].ID != idShopWeb || req.Targets[0].Type != domain.ResourceService {
		t.Errorf("plan request = %+v, want a restart of the web component's service", req)
	}
	contains(t, h.view(), "Needs 1 approval(s)")
	if len(api.submitted) != 0 {
		t.Fatal("R submitted before any confirmation")
	}
	h.press("y")
	if len(api.submitted) != 1 {
		t.Fatalf("submitted = %v after y", api.submitted)
	}
	contains(t, h.view(), "waiting for approval")
}

func TestNoActionForAWholeApp(t *testing.T) {
	api := newAppsFake()
	h := openApps(t, api, 100, 28)
	h.press("R", "S", "X")
	if len(api.planRequests) != 0 || h.m.confirm != nil {
		t.Errorf("an action key on the overview planned something: %+v", api.planRequests)
	}
	h.press("enter")
	hints := h.m.keyHints()
	for _, want := range []string{"R restart", "S start", "X stop"} {
		contains(t, hints, want)
	}
	lacks(t, hints, "app")
}

func TestPlanDeniedByPolicyIsShownFromThePanel(t *testing.T) {
	api := newAppsFake()
	api.plan.Policy = wire.Policy{Decision: "deny", Reason: "POLICY_FLOOR"}
	h := openShop(t, api, 100, 28)
	h.press("X")
	contains(t, h.view(), "cannot submit: policy: deny")
}

// Scenario 6.
func TestUnreachableNodeShowsTheLastDiscoveryStaleAndRefusesActions(t *testing.T) {
	api := newAppsFake()
	stale := epoch.Add(-10 * 60e9)
	for i := range api.nodes[0].Apps {
		api.nodes[0].Apps[i].Stale, api.nodes[0].Apps[i].ReadAt, api.nodes[0].Apps[i].Stats = true, stale, nil
	}
	api.nodes[0].Problem = wire.AppsProblemUnreachable
	api.app.Stale, api.app.ReadAt = true, stale

	h := openApps(t, api, 100, 28)
	v := h.view()
	contains(t, v, "the node cannot be reached: showing the last discovery, marked stale")
	contains(t, v, "stale, last seen 10-10 11:50:00")
	lacks(t, v, "cpu")

	h.press("enter")
	contains(t, h.view(), "stale: the node cannot be read live")
	h.press("R")
	contains(t, h.view(), "cannot restart web: the node cannot be read live")
	if len(api.planRequests) != 0 {
		t.Error("an action was planned on a node that cannot be read")
	}
}

func TestLiveReadsFailingShowTheErrorAndKeepTheLastData(t *testing.T) {
	api := newAppsFake()
	h := openShop(t, api, 100, 28)
	api.hook("NodeAppStats", func(context.Context) error { return errors.New("node down") })
	h.drain(h.send(tickMsg{}))
	contains(t, h.view(), "stale · ")
	contains(t, h.view(), "shop on web-1")
}

// Scenario 7.
func TestDockerNotAccessibleNamesTheCommandAndChangesNothing(t *testing.T) {
	api := newAppsFake()
	api.nodes = []wire.NodeApps{{
		NodeID: idDB, Node: "db-1", Problem: wire.AppsProblemDocker, Hint: "sm nodes setup db-1 --docker-access",
		Apps: []wire.App{}, OtherServices: []wire.OtherService{},
	}}
	h := openApps(t, api, 100, 28)
	v := h.view()
	contains(t, v, "apps cannot be read")
	contains(t, v, "sm nodes setup db-1 --docker-access")
	if len(api.planRequests) != 0 || len(api.submitted) != 0 {
		t.Error("the overview changed something on a node")
	}
}

func TestPaletteOpensAppsAndAPanel(t *testing.T) {
	api := newAppsFake()
	h := newHarness(t, api, 100, 28)
	h.start()
	h.press("/")
	h.typeText("apps")
	h.press("enter")
	if h.m.screen != screenApps {
		t.Fatalf("screen = %v, want the overview", h.m.screen)
	}
	h.press("/")
	h.typeText("apps web shop")
	h.press("enter")
	if h.m.screen != screenApp || h.m.apps.project != "shop" {
		t.Fatalf("screen = %v project %q, want the shop panel", h.m.screen, h.m.apps.project)
	}
}

func TestOtherServiceOpensTheServiceScreen(t *testing.T) {
	h := openApps(t, newAppsFake(), 100, 28)
	h.press("j", "j", "j") // shop, blog, redis, then sm-demo.service
	h.press("enter")
	if h.m.screen != screenService || h.m.svcID != idAPI {
		t.Fatalf("screen = %v service %q, want the service screen of sm-demo.service", h.m.screen, h.m.svcID)
	}
}

func TestAppsGoldenViews(t *testing.T) {
	cases := []struct {
		name string
		w, h int
		to   func(*testing.T, *appsFake) *harness
	}{
		{"apps_overview_100x28", 100, 28, func(t *testing.T, a *appsFake) *harness { return openApps(t, a, 100, 28) }},
		{"apps_overview_80x24", 80, 24, func(t *testing.T, a *appsFake) *harness { return openApps(t, a, 80, 24) }},
		{"apps_panel_120x40", 120, 40, func(t *testing.T, a *appsFake) *harness { return openShop(t, a, 120, 40) }},
		{"apps_panel_80x24", 80, 24, func(t *testing.T, a *appsFake) *harness { return openShop(t, a, 80, 24) }},
		{"apps_logs_100x28", 100, 28, func(t *testing.T, a *appsFake) *harness {
			h := openShop(t, a, 100, 28)
			h.press("l", "f")
			return h
		}},
		{"apps_logs_search_100x28", 100, 28, func(t *testing.T, a *appsFake) *harness {
			h := openShop(t, a, 100, 28)
			h.press("l", "/")
			h.typeText("timeout")
			h.press("enter")
			return h
		}},
		{"apps_stale_100x28", 100, 28, func(t *testing.T, a *appsFake) *harness {
			stale := epoch.Add(-10 * 60e9)
			for i := range a.nodes[0].Apps {
				a.nodes[0].Apps[i].Stale, a.nodes[0].Apps[i].ReadAt, a.nodes[0].Apps[i].Stats = true, stale, nil
			}
			a.nodes[0].Problem = wire.AppsProblemUnreachable
			return openApps(t, a, 100, 28)
		}},
		{"apps_docker_unavailable_80x24", 80, 24, func(t *testing.T, a *appsFake) *harness {
			a.nodes = []wire.NodeApps{{NodeID: idDB, Node: "db-1", Problem: wire.AppsProblemDocker, Hint: "sm nodes setup db-1 --docker-access"}}
			return openApps(t, a, 80, 24)
		}},
		{"apps_confirm_restart_80x24", 80, 24, func(t *testing.T, a *appsFake) *harness {
			h := openShop(t, a, 80, 24)
			h.press("R")
			return h
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.to(t, newAppsFake())
			assertGolden(t, tc.name, h.view(), tc.w, tc.h)
		})
	}
}
