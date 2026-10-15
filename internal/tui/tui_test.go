package tui

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func contains(t *testing.T, view, want string) {
	t.Helper()
	if !strings.Contains(view, want) {
		t.Errorf("view does not contain %q:\n%s", want, view)
	}
}

func lacks(t *testing.T, view, unwanted string) {
	t.Helper()
	if strings.Contains(view, unwanted) {
		t.Errorf("view contains %q:\n%s", unwanted, view)
	}
}

// ---- nothing blocks ------------------------------------------------------------

func TestInitAndViewMakeNoAPICall(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	cmd := h.m.Init()
	_ = h.view()
	if cmd == nil {
		t.Fatal("Init returned no commands")
	}
	for name, n := range api.calls {
		t.Errorf("%s was called %d times before any command ran", name, n)
	}
	contains(t, h.view(), "loading…")
}

func TestFirstPaintNeedsNoData(t *testing.T) {
	h := newHarness(t, newFake(), 80, 24)
	for _, k := range []string{"2", "3", "4", "5", "?", "esc", "1"} {
		_ = h.send(keyMsg(k)) // commands deliberately not run: no daemon has answered yet
		if len(h.view()) == 0 {
			t.Fatalf("empty view after %q", k)
		}
	}
}

// A node that never answers must not freeze the UI: keys and rendering stay
// fast while its request is pending, and the request ends in a visible error.
func TestOfflineNodeNeverFreezesTheTUI(t *testing.T) {
	for name, hook := range map[string]func(ctx context.Context) error{
		"honours its context": func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		"ignores its context": nil, // set below: blocks until the test ends
	} {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			if hook == nil {
				hook = func(context.Context) error { <-release; return nil }
			}
			api := newFake()
			h := newHarness(t, api, 80, 24)
			h.m.opts.Timeout = 150 * time.Millisecond
			h.start()
			h.press("2")
			h.selectNode("web-1")
			api.hook("GetNode", hook)
			api.hook("ListServices", hook)

			pending := h.send(keyMsg("enter")) // opens the node: two requests that never answer
			replies := make(chan tea.Msg, 16)
			var wg sync.WaitGroup
			for _, c := range flatten(pending) {
				wg.Add(1)
				go func() { defer wg.Done(); replies <- c() }()
			}

			for range 100 {
				completesWithin(t, 50*time.Millisecond, "a key press while a node does not answer", func() {
					_ = h.send(keyMsg("j"))
					_ = h.view()
				})
			}
			wg.Wait()
			close(replies)
			for msg := range replies {
				h.drain(func() tea.Msg { return msg })
			}
			contains(t, h.view(), "no answer within")
		})
	}
}

func flatten(cmd tea.Cmd) []tea.Cmd {
	if cmd == nil {
		return nil
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		return nil
	}
	return batch
}

func TestRefreshTickSkipsRequestsStillInFlight(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	first := h.m.Init()
	_ = first // issued, never answered: every key stays loading
	before := h.m.state(keyNodes).gen
	h.drain(h.send(tickMsg{}))
	if got := h.m.state(keyNodes).gen; got != before {
		t.Errorf("tick re-issued a nodes request while one was in flight (gen %d -> %d)", before, got)
	}
	if api.count("ListNodes") != 0 {
		t.Errorf("tick called the API while requests were pending")
	}
}

func TestRefreshTickReloadsWhenIdle(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	h.start()
	h.drain(h.send(tickMsg{}))
	if api.count("ListNodes") != 2 {
		t.Errorf("ListNodes called %d times, want 2 (start + tick)", api.count("ListNodes"))
	}
}

func TestEveryCallRunsWithTheConfiguredTimeout(t *testing.T) {
	api := newFake()
	var mu sync.Mutex
	var deadlines []time.Duration
	api.hook("ListNodes", func(ctx context.Context) error {
		d, ok := ctx.Deadline()
		mu.Lock()
		defer mu.Unlock()
		if ok {
			deadlines = append(deadlines, time.Until(d))
		} else {
			deadlines = append(deadlines, -1)
		}
		return nil
	})
	h := newHarness(t, api, 80, 24)
	h.m.opts.Timeout = 2 * time.Second
	h.start()
	if len(deadlines) != 1 || deadlines[0] <= 0 || deadlines[0] > 2*time.Second {
		t.Errorf("deadlines = %v, want one in (0, 2s]", deadlines)
	}
	if DefaultTimeout != 2*time.Second {
		t.Errorf("DefaultTimeout = %s, want 2s", DefaultTimeout)
	}
}

// ---- generations and badges -----------------------------------------------------

func TestStaleGenerationIsDropped(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	older := h.m.loadNodes()
	api.nodes = api.nodes[:1] // the newer request sees a different inventory
	newer := h.m.loadNodes()

	newerMsg, olderMsg := newer(), older()
	h.send(newerMsg)
	h.send(olderMsg) // arrives last but was issued first
	if len(h.m.nodes) != 1 {
		t.Errorf("nodes = %d, want the newer reply's 1", len(h.m.nodes))
	}
}

func TestReplyForAnotherNodeIsDropped(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	h.start()
	h.press("2")
	h.selectNode("web-1")
	h.press("v")
	if len(h.m.services) != 2 {
		t.Fatalf("web-1 services = %d, want 2", len(h.m.services))
	}
	h.press("esc", "k", "k") // db-1
	slow := h.m.openNode(h.m.nodes[h.m.nodeCur], screenServices)
	h.send(loadedMsg{key: keyServices, gen: h.m.state(keyServices).gen - 1, apply: func(m *Model) { m.services = nil }})
	h.drain(slow)
	if h.m.node != idDB || len(h.m.services) != 0 {
		t.Errorf("node = %s with %d services, want db-1 with none", h.m.node, len(h.m.services))
	}
}

func TestFailureShowsErrorThenStaleBadgeWithCorrelationID(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	failure := smerr.New(smerr.CodeInternal, "", "the daemon is unwell")
	failure.Details = map[string]any{detailCorrelationID: "corr-42"}
	api.hook("ListNodes", func(context.Context) error { return failure })
	h.start()
	contains(t, h.view(), "error · INTERNAL: the daemon is unwell (correlation id corr-42)")

	api.hook("ListNodes", nil)
	h.press("r")
	lacks(t, h.view(), "corr-42")

	api.hook("ListNodes", func(context.Context) error { return failure })
	h.press("r")
	contains(t, h.view(), "stale · INTERNAL")
	contains(t, h.view(), "corr-42")
	contains(t, h.view(), "lab-1") // stale data stays on screen
}

func TestRemoteTextCannotInjectEscapeSequences(t *testing.T) {
	api := newFake()
	api.nodes[0].Name = "evil\x1b]0;pwned\x07-node"
	api.nodes[0].Connection.LastError = "boom\x1b[2J"
	h := newHarness(t, api, 80, 24)
	h.start()
	h.press("2")
	raw := h.m.render()
	if strings.Contains(raw, "pwned") || strings.Contains(raw, "\x1b]") || strings.Contains(raw, "\x1b[2J") {
		t.Errorf("remote escape sequence reached the screen: %q", raw)
	}
}

// ---- navigation -----------------------------------------------------------------

func TestKeyboardNavigation(t *testing.T) {
	h := newHarness(t, newFake(), 100, 28)
	h.start()
	steps := []struct {
		key    string
		screen screen
	}{
		{"2", screenResources},
		{"3", screenJobs},
		{"4", screenApprovals},
		{"5", screenEvents},
		{"1", screenDashboard},
		{"?", screenHelp},
		{"esc", screenDashboard},
		{"2", screenResources},
		{"enter", screenNode},
		{"v", screenServices},
		{"enter", screenService},
		{"l", screenLogs},
		{"esc", screenService},
		{"esc", screenServices},
		{"esc", screenNode},
		{"esc", screenResources},
		{"esc", screenResources},
	}
	for _, s := range steps {
		h.press(s.key)
		if s.key == "2" && h.m.screen == screenResources {
			h.selectNode("web-1")
		}
		if h.m.screen != s.screen {
			t.Fatalf("after %q screen = %s, want %s", s.key, screenTitles[h.m.screen], screenTitles[s.screen])
		}
	}
}

func TestCursorMovesAndStaysInBounds(t *testing.T) {
	h := newHarness(t, newFake(), 80, 24)
	h.start()
	h.press("2")
	for _, tc := range []struct {
		keys []string
		want int
	}{
		{[]string{"j"}, 1},
		{[]string{"down", "down"}, 3},
		{[]string{"j", "j", "j"}, 3},
		{[]string{"k"}, 2},
		{[]string{"g"}, 0},
		{[]string{"k"}, 0},
		{[]string{"G"}, 3},
		{[]string{"up"}, 2},
	} {
		h.press(tc.keys...)
		if h.m.nodeCur != tc.want {
			t.Fatalf("after %v cursor = %d, want %d", tc.keys, h.m.nodeCur, tc.want)
		}
	}
}

func TestCursorFollowsItsNodeAcrossRefreshes(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	h.start()
	h.press("2")
	h.selectNode("web-1")
	api.nodes = append([]wire.Node{{ID: "0192a000-0000-7000-8000-00000000a000", Name: "aaa", Provider: "aaa"}}, api.nodes...)
	h.press("r")
	if n, _ := h.m.selectedNode(); n.Name != "web-1" {
		t.Errorf("selected %q after a new node appeared, want web-1", n.Name)
	}
}

func TestQuitKeys(t *testing.T) {
	for _, k := range []string{"q", "ctrl+c"} {
		h := newHarness(t, newFake(), 80, 24)
		cmd := h.send(keyMsg(k))
		if cmd == nil {
			t.Fatalf("%s returned no command", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("%s did not quit", k)
		}
	}
}

func TestSmallTerminalExplainsInsteadOfBreaking(t *testing.T) {
	h := newHarness(t, newFake(), 20, 5)
	h.start()
	contains(t, h.view(), "terminal too small")
}

// ---- palette ----------------------------------------------------------------------

func TestPaletteCommands(t *testing.T) {
	h := newHarness(t, newFake(), 100, 28)
	h.start()

	h.press("/")
	h.typeText("services web")
	h.press("enter")
	if h.m.screen != screenServices || h.m.node != idWeb {
		t.Fatalf("services web -> %s on %s", screenTitles[h.m.screen], h.m.node)
	}

	h.press("/")
	h.typeText("logs sm-demo.service")
	h.press("enter")
	if h.m.screen != screenLogs || h.m.svcID != idAPI {
		t.Fatalf("logs -> %s on %s", screenTitles[h.m.screen], h.m.svcID)
	}

	h.press("/")
	h.typeText("bogus")
	h.press("enter")
	contains(t, h.view(), `unknown command "bogus"`)

	h.press("/")
	h.typeText("services nothing")
	h.press("enter")
	contains(t, h.view(), `no node matches "nothing"`)

	h.press("/")
	h.typeText("logs unknown")
	h.press("enter")
	contains(t, h.view(), "not loaded yet")
}

func TestPaletteEscapeCancelsAndPrefixesMustBeUnique(t *testing.T) {
	api := newFake()
	api.nodes = append(api.nodes, wire.Node{ID: "0192a000-0000-7000-8000-00000000a009", Name: "web-2", Provider: "ssh"})
	h := newHarness(t, api, 100, 28)
	h.start()
	h.press("/")
	h.typeText("services w")
	h.press("esc")
	if h.m.prompt != nil || h.m.screen != screenDashboard {
		t.Fatal("esc did not cancel the palette")
	}
	h.press("/")
	h.typeText("services web")
	h.press("enter")
	contains(t, h.view(), "matches several nodes: web-1, web-2")
}

func TestPaletteRefreshReloads(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	h.start()
	h.press("/")
	h.typeText("refresh")
	h.press("enter")
	if api.count("ListNodes") != 2 {
		t.Errorf("ListNodes = %d, want 2", api.count("ListNodes"))
	}
}

// ---- destructive shortcuts open a plan --------------------------------------------

func TestServiceActionNeedsAPlanAndAConfirmation(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 100, 28)
	h.start()
	h.openAPIService()

	h.press("R")
	if len(api.submitted) != 0 {
		t.Fatal("R submitted something before any confirmation")
	}
	req := api.planRequests[0]
	if req.Action != "service.restart" || len(req.Targets) != 1 || req.Targets[0].ID != idAPI || req.Targets[0].Type != domain.ResourceService {
		t.Errorf("plan request = %+v", req)
	}
	contains(t, h.view(), "Stop sm-demo.service")
	contains(t, h.view(), "Needs 1 approval(s)")

	h.press("n")
	if h.m.confirm != nil || len(api.submitted) != 0 {
		t.Fatal("n did not cancel cleanly")
	}

	h.press("R", "y")
	if len(api.submitted) != 1 || api.submitted[0] != idPlan {
		t.Fatalf("submitted = %v, want the plan once", api.submitted)
	}
	contains(t, h.view(), "waiting for approval")
}

func TestPlanDeniedByPolicyCannotBeSubmitted(t *testing.T) {
	api := newFake()
	api.plan.Policy = wire.Policy{Decision: "deny", Reason: "POLICY_FLOOR"}
	h := newHarness(t, api, 100, 28)
	h.start()
	h.openAPIService()
	h.press("R", "y")
	if len(api.submitted) != 0 {
		t.Fatal("a denied plan was submitted")
	}
	contains(t, h.view(), "cannot submit: policy: deny (POLICY_FLOOR)")
}

func TestServiceVerbMissingFromActionsIsRefused(t *testing.T) {
	api := newFake()
	api.services[idWeb][0].Actions = nil
	h := newHarness(t, api, 100, 28)
	h.start()
	h.openAPIService()
	h.press("R")
	if len(api.planRequests) != 0 {
		t.Fatal("a plan was requested for a verb the node does not offer")
	}
	contains(t, h.view(), "the node needs setup")
}

func TestSetupViaPaletteWarnsAboutDockerAccess(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 100, 28)
	h.start()
	h.press("/")
	h.typeText("setup web docker")
	h.press("enter")
	req := api.planRequests[0]
	if req.Action != "node.setup" || req.Parameters["docker_access"] != "true" || req.Parameters["logs_mode"] != "journal-group" {
		t.Errorf("setup request = %+v", req)
	}
	contains(t, h.view(), "equivalent to root")

	h.press("esc", "/")
	h.typeText("setup web")
	h.press("enter")
	if got := api.planRequests[1].Parameters["docker_access"]; got != "false" {
		t.Errorf("docker_access = %v without the docker word, want false", got)
	}
	lacks(t, h.view(), "equivalent to root")
}

func TestSetupViaPaletteGrantsUnitsAndKeepsThemOnARerun(t *testing.T) {
	api := newFake()
	api.nodes[0].Setup.Units = []wire.UnitGrant{{Unit: "sm-demo.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}}}
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("setup web unit nginx.service:restart unit app.service")
	h.press("enter")
	want := []any{"restart nginx.service", "start app.service", "stop app.service", "restart app.service"}
	if got := api.planRequests[0].Parameters["grants"]; !reflect.DeepEqual(toAny(got), want) {
		t.Errorf("grants = %#v, want %#v", got, want)
	}
	contains(t, h.view(), "units: nginx.service (restart), app.service (start, stop, restart)")

	h.press("esc", "/")
	h.typeText("setup web")
	h.press("enter")
	if got := api.planRequests[1].Parameters["grants"]; !reflect.DeepEqual(toAny(got), []any{"restart sm-demo.service"}) {
		t.Errorf("a re-run without unit words must keep the node's grants: %#v", got)
	}
	contains(t, h.view(), "(kept from the previous setup)")
}

func TestSetupViaPaletteShowsWhatAReplacementRemoves(t *testing.T) {
	api := newFake()
	api.nodes[0].Setup.Units = []wire.UnitGrant{{Unit: "sm-demo.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}}}
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("setup web unit nginx.service:restart")
	h.press("enter")

	contains(t, h.view(), "(was: sm-demo.service (restart))")
}

func TestSetupViaPaletteReadsTheWordAfterUnitAsAUnit(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("setup web unit docker")
	h.press("enter")
	if got := api.planRequests[0].Parameters["docker_access"]; got != "false" {
		t.Errorf("docker_access = %v; the word after unit is a unit name, not the docker flag", got)
	}

	for _, words := range []string{"setup web unit", "setup web dockr"} {
		h.press("esc", "/")
		h.typeText(words)
		h.press("enter")
		if len(api.planRequests) != 1 {
			t.Errorf("%q planned anyway", words)
		}
		contains(t, h.view(), "setup: ")
	}
}

// toAny turns the []string the TUI builds into the []any a JSON round trip gives.
func toAny(v any) any {
	list, ok := v.([]string)
	if !ok {
		return v
	}
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

func TestCancelJobAsksFirstAndSendsThePlanHash(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 100, 28)
	h.start()
	h.press("3", "c")
	if len(api.cancelled) != 0 {
		t.Fatal("c cancelled without confirmation")
	}
	h.press("y")
	if len(api.cancelled) != 1 || api.cancelled[0] != jobHash {
		t.Errorf("cancelled with %v, want [%s]", api.cancelled, jobHash)
	}
	h.press("j", "c") // the finished job
	if len(api.cancelled) != 1 || h.m.confirm != nil {
		t.Error("a finished job opened a cancel confirmation")
	}
}

// ---- approvals (§39.5) ---------------------------------------------------------------

func TestApproveSendsThePlanHashOnce(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 30)
	h.start()
	h.press("4")
	contains(t, h.view(), "[A] Approve  [R] Reject")

	cmd := h.send(keyMsg("A"))
	second := h.send(keyMsg("A")) // while the first is in flight
	if second != nil {
		t.Error("a second approval was issued while the first was in flight")
	}
	h.drain(cmd)
	if len(api.approved) != 1 || api.approved[0].PlanHash != jobHash {
		t.Errorf("approved = %+v, want one with plan hash %s", api.approved, jobHash)
	}
	contains(t, h.view(), "approved job")
}

func TestRejectNeedsAReason(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 30)
	h.start()
	h.press("4", "R", "enter")
	if len(api.rejected) != 0 {
		t.Fatal("rejected without a reason")
	}
	contains(t, h.view(), "a reason is required")

	h.press("R")
	h.typeText("too risky")
	h.press("enter")
	if len(api.rejected) != 1 || api.rejected[0].Reason != "too risky" || api.rejected[0].PlanHash != jobHash {
		t.Errorf("rejected = %+v", api.rejected)
	}
}

func TestMutationTimeoutWarnsItMayHaveApplied(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 30)
	h.m.opts.Timeout = 30 * time.Millisecond
	h.start()
	api.hook("Approve", func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	h.press("4", "A")
	contains(t, h.view(), "no answer within")
	contains(t, h.view(), "check Jobs before retrying")
	if h.m.acting {
		t.Error("the TUI stays locked after a timed-out mutation")
	}
}

func TestMutationErrorShowsCorrelationID(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 30)
	h.start()
	denied := smerr.New(smerr.CodePolicyDenied, "", "you cannot approve your own request")
	denied.Details = map[string]any{detailCorrelationID: "corr-9"}
	api.hook("Approve", func(context.Context) error { return denied })
	h.press("4", "A")
	contains(t, h.view(), "you cannot approve your own request (correlation id corr-9)")
}

// ---- handoff (§17.1) -------------------------------------------------------------------

type handoffProbe struct {
	mu    sync.Mutex
	calls []doneCall
	ended chan struct{}
}

type doneCall struct {
	code int
	err  error
}

func (p *handoffProbe) done(code int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, doneCall{code, err})
	if p.ended != nil {
		p.ended <- struct{}{}
	}
}

func (p *handoffProbe) snapshot() []doneCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]doneCall(nil), p.calls...)
}

func (p *handoffProbe) handoff(program string, args ...string) func(context.Context, domain.ID, string) (Handoff, error) {
	return func(ctx context.Context, _ domain.ID, _ string) (Handoff, error) {
		return Handoff{Cmd: exec.CommandContext(ctx, program, args...), Done: p.done}, nil
	}
}

func startShell(t *testing.T, api *fakeAPI) (*harness, tea.Cmd) {
	t.Helper()
	h := newHarness(t, api, 100, 28)
	h.start()
	h.press("2")
	h.selectNode("web-1")
	return h, h.send(keyMsg("s"))
}

// returnFromChild feeds the handoff outcome the way tea.ExecProcess reports it.
func returnFromChild(t *testing.T, h *harness, opened tea.Msg, childErr error) tea.Cmd {
	t.Helper()
	msg, ok := opened.(handoffOpenedMsg)
	if !ok {
		t.Fatalf("got %T, want handoffOpenedMsg", opened)
	}
	if h.send(msg) == nil {
		t.Fatal("an opened handoff did not start tea.ExecProcess")
	}
	return h.send(handoffReturnedMsg{node: msg.node, tool: msg.tool, h: msg.h, err: childErr})
}

func TestHandoffReportsExitCodeAndRefreshes(t *testing.T) {
	var probe handoffProbe
	api := newFake()
	api.handoff = probe.handoff("/bin/sh", "-c", "exit 3")
	h, open := startShell(t, api)
	contains(t, h.view(), "opening shell on web-1")

	childErr := exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 3").Run()
	end := returnFromChild(t, h, open(), childErr)
	contains(t, h.view(), "shell on web-1 exited with code 3")

	nodesBefore := api.count("ListNodes")
	h.drain(end) // Done, then the refresh
	calls := probe.snapshot()
	if len(calls) != 1 || calls[0].code != 3 || calls[0].err != nil {
		t.Errorf("Done calls = %+v, want one (3, nil)", calls)
	}
	if api.count("ListNodes") != nodesBefore+1 {
		t.Error("the node data was not refreshed after the handoff")
	}
	if h.m.handingOff {
		t.Error("input stays locked after the session ended")
	}
}

func TestHandoffCleanExit(t *testing.T) {
	var probe handoffProbe
	api := newFake()
	api.handoff = probe.handoff("/bin/sh", "-c", "exit 0")
	h, open := startShell(t, api)
	h.drain(returnFromChild(t, h, open(), nil))
	if calls := probe.snapshot(); len(calls) != 1 || calls[0].code != 0 || calls[0].err != nil {
		t.Errorf("Done calls = %+v, want one (0, nil)", calls)
	}
	contains(t, h.view(), "back from shell on web-1")
}

func TestHandoffLaunchFailureIsShownAndEndsTheSession(t *testing.T) {
	var probe handoffProbe
	api := newFake()
	api.handoff = probe.handoff("/nonexistent/ssh")
	h, open := startShell(t, api)
	launchErr := exec.CommandContext(context.Background(), "/nonexistent/ssh").Run()
	h.drain(returnFromChild(t, h, open(), launchErr))
	calls := probe.snapshot()
	if len(calls) != 1 || calls[0].err == nil {
		t.Fatalf("Done calls = %+v, want one with the launch error", calls)
	}
	contains(t, h.view(), "could not start shell on web-1")
}

func TestHandoffThatCannotStartSkipsTheTerminalHandover(t *testing.T) {
	var probe handoffProbe
	api := newFake()
	api.handoff = probe.handoff("sm-no-such-program")
	h, open := startShell(t, api)
	opened, ok := open().(handoffOpenedMsg)
	if !ok {
		t.Fatal("the session did not open")
	}
	cmd := h.send(opened)
	if cmd == nil {
		t.Fatal("an opened handoff produced no command")
	}
	msg := cmd()
	returned, ok := msg.(handoffReturnedMsg)
	if !ok {
		t.Fatalf("got %T, want handoffReturnedMsg without handing the terminal over", msg)
	}
	if !errors.Is(returned.err, exec.ErrNotFound) {
		t.Errorf("err = %v, want exec.ErrNotFound", returned.err)
	}
}

func TestHandoffSignalledChildIsReportedAsFailureCode(t *testing.T) {
	var probe handoffProbe
	api := newFake()
	api.handoff = probe.handoff("/bin/sh", "-c", "kill -9 $$")
	h, open := startShell(t, api)
	childErr := exec.CommandContext(context.Background(), "/bin/sh", "-c", "kill -9 $$").Run()
	h.drain(returnFromChild(t, h, open(), childErr))
	if calls := probe.snapshot(); len(calls) != 1 || calls[0].code != exitSignaled {
		t.Errorf("Done calls = %+v, want code %d", calls, exitSignaled)
	}
}

func TestHandoffIgnoresInputUntilTheSessionEnds(t *testing.T) {
	var probe handoffProbe
	api := newFake()
	api.handoff = probe.handoff("/bin/sh", "-c", "exit 0")
	h, open := startShell(t, api)
	if cmd := h.send(keyMsg("q")); cmd != nil {
		t.Error("q quit while a session was being issued")
	}
	end := returnFromChild(t, h, open(), nil)
	if cmd := h.send(keyMsg("q")); cmd != nil {
		t.Error("q quit before the session end was posted")
	}
	h.drain(end)
	if cmd := h.send(keyMsg("q")); cmd == nil {
		t.Error("q does nothing after the session ended")
	}
}

func TestHandoffOpenFailureShowsCorrelationID(t *testing.T) {
	api := newFake()
	unreachable := smerr.New(smerr.CodeNodeUnreachable, "", "dial timed out")
	unreachable.Details = map[string]any{detailCorrelationID: "corr-7"}
	api.hook("OpenSession", func(context.Context) error { return unreachable })
	h, open := startShell(t, api)
	h.send(open())
	contains(t, h.view(), "cannot open a session: NODE_UNREACHABLE: dial timed out (correlation id corr-7)")
	if h.m.handingOff {
		t.Error("input stays locked after a failed open")
	}
}

func TestSessionIssuedAfterTheTimeoutIsClosed(t *testing.T) {
	probe := handoffProbe{ended: make(chan struct{}, 4)}
	api := newFake()
	release := make(chan struct{})
	api.handoff = func(ctx context.Context, node domain.ID, tool string) (Handoff, error) {
		<-release
		return probe.handoff("/bin/true")(ctx, node, tool)
	}
	h := newHarness(t, api, 100, 28)
	h.start()
	h.press("2")
	h.selectNode("web-1")
	h.m.opts.Timeout = 30 * time.Millisecond
	msg := h.send(keyMsg("s"))()
	if err := msg.(handoffOpenedMsg).err; err == nil {
		t.Fatal("OpenSession did not time out")
	}
	close(release)
	select {
	case <-probe.ended:
	case <-time.After(2 * time.Second):
		t.Fatal("the late session was never closed")
	}
	calls := probe.snapshot()
	if len(calls) != 1 || !errors.Is(calls[0].err, errHandoffAbandoned) {
		t.Errorf("Done calls = %+v, want one abandoned", calls)
	}
}

func TestHandoffGating(t *testing.T) {
	tests := []struct {
		name string
		node string
		keys []string
		want string
	}{
		{"no ssh capability", "laptop", []string{"s"}, "cannot be reached over SSH"},
		{"no docker", "db-1", []string{"d"}, "Docker is not available"},
		{"lazydocker missing", "lab-1", []string{"d"}, "Docker is not available"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := newFake()
			h := newHarness(t, api, 100, 28)
			h.start()
			h.press("2")
			h.selectNode(tc.node)
			h.press(tc.keys...)
			contains(t, h.view(), tc.want)
			if api.count("OpenSession") != 0 {
				t.Error("a session was opened for a gated tool")
			}
		})
	}

	t.Run("lazydocker not installed shows instructions and never installs", func(t *testing.T) {
		api := newFake()
		api.nodes[0].Capabilities = []wire.Capability{{Name: "node.ssh", Available: true}, {Name: "docker.read", Available: true}}
		h := newHarness(t, api, 160, 28)
		h.start()
		h.press("2")
		h.selectNode("web-1")
		h.press("d")
		contains(t, h.view(), "lazydocker is not installed")
		contains(t, h.view(), "never installs it")
		if api.count("OpenSession") != 0 {
			t.Error("a session was opened although lazydocker is missing")
		}
	})

	t.Run("unknown tool from the palette", func(t *testing.T) {
		h := newHarness(t, newFake(), 100, 28)
		h.start()
		h.press("/")
		h.typeText("ssh web emacs")
		h.press("enter")
		contains(t, h.view(), `unknown tool "emacs"`)
	})
}

func TestExitOutcome(t *testing.T) {
	exit3 := exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 3").Run()
	missing := exec.CommandContext(context.Background(), "/nonexistent/x").Run()
	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantLaunch bool
	}{
		{"success", nil, 0, false},
		{"exit 3", exit3, 3, false},
		{"missing executable", missing, 0, true},
	}
	for _, tc := range tests {
		code, launch := exitOutcome(tc.err)
		if code != tc.wantCode || (launch != nil) != tc.wantLaunch {
			t.Errorf("%s: exitOutcome = (%d, %v), want (%d, launch %v)", tc.name, code, launch, tc.wantCode, tc.wantLaunch)
		}
	}
}

// ---- scale ----------------------------------------------------------------------------

// The dashboard renders from cached data: 500 nodes must stay far under the
// §34 budget (500ms), and a key press must stay interactive.
func TestLargeInventoryStaysResponsive(t *testing.T) {
	api := newFake()
	base := api.nodes[0]
	api.nodes = nil
	for i := range 500 {
		n := base
		n.ID = domain.ID("0192a000-0000-7000-8000-" + strings.Repeat("0", 8) + pad4(i))
		n.Name = "node-" + pad4(i)
		if i%7 == 0 {
			n.Reachability, n.Stale = domain.ReachabilityUnreachable, true
		}
		api.nodes = append(api.nodes, n)
	}
	h := newHarness(t, api, 120, 40)
	h.start()
	for _, k := range []string{"1", "2", "j"} {
		completesWithin(t, 500*time.Millisecond, "key "+k+" with 500 nodes", func() {
			h.press(k)
			_ = h.m.render()
		})
	}
}

func pad4(i int) string {
	s := "0000" + strings.TrimLeft(strings.Repeat("", 0), "") + itoa(i)
	return s[len(s)-4:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// completesWithin fails the test when fn does not return in time.
func completesWithin(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not finish within %s", what, limit)
	}
}
