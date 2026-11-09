package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	idAssistant domain.ID = "0192a000-0000-7000-8000-00000000e001"
	idStranger  domain.ID = "0192a000-0000-7000-8000-00000000e002"
)

// fakeConv is a Conversation the test drives by hand.
type fakeConv struct {
	events  chan assistant.Event
	mu      sync.Mutex
	sent    []string
	closed  bool
	sendErr error
}

func newFakeConv() *fakeConv { return &fakeConv{events: make(chan assistant.Event, 16)} }

func (c *fakeConv) Start(context.Context) error    { return nil }
func (c *fakeConv) Events() <-chan assistant.Event { return c.events }

func (c *fakeConv) Send(text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, text)
	return c.sendErr
}

func (c *fakeConv) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConv) sentTexts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.sent...)
}

func (c *fakeConv) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// fakeLauncher counts what the screen asks of the launcher.
type fakeLauncher struct {
	mu                 sync.Mutex
	checks, starts     int
	checkErr, startErr error
	conv               *fakeConv
	convs              []*fakeConv
}

func newFakeLauncher() *fakeLauncher { return &fakeLauncher{} }

func (l *fakeLauncher) launcher() *assistant.Launcher {
	return &assistant.Launcher{
		Check: func(context.Context) (assistant.Identity, error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.checks++
			if l.checkErr != nil {
				return assistant.Identity{}, l.checkErr
			}
			return assistant.Identity{ClientName: "assistant", ClientID: idAssistant, Instance: "the local daemon", Auth: assistant.AuthSubscription}, nil
		},
		Start: func(context.Context) (assistant.Conversation, error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.starts++
			if l.startErr != nil {
				return nil, l.startErr
			}
			l.conv = newFakeConv()
			l.convs = append(l.convs, l.conv)
			return l.conv, nil
		},
	}
}

func (l *fakeLauncher) counts() (checks, starts int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checks, l.starts
}

// asstFixture is the fake daemon, the launcher and a harness on the assistant's side.
type asstFixture struct {
	*harness
	api *fakeAPI
	l   *fakeLauncher
}

func newAsst(t *testing.T, w, h int) *asstFixture {
	t.Helper()
	api := newFake()
	api.jobs[0].ActorID = idAssistant
	l := newFakeLauncher()
	m := New(api, Options{Timeout: time.Second, Location: time.UTC, Assistant: l.launcher()})
	hs := &harness{t: t, m: m}
	hs.send(tea.WindowSizeMsg{Width: w, Height: h})
	return &asstFixture{harness: hs, api: api, l: l}
}

// converse opens the screen and sends one message, starting the session.
func (f *asstFixture) converse(text string) *fakeConv {
	f.t.Helper()
	f.press("8")
	f.typeText(text)
	f.press("enter")
	if f.l.conv == nil {
		f.t.Fatal("the session was not started")
	}
	return f.l.conv
}

func (f *asstFixture) event(ev assistant.Event) tea.Cmd {
	return f.send(assistantEventMsg{gen: f.m.asst.gen, ev: ev})
}

func (f *asstFixture) say(text string) {
	f.event(assistant.Event{Kind: assistant.KindText, Text: text})
}

// raiseCard has the model signal job id and finish its turn, then shows the
// card the way the runtime would, without waiting out the arming delay.
func (f *asstFixture) raiseCard(id domain.ID) {
	f.t.Helper()
	f.event(assistant.Event{Kind: assistant.KindApproval, Approval: &assistant.Signal{JobID: id, Tool: "service_restart"}})
	cmd := f.event(assistant.Event{Kind: assistant.KindTurnDone})
	if cmd == nil {
		f.t.Fatal("the turn raised no load")
	}
	f.send(cmd())
}

func (f *asstFixture) arm() {
	f.t.Helper()
	if f.m.asst.card == nil {
		f.t.Fatal("no card is open")
	}
	c := f.m.asst.card
	f.send(assistantArmedMsg{seq: c.seq, token: c.token})
}

func quits(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	done := make(chan bool, 1)
	go func() { _, ok := cmd().(tea.QuitMsg); done <- ok }()
	select {
	case ok := <-done:
		return ok
	case <-time.After(100 * time.Millisecond):
		return false
	}
}

func mustContain(t *testing.T, view string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(view, w) {
			t.Errorf("view lacks %q:\n%s", w, view)
		}
	}
}

func mustNotContain(t *testing.T, view string, bad ...string) {
	t.Helper()
	for _, w := range bad {
		if strings.Contains(view, w) {
			t.Errorf("view has %q:\n%s", w, view)
		}
	}
}

func assertFrame(t *testing.T, view string, w, h int) {
	t.Helper()
	rows := strings.Split(view, "\n")
	if len(rows) != h {
		t.Errorf("view has %d rows, want %d", len(rows), h)
	}
	for i, r := range rows {
		if n := lipgloss.Width(r); n != w {
			t.Errorf("row %d is %d cells, want %d: %q", i, n, w, r)
		}
	}
}

func TestAssistantTypingIsTextNotNavigation(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.press("8")
	for _, k := range []string{"q", "1", "7", "?", "/", "r"} {
		if quits(f.send(keyMsg(k))) {
			t.Fatalf("%q quit the TUI", k)
		}
	}
	if got := f.m.asst.ask.Value(); got != "q17?/r" {
		t.Errorf("input = %q, want q17?/r", got)
	}
	if f.m.screen != screenAssistant || f.m.prompt != nil {
		t.Errorf("screen = %v, prompt open = %v: typing navigated", f.m.screen, f.m.prompt != nil)
	}
}

func TestAssistantCtrlCQuitsAndEscLeaves(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.press("8")
	if !quits(f.send(keyMsg("ctrl+c"))) {
		t.Error("ctrl+c did not quit")
	}
	f.press("esc")
	if f.m.screen != screenDashboard {
		t.Errorf("esc left to %v, want the dashboard", f.m.screen)
	}
	f.press("q")
	// q is a global again outside the screen.
	if !quits(f.send(keyMsg("q"))) {
		t.Error("q does not quit outside the assistant")
	}
}

func TestAssistantConversationStreamsIntoTranscript(t *testing.T) {
	f := newAsst(t, 80, 24)
	conv := f.converse("how is web-1?")
	if got := conv.sentTexts(); len(got) != 1 || got[0] != "how is web-1?" {
		t.Fatalf("sent %v", got)
	}
	f.say("web-1 is fine.\nAll units are active.")
	f.event(assistant.Event{Kind: assistant.KindToolCall, Text: "node_list {}"})
	f.event(assistant.Event{Kind: assistant.KindToolResult, Text: "node_list: 4 nodes"})
	f.say("[sm] job x approved by the operator")
	f.event(assistant.Event{Kind: assistant.KindTurnDone})
	view := f.view()
	mustContain(t, view, "> how is web-1?", "| web-1 is fine.", "| All units are active.", "| [tool] node_list {}", "| [result] node_list: 4 nodes",
		"| [sm] job x approved by the operator", "assistant · ready")
	if f.m.asst.working {
		t.Error("still working after the turn ended")
	}
	if _, starts := f.l.counts(); starts != 1 {
		t.Errorf("starts = %d, want 1", starts)
	}
	f.typeText("and db-1?")
	f.press("enter")
	if got := conv.sentTexts(); len(got) != 2 || got[1] != "and db-1?" {
		t.Errorf("second turn sent %v on the same session", got)
	}
}

func TestAssistantRefusesASecondMessageWhileWorking(t *testing.T) {
	f := newAsst(t, 80, 24)
	conv := f.converse("one")
	f.typeText("two")
	f.press("enter")
	if got := conv.sentTexts(); len(got) != 1 {
		t.Errorf("sent %v while a turn was in flight", got)
	}
	if !strings.Contains(f.m.notice.text, "still working") {
		t.Errorf("notice = %q", f.m.notice.text)
	}
	if f.m.asst.ask.Value() != "two" {
		t.Errorf("draft = %q, want it kept", f.m.asst.ask.Value())
	}
}

func TestAssistantStalledChildKeepsTheTUIResponsive(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.start()
	f.converse("anyone there?")
	// The child says nothing. The operator moves around and comes back.
	f.press("esc")
	f.press("2")
	if f.m.screen != screenResources {
		t.Fatalf("screen = %v after 2", f.m.screen)
	}
	f.press("3")
	mustContain(t, f.view(), "Jobs")
	f.press("8")
	mustContain(t, f.view(), "assistant · working…", "> anyone there?")
	f.say("sorry, here now")
	mustContain(t, f.view(), "| sorry, here now")
}

func TestAssistantChildDeathIsShownAndTheNextMessageRestarts(t *testing.T) {
	f := newAsst(t, 80, 24)
	first := f.converse("hello")
	cmd := f.event(assistant.Event{Kind: assistant.KindError, Fatal: true, Text: "claude is not signed in; run claude in a terminal"})
	f.drain(cmd)
	cmd = f.event(assistant.Event{Kind: assistant.KindEnded, Text: "the assistant ended", Err: errors.New("exit status 1")})
	f.drain(cmd)
	view := f.view()
	mustContain(t, view, "[sm] error: claude is not signed in", "assistant · ended")
	mustNotContain(t, view, "[sm] the assistant ended") // explained once, not twice
	if !first.isClosed() {
		t.Error("the dead session was not closed")
	}
	f.press("1")
	f.press("8")
	f.typeText("again")
	f.press("enter")
	if _, starts := f.l.counts(); starts != 2 {
		t.Errorf("starts = %d, want a new session", starts)
	}
	// Late events of the dead session are dropped.
	f.send(assistantEventMsg{gen: 1, ev: assistant.Event{Kind: assistant.KindText, Text: "ghost"}})
	mustNotContain(t, f.view(), "ghost")
}

func TestAssistantChannelClosingWithoutEndedIsReported(t *testing.T) {
	f := newAsst(t, 80, 24)
	conv := f.converse("hello")
	f.drain(f.send(assistantEndedMsg{gen: f.m.asst.gen}))
	mustContain(t, f.view(), "[sm] the assistant ended")
	if !conv.isClosed() || f.m.asst.working {
		t.Errorf("closed = %v, working = %v", conv.isClosed(), f.m.asst.working)
	}
}

func TestAssistantReaderForwardsEventsAndEnd(t *testing.T) {
	f := newAsst(t, 80, 24)
	got := make(chan tea.Msg, 8)
	f.m.send = func(msg tea.Msg) { got <- msg }
	conv := f.converse("hello")
	conv.events <- assistant.Event{Kind: assistant.KindText, Text: "hi"}
	close(conv.events)
	var kinds []string
	for range 2 {
		select {
		case msg := <-got:
			kinds = append(kinds, fmt.Sprintf("%T", msg))
		case <-time.After(2 * time.Second):
			t.Fatal("the reader forwarded nothing")
		}
	}
	if kinds[0] != "tui.assistantEventMsg" || kinds[1] != "tui.assistantEndedMsg" {
		t.Errorf("forwarded %v", kinds)
	}
}

func TestAssistantSendFailureEndsTheSession(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.press("8")
	f.typeText("hello")
	f.l.startErr = nil
	cmd := f.send(keyMsg("enter"))
	// Run the start, then make the send fail.
	started := runCmd(t, cmd).(assistantStartedMsg)
	started.conv.(*fakeConv).sendErr = errors.New("broken pipe")
	f.drain(f.send(started))
	mustContain(t, f.view(), "[sm] the assistant is gone: broken pipe")
	if f.m.asst.conv != nil {
		t.Error("the session was kept")
	}
}

func runCmd(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	if cmd == nil {
		t.Fatal("no command")
	}
	return cmd()
}

func TestAssistantNothingLaunchedUntilAsked(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.start()
	for _, k := range []string{"2", "3", "4", "5", "6", "7", "?", "esc", "1"} {
		f.press(k)
	}
	if checks, starts := f.l.counts(); checks != 0 || starts != 0 {
		t.Errorf("checks = %d, starts = %d before the screen was opened", checks, starts)
	}
	f.press("8")
	if checks, starts := f.l.counts(); checks != 1 || starts != 0 {
		t.Errorf("checks = %d, starts = %d after opening: only a check may run", checks, starts)
	}
	f.typeText("draft, never sent")
	f.press("esc")
	if _, starts := f.l.counts(); starts != 0 {
		t.Errorf("starts = %d without a message", starts)
	}
}

func TestAssistantRefusalsAreShownAsTheCLIPrintsThem(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.l.checkErr = errors.New("no MCP client named assistant; register it (approval may be needed, then run the same line again):\n  sm mcp clients add assistant --keychain supermgmt-assistant")
	f.press("8")
	view := f.view()
	mustContain(t, view, "[sm] no MCP client named assistant; register it", "sm mcp clients add assistant --keychain supermgmt-assistant")
	if _, starts := f.l.counts(); starts != 0 {
		t.Errorf("starts = %d with no client", starts)
	}
	// The same refusal again on the first message, and the draft is not lost.
	f.typeText("hello")
	f.press("enter")
	if f.m.asst.conv != nil || f.m.asst.working {
		t.Error("a refused start left a session behind")
	}
	if got := f.m.asst.ask.Value(); got != "hello" {
		t.Errorf("draft = %q after a refused start", got)
	}
}

func TestAssistantStartFailureIsShown(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.l.startErr = errors.New("assistant: start claude: exec: permission denied")
	f.press("8")
	f.typeText("hi")
	f.press("enter")
	mustContain(t, f.view(), "[sm] assistant: start claude: exec: permission denied")
}

func TestAssistantWithoutALauncherSaysSo(t *testing.T) {
	m := New(newFake(), Options{Timeout: time.Second, Location: time.UTC})
	h := &harness{t: t, m: m}
	h.send(tea.WindowSizeMsg{Width: 80, Height: 24})
	h.press("8")
	h.typeText("hi")
	h.press("enter")
	mustContain(t, h.view(), "this TUI was started without an assistant")
}

func TestAssistantCardTwoStepsAfterArming(t *testing.T) {
	f := newAsst(t, 120, 40)
	conv := f.converse("restart the api")
	f.raiseCard(idJob)
	view := f.view()
	mustContain(t, view, "=== approval requested by the assistant ===", "the local daemon", "assistant (MCP client)", string(idJob), jobHash,
		"Action: service.restart", "1. Stop sm-demo.service", "service sm-demo.service@web-1", "Risk: high", "reading the card")
	mustNotContain(t, view, "| ===")

	// Keys typed before the card is armed decide nothing.
	f.press("A", "y", "R", "esc", "enter")
	if f.api.count("Approve") != 0 || f.api.count("Reject") != 0 || f.m.asst.card == nil || f.m.asst.card.step != stepChoose || f.m.prompt != nil {
		t.Fatalf("a key before arming did something: approve %d, reject %d, step %v", f.api.count("Approve"), f.api.count("Reject"), f.m.asst.card.step)
	}

	f.arm()
	mustContain(t, f.view(), "A approve  R reject  esc leave pending")
	f.press("y") // not a choice
	if f.api.count("Approve") != 0 {
		t.Fatal("y alone approved")
	}
	f.arm()
	f.press("A")
	mustContain(t, f.view(), "approve job "+string(idJob), "wait, then y")
	f.arm()
	mustContain(t, f.view(), "y/n: approve job "+string(idJob), "y approve  any other key goes back")
	f.press("n")
	f.arm()
	f.press("A")
	mustContain(t, f.view(), "wait, then y to approve  (any key goes back)")
	mustNotContain(t, f.view(), "y/n:")
	f.press("y") // typed straight after A: y during the pause goes back
	if f.api.count("Approve") != 0 || f.m.asst.card.step != stepChoose {
		t.Fatal("y before the confirm step was armed approved or stayed")
	}
	f.arm()
	f.press("A")
	f.arm()
	f.press("A") // a second A is not the confirmation either
	if f.api.count("Approve") != 0 || f.m.asst.card.step != stepChoose {
		t.Fatal("a second A approved or stayed in the confirm step")
	}
	f.arm()
	f.press("A")
	f.arm()
	f.press("n")
	f.arm()
	mustContain(t, f.view(), "A approve  R reject")
	f.press("A")
	f.arm()
	f.press("y")
	if got := f.api.count("Approve"); got != 1 {
		t.Fatalf("Approve called %d times", got)
	}
	if len(f.api.approved) != 1 || f.api.approved[0].PlanHash != jobHash {
		t.Errorf("approved with %+v, want the API's hash %s", f.api.approved, jobHash)
	}
	sent := conv.sentTexts()
	if len(sent) != 2 || sent[1] != fmt.Sprintf("[sm] job %s approved by the operator", idJob) {
		t.Errorf("the model was told %v", sent)
	}
	if f.m.asst.card != nil || !f.m.asst.working {
		t.Errorf("card = %v, working = %v after the decision", f.m.asst.card, f.m.asst.working)
	}
}

func TestAssistantCardKeysBeforeArmingAreIgnoredEvenIfLoadedByTheRuntime(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.raiseCard(idJob)
	f.press("A", "y")
	if f.api.count("Approve") != 0 {
		t.Fatal("approved before arming")
	}
	// A stale arming (another card's seq) does not arm this one.
	f.send(assistantArmedMsg{seq: f.m.asst.card.seq + 1})
	f.press("A", "y")
	if f.api.count("Approve") != 0 {
		t.Fatal("a stale arming armed the card")
	}
}

func TestAssistantRejectNeedsAReason(t *testing.T) {
	f := newAsst(t, 80, 24)
	conv := f.converse("go")
	f.raiseCard(idJob)
	f.arm()
	f.press("R")
	if f.m.prompt == nil {
		t.Fatal("R did not ask for a reason")
	}
	f.press("enter")
	if f.api.count("Reject") != 0 || f.m.asst.card == nil {
		t.Fatal("rejected without a reason")
	}
	f.arm()
	f.press("R")
	f.typeText("not now")
	f.press("enter")
	if len(f.api.rejected) != 1 || f.api.rejected[0].Reason != "not now" || f.api.rejected[0].PlanHash != jobHash {
		t.Fatalf("rejected %+v", f.api.rejected)
	}
	sent := conv.sentTexts()
	if got := sent[len(sent)-1]; got != fmt.Sprintf("[sm] job %s rejected by the operator: not now", idJob) {
		t.Errorf("the model was told %q", got)
	}
}

func TestAssistantEscLeavesTheApprovalPending(t *testing.T) {
	f := newAsst(t, 80, 24)
	conv := f.converse("go")
	f.raiseCard(idJob)
	f.arm()
	f.press("esc")
	if f.api.count("Approve")+f.api.count("Reject") != 0 || f.m.asst.card != nil {
		t.Fatal("esc decided something or kept the card")
	}
	sent := conv.sentTexts()
	if got := sent[len(sent)-1]; got != fmt.Sprintf("[sm] job %s left pending by the operator", idJob) {
		t.Errorf("the model was told %q", got)
	}
	f.press("esc")
	if f.m.screen != screenDashboard {
		t.Errorf("second esc: screen = %v", f.m.screen)
	}
}

func TestAssistantSeveralApprovalsAreDecidedOneByOneAndAnsweredOnce(t *testing.T) {
	f := newAsst(t, 80, 24)
	second := f.api.jobs[1]
	second.ID, second.State, second.ActorID, second.PlanHash = "0192a000-0000-7000-8000-00000000c003", domain.JobAwaitingApproval, idAssistant, "ff"+jobHash[2:]
	f.api.jobs = append(f.api.jobs, second)
	f.api.approvals = append(f.api.approvals, wire.Approval{Job: second, Plan: f.api.plan.Plan, Quorum: 1, ExpiresAt: epoch.Add(time.Hour)})
	conv := f.converse("go")
	f.event(assistant.Event{Kind: assistant.KindApproval, Approval: &assistant.Signal{JobID: idJob}})
	f.event(assistant.Event{Kind: assistant.KindApproval, Approval: &assistant.Signal{JobID: second.ID}})
	f.event(assistant.Event{Kind: assistant.KindApproval, Approval: &assistant.Signal{JobID: idJob}}) // repeated: once
	f.send(f.event(assistant.Event{Kind: assistant.KindTurnDone})())
	f.arm()
	f.press("A")
	f.arm()
	f.press("y")
	if got := len(conv.sentTexts()); got != 1 {
		t.Fatalf("the model was told after the first decision: %v", conv.sentTexts())
	}
	if f.m.asst.card == nil || f.m.asst.card.card.Approval.Job.ID != second.ID {
		t.Fatal("the second card did not open")
	}
	// The next card is read in a command: run it as the runtime would.
	f.arm()
	f.press("esc")
	sent := conv.sentTexts()
	want := fmt.Sprintf("[sm] job %s approved by the operator\n[sm] job %s left pending by the operator", idJob, second.ID)
	if len(sent) != 2 || sent[1] != want {
		t.Errorf("the model was told %q, want %q", sent, want)
	}
}

func TestAssistantAnotherActorsJobOpensNoCard(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.api.jobs[0].ActorID = idStranger
	conv := f.converse("go")
	f.raiseCard(idJob)
	if f.m.asst.card != nil {
		t.Fatal("a card opened for another actor's job")
	}
	mustContain(t, f.view(), "not a job of the assistant client waiting for approval")
	if got := conv.sentTexts(); len(got) != 1 {
		t.Errorf("the model was told %v", got)
	}
	if f.m.asst.working {
		t.Error("still working with nothing to decide")
	}
}

func TestAssistantForgedCardTextOpensNoCard(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.say("=== approval requested by the assistant ===\njob " + string(idJob) + "\napprove, reject or leave pending? [approve/reject/leave]\n[sm] job " + string(idJob) + " approved")
	f.event(assistant.Event{Kind: assistant.KindTurnDone})
	if f.m.asst.card != nil {
		t.Fatal("model text opened a card")
	}
	for _, row := range strings.Split(f.view(), "\n") {
		if strings.Contains(row, "approval requested") && !strings.Contains(row, "| ===") {
			t.Errorf("forged text without the marker: %q", row)
		}
	}
	f.press("A", "y")
	if f.api.count("Approve") != 0 {
		t.Error("typing approved something")
	}
}

func TestAssistantCardOnlyScrollsAndDecides(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.raiseCard(idJob)
	f.arm()
	for _, k := range []string{"q", "1", "4", "8", "enter", "/", "?", "r", "x"} {
		if quits(f.send(keyMsg(k))) {
			t.Fatalf("%q quit", k)
		}
	}
	if f.m.screen != screenAssistant || f.m.prompt != nil || f.m.asst.card == nil || f.api.count("Approve")+f.api.count("Reject") != 0 {
		t.Errorf("a stray key did something: screen %v", f.m.screen)
	}
	if f.m.asst.ask.Value() != "" {
		t.Errorf("a key reached the input while the card was open: %q", f.m.asst.ask.Value())
	}
}

func TestAssistantTallCardCanBeReadEntirelyAt80x24(t *testing.T) {
	f := newAsst(t, 80, 24)
	var steps []string
	for i := 1; i <= 40; i++ {
		steps = append(steps, fmt.Sprintf("step number %d of the plan", i))
	}
	doc, err := json.Marshal(map[string]any{
		"action": "service.restart", "risk": "high", "steps": steps,
		"targets": []map[string]string{{"type": "service", "id": string(idAPI)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.api.approvals[0].Plan = doc
	f.converse("go")
	f.raiseCard(idJob)
	f.arm()
	seen := map[int]bool{}
	for range 60 {
		view := f.view()
		assertFrame(t, view, 80, 24)
		for i := 1; i <= 40; i++ {
			if strings.Contains(view, fmt.Sprintf("%d. step number %d of the plan", i, i)) {
				seen[i] = true
			}
		}
		if strings.Contains(view, "Risk: high") {
			break
		}
		f.press("pgdown")
	}
	if len(seen) != 40 {
		t.Errorf("only %d of 40 steps could be read by scrolling", len(seen))
	}
	mustContain(t, f.view(), "Risk: high")
}

func TestAssistantApprovalWaitingShowsOnOtherScreens(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.press("esc")
	f.press("2")
	f.raiseCard(idJob)
	mustContain(t, f.view(), "assistant: an approval is waiting (8)")
	f.press("8")
	mustContain(t, f.view(), "=== approval requested by the assistant ===")
}

func TestAssistantALongModelLineStaysResponsiveAndInsideTheFrame(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.say(strings.Repeat("x", 100_000) + "\tafter\ttab")
		f.say(strings.Repeat("字", 50_000))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ingesting long lines stalled")
	}
	view := f.view()
	assertFrame(t, view, 80, 24)
	mustNotContain(t, view, "\t")
	f.say("short")
	mustContain(t, f.view(), "| short")
	assertFrame(t, f.view(), 80, 24)
}

func TestAssistantTabsInModelTextKeepTheFrame(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.say("col1\tcol2\tcol3")
	view := f.view()
	assertFrame(t, view, 80, 24)
	mustContain(t, view, "| col1    col2    col3")
}

func TestAssistantTranscriptIsBounded(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	for i := range maxTranscript + 2*trimChunk {
		f.say(fmt.Sprintf("line %d", i))
	}
	if n := len(f.m.asst.entries); n > maxTranscript+trimChunk {
		t.Errorf("%d entries kept, bound is %d", n, maxTranscript+trimChunk)
	}
	mustContain(t, f.view(), fmt.Sprintf("| line %d", maxTranscript+2*trimChunk-1))
}

func TestAssistantFollowsTheBottomUnlessScrolledUp(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	for i := range 60 {
		f.say(fmt.Sprintf("old %d", i))
	}
	mustContain(t, f.view(), "| old 59")
	f.press("pgup")
	before := f.view()
	mustContain(t, before, "scrolled")
	f.say("new arrival")
	mustNotContain(t, f.view(), "new arrival")
	f.press("pgdown", "pgdown", "pgdown", "pgdown")
	mustContain(t, f.view(), "| new arrival")
}

func TestAssistantResizeRewrapsTranscriptAndCard(t *testing.T) {
	f := newAsst(t, 120, 30)
	f.converse("go")
	f.say(strings.Repeat("word ", 40))
	f.raiseCard(idJob)
	for _, size := range [][2]int{{80, 24}, {50, 14}, {120, 30}} {
		f.send(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		assertFrame(t, f.view(), size[0], size[1])
	}
	mustContain(t, f.view(), jobHash)
}

func TestAssistantPasteGoesToTheInputOnOneLine(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.press("8")
	f.send(tea.PasteMsg{Content: "restart\nthe api"})
	if got := f.m.asst.ask.Value(); strings.Contains(got, "\n") || !strings.Contains(got, "restart") {
		t.Errorf("input = %q", got)
	}
}

func TestAssistantDraftSurvivesLeavingTheScreen(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.press("8")
	f.typeText("half a thought")
	f.press("esc")
	f.press("/")
	f.typeText("refresh")
	f.press("esc")
	f.press("8")
	if got := f.m.asst.ask.Value(); got != "half a thought" {
		t.Errorf("draft = %q", got)
	}
}

func TestAssistantQuitClosesTheChildBeforeRunReturns(t *testing.T) {
	f := newAsst(t, 80, 24)
	conv := f.converse("hello")
	f.m.closeAssistant()
	if !conv.isClosed() {
		t.Error("closeAssistant left the child running")
	}
}

func TestAssistantStartThatFinishesAfterShutdownIsClosed(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.press("8")
	f.typeText("hello")
	cmd := f.send(keyMsg("enter"))
	f.m.closeAssistant() // the operator quit while the child was starting
	msg := runCmd(t, cmd).(assistantStartedMsg)
	if msg.err == nil || !f.l.conv.isClosed() {
		t.Errorf("err = %v, closed = %v: the late child was kept", msg.err, f.l.conv.isClosed())
	}
}

// blockingReader feeds a program keys on demand; it never reports end of input.
type blockingReader struct {
	keys chan string
	rest []byte
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if len(r.rest) == 0 {
		k, ok := <-r.keys
		if !ok {
			return 0, io.EOF
		}
		r.rest = []byte(k)
	}
	n := copy(p, r.rest)
	r.rest = r.rest[n:]
	return n, nil
}

func TestRunClosesTheConversationBeforeItReturns(t *testing.T) {
	api := newFake()
	l := newFakeLauncher()
	in := &blockingReader{keys: make(chan string, 8)}
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), api, Options{Timeout: time.Second, Location: time.UTC, Assistant: l.launcher()},
			tea.WithInput(in), tea.WithOutput(io.Discard), tea.WithWindowSize(80, 24))
	}()
	in.keys <- "8"
	in.keys <- "hello"
	in.keys <- "\r"
	delivered := false
	for range 500 {
		l.mu.Lock()
		conv := l.conv
		l.mu.Unlock()
		if delivered = conv != nil && len(conv.sentTexts()) == 1; delivered {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !delivered {
		t.Fatal("the message never reached the assistant")
	}
	in.keys <- "\x03"
	select {
	case err := <-done:
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctrl+c")
	}
	if !l.conv.isClosed() {
		t.Error("Run returned with the conversation still open")
	}
}

func TestAssistantGolden(t *testing.T) {
	cases := []struct {
		name string
		w, h int
		to   func(*asstFixture)
	}{
		{"assistant_transcript_80x24", 80, 24, func(f *asstFixture) {
			f.converse("what is running on web-1?")
			f.say("web-1 runs two services:\nsm-demo.service (active) and sm-demo-web (unhealthy).")
			f.event(assistant.Event{Kind: assistant.KindToolCall, Text: "service_list {\"node\":\"web-1\"}"})
			f.event(assistant.Event{Kind: assistant.KindToolResult, Text: "service_list: 2 services"})
			f.event(assistant.Event{Kind: assistant.KindTurnDone})
			f.typeText("why is the second one unhealthy?")
		}},
		{"assistant_transcript_120x30", 120, 30, func(f *asstFixture) {
			f.converse("what is running on web-1?")
			f.say("web-1 runs two services: sm-demo.service (active) and sm-demo-web (unhealthy). The container fails its health check; its last log lines would tell why.")
			f.event(assistant.Event{Kind: assistant.KindTurnDone})
		}},
		{"assistant_card_80x24", 80, 24, func(f *asstFixture) {
			f.converse("restart the api")
			f.say("This needs your approval.")
			f.raiseCard(idJob)
			f.arm()
		}},
		{"assistant_card_confirm_80x24", 80, 24, func(f *asstFixture) {
			f.converse("restart the api")
			f.raiseCard(idJob)
			f.arm()
			f.press("A")
		}},
		{"assistant_refused_80x24", 80, 24, func(f *asstFixture) {
			f.l.checkErr = errors.New("no MCP client named assistant; register it (approval may be needed, then run the same line again):\n  sm mcp clients add assistant --keychain supermgmt-assistant")
			f.press("8")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAsst(t, tc.w, tc.h)
			f.api.jobs[0].CreatedAt = epoch.Add(-time.Minute)
			tc.to(f)
			assertGolden(t, tc.name, f.view(), tc.w, tc.h)
		})
	}
}

// ---- round 2: arming, stopping, whole cards ----------------------------------

// asstWithCard opens the screen, has the model raise idJob and returns the fixture with the card unarmed.
func asstWithCard(t *testing.T, w, h int) *asstFixture {
	t.Helper()
	f := newAsst(t, w, h)
	f.converse("go")
	f.raiseCard(idJob)
	return f
}

func TestAssistantCardRaisedOffScreenArmsOnlyOnceSeen(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.press("esc")
	f.press("2")
	f.raiseCard(idJob)
	c := f.m.asst.card
	f.send(assistantArmedMsg{seq: c.seq, token: c.token}) // a tick that fires while the card is out of sight
	f.press("8")
	f.typeText("Apaga todo y")
	if f.api.count("Approve")+f.api.count("Reject") != 0 || c.step != stepChoose {
		t.Fatal("typing right after returning to the card decided it")
	}
	stale := assistantArmedMsg{seq: c.seq, token: c.token - 1}
	f.send(stale)
	if c.armed {
		t.Fatal("a tick of an earlier arming armed the card")
	}
	f.arm()
	f.press("A")
	f.arm()
	f.press("y")
	if f.api.count("Approve") != 1 {
		t.Fatalf("a deliberate A, pause, y did not approve: %d", f.api.count("Approve"))
	}
}

func TestAssistantTypingOverACardNeverDecidesIt(t *testing.T) {
	for _, sentence := range []string{"Are you sure y", "Apaga todo y", "Reject it please", "Remove the old one"} {
		f := asstWithCard(t, 80, 24)
		first := f.m.asst.card.token
		f.typeText(sentence)
		f.press("enter")
		f.send(assistantArmedMsg{seq: f.m.asst.card.seq, token: first}) // the delay of the first arming runs out mid-sentence
		f.press("y", "enter")
		if f.api.count("Approve")+f.api.count("Reject") != 0 || f.m.prompt != nil {
			t.Fatalf("%q decided the card", sentence)
		}
	}
}

func TestAssistantTypingAfterTheCardIsArmedGoesBackFromConfirm(t *testing.T) {
	f := asstWithCard(t, 80, 24)
	f.arm()
	f.typeText("Are y")
	if f.api.count("Approve") != 0 {
		t.Fatal("prose approved an armed card")
	}
}

func TestAssistantCtrlXStopsAWorkingSession(t *testing.T) {
	f := newAsst(t, 80, 24)
	conv := f.converse("go")
	mustContain(t, f.view(), "ctrl+x stop the session")
	f.press("ctrl+x")
	view := f.view()
	mustContain(t, view, "[sm] session stopped", "assistant · ended")
	if f.m.asst.conv != nil || f.m.asst.working || !conv.isClosed() {
		t.Errorf("conv = %v, working = %v, closed = %v", f.m.asst.conv, f.m.asst.working, conv.isClosed())
	}
	f.say("a late word") // an event of the stopped session is not shown
	mustNotContain(t, f.view(), "a late word")
	f.typeText("again")
	f.press("enter")
	if _, starts := f.l.counts(); starts != 2 {
		t.Errorf("starts = %d, a new message should start a new session", starts)
	}
}

func TestAssistantSilentChildGetsOneNoteWithTheWayOut(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	seq, act := f.m.asst.stallSeq, f.m.asst.activity
	f.send(assistantStallMsg{seq: seq, activity: act - 1}) // it spoke since: no note
	mustNotContain(t, f.view(), "no output from the assistant")
	f.send(assistantStallMsg{seq: seq, activity: act})
	f.send(assistantStallMsg{seq: seq, activity: act})
	if n := strings.Count(f.view(), "no output from the assistant for 60s; ctrl+x stops it"); n != 1 {
		t.Fatalf("the note shows %d times:\n%s", n, f.view())
	}
	f.say("back")
	f.send(assistantStallMsg{seq: seq, activity: f.m.asst.activity})
	if n := strings.Count(strings.Join(f.m.asst.rows, "\n"), "no output from the assistant"); n != 2 {
		t.Errorf("after activity a new silence did not get its note (%d)", n)
	}
}

func TestAssistantCtrlXDuringACardIsNotAStop(t *testing.T) {
	f := asstWithCard(t, 80, 24)
	f.arm()
	f.press("ctrl+x")
	if f.m.asst.conv == nil {
		t.Fatal("ctrl+x ended the session with a card open")
	}
}

func TestAssistantCardLinesAreNotCutAndStayReachable(t *testing.T) {
	f := newAsst(t, 80, 24)
	tail := "TAILMARKER"
	doc, err := json.Marshal(map[string]any{
		"action": "service.restart", "risk": "high",
		"steps":   []string{strings.Repeat("a", maxLineRunes+500) + " " + tail},
		"targets": []map[string]string{{"type": "service", "id": string(idAPI)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.api.approvals[0].Plan = doc
	f.converse("go")
	f.raiseCard(idJob)
	f.arm()
	found := false
	for range 200 {
		view := f.view()
		mustNotContain(t, view, "[cut]")
		if strings.Contains(view, tail) {
			found = true
			break
		}
		f.send(keyMsg("pgdown"))
	}
	if !found {
		t.Fatal("the end of a long step could not be read by scrolling")
	}
}

func TestAssistantOpenCardIsNotTrimmedAwayFromItsHead(t *testing.T) {
	f := newAsst(t, 80, 24)
	var steps []string
	for i := 1; i <= 300; i++ {
		steps = append(steps, fmt.Sprintf("step %d", i))
	}
	doc, err := json.Marshal(map[string]any{"action": "service.restart", "risk": "high", "steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	f.api.approvals[0].Plan = doc
	f.converse("go")
	for i := range maxTranscript + trimChunk - 100 {
		f.say(fmt.Sprintf("line %d", i))
	}
	f.raiseCard(idJob)
	head := false
	for _, e := range f.m.asst.entries {
		head = head || e.kind == kindCardHead
	}
	if !head || len(f.m.asst.entries) < f.m.asst.cardStart {
		t.Fatalf("the card head was trimmed away (cardStart %d of %d)", f.m.asst.cardStart, len(f.m.asst.entries))
	}
	steps1 := false
	for _, e := range f.m.asst.entries {
		steps1 = steps1 || (e.kind == kindCard && e.prefix == "1. ")
	}
	if !steps1 {
		t.Fatal("the first step of the open card was trimmed away")
	}
}

func TestAssistantTrimmingKeepsAScrolledUpViewInPlace(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	for i := range maxTranscript {
		f.say(fmt.Sprintf("line %d", i))
	}
	f.press("pgup", "pgup")
	before := f.m.asst.vp.YOffset()
	for i := range trimChunk + 5 {
		f.say(fmt.Sprintf("later %d", i))
	}
	if after := f.m.asst.vp.YOffset(); after >= before {
		t.Errorf("offset went %d -> %d although %d rows were dropped above", before, after, trimChunk)
	}
}

func TestAssistantTrimmingNearTheBottomKeepsTheSameTopRow(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	for i := range maxTranscript + trimChunk - 8 {
		f.say(fmt.Sprintf("line %d", i))
	}
	f.press("pgup")
	first := f.m.asst.vp.View()
	first = strings.SplitN(first, "\n", 2)[0]
	for i := range 12 {
		f.say(fmt.Sprintf("later %d", i))
	}
	if got := strings.SplitN(f.m.asst.vp.View(), "\n", 2)[0]; got != first {
		t.Errorf("top row %q became %q after a trim", first, got)
	}
}

func TestAssistantOutcomeIsVisibleAfterADecisionOnATallCard(t *testing.T) {
	f := newAsst(t, 80, 24)
	var steps []string
	for i := 1; i <= 40; i++ {
		steps = append(steps, fmt.Sprintf("step number %d of the plan", i))
	}
	doc, err := json.Marshal(map[string]any{"action": "service.restart", "risk": "high", "steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	f.api.approvals[0].Plan = doc
	f.converse("go")
	f.raiseCard(idJob)
	f.arm()
	f.press("A")
	f.arm()
	f.press("y")
	mustContain(t, f.view(), "approved")
	mustNotContain(t, f.view(), "scrolled")
}

func TestAssistantEscLeavesOnlyTheOpenCardAndShowsTheNext(t *testing.T) {
	f := newAsst(t, 80, 24)
	second := f.api.jobs[1]
	second.ID, second.State, second.ActorID, second.PlanHash = "0192a000-0000-7000-8000-00000000c003", domain.JobAwaitingApproval, idAssistant, "ff"+jobHash[2:]
	f.api.jobs = append(f.api.jobs, second)
	f.api.approvals = append(f.api.approvals, wire.Approval{Job: second, Plan: f.api.plan.Plan, Quorum: 1, ExpiresAt: epoch.Add(time.Hour)})
	conv := f.converse("go")
	f.event(assistant.Event{Kind: assistant.KindApproval, Approval: &assistant.Signal{JobID: idJob}})
	f.event(assistant.Event{Kind: assistant.KindApproval, Approval: &assistant.Signal{JobID: second.ID}})
	f.drain(f.event(assistant.Event{Kind: assistant.KindTurnDone}))
	f.arm()
	f.press("esc")
	if f.m.asst.card == nil || f.m.asst.card.card.Approval.Job.ID != second.ID {
		t.Fatal("the second card did not open after esc on the first")
	}
	if got := len(conv.sentTexts()); got != 1 {
		t.Errorf("the model was told before every card was settled: %v", conv.sentTexts())
	}
}

func TestAssistantSendingWhileScrolledUpShowsTheMessage(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.event(assistant.Event{Kind: assistant.KindTurnDone})
	for i := range 60 {
		f.say(fmt.Sprintf("old %d", i))
	}
	f.press("pgup", "pgup")
	f.typeText("still there")
	f.press("enter")
	mustContain(t, f.view(), "> still there")
}

func TestAssistantWaitingCardShowsOverANoticeOnOtherScreens(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.press("esc")
	f.press("2")
	f.m.notice = notice{text: "something else happened"}
	f.raiseCard(idJob)
	mustContain(t, f.view(), "assistant: an approval is waiting (8)")
}

func TestAssistantMessageIsBounded(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.press("8")
	f.send(tea.PasteMsg{Content: strings.Repeat("x", 3*askLimit)})
	if n := len([]rune(f.m.asst.ask.Value())); n > askLimit {
		t.Errorf("the input holds %d runes, limit %d", n, askLimit)
	}
}

func TestAssistantUnavailableHeadingDoesNotPromiseAStart(t *testing.T) {
	h := newHarness(t, newFake(), 80, 24)
	h.press("8")
	mustContain(t, h.view(), "assistant · not available: see below")
}

func TestAssistantProseWithPausesNeverApproves(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.converse("go")
	f.raiseCard(idJob)
	f.arm()
	for _, k := range []string{"A", "p", "a", "g", "a"} { // "Apaga": each key restarts the wait
		f.press(k)
	}
	if f.m.asst.card.step != stepChoose {
		t.Fatalf("step = %v after prose, want choose", f.m.asst.card.step)
	}
	f.arm()
	f.press("y")
	if f.api.count("Approve") != 0 {
		t.Fatal("prose with a pause before y approved")
	}
}

func TestAssistantHeadingRecoversOnceTheSessionStarts(t *testing.T) {
	f := newAsst(t, 80, 24)
	f.l.checkErr = errors.New("api unreachable")
	f.press("8")
	mustContain(t, f.view(), "not available")
	f.l.checkErr = nil
	f.converse("go")
	mustContain(t, f.view(), "working…")
	mustNotContain(t, f.view(), "not available")
}
