package integration

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/autarquico/supermgmt/internal/database"
)

// The scenarios of assistant-tui, end to end: the real `sm tui` under a
// pseudo-terminal, the rig's real daemon, and the fake claude of
// assistant-claude-cli as the only stand-in. The screen is read as text
// (escape sequences stripped); what the child saw and whether it is still
// alive come from the fake's own record.

var ansi = regexp.MustCompile(`\x1b(\[[0-9;?<>=]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[()][0-9A-B]|[=>78])`)

var tuiSize = pty.Winsize{Rows: 30, Cols: 120}

// sinceKey is what was drawn after the last key was pressed: a wait must see an effect of the key, not older text.
func (x *terminal) sinceKey() string {
	full := x.screen()
	x.mu.Lock()
	defer x.mu.Unlock()
	return full[min(x.mark, len(full)):]
}

// screen is what the terminal has been told to show, without styling.
func (x *terminal) screen() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return ansi.ReplaceAllString(strings.ReplaceAll(x.buf.String(), "\r", ""), "")
}

func (x *terminal) waitForScreen(substr string) string {
	x.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), assistantTimeout)
	defer cancel()
	for ctx.Err() == nil {
		if out := x.sinceKey(); strings.Contains(out, substr) {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
	x.t.Fatalf("timed out waiting for %q on the screen; so far:\n%s", substr, x.screen())
	return ""
}

// waitForWrapped is waitForScreen for text the screen may have wrapped anywhere: whitespace is ignored.
func (x *terminal) waitForWrapped(substr string) {
	x.t.Helper()
	squash := func(v string) string { return strings.Join(strings.Fields(v), "") }
	ctx, cancel := context.WithTimeout(context.Background(), assistantTimeout)
	defer cancel()
	for ctx.Err() == nil {
		if strings.Contains(squash(x.sinceKey()), squash(substr)) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	x.t.Fatalf("timed out waiting for %q on the screen; so far:\n%s", substr, x.screen())
}

func (x *terminal) press(keys string) {
	x.t.Helper()
	full := x.screen()
	x.mu.Lock()
	x.mark = len(full)
	x.mu.Unlock()
	_, err := x.ptmx.WriteString(keys)
	mcpRigMust(x.t, err)
}

// ask opens the assistant screen and sends one message, as an operator does.
func (x *terminal) ask(text string) {
	x.t.Helper()
	x.waitForScreen("Dashboard")
	x.press("8")
	x.waitForScreen("assistant")
	x.press(text)
	x.press("\r")
}

// quit sends Ctrl-C and waits for sm to leave.
func (x *terminal) quit() {
	x.t.Helper()
	x.press("\x03")
	x.finish()
}

func (a *assistantRig) tui(args ...string) *terminal {
	a.t.Helper()
	return a.terminalRunning(a.env, tuiSize, append([]string{"tui"}, args...)...)
}

// mcpConfigPath is the --mcp-config file the child was given, which lives in the session's temporary directory.
func (a *assistantRig) mcpConfigPath() string {
	a.t.Helper()
	argv := a.record().Argv
	i := slices.Index(argv, "--mcp-config")
	if i < 0 || i+1 >= len(argv) {
		a.t.Fatalf("the child was launched without --mcp-config: %v", argv)
	}
	return argv[i+1]
}

func TestAssistantTUI_TheReplyStreamsIntoTheTranscriptWithToolLines(t *testing.T) {
	a := newAssistantRig(t)
	a.replay("tool-call.jsonl")
	term := a.tui()

	term.ask("is the daemon up?")

	term.waitForScreen("infra_ping")
	if lines := a.stdinLog(); len(lines) != 1 || !strings.Contains(lines[0], "is the daemon up?") {
		t.Errorf("the child received %q, want the operator's message", lines)
	}
	screen := term.waitForScreen("done")
	if !strings.Contains(screen, "infra_ping") {
		t.Errorf("no tool line in the transcript:\n%s", screen)
	}
	term.quit()
}

func TestAssistantTUI_ASessionWithOtherToolsStopsBeforeAnyOutput(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "foreign-tool"})
	term := a.tui()

	term.ask("hello")

	term.waitForScreen("Bash")
	if strings.Contains(term.screen(), "SHOULD-NEVER-SHOW") {
		t.Error("the model's output reached the transcript from a session with foreign tools")
	}
	term.quit()
	if pid := a.record().PID; !processGone(pid) {
		t.Errorf("the refused child %d is still running", pid)
	}
}

func TestAssistantTUI_AChildThatDiesShowsItsReasonAndTheTUIKeepsResponding(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "exit", ExitCode: 3, Stderr: "claude-fake: the model went away\n"})
	term := a.tui()

	term.ask("hello")

	term.waitForScreen("the model went away")
	term.press("\x1b")
	term.waitForScreen("Awaiting approval")
	term.quit()
}

func TestAssistantTUI_QuittingEndsTheChildAndItsTemporaryDirectory(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "stall"})
	term := a.tui()
	term.ask("hello")
	assistantWaitUntil(t, "the child to receive the message", func() bool { return len(a.stdinLog()) > 0 })
	pid, config := a.record().PID, a.mcpConfigPath()
	if _, err := os.Stat(config); err != nil {
		t.Fatalf("the temporary MCP config is not there while the session runs: %v", err)
	}

	term.quit()

	if !processGone(pid) {
		t.Errorf("the stalled child %d outlived the TUI", pid)
	}
	if _, err := os.Stat(filepath.Dir(config)); !os.IsNotExist(err) {
		t.Errorf("the session's temporary directory %s survived the TUI: %v", filepath.Dir(config), err)
	}
}

func TestAssistantTUI_NothingIsLaunchedUntilTheOperatorAsks(t *testing.T) {
	a := newAssistantRig(t)
	a.replay("tool-call.jsonl")
	term := a.tui()
	term.waitForScreen("Dashboard")

	term.press("8")
	term.waitForScreen("assistant")
	term.press("hello, not sent")
	time.Sleep(300 * time.Millisecond)
	term.press("\x1b")
	term.waitForScreen("Awaiting approval") // a lone esc, not the start of alt+ctrl+c
	term.quit()

	if a.launched() {
		t.Error("claude was launched without a message having been sent")
	}
}

func TestAssistantTUI_WithoutARegisteredClientItShowsTheCommandAndStartsNothing(t *testing.T) {
	a := newAssistantRig(t)
	a.replay("tool-call.jsonl")
	a.rig.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE mcp_clients SET name = 'someone-else' WHERE id = ?`, a.rig.mcp.Credential.ID)
		return err
	})
	term := a.tui()
	term.waitForScreen("Dashboard")

	term.press("8")

	token := filepath.Join(a.home, "xdg", "supermgmt", "assistant.token")
	term.waitForWrapped("sm mcp clients add assistant --token-file " + token)
	term.press("hello")
	term.press("\r")
	time.Sleep(300 * time.Millisecond)
	term.quit()
	if a.launched() {
		t.Error("claude was launched without a registered client")
	}
}

func TestAssistantTUI_ARealApprovalIsDecidedInPlaceWithTheAPIsHash(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "probe", Tool: "infra_restart_service", Args: map[string]any{"ref": "api@web-1"}})
	term := a.tui()

	term.ask("restart the api")
	term.waitForScreen("=== approval requested by the assistant ===")
	ids, hashes := a.pendingJobs(a.rig.mcp.ID)
	if len(ids) != 1 {
		t.Fatalf("the model's real token submitted %d pending jobs, want 1", len(ids))
	}
	card := term.sinceKey()
	for _, want := range []string{"assistant (MCP client)", ids[0], hashes[0], "service.restart"} {
		if !strings.Contains(card, want) {
			t.Errorf("card lacks %q:\n%s", want, card)
		}
	}

	// Past the arming delay; a first key only chooses, the second, after a pause, confirms.
	time.Sleep(time.Second)
	term.press("A")
	term.waitForScreen("y/n")
	if got := a.decisions(ids[0]); len(got) != 0 {
		t.Fatalf("a single key decided the job: %+v", got)
	}
	time.Sleep(time.Second) // the confirmation waits for its own pause
	term.press("y")
	term.waitForScreen("ack: [sm] job " + ids[0])

	got := a.decisions(ids[0])
	if len(got) != 1 || got[0].approver != a.rig.admin.ID.String() || got[0].hash != hashes[0] || got[0].verdict != "approve" {
		t.Errorf("decisions = %+v, want one approval by the human with the API's hash %s", got, hashes[0])
	}
	term.quit()
}

func TestAssistantTUI_AHostileModelOpensNoCard(t *testing.T) {
	a := newAssistantRig(t)
	own := a.submitRestart(a.rig.mcp)
	foreign := a.submitRestart(a.rig.admin)
	a.script(script{Mode: "hostile", OwnJob: own, ForeignJob: foreign})
	term := a.tui()

	term.ask("do the thing")

	term.waitForWrapped("which is not a job of the assistant client waiting for approval")
	screen := term.screen()
	if strings.Contains(screen, "A approve  R reject") {
		t.Errorf("a card was opened:\n%s", screen)
	}
	for _, line := range strings.Split(screen, "\n") {
		forgery := strings.Contains(line, "=== approval requested") || strings.Contains(line, "approve, reject or leave pending")
		if forgery && !strings.Contains(line, "| ") {
			t.Errorf("model text can pass for ours: %q", line)
		}
	}
	if lines := a.stdinLog(); len(lines) != 1 {
		t.Errorf("the model was sent %d messages, want only the operator's own", len(lines))
	}
	for _, job := range []string{own, foreign} {
		if got := a.decisions(job); len(got) != 0 {
			t.Errorf("job %s was decided: %+v", job, got)
		}
	}
	term.quit()
}

func TestAssistantTUI_AuthAPIKeyWithoutTheKeyIsAUsageErrorAndStartsNoTUI(t *testing.T) {
	a := newAssistantRig(t)

	res := runSMIn(t, a.sm, a.home, a.env, "tui", "--auth", "api-key")

	if res.exit != 2 || !strings.Contains(res.stderr, "ANTHROPIC_API_KEY") {
		t.Errorf("exit %d, stderr %q; want a usage error naming ANTHROPIC_API_KEY", res.exit, res.stderr)
	}
	if a.launched() {
		t.Error("claude was launched")
	}
}
