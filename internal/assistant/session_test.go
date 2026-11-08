package assistant

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeClaude writes an executable that behaves as script says. $CAPTURE is
// the file the script may write its observations to.
func fakeClaude(t *testing.T, script string) (path, capture string) {
	t.Helper()
	dir := t.TempDir()
	capture = filepath.Join(dir, "capture")
	path = filepath.Join(dir, "claude")
	body := "#!/bin/sh\nCAPTURE='" + capture + "'\n" + script
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, capture
}

func sessionConfig(claude string) Config {
	cfg := testConfig(AuthSubscription)
	cfg.Claude = claude
	cfg.Env = append(slices.Clone(poisoned), "PATH="+os.Getenv("PATH"))
	return cfg
}

func startSession(t *testing.T, cfg Config) *Session {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func drain(t *testing.T, s *Session) []Event {
	t.Helper()
	var events []Event
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-s.Events():
			if !ok {
				return events
			}
			events = append(events, e)
		case <-timeout:
			t.Fatalf("session did not end; events so far: %+v", events)
		}
	}
}

func TestSession_ReplaysARecordedRun(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join(fixtureDir, "approval-required.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	claude, capture := fakeClaude(t, `read line
printf '%s\n' "$line" > "$CAPTURE"
cat '`+fixture+`'
`)
	s := startSession(t, sessionConfig(claude))
	if err := s.Send("restart it"); err != nil {
		t.Fatal(err)
	}
	events := drain(t, s)
	want := []Kind{KindToolCall, KindToolResult, KindApproval, KindText, KindTurnDone, KindEnded}
	if got := kinds(events); !equalKinds(got, want) {
		t.Fatalf("kinds = %v, want %v; %+v", got, want, events)
	}
	if events[2].Approval.JobID != jobID {
		t.Fatalf("approval = %+v", events[2].Approval)
	}
	sent, _ := os.ReadFile(capture)
	if string(sent) != `{"message":{"content":"restart it","role":"user"},"type":"user"}`+"\n" {
		t.Fatalf("the child received %q", sent)
	}
}

func TestSession_ChildSeesTheLockedDownLaunch(t *testing.T) {
	claude, capture := fakeClaude(t, `read line
{ pwd; echo ARGS; printf '%s\n' "$@"; echo ENV; env; echo MCP; cat mcp.json; echo; stat -f %Lp mcp.json 2>/dev/null || stat -c %a mcp.json; } > "$CAPTURE"
`)
	s := startSession(t, sessionConfig(claude))
	if err := s.Send("hi"); err != nil {
		t.Fatal(err)
	}
	drain(t, s)
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	report := string(raw)
	cwd := strings.SplitN(report, "\n", 2)[0]
	args := between(report, "ARGS\n", "ENV\n")
	env := between(report, "ENV\n", "MCP\n")

	if !strings.Contains(args, "--tools\n\n--strict-mcp-config") || strings.Contains(args, "dangerously") {
		t.Fatalf("args = %q", args)
	}
	for _, leaked := range []string{"SUPERMGMT_", "SSH_AUTH_SOCK", "ANTHROPIC_", "GITHUB_TOKEN", "LD_PRELOAD", "NODE_OPTIONS"} {
		if strings.Contains(env, leaked) {
			t.Fatalf("%s reached the child:\n%s", leaked, env)
		}
	}
	if !strings.Contains(env, "HOME=/home/op") || !strings.Contains(env, "USER=op") {
		t.Fatalf("allowlisted variables missing:\n%s", env)
	}
	mcp := report[strings.LastIndex(report, "\nMCP\n")+5:]
	if !strings.Contains(mcp, `"--keychain","supermgmt-assistant","--profile","prod"`) || !strings.HasSuffix(strings.TrimSpace(mcp), "600") {
		t.Fatalf("mcp config = %q", mcp)
	}
	if !strings.Contains(filepath.Base(cwd), "sm-assistant-") {
		t.Fatalf("cwd = %q, want a private temp dir", cwd)
	}
	if _, err := os.Stat(cwd); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the private directory outlived the session: %v", err)
	}
}

func TestSession_RefusesASessionWithOtherToolsBeforeShowingAnything(t *testing.T) {
	claude, _ := fakeClaude(t, `read line
echo '{"type":"system","subtype":"init","tools":["Bash","mcp__sm__infra_ping"],"mcp_servers":[{"name":"sm","status":"connected"}]}'
echo '{"type":"assistant","message":{"content":[{"type":"text","text":"should never show"}]}}'
exec sleep 30
`)
	s := startSession(t, sessionConfig(claude))
	_ = s.Send("hi")
	events := drain(t, s)
	if got := kinds(events); !equalKinds(got, []Kind{KindError, KindEnded}) {
		t.Fatalf("events = %+v", events)
	}
	if !events[0].Fatal || events[1].Err != nil || strings.Contains(events[1].Text, "killed") {
		t.Fatalf("a stop sm made itself must be fatal and not read as a crash: %+v", events)
	}
	if !strings.Contains(events[0].Text, "not SuperMgmt's: Bash") {
		t.Fatalf("reason = %q", events[0].Text)
	}
}

func TestSession_StopsOnAMalformedLine(t *testing.T) {
	claude, _ := fakeClaude(t, `read line
echo '{"type":"system","subtype":"init","tools":[],"mcp_servers":[{"name":"sm","status":"connected"}]}'
echo 'this is not json'
echo '{"type":"assistant","message":{"content":[{"type":"text","text":"after"}]}}'
exec sleep 30
`)
	s := startSession(t, sessionConfig(claude))
	_ = s.Send("hi")
	events := drain(t, s)
	if got := kinds(events); !equalKinds(got, []Kind{KindError, KindEnded}) {
		t.Fatalf("events = %+v", events)
	}
}

func TestSession_StopsOnAnOverlongLine(t *testing.T) {
	claude, _ := fakeClaude(t, `read line
head -c 2000000 /dev/zero | tr '\0' a
echo
exec sleep 30
`)
	s := startSession(t, sessionConfig(claude))
	_ = s.Send("hi")
	events := drain(t, s)
	if got := kinds(events); !equalKinds(got, []Kind{KindError, KindEnded}) || !strings.Contains(events[0].Text, "longer than") {
		t.Fatalf("events = %+v", events)
	}
}

func TestSession_ReportsExitAndSanitisedStderr(t *testing.T) {
	claude, _ := fakeClaude(t, "read line\nprintf 'please \\033[2Jsign in\\n' >&2\nexit 3\n")
	s := startSession(t, sessionConfig(claude))
	_ = s.Send("hi")
	events := drain(t, s)
	last := events[len(events)-1]
	if last.Kind != KindEnded || last.Err == nil || !strings.Contains(last.Text, "exit status 3") || !strings.Contains(last.Text, "please sign in") {
		t.Fatalf("last = %+v", last)
	}
}

func TestSession_CloseKillsAStalledChildAndIsIdempotent(t *testing.T) {
	claude, _ := fakeClaude(t, "exec sleep 30\n")
	s := startSession(t, sessionConfig(claude))
	closed := make(chan error, 1)
	go func() { closed <- errors.Join(s.Close(), s.Close()) }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Close did not kill the child")
	}
	if err := s.Send("late"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after Close = %v, want ErrClosed", err)
	}
	if events := drain(t, s); len(events) > 0 && events[len(events)-1].Kind != KindEnded {
		t.Fatalf("events = %+v", events)
	}
}

func TestSession_CloseReturnsEvenWhenADescendantHoldsStdout(t *testing.T) {
	claude, _ := fakeClaude(t, "sleep 30 &\nwait\n")
	s := startSession(t, sessionConfig(claude))
	closed := make(chan struct{})
	go func() { _ = s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(closeGraceTime + waitDelay + 2*time.Second):
		t.Fatal("Close stalled on a descendant that holds the stdout pipe")
	}
}

func TestSession_CloseSendsNoFatalError(t *testing.T) {
	claude, _ := fakeClaude(t, "exec sleep 30\n")
	s := startSession(t, sessionConfig(claude))
	_ = s.Close()
	for _, e := range drain(t, s) {
		if e.Fatal {
			t.Fatalf("Close reported a fatal error: %+v", e)
		}
	}
}

func TestSession_StartRefusals(t *testing.T) {
	t.Run("claude missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		s, _ := New(testConfig(AuthSubscription))
		if err := s.Start(context.Background()); !errors.Is(err, ErrClaudeNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("api-key without a key", func(t *testing.T) {
		claude, capture := fakeClaude(t, "echo ran > \"$CAPTURE\"\n")
		cfg := testConfig(AuthAPIKey)
		cfg.Claude, cfg.Env = claude, []string{"HOME=/h"}
		s, _ := New(cfg)
		err := s.Start(context.Background())
		if !errors.Is(err, ErrNoAPIKey) {
			t.Fatalf("err = %v", err)
		}
		if _, statErr := os.Stat(capture); statErr == nil {
			t.Fatal("claude was launched without a key")
		}
	})
}

func TestSession_APIKeyReachesTheChildOnlyThroughTheEnvironment(t *testing.T) {
	claude, capture := fakeClaude(t, "read line\n{ printf '%s\\n' \"$@\"; env; } > \"$CAPTURE\"\n")
	cfg := sessionConfig(claude)
	cfg.Auth = AuthAPIKey
	s := startSession(t, cfg)
	_ = s.Send("hi")
	drain(t, s)
	raw, _ := os.ReadFile(capture)
	lines := strings.Split(string(raw), "\n")
	if !slices.Contains(lines, "--bare") || !slices.Contains(lines, "ANTHROPIC_API_KEY=sk-ant-key") {
		t.Fatalf("capture:\n%s", raw)
	}
	for _, l := range lines {
		if strings.Contains(l, "sk-ant-key") && !strings.HasPrefix(l, "ANTHROPIC_API_KEY=") {
			t.Fatalf("the key appears outside its variable: %q", l)
		}
	}
}

func between(s, from, to string) string {
	start := strings.Index(s, from) + len(from)
	end := strings.Index(s, to)
	return s[start:end]
}

func TestSession_CloseDoesNotWaitBehindASendBlockedOnAStalledChild(t *testing.T) {
	claude, _ := fakeClaude(t, "exec sleep 30\n")
	s := startSession(t, sessionConfig(claude))
	sent := make(chan error, 1)
	go func() { sent <- s.Send(strings.Repeat("x", 1<<20)) }() // far beyond the pipe buffer
	time.Sleep(200 * time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(closeGraceTime + waitDelay + 2*time.Second):
		t.Fatal("Close waited behind a blocked Send")
	}
	select {
	case err := <-sent:
		if err == nil {
			t.Error("the blocked Send reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the blocked Send was not released by Close")
	}
}
