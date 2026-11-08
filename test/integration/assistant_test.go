package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The scenarios of assistant-claude-cli, end to end: the real `sm` binary, the
// rig's real API on a Unix socket (real database, app services and policy), the
// real `sm mcp` child where a scenario needs the model's tools, and a fake
// `claude` (test/fixtures/claude-fake) that records how it was launched. The
// fake is the only stand-in: it is the model's side of the boundary.

const (
	assistantTimeout = 60 * time.Second
	assistantKeySent = "sk-ant-SENTINEL-do-not-leak"
	assistantCredSen = "claude-credential-SENTINEL"
)

var (
	assistantBinOnce sync.Once
	assistantBinDir  string // holds sm and claude
	assistantBinErr  error
)

// assistantBinaries builds the real sm and the fake claude once per test binary.
func assistantBinaries(t *testing.T) (sm, claudeDir string) {
	t.Helper()
	assistantBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sm-assistant-bin")
		if err != nil {
			assistantBinErr = err
			return
		}
		assistantBinDir = dir
		for out, pkg := range map[string]string{
			filepath.Join(dir, "sm"):               "./cmd/sm",
			filepath.Join(dir, "claude", "claude"): "./test/fixtures/claude-fake",
		} {
			build := exec.CommandContext(context.Background(), "go", "build", "-o", out, pkg)
			build.Dir = repoRoot(t)
			build.Env = append(os.Environ(), "CGO_ENABLED=0")
			if msg, err := build.CombinedOutput(); err != nil {
				assistantBinErr = errors.New("go build " + pkg + ": " + err.Error() + "\n" + string(msg))
				return
			}
		}
	})
	if assistantBinErr != nil {
		t.Fatal(assistantBinErr)
	}
	return filepath.Join(assistantBinDir, "sm"), filepath.Join(assistantBinDir, "claude")
}

// assistantRig is one operator: a rig daemon on a socket, a configuration file
// that names it, an MCP client called "assistant" whose token is a file, and a
// fake claude on PATH steered through script.json in its configuration directory.
type assistantRig struct {
	t         *testing.T
	rig       *mcpRig
	sm        string
	home      string
	configDir string // CLAUDE_CONFIG_DIR: the fake's script, record and logs
	configYML string
	env       []string
}

func newAssistantRig(t *testing.T) *assistantRig {
	t.Helper()
	sm, claudeDir := assistantBinaries(t)
	rig := newMCPRigGranting(t, true, "")
	home, err := filepath.EvalSymlinks(t.TempDir())
	mcpRigMust(t, err)
	a := &assistantRig{t: t, rig: rig, sm: sm, home: home, configDir: filepath.Join(home, "claude-config")}
	mcpRigMust(t, os.MkdirAll(a.configDir, 0o700))

	a.registerAssistantClient()
	a.writeConfig(a.socketPath())
	a.writeToken(filepath.Join(home, "xdg", "supermgmt", "assistant.token"))
	a.env = []string{
		"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "xdg"), "PATH=" + claudeDir,
		"CLAUDE_CONFIG_DIR=" + a.configDir, "SUPERMGMT_NO_AUTOSTART=1",
		"USER=op", "LANG=en_US.UTF-8", "TERM=xterm",
	}
	return a
}

// registerAssistantClient makes the rig's MCP client the active "assistant"
// client: its identity is the actor of every job the model's token submits.
func (a *assistantRig) registerAssistantClient() {
	a.rig.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE mcp_clients SET name = 'assistant', state = 'active', over_https = 0 WHERE id = ?`,
			a.rig.mcp.Credential.ID)
		return err
	})
}

// socketPath is where the rig's API listens: the address a dial reports.
func (a *assistantRig) socketPath() string {
	conn, err := a.rig.socket.Transport.(*http.Transport).DialContext(context.Background(), "unix", "")
	mcpRigMust(a.t, err)
	defer func() { _ = conn.Close() }()
	return conn.RemoteAddr().String()
}

func (a *assistantRig) writeConfig(socket string) {
	a.t.Helper()
	a.configYML = filepath.Join(a.home, "xdg", "supermgmt", "config.yaml")
	mcpRigMust(a.t, os.MkdirAll(filepath.Dir(a.configYML), 0o700))
	body := "version: 1\ninstance:\n  name: assistant-it\n  mode: local\n  data_dir: " + filepath.Join(a.home, "data") +
		"\ndaemon:\n  socket: " + socket + "\n"
	mcpRigMust(a.t, os.WriteFile(a.configYML, []byte(body), 0o600))
}

func (a *assistantRig) writeToken(path string) {
	a.t.Helper()
	mcpRigMust(a.t, os.MkdirAll(filepath.Dir(path), 0o700))
	mcpRigMust(a.t, os.WriteFile(path, []byte(mcpRigToken+"\n"), 0o600))
}

// script tells the fake claude what to do.
type script struct {
	Mode       string         `json:"mode"`
	Fixture    string         `json:"fixture,omitempty"`
	ExitCode   int            `json:"exit_code,omitempty"`
	Stderr     string         `json:"stderr,omitempty"`
	Tool       string         `json:"tool,omitempty"`
	Args       map[string]any `json:"args,omitempty"`
	OwnJob     string         `json:"own_job,omitempty"`
	ForeignJob string         `json:"foreign_job,omitempty"`
}

func (a *assistantRig) script(s script) {
	a.t.Helper()
	raw, err := json.Marshal(s)
	mcpRigMust(a.t, err)
	mcpRigMust(a.t, os.WriteFile(filepath.Join(a.configDir, "script.json"), raw, 0o600))
}

func (a *assistantRig) replay(fixture string) {
	a.t.Helper()
	path, err := filepath.Abs(filepath.Join(repoRoot(a.t), "test", "fixtures", "claude-stream", "2.1.311", fixture))
	mcpRigMust(a.t, err)
	a.script(script{Mode: "replay", Fixture: path})
}

// fakeRecord is what the fake claude wrote about its own launch.
type fakeRecord struct {
	PID       int      `json:"pid"`
	Argv      []string `json:"argv"`
	Env       []string `json:"env"`
	Cwd       string   `json:"cwd"`
	MCPConfig string   `json:"mcp_config"`
	MCPMode   string   `json:"mcp_config_mode"`
}

func (a *assistantRig) record() fakeRecord {
	a.t.Helper()
	raw, err := os.ReadFile(filepath.Join(a.configDir, "record.json"))
	mcpRigMust(a.t, err)
	var rec fakeRecord
	mcpRigMust(a.t, json.Unmarshal(raw, &rec))
	return rec
}

func (a *assistantRig) launched() bool {
	_, err := os.Stat(filepath.Join(a.configDir, "record.json"))
	return err == nil
}

func (a *assistantRig) stdinLog() []string {
	raw, _ := os.ReadFile(filepath.Join(a.configDir, "stdin.log"))
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func (a *assistantRig) sawEOF() bool {
	_, err := os.Stat(filepath.Join(a.configDir, "eof"))
	return err == nil
}

// poisoned is an operator environment full of what must never reach the model.
func poisonedEnv(extra ...string) []string {
	return append([]string{
		"SUPERMGMT_TOKEN=smm_human-token-SENTINEL", "SUPERMGMT_CONFIG_DIR=/poison/config", "SUPERMGMT_PROFILE=poison",
		"SSH_AUTH_SOCK=/poison/agent.sock", "GITHUB_TOKEN=ghp_SENTINEL", "AWS_SECRET_ACCESS_KEY=aws-SENTINEL",
		"NODE_OPTIONS=--require=/poison/x.js", "LD_PRELOAD=/poison/x.so", "OPENAI_API_KEY=sk-openai-SENTINEL",
		"ANTHROPIC_AUTH_TOKEN=claude-auth-SENTINEL", "CLAUDE_CODE_OAUTH_TOKEN=claude-oauth-SENTINEL",
	}, extra...)
}

type assistantRun struct {
	stdout, stderr string
	exit           int
}

// runAssistant runs `sm assistant` with stdin as the operator's typing.
func (a *assistantRig) runAssistant(env []string, dir, stdin string, args ...string) assistantRun {
	a.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), assistantTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.sm, append([]string{"assistant"}, args...)...)
	cmd.Dir, cmd.Env = dir, env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	run := assistantRun{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		run.exit = exitErr.ExitCode()
	case err != nil:
		a.t.Fatalf("run sm assistant: %v", err)
	}
	return run
}

func (r assistantRun) all() string { return r.stdout + r.stderr }

func processGone(pid int) bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }

func requireAbsent(t *testing.T, what, haystack string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(haystack, secret) {
			t.Errorf("%s holds %q", what, secret)
		}
	}
}

// ---- terminal -------------------------------------------------------------------

// terminal runs sm under a pseudo-terminal, so that it believes an operator is
// there to be asked.
type terminal struct {
	t    *testing.T
	ptmx *os.File
	cmd  *exec.Cmd
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan error
}

func (a *assistantRig) terminal(env []string, args ...string) *terminal {
	a.t.Helper()
	cmd := exec.CommandContext(context.Background(), a.sm, append([]string{"assistant"}, args...)...)
	cmd.Dir, cmd.Env = a.home, env
	ptmx, err := pty.Start(cmd)
	mcpRigMust(a.t, err)
	x := &terminal{t: a.t, ptmx: ptmx, cmd: cmd, done: make(chan error, 1)}
	go func() {
		chunk := make([]byte, 4096)
		for {
			n, err := ptmx.Read(chunk)
			x.mu.Lock()
			x.buf.Write(chunk[:n])
			x.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() { x.done <- cmd.Wait() }()
	a.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = ptmx.Close()
	})
	return x
}

func (x *terminal) output() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return strings.ReplaceAll(x.buf.String(), "\r", "")
}

func (x *terminal) waitFor(substr string) string {
	x.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), assistantTimeout)
	defer cancel()
	for ctx.Err() == nil {
		if out := x.output(); strings.Contains(out, substr) {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
	x.t.Fatalf("timed out waiting for %q; output so far:\n%s", substr, x.output())
	return ""
}

func (x *terminal) typeLine(line string) {
	x.t.Helper()
	_, err := x.ptmx.WriteString(line + "\n")
	mcpRigMust(x.t, err)
}

// finish waits for sm to exit and returns everything it printed.
func (x *terminal) finish() string {
	x.t.Helper()
	select {
	case err := <-x.done:
		x.t.Logf("sm exited: %v", err)
	case <-time.After(assistantTimeout):
		x.t.Fatalf("sm did not exit; output:\n%s", x.output())
	}
	time.Sleep(50 * time.Millisecond)
	return x.output()
}

// ---- jobs -----------------------------------------------------------------------

func (a *assistantRig) pendingJobs(actor domain.ID) (ids, hashes []string) {
	a.t.Helper()
	rows, err := a.rig.db.Reader().QueryContext(context.Background(),
		`SELECT id, plan_hash FROM jobs WHERE actor_id = ? AND state = 'awaiting_approval' ORDER BY created_at, id`, actor)
	mcpRigMust(a.t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, hash string
		mcpRigMust(a.t, rows.Scan(&id, &hash))
		ids, hashes = append(ids, id), append(hashes, hash)
	}
	mcpRigMust(a.t, rows.Err())
	return ids, hashes
}

type decision struct{ approver, hash, verdict string }

func (a *assistantRig) decisions(job string) []decision {
	a.t.Helper()
	rows, err := a.rig.db.Reader().QueryContext(context.Background(),
		`SELECT approver_id, plan_hash, decision FROM job_approvals WHERE job_id = ?`, job)
	mcpRigMust(a.t, err)
	defer func() { _ = rows.Close() }()
	var out []decision
	for rows.Next() {
		var d decision
		mcpRigMust(a.t, rows.Scan(&d.approver, &d.hash, &d.verdict))
		out = append(out, d)
	}
	mcpRigMust(a.t, rows.Err())
	return out
}

// submitRestart plans and submits a restart of the prod service as caller; the
// job waits for approval.
func (a *assistantRig) submitRestart(caller app.Caller) string {
	a.t.Helper()
	ctx := context.Background()
	created, err := a.rig.services.Plans.Create(ctx, caller, app.PlanRequest{
		Action: "service.restart",
		Target: domain.ResourceRef{Type: domain.ResourceService, ID: domain.ID(a.rig.fixtures["prod_service"])},
	})
	mcpRigMust(a.t, err)
	sub, err := a.rig.services.Plans.Submit(ctx, caller, created.Record.ID, created.Record.PlanHash)
	mcpRigMust(a.t, err)
	if sub.Job.State != domain.JobAwaitingApproval {
		a.t.Fatalf("job %s is %s, want awaiting_approval", sub.Job.ID, sub.Job.State)
	}
	return sub.Job.ID.String()
}

// ---- scenarios ------------------------------------------------------------------

func TestAssistant_ChildGetsOnlyTheLockedDownLaunch(t *testing.T) {
	for _, mode := range []string{"subscription", "api-key"} {
		t.Run(mode, func(t *testing.T) {
			a := newAssistantRig(t)
			a.replay("tool-call.jsonl")
			env := append(slices.Clone(a.env), poisonedEnv(
				"ANTHROPIC_API_KEY="+assistantKeySent, "SUPERMGMT_NO_AUTOSTART=1")...)

			run := a.runAssistant(env, repoRoot(t), "hello\n", "--auth", mode)

			if run.exit != 0 || !strings.Contains(run.stdout, "| done") {
				t.Fatalf("exit %d, want a finished turn\n%s", run.exit, run.all())
			}
			rec := a.record()
			argv := strings.Join(rec.Argv[1:], "\x00")
			for _, pair := range [][]string{
				{"--tools", ""},
				{"--allowedTools", "mcp__sm"},
				{"--permission-prompts", "none"},
				{"--setting-sources", ""},
				{"--input-format", "stream-json"},
				{"--output-format", "stream-json"},
			} {
				if !strings.Contains(argv, strings.Join(pair, "\x00")) {
					t.Errorf("argv lacks %v: %q", pair, rec.Argv)
				}
			}
			for _, flag := range []string{"--strict-mcp-config", "--no-session-persistence", "--disable-slash-commands", "--system-prompt"} {
				if !slices.Contains(rec.Argv, flag) {
					t.Errorf("argv lacks %s: %q", flag, rec.Argv)
				}
			}
			for _, banned := range []string{"dangerously", "--permission-mode", "--safe-mode", "--allow-dangerously-skip-permissions"} {
				if strings.Contains(argv, banned) {
					t.Errorf("argv holds %s: %q", banned, rec.Argv)
				}
			}
			if bare := slices.Contains(rec.Argv, "--bare"); bare != (mode == "api-key") {
				t.Errorf("--bare = %v in %s mode", bare, mode)
			}
			requireAbsent(t, "argv", argv, assistantKeySent, mcpRigToken, "SENTINEL")

			names := map[string]string{}
			for _, kv := range rec.Env {
				name, value, _ := strings.Cut(kv, "=")
				names[name] = value
			}
			for name := range names {
				if strings.HasPrefix(name, "SUPERMGMT_") || slices.Contains([]string{
					"SSH_AUTH_SOCK", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "NODE_OPTIONS", "LD_PRELOAD", "OPENAI_API_KEY",
					"ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
				}, name) {
					t.Errorf("%s reached the child", name)
				}
			}
			for _, name := range []string{"HOME", "PATH", "USER", "LANG", "CLAUDE_CONFIG_DIR"} {
				if names[name] == "" {
					t.Errorf("allowlisted %s did not reach the child", name)
				}
			}
			if _, has := names["ANTHROPIC_API_KEY"]; has != (mode == "api-key") {
				t.Errorf("ANTHROPIC_API_KEY present = %v in %s mode", has, mode)
			}
			if mode == "api-key" && names["ANTHROPIC_API_KEY"] != assistantKeySent {
				t.Errorf("the key reached the child as %q", names["ANTHROPIC_API_KEY"])
			}
			requireAbsent(t, "sm output", run.all(), assistantKeySent)
			requireAbsent(t, "mcp config", rec.MCPConfig, assistantKeySent, mcpRigToken)

			if !strings.HasPrefix(filepath.Base(rec.Cwd), "sm-assistant-") || rec.Cwd == repoRoot(t) {
				t.Errorf("the child ran in %q, want a private temporary directory", rec.Cwd)
			}
			if _, err := os.Stat(rec.Cwd); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the private directory outlived the session: %v", err)
			}
			if rec.MCPMode != "0600" {
				t.Errorf("mcp config mode = %s", rec.MCPMode)
			}
			if !a.sawEOF() {
				t.Error("the child was killed instead of seeing its stdin close")
			}
		})
	}
}

func TestAssistant_ASessionWithOtherToolsStopsBeforeAnyOutput(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "foreign-tool"})

	run := a.runAssistant(a.env, a.home, "hello\n")

	out := run.all()
	if strings.Contains(out, "SHOULD-NEVER-SHOW") {
		t.Errorf("model output was shown:\n%s", out)
	}
	if !strings.Contains(out, "not SuperMgmt's: Bash") {
		t.Errorf("the operator is not told why:\n%s", out)
	}
	if pid := a.record().PID; !processGone(pid) {
		t.Errorf("the child %d was not stopped", pid)
	}
	if run.exit == 0 {
		t.Error("a refused session exited 0")
	}
}

func TestAssistant_ASessionWithoutItsServerStopsBeforeAnyOutput(t *testing.T) {
	a := newAssistantRig(t)
	a.replay("not-signed-in-no-mcp.jsonl")

	run := a.runAssistant(a.env, a.home, "hello\n")

	out := run.all()
	if !strings.Contains(out, "could not start its MCP tools") || strings.Contains(out, "Not logged in") {
		t.Errorf("want the stop reason and none of the session's output:\n%s", out)
	}
	if run.exit == 0 {
		t.Error("a refused session exited 0")
	}
}

func TestAssistant_SubscriptionModeReadsNoClaudeCredentialAndPassesNoKey(t *testing.T) {
	a := newAssistantRig(t)
	a.replay("tool-call.jsonl")
	for _, path := range []string{
		filepath.Join(a.home, ".claude", ".credentials.json"), filepath.Join(a.configDir, ".credentials.json"),
	} {
		mcpRigMust(t, os.MkdirAll(filepath.Dir(path), 0o700))
		mcpRigMust(t, os.WriteFile(path, []byte(`{"claudeAiOauth":{"accessToken":"`+assistantCredSen+`"}}`), 0o600))
	}
	env := append(slices.Clone(a.env), "ANTHROPIC_API_KEY="+assistantKeySent, "ANTHROPIC_AUTH_TOKEN=claude-auth-SENTINEL")

	run := a.runAssistant(env, a.home, "hello\n")

	rec := a.record()
	seen := strings.Join(rec.Argv, " ") + strings.Join(rec.Env, " ") + rec.MCPConfig + run.all()
	requireAbsent(t, "what sm gave the child or printed", seen, assistantCredSen, assistantKeySent, "claude-auth-SENTINEL", "ANTHROPIC_API_KEY")
}

func TestAssistant_ANotSignedInClaudeEndsWithOneFixedLineAndFails(t *testing.T) {
	a := newAssistantRig(t)
	fixture := filepath.Join(a.configDir, "signed-out.jsonl")
	lines := []string{
		`{"type":"system","subtype":"init","tools":["mcp__sm__infra_ping"],"mcp_servers":[{"name":"sm","status":"connected"}]}`,
		`{"type":"assistant","error":"authentication_failed","message":{"role":"assistant","content":[{"type":"text","text":"Not logged in \u00b7 Please run /login"}]}}`,
		`{"type":"result","subtype":"success","is_error":true,"result":"Not logged in \u00b7 Please run /login"}`,
	}
	mcpRigMust(t, os.WriteFile(fixture, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	a.script(script{Mode: "replay", Fixture: fixture})

	run := a.runAssistant(a.env, a.home, "hello\n")

	if got := strings.Count(run.stdout, assistant.ErrNotSignedIn.Error()); got != 1 {
		t.Errorf("the sign-in line was printed %d times, want once:\n%s", got, run.all())
	}
	if strings.Contains(run.stdout, "/login") || run.exit == 0 {
		t.Errorf("exit %d; claude's own /login hint must not be shown:\n%s", run.exit, run.all())
	}
}

func TestAssistant_AClaudeThatDiesAtLaunchShowsItsReasonAndFails(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "launch-exit", ExitCode: 2, Stderr: "error: unknown option '--permission-prompts'\n"})

	run := a.runAssistant(a.env, a.home, "hello\n")

	if !strings.Contains(run.stdout, "unknown option") || strings.Contains(run.stdout, "broken pipe") || run.exit == 0 {
		t.Errorf("exit %d; the operator must read claude's reason, not a write error:\n%s", run.exit, run.all())
	}
}

func TestAssistant_APIKeyModeWithoutTheKeyRefusesAndNeverLaunches(t *testing.T) {
	for name, extra := range map[string][]string{"unset": nil, "empty": {"ANTHROPIC_API_KEY="}} {
		t.Run(name, func(t *testing.T) {
			a := newAssistantRig(t)
			a.replay("tool-call.jsonl")

			run := a.runAssistant(append(slices.Clone(a.env), extra...), a.home, "hello\n", "--auth", "api-key")

			if run.exit == 0 || !strings.Contains(run.stderr, "ANTHROPIC_API_KEY") {
				t.Errorf("exit %d, want a refusal naming ANTHROPIC_API_KEY\n%s", run.exit, run.all())
			}
			if a.launched() {
				t.Error("claude was launched without a key")
			}
		})
	}
}

func TestAssistant_WithoutARegisteredClientItPrintsTheCommandAndNeverLaunches(t *testing.T) {
	a := newAssistantRig(t)
	a.replay("tool-call.jsonl")

	run := a.runAssistant(a.env, a.home, "hello\n", "--client", "ghost")

	token := filepath.Join(a.home, "xdg", "supermgmt", "assistant-c-ghost.token")
	for _, want := range []string{"sm mcp clients add ghost --token-file " + token, "approval may be needed"} {
		if !strings.Contains(run.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, run.stderr)
		}
	}
	if run.exit == 0 || a.launched() {
		t.Errorf("exit %d, launched %v; want a refusal before the model starts", run.exit, a.launched())
	}
}

func TestAssistant_TheMCPConfigNamesTheTargetTheOperatorIsConnectedTo(t *testing.T) {
	poison := poisonedEnv()
	t.Run("an active profile wins over SUPERMGMT_* in the environment", func(t *testing.T) {
		a := newAssistantRig(t)
		a.script(script{Mode: "probe", Tool: "infra_list_nodes"})
		env := append(slices.Clone(a.env), poison...)
		if res := runSMIn(t, a.sm, a.home, env, "profile", "add", "rig", "--local", "--config-file", a.configYML, "--use"); res.exit != 0 {
			t.Fatalf("profile add: %s%s", res.stdout, res.stderr)
		}

		run := a.runAssistant(env, a.home, "list my nodes\n")

		cfg := a.record().MCPConfig
		if !strings.Contains(cfg, `"--profile","rig"`) || strings.Contains(cfg, "/poison") {
			t.Errorf("mcp config = %s", cfg)
		}
		// The model's real tools, launched from that config with the child's filtered
		// environment, read the same daemon as the card would.
		if !strings.Contains(run.stdout, "dev-1") {
			t.Errorf("the model's tools did not read the operator's daemon:\n%s", run.all())
		}
	})

	t.Run("without a profile the absolute configuration path is spelled out", func(t *testing.T) {
		a := newAssistantRig(t)
		a.script(script{Mode: "probe", Tool: "infra_list_nodes"})
		env := append(slices.Clone(a.env), poison...)

		run := a.runAssistant(env, filepath.Dir(a.configYML), "list my nodes\n", "--config", filepath.Base(a.configYML))

		cfg := a.record().MCPConfig
		if !strings.Contains(cfg, `"--config","`+a.configYML+`"`) || strings.Contains(cfg, "/poison") {
			t.Errorf("mcp config = %s", cfg)
		}
		if !strings.Contains(run.stdout, "dev-1") {
			t.Errorf("the model's tools did not read the operator's daemon:\n%s", run.all())
		}
	})
}

func TestAssistant_EndOfInputClosesTheChild(t *testing.T) {
	a := newAssistantRig(t)
	a.replay("tool-call.jsonl")

	run := a.runAssistant(a.env, a.home, "hello\n")

	if run.exit != 0 || !a.sawEOF() || !processGone(a.record().PID) {
		t.Errorf("exit %d, eof seen %v, child gone %v", run.exit, a.sawEOF(), processGone(a.record().PID))
	}
}

func TestAssistant_CtrlCStopsAStalledChild(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "stall"})
	ctx, cancel := context.WithTimeout(context.Background(), assistantTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.sm, "assistant")
	cmd.Dir, cmd.Env = a.home, a.env
	stdin, err := cmd.StdinPipe()
	mcpRigMust(t, err)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	mcpRigMust(t, cmd.Start())
	_, err = stdin.Write([]byte("hello\n"))
	mcpRigMust(t, err)
	assistantWaitUntil(t, "the child to receive the message", func() bool { return len(a.stdinLog()) > 0 })

	mcpRigMust(t, cmd.Process.Signal(os.Interrupt))
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		t.Logf("sm exited: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatalf("sm did not stop on Ctrl-C:\n%s", out.String())
	}

	if pid := a.record().PID; !processGone(pid) {
		t.Errorf("the stalled child %d outlived sm", pid)
	}
}

func TestAssistant_TheCardComesFromTheJobAndApprovalUsesTheAPIsHash(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "probe", Tool: "infra_restart_service", Args: map[string]any{"ref": "api@web-1"}})
	term := a.terminal(a.env)

	term.typeLine("restart the api")
	card := term.waitFor("approve, reject or leave pending?")

	ids, hashes := a.pendingJobs(a.rig.mcp.ID)
	if len(ids) != 1 {
		t.Fatalf("the model's real token submitted %d pending jobs, want 1", len(ids))
	}
	for _, want := range []string{
		"=== approval requested by the assistant ===", "assistant (MCP client)", ids[0], hashes[0], "service.restart", "api@web-1 (" + a.rig.fixtures["prod_service"] + ")", "the local daemon",
	} {
		if !strings.Contains(card, want) {
			t.Errorf("card lacks %q:\n%s", want, card)
		}
	}

	term.typeLine("approve")
	// The rig's policy asks for two approvers: one approval is recorded, and both the
	// operator and the model are told it is not yet a go.
	term.waitFor("ack: [sm] job " + ids[0] + ": the operator's approval was recorded (1/2)")
	term.typeLine("/exit")
	term.finish()

	got := a.decisions(ids[0])
	if len(got) != 1 || got[0].approver != a.rig.admin.ID.String() || got[0].hash != hashes[0] || got[0].verdict != "approve" {
		t.Errorf("decisions = %+v, want one approval by the human with the API's hash %s", got, hashes[0])
	}
}

func TestAssistant_RejectingCarriesTheReasonToTheModel(t *testing.T) {
	a := newAssistantRig(t)
	a.script(script{Mode: "probe", Tool: "infra_restart_service", Args: map[string]any{"ref": "api@web-1"}})
	term := a.terminal(a.env)

	term.typeLine("restart the api")
	term.waitFor("approve, reject or leave pending?")
	term.typeLine("reject")
	term.waitFor("reason (required): ")
	term.typeLine("not during the sale")
	term.waitFor("rejected by the operator: not during the sale")
	term.typeLine("/exit")
	term.finish()

	ids, _ := a.pendingJobs(a.rig.mcp.ID)
	if len(ids) != 0 {
		t.Errorf("jobs still waiting after a rejection: %v", ids)
	}
}

func TestAssistant_AHostileModelOpensNoCardAndItsTextIsSanitised(t *testing.T) {
	a := newAssistantRig(t)
	own := a.submitRestart(a.rig.mcp)
	foreign := a.submitRestart(a.rig.admin)
	a.script(script{Mode: "hostile", OwnJob: own, ForeignJob: foreign})
	term := a.terminal(a.env)

	term.typeLine("do the thing")
	term.waitFor("which is not a job of the assistant client waiting for approval")
	term.typeLine("/exit")
	out := term.finish()

	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("control characters reached the terminal: %q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		forgery := strings.Contains(line, "=== approval requested") || strings.Contains(line, "approve, reject or leave pending")
		if forgery && !strings.Contains(line, "| ") {
			t.Errorf("model text can pass for ours: %q", line)
		}
	}
	if strings.Contains(out, "\n=== approval requested") {
		t.Errorf("a card was opened:\n%s", out)
	}
	if !strings.Contains(out, "| =") && !strings.Contains(out, "| === approval requested by the assistant ===") {
		t.Errorf("the forged card is not shown as model text:\n%s", out)
	}
	if lines := a.stdinLog(); len(lines) != 1 {
		t.Errorf("the model was sent %d messages, want only the operator's own (no outcome for a job that is not the assistant's)", len(lines))
	}
	for _, job := range []string{own, foreign} {
		if got := a.decisions(job); len(got) != 0 {
			t.Errorf("job %s was decided: %+v", job, got)
		}
	}
}

// ---- helpers --------------------------------------------------------------------

func runSMIn(t *testing.T, sm, dir string, env []string, args ...string) result {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), sm, args...)
	cmd.Dir, cmd.Env = dir, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := result{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		res.exit = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("run sm %v: %v", args, err)
	}
	return res
}

func assistantWaitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), assistantTimeout)
	defer cancel()
	for ctx.Err() == nil {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
