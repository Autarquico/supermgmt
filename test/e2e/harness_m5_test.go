//go:build e2e && fixtures

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/e2e/harness"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// The M5 world: `sm daemon` in local mode on the test machine, one production node (the fixture)
// described by the static configuration, and an MCP client that reaches the daemon through the
// `sm mcp` stdio bridge exactly as an MCP host would launch it. Policy is the built-in one plus
// a rule that lets MCP clients restart services (which production gates behind approval) and read
// logs, and one that tries to let them approve (which governance refuses whatever the policy says).
const (
	m5NodeName    = "m5-node"
	m5EnvName     = "production"
	m5DemoUnit    = "sm-demo.service"
	m5LeakUnit    = "sm-leak.service"
	m5LeakSecret  = "m5-planted-bearer-Qw7Zk2mX9p"
	m5JobTimeout  = 4 * time.Minute
	m5DaemonStart = 30 * time.Second
)

const m5PolicyExtras = `  - name: e2e-mcp-operate
    subjects: ["type:mcp"]
    allow: ["service.restart", "service.logs"]
  - name: e2e-mcp-tries-to-approve
    subjects: ["type:mcp"]
    allow: ["approval.grant", "approval.reject", "job.resolve"]
`

type m5World struct {
	t          *testing.T
	dir        string
	bin        string
	env        []string
	configFile string
	socket     string
	dataDir    string
	laptop     *harness.Client
	human      *client.Client
	daemon     *harness.Proc
	node       *m4Node
	nodeRec    wire.Node
}

// newM5LocalWorld starts the daemon. With a node, the fixture is started, set up with grants for
// the demo and leak units, and probed until its services are listed.
func newM5LocalWorld(t *testing.T, withNode bool) *m5World {
	t.Helper()
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "sm-m5-") // short: Unix socket paths are limited to ~100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	w := &m5World{
		t: t, dir: dir, bin: harness.HostSM(t),
		socket: filepath.Join(dir, "d.sock"), dataDir: filepath.Join(dir, "data"),
		laptop: harness.NewClient(t),
	}
	w.env = m5BridgeEnv(t)
	w.human = client.New(client.Options{Socket: w.socket})

	config := fmt.Sprintf("version: 1\ninstance:\n  mode: local\n  data_dir: %s\ndaemon:\n  socket: %s\n", w.dataDir, w.socket)
	config += "security:\n  policy_file: " + w.writePolicy() + "\nmcp:\n  write_tools_enabled: true\n"
	if withNode {
		w.node = w.startNode(t)
		config += fmt.Sprintf("environments:\n  - name: %s\n    risk_level: production\nproviders:\n  - type: ssh\n    name: %s\n%s    admin_credential_ref: file://%s\n    environment: %s\n",
			m5EnvName, m5NodeName, w.node.sshEndpoint(w.node.fx.Host, w.node.fx.Port), w.node.adminKey, m5EnvName)
	}
	w.configFile = harness.WriteHostFile(t, dir, "config.yaml", []byte(config), 0o600)
	w.daemon = w.laptop.Start(ctx, "", "daemon", "--config", w.configFile)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", w.daemon.Stderr())
		}
	})
	waitForLocalDaemon(t, ctx, w.laptop, w.configFile)
	if withNode {
		w.nodeRec = w.prepareNode()
	}
	return w
}

// m5BridgeEnv is the environment of `sm mcp` as an MCP host would start it: a home of its own and
// no OS credential tool, so the token can only come from a file.
func m5BridgeEnv(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	empty := filepath.Join(home, "empty-path")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{
		"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"XDG_STATE_HOME=" + filepath.Join(home, "state"), "XDG_RUNTIME_DIR=" + home,
		"PATH=" + empty, "SUPERMGMT_NO_AUTOSTART=1", "NO_COLOR=1",
	}
}

func (w *m5World) writePolicy() string {
	w.t.Helper()
	base, err := os.ReadFile(filepath.Join(harness.RepoRoot(), "internal", "policy", "default.yaml"))
	if err != nil {
		w.t.Fatal(err)
	}
	text := strings.TrimRight(string(base), "\n") + "\n" + m5PolicyExtras
	return harness.WriteHostFile(w.t, w.dir, "policy.yaml", []byte(text), 0o600)
}

// startNode starts the fixture and a transient unit whose log carries a bearer credential.
func (w *m5World) startNode(t *testing.T) *m4Node {
	t.Helper()
	ctx := context.Background()
	if err := fixture.Build(ctx); err != nil {
		t.Fatal(err)
	}
	fx, err := fixture.Start(ctx, fixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fx.Stop(context.WithoutCancel(ctx)) })
	node := &m4Node{fx: fx, c: harness.Adopt(t, fx.Name)}
	node.hostKeyPin = m5HostKeyPin(fx)
	node.adminKey = node.authorizeAdminKey(t)
	// The product refuses a unit whose command is an interpreter with inline code, so the log line
	// comes from a script file.
	script := fmt.Sprintf("#!/bin/sh\necho \"Authorization: Bearer %s\"\nexec sleep 3600\n", m5LeakSecret)
	node.c.WriteFile(ctx, "/usr/local/bin/sm-leak.sh", []byte(script), "0755")
	node.c.MustExec(ctx, "systemd-run", "--unit=sm-leak", "--quiet", "/usr/local/bin/sm-leak.sh")
	return node
}

func m5HostKeyPin(fx *fixture.Node) string {
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(fx.HostKey)))
}

// prepareNode waits for the static node, probes it, sets it up with grants for both units
// (approving as the human, which local mode allows) and probes again.
func (w *m5World) prepareNode() wire.Node {
	w.t.Helper()
	node := w.waitForNode()
	w.settle(w.probeJob(node.ID))
	plan, err := w.human.CreatePlan(w.ctx(), wire.CreatePlanRequest{
		Action:  "node.setup",
		Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: node.ID}},
		Parameters: map[string]any{
			"docker_access": "false", "logs_mode": "journal-group", "grants": m5Grants(m5DemoUnit, m5LeakUnit),
		},
	})
	if err != nil {
		w.t.Fatalf("plan node.setup: %v", err)
	}
	submitted, err := w.human.SubmitPlan(w.ctx(), plan.PlanID, plan.PlanHash)
	if err != nil {
		w.t.Fatalf("submit node.setup: %v", err)
	}
	w.settle(jobOf(w.t, submitted))
	w.settle(w.probeJob(node.ID))
	return node
}

func m5Grants(units ...string) []string {
	var grants []string
	for _, unit := range units {
		for _, verb := range domain.AllServiceVerbs() {
			grants = append(grants, string(verb)+" "+unit)
		}
	}
	return grants
}

func (w *m5World) ctx() context.Context { return context.Background() }

func (w *m5World) waitForNode() wire.Node {
	w.t.Helper()
	deadline := harness.Now().Add(time.Minute)
	for harness.Now().Before(deadline) {
		page, err := w.human.ListNodes(w.ctx(), wire.NodeQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit}})
		if err != nil {
			w.t.Fatal(err)
		}
		for _, n := range page.Items {
			if n.Name == m5NodeName {
				return n
			}
		}
		time.Sleep(time.Second)
	}
	w.t.Fatalf("the static configuration did not produce node %s", m5NodeName)
	return wire.Node{}
}

func (w *m5World) probeJob(node domain.ID) domain.ID {
	w.t.Helper()
	probe, err := w.human.ProbeNode(w.ctx(), node)
	if err != nil {
		w.t.Fatalf("probe the node: %v", err)
	}
	return jobOf(w.t, probe)
}

// settle approves the job when it waits for approval and returns once it has succeeded.
func (w *m5World) settle(id domain.ID) {
	w.t.Helper()
	w.waitJobState(id, m5JobTimeout, domain.JobSucceeded, true)
}

// waitJobState polls until the job is in want. When approve is set it approves the job whenever
// it waits for approval; any other terminal state fails the test.
func (w *m5World) waitJobState(id domain.ID, timeout time.Duration, want domain.JobState, approve bool) wire.JobDetail {
	w.t.Helper()
	deadline := harness.Now().Add(timeout)
	var last wire.JobDetail
	for harness.Now().Before(deadline) {
		job, err := w.human.GetJob(w.ctx(), id)
		if err != nil {
			w.t.Fatalf("get job %s: %v", id, err)
		}
		last = job
		switch {
		case job.Job.State == want:
			return job
		case job.Job.State == domain.JobAwaitingApproval && approve:
			harness.ApproveJob(w.ctx(), w.t, w.human, id)
		case job.Job.State.Terminal():
			w.t.Fatalf("job %s ended %s (want %s): %+v", id, job.Job.State, want, job.Job.Error)
		}
		time.Sleep(time.Second)
	}
	w.t.Fatalf("job %s still %s after %s (want %s)", id, last.Job.State, timeout, want)
	return last
}

// ---- MCP clients -------------------------------------------------------------------------------

var approveHint = regexp.MustCompile(`sm approvals approve (\S+)`)

// addMCPClient runs `sm mcp clients add` the way a person does: when registration waits for
// approval, approve the job it names and run the command again. It returns the token file.
func (w *m5World) addMCPClient(name string) string {
	w.t.Helper()
	tokenFile := filepath.Join(w.dir, name+".token")
	args := []string{"mcp", "clients", "add", name, "--token-file", tokenFile, "--config", w.configFile}
	res := w.laptop.Must(w.ctx(), "", args...)
	if m := approveHint.FindStringSubmatch(res.Stdout); m != nil {
		w.settle(domain.ID(m[1]))
		res = w.laptop.Must(w.ctx(), "", args...)
	}
	w.requireStored(tokenFile, res)
	return tokenFile
}

func (w *m5World) requireStored(tokenFile string, res harness.Result) {
	w.t.Helper()
	info, err := os.Stat(tokenFile)
	if err != nil {
		w.t.Fatalf("no token file after `sm mcp clients add`: %v\n%s", err, res.Output())
	}
	if info.Mode().Perm() != 0o600 {
		w.t.Fatalf("token file mode = %o, want 600", info.Mode().Perm())
	}
}

func (w *m5World) readToken(tokenFile string) string {
	w.t.Helper()
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		w.t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// mcpAPI is an API client that presents the MCP client's token on the daemon socket.
func (w *m5World) mcpAPI(token string) *client.Client {
	return client.New(client.Options{Socket: w.socket, Token: audit.Secret(token)})
}

// bridge launches `sm mcp` as an MCP host would and connects the SDK client to it.
func (w *m5World) bridge(tokenFile string) (*sdk.ClientSession, *lockedBuffer) {
	w.t.Helper()
	stderr := &lockedBuffer{}
	cmd := exec.CommandContext(w.ctx(), w.bin, "mcp", "--token-file", tokenFile, "--config", w.configFile)
	cmd.Env = w.env
	cmd.Stderr = stderr
	mcpClient := sdk.NewClient(&sdk.Implementation{Name: "sm-e2e", Version: "0"}, nil)
	session, err := mcpClient.Connect(w.ctx(), &sdk.CommandTransport{Command: cmd}, nil)
	if err != nil {
		w.t.Fatalf("connect to `sm mcp`: %v\nstderr:\n%s", err, stderr.String())
	}
	w.t.Cleanup(func() { _ = session.Close() })
	return session, stderr
}

// lockedBuffer collects a child's stderr while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// mcpOutputs records every byte an MCP session returned, for the secret-leak scan.
type mcpOutputs struct{ text []byte }

// m5Call calls a tool, decodes its structured result into out (when given) and records the raw
// result in outputs. A tool error is returned as the text the model would read.
func m5Call(t *testing.T, outputs *mcpOutputs, session *sdk.ClientSession, tool string, args map[string]any, out any) (toolError string) {
	t.Helper()
	res, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", tool, err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	outputs.text = append(outputs.text, raw...)
	if res.IsError {
		return string(raw)
	}
	if out != nil {
		structured, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(structured, out); err != nil {
			t.Fatalf("decode %s result %s: %v", tool, structured, err)
		}
	}
	return ""
}

func m5ToolNames(t *testing.T, session *sdk.ClientSession) []string {
	t.Helper()
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := make([]string, len(listed.Tools))
	for i, tool := range listed.Tools {
		names[i] = tool.Name
	}
	return names
}

// m5DataFiles is every file of the daemon's data directory, keyed by path.
func (w *m5World) dataFiles() map[string][]byte {
	w.t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(w.dataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&os.ModeSocket != 0 {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil // a sqlite journal that vanished between listing and reading
		}
		files["data file "+strings.TrimPrefix(path, w.dataDir)] = raw
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return files
}
