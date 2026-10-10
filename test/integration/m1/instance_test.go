// Package m1 holds the milestone-1 acceptance scenarios (docs/specs/m1-local-ssh-tui.md)
// and the security end-to-end tests. Every test drives the real built `sm daemon`
// subprocess over its Unix socket with the typed client, against Docker node
// fixtures (test/fixtures/node, -tags fixtures) where a node is needed, the way
// an operator's TUI or CLI would.
package m1

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const pollEvery = 250 * time.Millisecond

var (
	buildSMOnce sync.Once
	smPath      string
	buildSMErr  error
)

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// smBinary builds the real `sm` once per test run.
func smBinary(t *testing.T) string {
	t.Helper()
	buildSMOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sm-m1-bin")
		if err != nil {
			buildSMErr = err
			return
		}
		smPath = filepath.Join(dir, "sm")
		build := exec.CommandContext(context.Background(), "go", "build", "-o", smPath, "./cmd/sm")
		build.Dir = repoRoot()
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			buildSMErr = fmt.Errorf("go build ./cmd/sm: %w\n%s", err, out)
		}
	})
	if buildSMErr != nil {
		t.Fatal(buildSMErr)
	}
	return smPath
}

// ---- the operator's ssh-agent ---------------------------------------------------

// keyring is an in-memory ssh-agent that can gain signers while the daemon
// runs: it authenticates admin_user on every fixture (ADR-0009 b).
type keyring struct {
	mu      sync.Mutex
	signers []cryptossh.Signer
}

var _ agent.Agent = (*keyring)(nil)

func (k *keyring) hold(s cryptossh.Signer) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.signers = append(k.signers, s)
}

func (k *keyring) List() ([]*agent.Key, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	keys := make([]*agent.Key, 0, len(k.signers))
	for _, s := range k.signers {
		keys = append(keys, &agent.Key{Format: s.PublicKey().Type(), Blob: s.PublicKey().Marshal()})
	}
	return keys, nil
}

func (k *keyring) Sign(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, s := range k.signers {
		if bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			return s.Sign(rand.Reader, data)
		}
	}
	return nil, errors.New("agent: unknown key")
}

func (k *keyring) Signers() ([]cryptossh.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]cryptossh.Signer(nil), k.signers...), nil
}

func (*keyring) Add(agent.AddedKey) error         { return errors.New("read-only agent") }
func (*keyring) Remove(cryptossh.PublicKey) error { return errors.New("read-only agent") }
func (*keyring) RemoveAll() error                 { return errors.New("read-only agent") }
func (*keyring) Lock([]byte) error                { return errors.New("read-only agent") }
func (*keyring) Unlock([]byte) error              { return errors.New("read-only agent") }

func serveAgent(t *testing.T, dir string) (socket string, ring *keyring) {
	t.Helper()
	socket = filepath.Join(dir, "a.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatalf("listen on the agent socket: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ring = &keyring{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = agent.ServeAgent(ring, c)
			}()
		}
	}()
	return socket, ring
}

// ---- the instance under test ------------------------------------------------------

// environmentSpec is an `environments:` entry of the configuration.
type environmentSpec struct {
	Name, RiskLevel string
}

// instanceOptions tune the configuration the daemon runs with.
type instanceOptions struct {
	Environments   []environmentSpec
	ReconcileGrace time.Duration
	IdleExit       time.Duration
	// FastRefresh makes the background refresher probe every few seconds.
	FastRefresh bool
}

// instance is one SuperMgmt installation: configuration, state directories and
// a daemon subprocess, all under dir.
type instance struct {
	t           *testing.T
	dir         string
	bin         string
	config      string
	socket      string
	agent       *keyring
	agentSocket string
	env         []string
	daemonLog   string
	dataDir     string // holds the database; keys and logs stay under dir

	mu  sync.Mutex
	cmd *exec.Cmd
}

func newInstance(t *testing.T, o instanceOptions) *instance {
	t.Helper()
	dir, err := os.MkdirTemp("", "smm") // short: sun_path is limited on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	agentSocket, ring := serveAgent(t, dir)
	in := &instance{
		t: t, dir: dir, bin: smBinary(t), agent: ring, agentSocket: agentSocket,
		config: filepath.Join(dir, "config.yaml"), socket: filepath.Join(dir, "d.sock"),
		daemonLog: filepath.Join(dir, "daemon.log"),
		env: []string{
			"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "SSH_AUTH_SOCK=" + agentSocket,
			"XDG_CONFIG_HOME=" + filepath.Join(dir, "cfg"), "XDG_DATA_HOME=" + filepath.Join(dir, "share"),
			"XDG_STATE_HOME=" + filepath.Join(dir, "state"), "LANG=C.UTF-8",
		},
	}
	in.writeConfig(o)
	return in
}

func (in *instance) writeConfig(o instanceOptions) {
	grace := o.ReconcileGrace
	if grace == 0 {
		grace = 30 * time.Second
	}
	idle := o.IdleExit
	if idle == 0 {
		idle = time.Hour
	}
	var b strings.Builder
	data := in.dataDir
	if data == "" {
		data = filepath.Join(in.dir, "data")
	}
	fmt.Fprintf(&b, "version: 1\ninstance:\n  name: m1-e2e\n  mode: local\n  data_dir: %s\n", data)
	fmt.Fprintf(&b, "daemon:\n  socket: %s\n  idle_exit: %s\n", in.socket, idle)
	fmt.Fprintf(&b, "storage:\n  sqlite:\n    path: %s\n", filepath.Join(data, "supermgmt.db"))
	fmt.Fprintf(&b, "security:\n  keys_dir: %s\n", filepath.Join(in.dir, "keys"))
	fmt.Fprintf(&b, "jobs:\n  reconcile_grace: %s\n", grace)
	fmt.Fprintf(&b, "ssh:\n  connect_timeout: 3s\n  command_timeout: 20s\n")
	if o.FastRefresh {
		b.WriteString("refresh:\n  focused_interval: 1s\n  inventory_interval: 3s\n  metrics_interval: 2s\n  discovery_interval: 6s\n")
	}
	environments := o.Environments
	if len(environments) == 0 {
		environments = []environmentSpec{{"staging", "staging"}, {"production", "production"}}
	}
	b.WriteString("environments:\n")
	for _, e := range environments {
		fmt.Fprintf(&b, "  - name: %s\n    risk_level: %s\n", e.Name, e.RiskLevel)
	}
	if err := os.WriteFile(in.config, []byte(b.String()), 0o600); err != nil {
		in.t.Fatal(err)
	}
}

// command is the `sm daemon` invocation, also what autostart spawns.
func (in *instance) daemonArgs() []string { return []string{"--config", in.config, "daemon"} }

// startDaemon runs `sm daemon` and waits until it answers.
func (in *instance) startDaemon() {
	in.t.Helper()
	log, err := os.OpenFile(in.daemonLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		in.t.Fatal(err)
	}
	cmd := exec.CommandContext(context.WithoutCancel(in.t.Context()), in.bin, in.daemonArgs()...) // outlives the test body: stopped by the cleanup
	cmd.Env = in.env
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		in.t.Fatalf("start sm daemon: %v", err)
	}
	_ = log.Close()
	in.mu.Lock()
	in.cmd = cmd
	in.mu.Unlock()
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	in.t.Cleanup(func() { in.stopDaemon(syscall.SIGTERM) })
	api := in.client()
	deadline := monotonicNow().Add(30 * time.Second)
	for monotonicNow().Before(deadline) {
		select {
		case <-exited:
			in.t.Fatalf("sm daemon exited early: %v\n%s", cmd.ProcessState, in.logText())
		default:
		}
		ctx, cancel := context.WithTimeout(in.t.Context(), 2*time.Second)
		_, err := api.Me(ctx)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	in.t.Fatalf("sm daemon did not answer within 30s:\n%s", in.logText())
}

// stopDaemon signals the daemon and waits for it; it is idempotent.
func (in *instance) stopDaemon(sig syscall.Signal) {
	in.mu.Lock()
	cmd := in.cmd
	in.cmd = nil
	in.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(sig)
	deadline := monotonicNow().Add(20 * time.Second)
	for monotonicNow().Before(deadline) {
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
}

// killDaemon is SIGKILL: no shutdown path runs.
func (in *instance) killDaemon() { in.stopDaemon(syscall.SIGKILL) }

func (in *instance) logText() string {
	b, _ := os.ReadFile(in.daemonLog)
	return string(b)
}

func (in *instance) client() *client.Client { return client.New(client.Options{Socket: in.socket}) }

func waitJob(t *testing.T, api *client.Client, id domain.ID, want domain.JobState, within time.Duration) wire.Job {
	t.Helper()
	deadline := monotonicNow().Add(within)
	var last wire.Job
	for monotonicNow().Before(deadline) {
		detail, err := api.GetJob(t.Context(), id)
		if err == nil {
			last = detail.Job
			if last.State == want {
				return last
			}
			if isFinal(last.State) {
				t.Fatalf("job %s ended %s (want %s): %s", id, last.State, want, describeFailure(last))
			}
		}
		time.Sleep(pollEvery)
	}
	t.Fatalf("job %s is %s after %s, want %s", id, last.State, within, want)
	return last
}

func isFinal(s domain.JobState) bool {
	return s == domain.JobSucceeded || s == domain.JobFailed || s == domain.JobCancelled
}

func describeFailure(j wire.Job) string {
	if j.Error == nil {
		return "no error recorded"
	}
	return fmt.Sprintf("%s/%s: %s", j.Error.Code, j.Error.Reason, j.Error.Message)
}

// probe runs an audited node.probe job to completion.
func codeOf(err error) smerr.Code { return smerr.CodeOf(err) }

// eventually polls cond until it holds.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := monotonicNow().Add(within)
	for monotonicNow().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(pollEvery)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// waitDiscovered waits for the background refresher's first full probe of a
// freshly added node: until then the node advertises no capability, and an
// explicit node.probe is refused with CAPABILITY_UNAVAILABLE.
func waitDiscovered(t *testing.T, api *client.Client, id domain.ID) wire.Node {
	t.Helper()
	var last wire.Node
	eventually(t, 2*time.Minute, "the first background probe of node "+string(id), func() bool {
		n, err := api.GetNode(t.Context(), id, false)
		if err != nil {
			return false
		}
		last = n
		for _, c := range n.Capabilities {
			if c.Name == "node.read" && c.Available {
				return true
			}
		}
		return false
	})
	return last
}

// monotonicNow is the one place the tests read the process clock: latency
// budgets need its monotonic reading, which a domain.Clock does not carry.
func monotonicNow() time.Time { return time.Now() } //nolint:forbidigo // see above
