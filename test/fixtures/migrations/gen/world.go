//go:build fixturegen && fixtures

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// ---- the operator's ssh-agent --------------------------------------------------------

// agentRing is an in-memory, read-only ssh-agent holding the key that authenticates admin_user on
// the fixture node (ADR-0009).
type agentRing struct {
	mu      sync.Mutex
	signers []cryptossh.Signer
}

var _ agent.Agent = (*agentRing)(nil)

func (a *agentRing) hold(s cryptossh.Signer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signers = append(a.signers, s)
}

func (a *agentRing) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := make([]*agent.Key, 0, len(a.signers))
	for _, s := range a.signers {
		keys = append(keys, &agent.Key{Format: s.PublicKey().Type(), Blob: s.PublicKey().Marshal()})
	}
	return keys, nil
}

func (a *agentRing) Sign(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.signers {
		if bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			return s.Sign(rand.Reader, data)
		}
	}
	return nil, errors.New("agent: unknown key")
}

func (a *agentRing) Signers() ([]cryptossh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]cryptossh.Signer(nil), a.signers...), nil
}

func (*agentRing) Add(agent.AddedKey) error         { return errors.New("read-only agent") }
func (*agentRing) Remove(cryptossh.PublicKey) error { return errors.New("read-only agent") }
func (*agentRing) RemoveAll() error                 { return errors.New("read-only agent") }
func (*agentRing) Lock([]byte) error                { return errors.New("read-only agent") }
func (*agentRing) Unlock([]byte) error              { return errors.New("read-only agent") }

func serveAgent(ctx context.Context, socket string, ring *agentRing) (func(), error) {
	l, err := (&net.ListenConfig{}).Listen(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen on the agent socket: %w", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = agent.ServeAgent(ring, c)
			}()
		}
	}()
	return func() { _ = l.Close() }, nil
}

// ---- one installation, as an older milestone ran it --------------------------------------

// installation is a local-mode SuperMgmt of one milestone: its configuration, state directories
// and the daemon of the milestone's own binary, all under dir.
type installation struct {
	m       milestone
	bin     string
	dir     string
	config  string
	dataDir string
	keysDir string
	backups string
	env     []string
	ring    *agentRing

	daemon     *exec.Cmd
	exited     chan struct{}
	closeAgent func()
}

func newInstallation(ctx context.Context, m milestone, bin string) (*installation, error) {
	dir, err := os.MkdirTemp("", "smg") // short: sun_path is limited on macOS
	if err != nil {
		return nil, err
	}
	in := &installation{
		m: m, bin: bin, dir: dir, config: filepath.Join(dir, "config.yaml"),
		dataDir: filepath.Join(dir, "data"), keysDir: filepath.Join(dir, "keys"), backups: filepath.Join(dir, "backups"),
		ring: &agentRing{},
	}
	agentSocket := filepath.Join(dir, "a.sock")
	if in.closeAgent, err = serveAgent(ctx, agentSocket, in.ring); err != nil {
		return nil, err
	}
	in.env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "SSH_AUTH_SOCK=" + agentSocket, "SUPERMGMT_NO_AUTOSTART=1",
		"XDG_CONFIG_HOME=" + filepath.Join(dir, "cfg"), "XDG_DATA_HOME=" + filepath.Join(dir, "share"),
		"XDG_STATE_HOME=" + filepath.Join(dir, "state"), "LANG=C.UTF-8", "NO_COLOR=1",
	}
	return in, os.WriteFile(in.config, []byte(in.configuration()), 0o600)
}

// configuration is the config.yaml every milestone accepts: local mode, two environments, short
// SSH timeouts. The backup directory exists from M2.
func (in *installation) configuration() string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: 1\ninstance:\n  name: migration-fixture\n  mode: local\n  data_dir: %s\n", in.dataDir)
	fmt.Fprintf(&b, "daemon:\n  socket: %s\n  idle_exit: 1h\n", filepath.Join(in.dir, "d.sock"))
	fmt.Fprintf(&b, "storage:\n  sqlite:\n    path: %s\n", in.databasePath())
	fmt.Fprintf(&b, "security:\n  keys_dir: %s\n", in.keysDir)
	b.WriteString("ssh:\n  connect_timeout: 3s\n  command_timeout: 20s\n")
	if in.m.number() >= 2 {
		fmt.Fprintf(&b, "backup:\n  directory: %s\n", in.backups)
	}
	b.WriteString("environments:\n  - name: staging\n    risk_level: staging\n  - name: production\n    risk_level: production\n")
	return b.String()
}

func (in *installation) databasePath() string { return filepath.Join(in.dataDir, "supermgmt.db") }

func (in *installation) start(ctx context.Context) error {
	cmd := exec.CommandContext(context.WithoutCancel(ctx), in.bin, "--config", in.config, "daemon") // stopped by stop
	cmd.Env = in.env
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the daemon: %w", err)
	}
	in.daemon, in.exited = cmd, make(chan struct{})
	go func() { _ = cmd.Wait(); close(in.exited) }()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) { //nolint:forbidigo // wall-clock wait for a subprocess
		select {
		case <-in.exited:
			return fmt.Errorf("the daemon exited early: %v\n%s", cmd.ProcessState, log.String())
		default:
		}
		if _, err := in.sm(ctx, "", "status"); err == nil {
			return nil
		}
	}
	return fmt.Errorf("the daemon did not answer within 30s\n%s", log.String())
}

// stop ends the daemon gracefully, so its write-ahead log is flushed.
func (in *installation) stop() error {
	if in.daemon == nil {
		return nil
	}
	_ = in.daemon.Process.Signal(syscall.SIGTERM)
	select {
	case <-in.exited:
	case <-time.After(30 * time.Second):
		_ = in.daemon.Process.Kill()
		<-in.exited
		return errors.New("the daemon ignored SIGTERM for 30s")
	}
	in.daemon = nil
	return nil
}

func (in *installation) close() {
	_ = in.stop()
	if in.closeAgent != nil {
		in.closeAgent()
	}
	_ = os.RemoveAll(in.dir)
}

// sm runs the milestone's own `sm` against this installation and returns its stdout.
func (in *installation) sm(ctx context.Context, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.bin, append([]string{"--config", in.config}, args...)...)
	cmd.Env = in.env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("sm %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// ---- jobs ---------------------------------------------------------------------------------

// jobView is the part of a job every milestone prints in --json.
type jobView struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	PlanHash string `json:"plan_hash"`
}

// jobIn finds the job in a submission ({"job":...}) or in a direct answer ({"pending":{"job":...}}).
// ok is false when the answer was applied at once and no job exists.
func jobIn(output string) (job jobView, ok bool, err error) {
	var answer struct {
		Job     *jobView `json:"job"`
		Pending *struct {
			Job jobView `json:"job"`
		} `json:"pending"`
	}
	if err := json.Unmarshal([]byte(output), &answer); err != nil {
		return jobView{}, false, fmt.Errorf("decode %q: %w", output, err)
	}
	switch {
	case answer.Job != nil:
		return *answer.Job, true, nil
	case answer.Pending != nil:
		return answer.Pending.Job, true, nil
	}
	return jobView{}, false, nil
}

// submitJob runs a command whose --json answer carries a job and returns it.
func (in *installation) submitJob(ctx context.Context, args ...string) (jobView, error) {
	out, err := in.sm(ctx, "", append([]string{"--json"}, args...)...)
	if err != nil {
		return jobView{}, err
	}
	job, ok, err := jobIn(out)
	if err != nil {
		return jobView{}, err
	}
	if !ok {
		return jobView{}, fmt.Errorf("sm %s answered without a job: %s", strings.Join(args, " "), out)
	}
	return job, nil
}

func (in *installation) decide(ctx context.Context, verb string, job jobView, extra ...string) error {
	args := append([]string{"jobs", verb, job.ID, "--plan-hash", job.PlanHash}, extra...)
	_, err := in.sm(ctx, "", args...)
	return err
}

func (in *installation) approve(ctx context.Context, job jobView) error {
	return in.decide(ctx, "approve", job)
}

// waitState polls a job until it is in want; any other final state is an error.
func (in *installation) waitState(ctx context.Context, job jobView, want string) error {
	final := map[string]bool{"succeeded": true, "failed": true, "cancelled": true}
	var last string
	for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) { //nolint:forbidigo // wall-clock wait for a daemon job
		out, err := in.sm(ctx, "", "--json", "jobs", "get", job.ID)
		if err != nil {
			return err
		}
		got, ok, err := jobIn(out)
		if err != nil {
			return err
		}
		if ok {
			last = got.State
		}
		if last == want {
			return nil
		}
		if final[last] {
			return fmt.Errorf("job %s ended %s, want %s", job.ID, last, want)
		}
	}
	return fmt.Errorf("job %s still %q after 3m, want %s", job.ID, last, want)
}

// settle approves the job of a command that may have been applied at once, and waits for it.
func (in *installation) settle(ctx context.Context, output string) error {
	job, ok, err := jobIn(output)
	if err != nil || !ok {
		return err
	}
	if job.State == "awaiting_approval" {
		if err := in.approve(ctx, job); err != nil {
			return err
		}
	}
	return in.waitState(ctx, job, "succeeded")
}

// ---- the scripted world -----------------------------------------------------------------

// world is what the scripted steps share: the installation, the fixture node and the transcript.
type world struct {
	in         *installation
	node       *fixture.Node
	transcript []string
}

const nodeName = "fixture-1"

// step is one scripted action. since is the first milestone whose `sm` has the commands it uses.
type step struct {
	since int
	text  string
	run   func(context.Context, *world) error
}

// steps is the world of ADR-0035: configuration (the installation's config.yaml), secrets, an SSH
// node through the fixture container, jobs in every terminal state (succeeded, failed, cancelled),
// events (written by the daemon for each of these), and from M2 a token and a backup, from M4 an
// app, from M5 a local MCP client. The backup comes last so the archive holds the whole world.
func steps() []step {
	return []step{
		{2, "import the secrets app/credential and app/api-token (approved) and app/parked (left awaiting approval)", importSecrets},
		{1, "add the SSH node fixture-1 (staging) through the fixture container and probe it -> succeeded", addFixtureNode},
		{1, "add a node in production and reject the approval -> failed", rejectProductionAdd},
		{1, "add a node in production and cancel it -> cancelled", cancelProductionAdd},
		{1, "probe fixture-1 while its container is paused -> failed", probeUnreachableNode},
		{2, "node.setup on fixture-1 -> succeeded", setupSucceeds},
		{2, "create the API token fixture-ci", createToken},
		{4, "create the app fixture-web and bind it to fixture-1 in staging", createApp},
		{5, "register the local MCP client fixture-agent and store its token", registerMCPClient},
		{2, "create a backup and keep it as the archive of the milestone", createBackup},
	}
}

// stepsFor is the part of the world the `sm` of milestone number n can run.
func stepsFor(n int) []step {
	var supported []step
	for _, s := range steps() {
		if s.since <= n {
			supported = append(supported, s)
		}
	}
	return supported
}

func (w *world) run(ctx context.Context) error {
	for _, s := range stepsFor(w.in.m.number()) {
		w.transcript = append(w.transcript, s.text)
		if err := s.run(ctx, w); err != nil {
			return fmt.Errorf("%s: %w", s.text, err)
		}
	}
	return nil
}

func importSecrets(ctx context.Context, w *world) error {
	for _, name := range []string{"app/credential", "app/api-token"} {
		out, err := w.in.sm(ctx, "fixture value of "+name+"\n", "--json", "secrets", "import", "--name", name)
		if err != nil {
			return err
		}
		if err := w.in.settle(ctx, out); err != nil {
			return err
		}
	}
	// A secret whose import is never approved: its job stays awaiting_approval in the fixture.
	_, err := w.in.sm(ctx, "fixture value of app/parked\n", "--json", "secrets", "import", "--name", "app/parked")
	return err
}

// addNodeArgs is `sm nodes add` for the fixture node under name in environment.
func (w *world) addNodeArgs(name, environment string) []string {
	return []string{
		"--json", "nodes", "add", "--name", name,
		"--host", w.node.Host, "--port", fmt.Sprint(w.node.Port), "--admin-user", fixture.AdminUser,
		"--fingerprint", cryptossh.FingerprintSHA256(w.node.HostKey), "--environment", environment,
	}
}

func addFixtureNode(ctx context.Context, w *world) error {
	if err := fixture.Build(ctx); err != nil {
		return err
	}
	node, err := fixture.Start(ctx, fixture.Options{})
	if err != nil {
		return err
	}
	w.node = node
	w.in.ring.hold(node.ClientSigner)
	out, err := w.in.sm(ctx, "", w.addNodeArgs(nodeName, "staging")...)
	if err != nil {
		return err
	}
	if err := w.in.settle(ctx, out); err != nil {
		return err
	}
	out, err = w.in.sm(ctx, "", "--json", "nodes", "probe", nodeName)
	if err != nil {
		return err
	}
	return w.in.settle(ctx, out)
}

// submitProductionAdd requests a node in production, which policy holds for approval.
func submitProductionAdd(ctx context.Context, w *world, name string) (jobView, error) {
	job, err := w.in.submitJob(ctx, w.addNodeArgs(name, "production")...)
	if err != nil {
		return jobView{}, err
	}
	if job.State != "awaiting_approval" {
		return jobView{}, fmt.Errorf("adding %s to production is %s, want awaiting_approval", name, job.State)
	}
	return job, nil
}

func rejectProductionAdd(ctx context.Context, w *world) error {
	job, err := submitProductionAdd(ctx, w, "fixture-rejected")
	if err != nil {
		return err
	}
	if err := w.in.decide(ctx, "reject", job, "--reason", "fixture: rejected on purpose"); err != nil {
		return err
	}
	return w.in.waitState(ctx, job, "failed") // a rejection ends the job failed
}

func cancelProductionAdd(ctx context.Context, w *world) error {
	job, err := submitProductionAdd(ctx, w, "fixture-cancelled")
	if err != nil {
		return err
	}
	if err := w.in.decide(ctx, "cancel", job); err != nil {
		return err
	}
	return w.in.waitState(ctx, job, "cancelled")
}

func probeUnreachableNode(ctx context.Context, w *world) error {
	if err := w.node.Pause(ctx); err != nil {
		return err
	}
	defer func() { _ = w.node.Unpause(context.WithoutCancel(ctx)) }()
	job, err := w.in.submitJob(ctx, "nodes", "probe", nodeName)
	if err != nil {
		return err
	}
	return w.in.waitState(ctx, job, "failed")
}

func setupSucceeds(ctx context.Context, w *world) error {
	job, err := w.in.submitJob(ctx, "nodes", "setup", nodeName, "--yes")
	if err != nil {
		return err
	}
	if job.State != "awaiting_approval" {
		return fmt.Errorf("node.setup is %s, want awaiting_approval", job.State)
	}
	if err := w.in.approve(ctx, job); err != nil {
		return err
	}
	return w.in.waitState(ctx, job, "succeeded")
}

func createToken(ctx context.Context, w *world) error {
	_, err := w.in.sm(ctx, "", "tokens", "create", "--name", "fixture-ci", "--expires-in", "30d")
	return err
}

func createApp(ctx context.Context, w *world) error {
	const compose = "services:\n  web:\n    image: registry.example.test/fixture/web:placeholder\n    ports:\n      - {target: 8080, published: 8080, host_ip: 127.0.0.1}\n"
	request, err := json.Marshal(map[string]any{
		"name": "fixture-web", "deployed_service": "web",
		"image_policy":   map[string]any{"deployed": "registry.example.test/fixture/web"},
		"compose_source": "control-plane", "compose_content": compose,
	})
	if err != nil {
		return err
	}
	requestFile := filepath.Join(w.in.dir, "app.json")
	if err := os.WriteFile(requestFile, request, 0o600); err != nil {
		return err
	}
	out, err := w.in.sm(ctx, "", "--json", "apps", "create", "--file", requestFile)
	if err != nil {
		return err
	}
	if err := w.in.settle(ctx, out); err != nil {
		return err
	}
	out, err = w.in.sm(ctx, "", "--json", "apps", "target", "add", "fixture-web", "--environment", "staging", "--node", nodeName)
	if err != nil {
		return err
	}
	return w.in.settle(ctx, out)
}

func registerMCPClient(ctx context.Context, w *world) error {
	tokenFile := filepath.Join(w.in.dir, "mcp.token")
	out, err := w.in.sm(ctx, "", "--json", "mcp", "clients", "add", "fixture-agent", "--token-file", tokenFile)
	if err != nil {
		return err
	}
	if job, ok, err := jobIn(out); err != nil {
		return err
	} else if ok {
		if err := w.in.approve(ctx, job); err != nil {
			return err
		}
		if err := w.in.waitState(ctx, job, "succeeded"); err != nil {
			return err
		}
		_, err = w.in.sm(ctx, "", "mcp", "clients", "add", "fixture-agent", "--token-file", tokenFile)
		return err
	}
	return nil
}

func createBackup(ctx context.Context, w *world) error {
	job, err := w.in.submitJob(ctx, "backup", "create")
	if err != nil {
		return err
	}
	if job.State == "awaiting_approval" {
		if err := w.in.approve(ctx, job); err != nil {
			return err
		}
	}
	return w.in.waitState(ctx, job, "succeeded")
}

// cleanup removes the fixture node.
func (w *world) cleanup(ctx context.Context) {
	if w.node != nil {
		_ = w.node.Stop(context.WithoutCancel(ctx))
	}
}
