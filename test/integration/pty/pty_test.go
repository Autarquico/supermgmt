//go:build unix

// Package pty is the mandatory terminal-restoration gate of milestone M1
// (spec §17.1, PLAN §9): the built `sm` TUI runs under a real pseudo-terminal
// against a fake daemon and a fake `ssh` on PATH, and must come back from the
// interactive handoff with the terminal modes and the screen restored.
package pty_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	waitTimeout   = 20 * time.Second
	altScreenOn   = "\x1b[?1049h"
	startRows     = 24
	startCols     = 80
	nodeID        = domain.ID("018f0000-0000-7000-8000-000000000001")
	sessionID     = domain.ID("018f0000-0000-7000-8000-000000000002")
	childReady    = "FAKE-SSH-READY"
	childFinished = "FAKE-SSH-LEFT"
)

var (
	builtOnce sync.Once
	builtPath string
	builtErr  error
)

// smBinary builds the real `sm` once.
func smBinary(t *testing.T) string {
	t.Helper()
	builtOnce.Do(func() {
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Join(filepath.Dir(file), "..", "..", "..")
		dir, err := os.MkdirTemp("", "sm-pty-bin")
		if err != nil {
			builtErr = err
			return
		}
		builtPath = filepath.Join(dir, "sm")
		build := exec.CommandContext(context.Background(), "go", "build", "-o", builtPath, "./cmd/sm")
		build.Dir = root
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			builtErr = fmt.Errorf("go build ./cmd/sm: %w\n%s", err, out)
		}
	})
	if builtErr != nil {
		t.Fatal(builtErr)
	}
	return builtPath
}

// ---- fake daemon ---------------------------------------------------------------

type fakeDaemon struct {
	socket string
	ends   chan wire.EndSessionRequest
}

func envelope(v any) []byte {
	b, err := json.Marshal(wire.Envelope[any]{Data: v})
	if err != nil {
		panic(err)
	}
	return b
}

func hostKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(k)))
}

func startFakeDaemon(t *testing.T, dir string) *fakeDaemon {
	t.Helper()
	hostKey := hostKeyLine(t)
	node := wire.Node{
		ID: nodeID, Name: "pty-node", Kind: "ssh", Provider: "ssh", Environment: "staging",
		ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityReachable,
		Endpoint:     wire.Endpoint{Host: "127.0.0.1", Port: 2222, User: "supermgmt", AdminUser: "admin", HostPublicKey: hostKey},
		Capabilities: []wire.Capability{{Name: "node.ssh", Available: true}},
		Connection:   wire.Connection{State: "connected"},
	}
	d := &fakeDaemon{socket: filepath.Join(dir, "d.sock"), ends: make(chan wire.EndSessionRequest, 4)}
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", wire.ContentType)
		_, _ = w.Write(envelope(v))
	}
	page := func(items ...any) any { return map[string]any{"items": items, "next_cursor": ""} }
	mux.HandleFunc("GET "+wire.PathMe, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, wire.Me{DisplayName: "pty-user", InstanceMode: "local"})
	})
	mux.HandleFunc("GET "+wire.PathPresence, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	mux.HandleFunc("GET "+wire.PathNodes, func(w http.ResponseWriter, _ *http.Request) { reply(w, page(node)) })
	mux.HandleFunc("GET "+wire.PathNode, func(w http.ResponseWriter, _ *http.Request) { reply(w, node) })
	mux.HandleFunc("POST "+wire.PathNodeSessions, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, wire.SessionOpened{
			Session: wire.Session{ID: sessionID, NodeID: nodeID, Tool: wire.ToolShell, State: "issued"},
			ConnectInfo: wire.ConnectInfo{
				NodeID: nodeID, Host: "127.0.0.1", Port: 2222, User: "admin",
				HostPublicKey: hostKey, HostKeyAlias: "sm-" + string(nodeID),
			},
		})
	})
	mux.HandleFunc("POST "+wire.PathNodeSessionEnd, func(w http.ResponseWriter, r *http.Request) {
		var end wire.EndSessionRequest
		_ = json.NewDecoder(r.Body).Decode(&end)
		d.ends <- end
		reply(w, wire.Session{ID: sessionID, NodeID: nodeID, State: "ended"})
	})
	mux.HandleFunc("GET "+wire.PathEvents, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // a daemon route that hangs: the offline-node case of spec scenario 2
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { reply(w, page()) })

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", d.socket)
	if err != nil {
		t.Fatalf("listen on fake daemon socket: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return d
}

func (d *fakeDaemon) nextEnd(t *testing.T) wire.EndSessionRequest {
	t.Helper()
	select {
	case end := <-d.ends:
		return end
	case <-time.After(waitTimeout):
		t.Fatal("the daemon never received the session end")
		return wire.EndSessionRequest{}
	}
}

// ---- terminal --------------------------------------------------------------------

// screen is the raw byte stream the program wrote to the terminal.
type screen struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *screen) since(from int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()[from:]
}

type app struct {
	t    *testing.T
	cmd  *exec.Cmd
	ptmx *os.File
	out  *screen
	tmp  string // TMPDIR of sm: where the isolated known_hosts directories appear
	done chan error
}

// start runs `sm tui` on a pty against the fake daemon with a fake ssh script.
// An empty sshScript means there is no ssh on PATH at all.
func start(t *testing.T, d *fakeDaemon, dir, sshScript string) *app {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	tmp := filepath.Join(dir, "tmp")
	for _, p := range []string{bin, tmp} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := bin
	if sshScript != "" {
		if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(sshScript), 0o700); err != nil {
			t.Fatal(err)
		}
		path += ":/usr/bin:/bin"
	}
	cfg := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("version: 1\ninstance:\n  mode: local\ndaemon:\n  socket: %s\n", d.socket)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), smBinary(t), "--config", cfg, "tui")
	cmd.Env = []string{
		"PATH=" + path, "HOME=" + dir, "TMPDIR=" + tmp, "TERM=xterm-256color",
		"SM_NO_AUTOSTART=1", "LANG=C.UTF-8",
	}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: startRows, Cols: startCols})
	if err != nil {
		t.Fatalf("start sm on a pty: %v", err)
	}
	a := &app{t: t, cmd: cmd, ptmx: ptmx, out: &screen{}, tmp: tmp, done: make(chan error, 1)}
	go a.pump()
	go func() { a.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = ptmx.Close()
	})
	return a
}

func (a *app) pump() {
	buf := make([]byte, 32<<10)
	for {
		n, err := a.ptmx.Read(buf)
		if n > 0 {
			_, _ = a.out.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// waitFor blocks until text appears after offset from and returns the offset
// just past it.
func (a *app) waitFor(text string, from int) int {
	a.t.Helper()
	deadline := monotonicNow().Add(waitTimeout)
	for monotonicNow().Before(deadline) {
		if i := strings.Index(a.out.since(from), text); i >= 0 {
			return from + i + len(text)
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.t.Fatalf("timed out waiting for %q; terminal output since %d:\n%q", text, from, a.out.since(from))
	return from
}

func (a *app) send(s string) {
	a.t.Helper()
	if _, err := a.ptmx.WriteString(s); err != nil {
		a.t.Fatalf("write %q to the terminal: %v", s, err)
	}
}

// openShell walks the TUI to the node and presses `s`; it returns the output
// offset to continue from.
func (a *app) openShell() int {
	a.t.Helper()
	at := a.waitFor("1 node", 0) // the dashboard header counts the node once loaded
	a.send("2")
	at = a.waitFor("Resources", at)
	at = a.waitFor("pty-node", at)
	a.send("s")
	return at
}

func (a *app) quit() {
	a.t.Helper()
	a.send("q")
	select {
	case err := <-a.done:
		if err != nil {
			a.t.Fatalf("sm exited abnormally after q: %v", err)
		}
	case <-time.After(waitTimeout):
		a.t.Fatal("sm did not exit after q")
	}
}

var privateModeSet = regexp.MustCompile(`\x1b\[\?([0-9;]+)h`)

// modesSet lists the DEC private modes switched on in output.
func modesSet(output string) map[string]bool {
	modes := map[string]bool{}
	for _, m := range privateModeSet.FindAllStringSubmatch(output, -1) {
		for _, n := range strings.Split(m[1], ";") {
			modes[n] = true
		}
	}
	return modes
}

func (a *app) knownHostsDirs() []string {
	dirs, _ := filepath.Glob(filepath.Join(a.tmp, "sm-kh-*"))
	return dirs
}

func (a *app) requireKnownHostsGone() {
	a.t.Helper()
	deadline := monotonicNow().Add(5 * time.Second)
	for monotonicNow().Before(deadline) {
		if len(a.knownHostsDirs()) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.t.Fatalf("temporary known_hosts directories remain: %v", a.knownHostsDirs())
}

// lastFrameWidth is the width of the last bottom border the TUI drew.
func lastFrameWidth(output string) int {
	width := 0
	for _, line := range strings.Split(output, "\n") {
		i := strings.Index(line, "└")
		if i < 0 {
			continue
		}
		if j := strings.Index(line[i:], "┘"); j > 0 {
			width = strings.Count(line[i:i+j], "─") + 2
		}
	}
	return width
}

// ---- fake ssh scripts ----------------------------------------------------------------

const sshWaitsForLine = "#!/bin/sh\n" +
	"echo " + childReady + "\n" +
	"read line\n" +
	"echo " + childFinished + "\n" +
	"exit 0\n"

func sshExiting(code int) string {
	return fmt.Sprintf("#!/bin/sh\necho %s\nread line\nexit %d\n", childReady, code)
}

// shortDir is a temp dir short enough for a Unix socket path on macOS.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "smp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// ---- the gate ----------------------------------------------------------------------

func TestHandoffRestoresTerminalAfterNormalExit(t *testing.T) {
	dir := shortDir(t)
	d := startFakeDaemon(t, dir)
	a := start(t, d, dir, sshWaitsForLine)
	a.waitFor(altScreenOn, 0)
	initial := modesSet(a.out.since(0))
	at := a.openShell()
	at = a.waitFor(childReady, at)
	if got := len(a.knownHostsDirs()); got != 1 {
		t.Fatalf("isolated known_hosts directories while the shell runs = %d, want 1", got)
	}
	a.send("\n")
	at = a.waitFor(childFinished, at)
	a.waitFor("back from shell on pty-node", at)
	back := a.out.since(at)

	if len(initial) == 0 {
		t.Fatal("the TUI enabled no terminal mode at startup; the comparison would be vacuous")
	}
	for mode := range initial {
		if !modesSet(back)[mode] {
			t.Errorf("terminal mode ?%sh was on before the handoff but is not re-enabled after it", mode)
		}
	}
	if !strings.Contains(back, altScreenOn) {
		t.Errorf("alt-screen (?1049h) is not re-entered after the shell exits")
	}
	if !strings.Contains(back, "Resources") {
		t.Errorf("the screen is not redrawn after the shell exits")
	}
	if end := d.nextEnd(t); end.Reason != wire.EndExited || end.ExitCode == nil || *end.ExitCode != 0 {
		t.Errorf("session end = %+v, want exited with code 0", end)
	}
	a.requireKnownHostsGone()
	a.quit()
}

func TestHandoffShowsNonZeroExitCode(t *testing.T) {
	dir := shortDir(t)
	d := startFakeDaemon(t, dir)
	a := start(t, d, dir, sshExiting(3))
	at := a.openShell()
	at = a.waitFor(childReady, at)
	a.send("\n")
	a.waitFor("exited with code 3", at)
	if end := d.nextEnd(t); end.Reason != wire.EndExited || end.ExitCode == nil || *end.ExitCode != 3 {
		t.Errorf("session end = %+v, want exited with code 3", end)
	}
	a.requireKnownHostsGone()
	a.quit()
}

func TestHandoffWithMissingSSHShowsErrorAndEndsSessionAsLaunchFailed(t *testing.T) {
	dir := shortDir(t)
	d := startFakeDaemon(t, dir)
	a := start(t, d, dir, "")
	at := a.openShell()
	a.waitFor("could not start shell on pty-node", at)
	if end := d.nextEnd(t); end.Reason != wire.EndLaunchFailed {
		t.Errorf("session end = %+v, want launch_failed", end)
	}
	a.requireKnownHostsGone()
	a.quit()
}

func TestCtrlCInTheChildDoesNotKillTheTUI(t *testing.T) {
	dir := shortDir(t)
	d := startFakeDaemon(t, dir)
	script := "#!/bin/sh\ntrap 'echo CHILD-GOT-INT; exit 130' INT\necho " + childReady + "\nwhile :; do sleep 0.05; done\n"
	a := start(t, d, dir, script)
	at := a.openShell()
	at = a.waitFor(childReady, at)
	a.send("\x03")
	at = a.waitFor("CHILD-GOT-INT", at)
	a.waitFor("exited with code 130", at)
	if end := d.nextEnd(t); end.ExitCode == nil || *end.ExitCode != 130 {
		t.Errorf("session end = %+v, want exit code 130", end)
	}
	select {
	case err := <-a.done:
		t.Fatalf("the TUI died with the child's Ctrl-C: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	a.requireKnownHostsGone()
	a.quit()
}

func TestResizeDuringHandoffIsUsedByTheNextFrame(t *testing.T) {
	dir := shortDir(t)
	d := startFakeDaemon(t, dir)
	a := start(t, d, dir, sshWaitsForLine)
	at := a.openShell()
	at = a.waitFor(childReady, at)
	if w := lastFrameWidth(a.out.since(0)); w != startCols {
		t.Fatalf("frame width before the handoff = %d, want %d", w, startCols)
	}
	const newCols = 110
	if err := pty.Setsize(a.ptmx, &pty.Winsize{Rows: 30, Cols: newCols}); err != nil {
		t.Fatalf("resize the terminal: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	a.send("\n")
	at = a.waitFor(childFinished, at)
	a.waitFor("back from shell on pty-node", at)
	time.Sleep(300 * time.Millisecond)
	if w := lastFrameWidth(a.out.since(at)); w != newCols {
		t.Errorf("frame width after the handoff = %d, want %d (the resize made during the shell)", w, newCols)
	}
	d.nextEnd(t)
	a.requireKnownHostsGone()
	a.quit()
}

const keyToFrameBudget = 50 * time.Millisecond

// Scenario: un nodo offline no congela la TUI (terminal side). While one daemon
// route hangs, a key press still produces its frame in under 50 ms.
func TestKeyProducesAFrameWithinBudgetWhileADaemonRouteHangs(t *testing.T) {
	dir := shortDir(t)
	d := startFakeDaemon(t, dir)
	a := start(t, d, dir, sshWaitsForLine)
	a.waitFor("1 node", 0)

	// The renderer repaints only what changed, so each key is recognised by a
	// token unique to its screen.
	for _, step := range []struct{ key, token string }{{"5", "SEV"}, {"2", "RESOURCES"}, {"1", "Needs attention"}} {
		before := len(a.out.since(0))
		sent := monotonicNow()
		a.send(step.key)
		a.waitForWithin(step.token, before)
		if took := time.Since(sent); took >= keyToFrameBudget {
			t.Errorf("key %q took %s to paint %q, want < %s", step.key, took, step.token, keyToFrameBudget)
		}
		time.Sleep(100 * time.Millisecond)
	}
	a.quit()
}

// waitForWithin is waitFor with a short deadline and a tight poll; it reports
// a miss through the test instead of aborting it.
func (a *app) waitForWithin(text string, from int) {
	a.t.Helper()
	deadline := monotonicNow().Add(waitTimeout) // a miss is measured by the caller, not truncated here
	for monotonicNow().Before(deadline) {
		if strings.Contains(a.out.since(from), text) {
			return
		}
		time.Sleep(200 * time.Microsecond)
	}
	a.t.Fatalf("%q never appeared; output:\n%q", text, a.out.since(from))
}

// monotonicNow is the one place the tests read the process clock: latency
// budgets need its monotonic reading, which a domain.Clock does not carry.
func monotonicNow() time.Time { return time.Now() } //nolint:forbidigo // see above
