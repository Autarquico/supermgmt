package m1

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/client"
)

// daemonPIDs lists the live `sm daemon` processes of this instance, found by
// their unique --config path.
func daemonPIDs(t *testing.T, in *instance) []int {
	t.Helper()
	out, err := exec.CommandContext(context.WithoutCancel(t.Context()), "ps", "-axo", "pid=,args=").Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.Contains(line, in.config+" daemon") {
			continue
		}
		if pid, err := strconv.Atoi(fields[0]); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// killLeftovers ends daemons the clients autostarted: no test owns their Cmd.
func killLeftovers(t *testing.T, in *instance) {
	t.Cleanup(func() {
		for _, pid := range daemonPIDs(t, in) {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		deadline := monotonicNow().Add(10 * time.Second)
		for monotonicNow().Before(deadline) && len(daemonPIDs(t, in)) > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		for _, pid := range daemonPIDs(t, in) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
}

// Lifecycle (ADR-0014): ten clients racing to autostart leave one daemon.
func TestM1Lifecycle_TenConcurrentClientsAutostartOneDaemon(t *testing.T) {
	in := newInstance(t, instanceOptions{})
	killLeftovers(t, in)
	autostart := &client.Autostart{
		Executable: in.bin, Args: in.daemonArgs(), LogPath: filepath.Join(in.dir, "autostart.log"), Wait: 20 * time.Second,
	}

	const clients = 10
	errs := make([]error, clients)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := client.New(client.Options{Socket: in.socket, Autostart: autostart})
			_, errs[i] = c.Me(t.Context())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("client %d: %v", i, err)
		}
	}
	// A losing daemon exits (code 2) once it fails to take the lock; give it a moment.
	eventually(t, 10*time.Second, "the losing daemons to exit", func() bool { return len(daemonPIDs(t, in)) == 1 })
	time.Sleep(time.Second)
	if pids := daemonPIDs(t, in); len(pids) != 1 {
		t.Errorf("%d daemons run after 10 concurrent autostarts (%v), want exactly 1", len(pids), pids)
	}
}

// Lifecycle (§2.1.1): a second daemon on the same state exits 2 and names the owner.
func TestM1Lifecycle_SecondDaemonOnTheSameStateExitsTwoNamingTheOwner(t *testing.T) {
	in := startedInstance(t)
	pids := daemonPIDs(t, in)
	if len(pids) != 1 {
		t.Fatalf("expected one running daemon, found %v", pids)
	}
	cmd := exec.CommandContext(t.Context(), in.bin, in.daemonArgs()...)
	cmd.Env = in.env
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("second daemon: err %v, want exit status 2\n%s", err, out)
	}
	if !strings.Contains(string(out), strconv.Itoa(pids[0])) {
		t.Errorf("second daemon output does not name the owner PID %d:\n%s", pids[0], out)
	}
}

// runDaemonToExit starts `sm daemon` for the instance and returns its exit
// code and combined output.
func (in *instance) runDaemonToExit(t *testing.T) (int, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), in.bin, in.daemonArgs()...)
	cmd.Env = in.env
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(out)
	}
	return 0, string(out)
}

// Lifecycle (§2.1.1): the same database reached through a symlinked parent is
// still the same database; the second daemon exits 2 naming the owner.
func TestM1Lifecycle_SecondDaemonOnTheSameDatabaseThroughASymlinkExitsTwo(t *testing.T) {
	first := startedInstance(t)
	owners := daemonPIDs(t, first)
	if len(owners) != 1 {
		t.Fatalf("expected one running daemon, found %v", owners)
	}
	second := newInstance(t, instanceOptions{})
	alias := filepath.Join(second.dir, "alias")
	if err := os.Symlink(filepath.Join(first.dir, "data"), alias); err != nil {
		t.Fatal(err)
	}
	second.dataDir = alias // the same database under another path; its socket and keys stay its own
	second.writeConfig(instanceOptions{})

	code, out := second.runDaemonToExit(t)
	if code != 2 {
		t.Fatalf("daemon on an aliased database exited %d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, strconv.Itoa(owners[0])) {
		t.Errorf("the refusal does not name the owner PID %d:\n%s", owners[0], out)
	}
}

// Lifecycle (§2.1.1): two databases cannot share one socket; the loser exits 2
// and the winner keeps serving.
func TestM1Lifecycle_TwoDatabasesOnOneSocketExitTwoSocketInUse(t *testing.T) {
	first := startedInstance(t)
	second := newInstance(t, instanceOptions{})
	second.socket = first.socket
	second.writeConfig(instanceOptions{})

	code, out := second.runDaemonToExit(t)
	if code != 2 {
		t.Fatalf("daemon on a socket in use exited %d, want 2\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "socket") {
		t.Errorf("the refusal does not say the socket is in use:\n%s", out)
	}
	if _, err := first.client().Me(t.Context()); err != nil {
		t.Errorf("the first daemon stopped serving after the second was refused: %v", err)
	}
}
