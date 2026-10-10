package database

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const lockHelperEnv = "SM_TEST_LOCK_HOLDER"

// TestMain doubles as the lock-holder subprocess: when lockHelperEnv names a
// database path, the process takes the lock, announces readiness and waits for
// stdin to close.
func TestMain(m *testing.M) {
	if dbPath := os.Getenv(lockHelperEnv); dbPath != "" {
		os.Exit(holdLockUntilStdinCloses(dbPath))
	}
	os.Exit(m.Run())
}

func holdLockUntilStdinCloses(dbPath string) int {
	lock, err := AcquireDatabaseLock(dbPath)
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		return 1
	}
	defer func() { _ = lock.Release() }()
	os.Stdout.WriteString("ready\n")
	buf := make([]byte, 1)
	_, _ = os.Stdin.Read(buf)
	return 0
}

func startLockHolder(t *testing.T, dbPath string) (pid int, stop func()) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+dbPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		_ = cmd.Process.Kill()
		t.Fatalf("lock holder did not become ready: %q, %v", line, err)
	}
	stop = func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)
	return cmd.Process.Pid, stop
}

func TestLockHeldBySubprocessNamesItsPID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state", "sm.db")
	pid, stop := startLockHolder(t, dbPath)

	_, err := AcquireDatabaseLock(dbPath)
	var held *LockHeldError
	if !errors.As(err, &held) {
		t.Fatalf("err = %v, want *LockHeldError", err)
	}
	if held.PID != pid {
		t.Fatalf("holder PID = %d, want %d", held.PID, pid)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(pid)) {
		t.Fatalf("error %q does not name PID %d", err, pid)
	}

	stop() // holder exits: the lock becomes free again
	lock, err := AcquireDatabaseLock(dbPath)
	if err != nil {
		t.Fatalf("lock after holder exit: %v", err)
	}
	_ = lock.Release()
}

func TestLockReleaseAllowsReacquire(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sm.db")
	first, err := AcquireDatabaseLock(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireDatabaseLock(dbPath); !errors.As(err, new(*LockHeldError)) {
		t.Fatalf("second acquire = %v, want *LockHeldError", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireDatabaseLock(dbPath)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	_ = second.Release()
}

func TestLockCreatesParentWithOwnerOnlyMode(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "a", "b")
	lock, err := AcquireDatabaseLock(filepath.Join(parent, "sm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("parent mode = %o, want 700", mode)
	}
}

func TestLockResolvesSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireDatabaseLock(filepath.Join(real, "sm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()
	// The same database reached through the symlink must contend for the same lock.
	if _, err := AcquireDatabaseLock(filepath.Join(link, "sm.db")); !errors.As(err, new(*LockHeldError)) {
		t.Fatalf("acquire via symlink = %v, want *LockHeldError", err)
	}
}
