package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
)

func TestNoDaemonWhenTheDatabaseIsFree(t *testing.T) {
	dir := t.TempDir()
	pid, err := localDaemonPID(filepath.Join(dir, "sm.db"), filepath.Join(dir, "sm.sock"))
	if err != nil || pid != 0 {
		t.Errorf("pid=%d err=%v", pid, err)
	}
}

// A holder of the database lock that does not own the socket lock (a server, a
// restore, an offline session) is refused, and the error names it.
func TestHolderWithoutTheSocketLockIsNotALocalDaemon(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "sm.db")
	lock, err := database.AcquireDatabaseLock(db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	pid, err := localDaemonPID(db, filepath.Join(dir, "sm.sock"))
	if err == nil || pid != 0 || !strings.Contains(err.Error(), "not the local daemon") {
		t.Errorf("pid=%d err=%v", pid, err)
	}
}

func TestHolderOfBothLocksIsTheLocalDaemon(t *testing.T) {
	dir := t.TempDir()
	db, sock := filepath.Join(dir, "sm.db"), filepath.Join(dir, "sm.sock")
	dbLock, err := database.AcquireDatabaseLock(db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dbLock.Release() }()
	sockLock, err := database.AcquireDatabaseLock(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sockLock.Release() }()
	if pid, err := localDaemonPID(db, sock); err != nil || pid != os.Getpid() {
		t.Errorf("pid=%d err=%v, want %d", pid, err, os.Getpid())
	}
}

func TestRestartRefusesAServerConfiguration(t *testing.T) {
	s := newSandbox(t)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("version: 1\ninstance:\n  mode: server\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := s.run("--config", cfg, "daemon", "restart")
	if r.code == 0 || !strings.Contains(r.stderr, "local daemon") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
}
