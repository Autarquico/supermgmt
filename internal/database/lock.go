package database

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// LockHeldError reports that another process owns the database lock (spec
// §2.1.1). PID is 0 when the holder has not recorded it yet.
type LockHeldError struct {
	Path string
	PID  int
}

func (e *LockHeldError) Error() string {
	if e.PID == 0 {
		return fmt.Sprintf("database is in use: lock %s is held by another process", e.Path)
	}
	return fmt.Sprintf("database is in use: lock %s is held by PID %d", e.Path, e.PID)
}

// Lock is the exclusive database lock, held until Release.
type Lock struct {
	file *os.File
	path string
}

// Path returns the lock file path.
func (l *Lock) Path() string { return l.path }

// AcquireDatabaseLock takes the non-blocking exclusive flock on
// "<canonical db path>.lock" and records this process's PID in it. The
// canonical path exists before the database does: the parent directory is
// created (0700) if missing, resolved with realpath, and the basename appended.
func AcquireDatabaseLock(dbPath string) (*Lock, error) {
	canonical, err := canonicalPath(dbPath)
	if err != nil {
		return nil, err
	}
	path := canonical + ".lock"
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // path derived from the configured database path
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder := readPID(file)
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &LockHeldError{Path: path, PID: holder}
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := writePID(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Lock{file: file, path: path}, nil
}

// Release drops the lock. The lock file stays on disk.
func (l *Lock) Release() error {
	return l.file.Close() // closing the descriptor releases the flock
}

func canonicalPath(dbPath string) (string, error) {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return "", fmt.Errorf("resolve database path: %w", err)
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o700); err != nil { //nolint:gosec // the database path is operator configuration
		return "", fmt.Errorf("create database directory: %w", err)
	}
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve database directory: %w", err)
	}
	return filepath.Join(real, filepath.Base(abs)), nil
}

func writePID(file *os.File) error {
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("reset lock file: %w", err)
	}
	if _, err := file.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		return fmt.Errorf("record PID in lock file: %w", err)
	}
	return nil
}

func readPID(file *os.File) int {
	buf := make([]byte, 32)
	n, _ := file.ReadAt(buf, 0)
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
