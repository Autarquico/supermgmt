package installer

import (
	"os"
	"path/filepath"
	"syscall"
)

// hostDisk is the optional disk-space capability the upgrade's pre-flight
// needs. Files stays the frozen M2 interface; the real host implements this
// beside it, and an upgrade on a host that cannot answer refuses to start.
type hostDisk interface {
	// FreeBytes is the space available to an unprivileged writer under dir.
	FreeBytes(dir string) (uint64, error)
	FileSize(path string) (int64, error)
}

// locker is the optional exclusive-lock capability (also part of applianceHost).
type locker interface {
	Lock(path string) (release func(), err error)
}

// canonicalizer resolves a path the way the daemon does before it names its lock file.
type canonicalizer interface {
	Canonical(path string) (string, error)
}

// Canonical makes path absolute and resolves symlinks in its directory; the file itself may not exist.
func (osFiles) Canonical(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

func (osFiles) FreeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(filepath.Clean(dir), &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil //nolint:gosec,unconvert,nolintlint // Bsize is a positive block size; signed on linux, unsigned on darwin
}

func (osFiles) FileSize(path string) (int64, error) {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
