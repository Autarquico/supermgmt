package ssh

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// requireTrustedExecutable refuses a cloudflared the daemon should not hand the
// Access service token to: the resolved file must be a regular file that only
// root or the daemon's own uid owns and that neither group nor others can
// write, and no directory above it, or above the symlink that names it, may be
// replaceable by somebody else.
func requireTrustedExecutable(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return untrusted(path, "it cannot be resolved")
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return untrusted(path, "it is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return untrusted(path, "it is writable by group or others")
	}
	if !ownedByRootOrDaemon(info) {
		return untrusted(path, "it is owned by another user")
	}
	// The directories of the target and of the path as given, which holds the
	// symlink itself: whoever can write either can swap what runs.
	if err := requireSafeDirectories(path, filepath.Dir(real)); err != nil {
		return err
	}
	return requireSafeDirectories(path, filepath.Dir(path))
}

// requireSafeDirectories checks start and every directory above it.
func requireSafeDirectories(path, start string) error {
	for dir := start; ; dir = filepath.Dir(dir) {
		dinfo, err := os.Stat(dir)
		if err != nil {
			return untrusted(path, "its directory cannot be read")
		}
		if !ownedByRootOrDaemon(dinfo) {
			return untrusted(path, dir+" is owned by another user")
		}
		if !directorySafe(dinfo) {
			return untrusted(path, dir+" is writable by others")
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// directorySafe: not writable by others, and group-writable only when the
// daemon's own user owns it (Homebrew's prefix is user-owned, admin-writable).
// A sticky directory owned by root (/tmp) keeps others from replacing files.
func directorySafe(info fs.FileInfo) bool {
	perm := info.Mode().Perm()
	if perm&0o002 != 0 && info.Mode()&fs.ModeSticky == 0 {
		return false
	}
	return perm&0o020 == 0 || ownedBy(info, os.Getuid())
}

func ownedByRootOrDaemon(info fs.FileInfo) bool {
	return ownedBy(info, 0) || ownedBy(info, os.Getuid())
}

func ownedBy(info fs.FileInfo, uid int) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}

func untrusted(path, reason string) error {
	return smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("cloudflared at %s is not trusted with the Access service token: %s", path, reason))
}

// securePrivateDir creates dir (0700) or tightens it to 0700, and refuses one
// that is not a directory or that another user owns.
func securePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return smerr.Wrap(err, smerr.CodeCapabilityUnavailable, "", "cannot create the cloudflared home directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the cloudflared home directory is not a directory: remove "+dir+" or choose a directory the daemon's user owns")
	}
	if !ownedBy(info, os.Getuid()) {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the cloudflared home directory is not owned by the daemon's user: remove "+dir+" or choose a directory the daemon's user owns")
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory: 0700 is the tightest usable mode
			return smerr.Wrap(err, smerr.CodeCapabilityUnavailable, "", "cannot restrict the cloudflared home directory to its owner: fix the permissions of "+dir+" or choose another directory")
		}
	}
	return nil
}
