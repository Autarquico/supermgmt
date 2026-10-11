// Package daemon is the resident process that owns the database, the job
// workers and the connectors, and serves the local API (spec §2.1.1,
// ADR-0014): the two flock locks, the socket directory rules, the listener,
// residency and the wiring of the application services.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	socketDirMode  fs.FileMode = 0o700
	socketFileMode fs.FileMode = 0o600
	socketUmask                = 0o177
)

// sunPathMax is the size of sockaddr_un.sun_path, NUL included.
func sunPathMax() int {
	if runtime.GOOS == "darwin" {
		return 104
	}
	return 108
}

// CheckSocketPath refuses a path that does not fit sockaddr_un. The daemon
// never silently shortens it to /tmp (spec §2.1.1).
func CheckSocketPath(socket string) error {
	if len(socket) >= sunPathMax() {
		return smerr.New(smerr.CodeInvalidArgument, "",
			fmt.Sprintf("socket path is %d bytes, over the platform limit of %d: set daemon.socket to a shorter path", len(socket), sunPathMax()-1))
	}
	return nil
}

// UnsafeSocketDirError says why the socket directory cannot be trusted.
type UnsafeSocketDirError struct {
	Dir    string
	Reason string
}

func (e *UnsafeSocketDirError) Error() string {
	return fmt.Sprintf("refusing to use socket directory %s: %s", e.Dir, e.Reason)
}

// SocketDir is a verified socket directory, pinned by an open descriptor so
// that it can be shown to be the same directory later (Recheck).
type SocketDir struct {
	path string
	uid  int
	pin  *os.File
}

// PrepareSocketDir creates the directory of socket with mode 0700 when it is
// missing and then verifies with lstat that it is a real directory (not a
// symlink) owned by uid with mode exactly 0700, and that no ancestor lets
// another user replace it: every directory on its real path must be owned by
// root or uid, and must not be writable by group or others unless it has the
// sticky bit (spec §2.1.1). Anything else is refused, never repaired.
func PrepareSocketDir(socket string, uid int) (*SocketDir, error) {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(filepath.Dir(dir), socketDirMode); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(dir), err)
	}
	if err := os.Mkdir(dir, socketDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := verifyDir(dir, uid); err != nil {
		return nil, err
	}
	if err := verifyAncestors(dir, uid); err != nil {
		return nil, err
	}
	pin, err := os.Open(dir) //nolint:gosec // the verified socket directory
	if err != nil {
		return nil, fmt.Errorf("pin socket directory: %w", err)
	}
	d := &SocketDir{path: dir, uid: uid, pin: pin}
	if err := d.Recheck(); err != nil {
		_ = pin.Close()
		return nil, err
	}
	return d, nil
}

// Recheck proves the path still names the directory that was verified: the
// same inode as the pinned descriptor, with the same owner and mode. Call it
// right before binding and again after.
func (d *SocketDir) Recheck() error {
	if err := verifyDir(d.path, d.uid); err != nil {
		return err
	}
	now, err := os.Lstat(d.path)
	if err != nil {
		return fmt.Errorf("inspect socket directory: %w", err)
	}
	pinned, err := d.pin.Stat()
	if err != nil {
		return fmt.Errorf("inspect pinned socket directory: %w", err)
	}
	if !os.SameFile(now, pinned) {
		return &UnsafeSocketDirError{Dir: d.path, Reason: "it was replaced while the daemon was starting"}
	}
	return nil
}

// Close releases the pin.
func (d *SocketDir) Close() error { return d.pin.Close() }

func verifyDir(dir string, uid int) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect socket directory: %w", err)
	}
	owner, ok := ownerOf(info)
	switch {
	case !info.IsDir():
		return &UnsafeSocketDirError{Dir: dir, Reason: "it is not a real directory (a symlink?)"}
	case !ok || owner != uid:
		return &UnsafeSocketDirError{Dir: dir, Reason: fmt.Sprintf("it is not owned by uid %d", uid)}
	case info.Mode().Perm() != socketDirMode:
		return &UnsafeSocketDirError{Dir: dir, Reason: fmt.Sprintf("its mode is %04o, want 0700", info.Mode().Perm())}
	}
	return nil
}

// verifyAncestors walks the real path of dir up to the root.
func verifyAncestors(dir string, uid int) error {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("resolve socket directory: %w", err)
	}
	for ancestor := filepath.Dir(real); ; ancestor = filepath.Dir(ancestor) {
		if err := verifyAncestor(ancestor, uid); err != nil {
			return err
		}
		if ancestor == filepath.Dir(ancestor) {
			return nil
		}
	}
}

func verifyAncestor(path string, uid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	owner, ok := ownerOf(info)
	switch {
	case !ok || (owner != 0 && owner != uid):
		return &UnsafeSocketDirError{Dir: path, Reason: fmt.Sprintf("a parent of the socket directory is owned by uid %d, who could replace it", owner)}
	case info.Mode().Perm()&0o022 != 0 && info.Mode()&fs.ModeSticky == 0:
		return &UnsafeSocketDirError{Dir: path, Reason: fmt.Sprintf("a parent of the socket directory is writable by other users (mode %04o) without the sticky bit", info.Mode().Perm())}
	}
	return nil
}

func ownerOf(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

// umaskMu serializes the process-wide umask change around bind.
var umaskMu sync.Mutex

// Bind unlinks a stale socket file and listens on socket with umask 0177, so
// the socket is created 0600. The caller holds the socket lock, which is the
// proof that no live daemon owns the old file (spec §2.1.1, "Startup and stale
// sockets"). Only a socket is ever unlinked.
func Bind(ctx context.Context, socket string) (net.Listener, error) {
	if err := unlinkStaleSocket(socket); err != nil {
		return nil, err
	}
	listener, err := listenPrivately(ctx, socket)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socket, err)
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode().Type() != fs.ModeSocket || info.Mode().Perm() != socketFileMode {
		_ = listener.Close()
		return nil, &UnsafeSocketDirError{Dir: filepath.Dir(socket), Reason: "the bound socket is not a private (0600) socket"}
	}
	return listener, nil
}

func unlinkStaleSocket(socket string) error {
	info, err := os.Lstat(socket)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("inspect %s: %w", socket, err)
	case info.Mode().Type() != fs.ModeSocket:
		return fmt.Errorf("%s exists and is not a socket; refusing to remove it", socket)
	}
	if err := os.Remove(socket); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

func listenPrivately(ctx context.Context, socket string) (net.Listener, error) {
	return listenMasked(ctx, socket, socketUmask)
}

// listenMasked listens on a Unix socket created under umask.
func listenMasked(ctx context.Context, socket string, umask int) (net.Listener, error) {
	umaskMu.Lock()
	defer umaskMu.Unlock()
	previous := syscall.Umask(umask)
	defer syscall.Umask(previous)
	var config net.ListenConfig
	return config.Listen(ctx, "unix", socket)
}
