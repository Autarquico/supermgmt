package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/autarquico/supermgmt/internal/client"
)

// tokenSink is where an MCP client's one-time token goes. It is preflighted
// before the token is issued, because the token can be shown only once:
// a destination that fails afterwards leaves a credential nobody holds.
type tokenSink interface {
	// Store keeps token and says where it ended up. On failure nothing is left behind.
	Store(ctx context.Context, token string) (location string, err error)
	// Abandon releases a destination that was preflighted but never used.
	Abandon()
}

const (
	tokenFileMode   os.FileMode = 0o600
	groupWorldWrite os.FileMode = 0o022
)

// tokenFile is the part of *os.File a sink writes through.
type tokenFile interface {
	io.Writer
	Sync() error
	Close() error
}

// fileSink owns a freshly created, empty, 0600 file.
type fileSink struct {
	path string
	out  tokenFile
}

// openFileSink creates path exclusively (never following a symlink) in an
// existing directory the caller owns and nobody else can write, and checks the
// descriptor it got. Any refusal leaves no file behind.
func openFileSink(path string) (*fileSink, error) {
	if err := checkTokenDir(filepath.Dir(path), os.Geteuid()); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, tokenFileMode)
	if err != nil {
		return nil, usageErrorf("--token-file: %s", err)
	}
	if err := checkTokenFile(file, os.Geteuid()); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &fileSink{path: path, out: file}, nil
}

func checkTokenDir(dir string, euid int) error {
	info, err := os.Stat(dir)
	switch {
	case err != nil:
		return usageErrorf("--token-file: %s", err)
	case !info.IsDir():
		return usageErrorf("--token-file: %s is not a directory", dir)
	case !ownedBy(info, euid):
		return usageErrorf("--token-file: directory %s is not owned by you", dir)
	case info.Mode().Perm()&groupWorldWrite != 0:
		return usageErrorf("--token-file: directory %s is writable by group or others", dir)
	}
	return nil
}

func checkTokenFile(file *os.File, euid int) error {
	info, err := file.Stat()
	switch {
	case err != nil:
		return usageErrorf("--token-file: %s", err)
	case !info.Mode().IsRegular():
		return usageErrorf("--token-file: %s is not a regular file", file.Name())
	case !ownedBy(info, euid):
		return usageErrorf("--token-file: %s is not owned by you", file.Name())
	case info.Mode().Perm() != tokenFileMode:
		return usageErrorf("--token-file: %s is not mode 0600", file.Name())
	}
	return nil
}

func ownedBy(info os.FileInfo, euid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == euid
}

func (s *fileSink) Store(_ context.Context, token string) (string, error) {
	if err := s.write(token); err != nil {
		_ = s.out.Close()
		_ = os.Remove(s.path)
		return "", err
	}
	if err := s.out.Close(); err != nil {
		_ = os.Remove(s.path)
		return "", fmt.Errorf("close %s: %w", s.path, err)
	}
	return s.path, nil
}

func (s *fileSink) write(token string) error {
	n, err := s.out.Write([]byte(token))
	switch {
	case err != nil:
		return fmt.Errorf("write %s: %w", s.path, err)
	case n != len(token):
		return fmt.Errorf("write %s: %w", s.path, io.ErrShortWrite)
	}
	if err := s.out.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", s.path, err)
	}
	return nil
}

func (s *fileSink) Abandon() {
	_ = s.out.Close()
	_ = os.Remove(s.path)
}

// keychainSink stores the token in the OS keychain under name, never in a file.
type keychainSink struct {
	store client.CredentialStore
	name  string
}

// openKeychainSink refuses an entry that already exists: overwriting it would
// destroy a credential another client may still use.
func openKeychainSink(ctx context.Context, store client.CredentialStore, name string) (*keychainSink, error) {
	_, err := store.Get(ctx, name)
	switch {
	case err == nil:
		return nil, usageErrorf("--keychain: an entry named %q already exists", name)
	case !errors.Is(err, client.ErrNoCredential):
		return nil, usageErrorf("--keychain: cannot check for an existing entry: %s", err)
	}
	return &keychainSink{store: store, name: name}, nil
}

func (k *keychainSink) Store(ctx context.Context, token string) (string, error) {
	location, err := k.store.Set(ctx, k.name, token)
	if err != nil {
		_ = k.store.Delete(ctx, k.name)
		return "", fmt.Errorf("keychain entry %q: %w", k.name, err)
	}
	return fmt.Sprintf("%s entry %q", location, k.name), nil
}

func (k *keychainSink) Abandon() {}
