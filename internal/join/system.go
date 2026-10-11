package join

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/autarquico/supermgmt/internal/config"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	maxAddresses = 16
	// sbinPath is appended to PATH: useradd and usermod live in directories a
	// minimal environment (sudo, cron) often lacks.
	sbinPath = ":/usr/local/sbin:/usr/sbin:/sbin"
)

// System is the Host backed by the machine it runs on. Root prefixes every
// path it reads or writes (empty on a real node); tests point it at a temporary tree.
type System struct {
	Root string
	// Run executes a program; the default runs it with the sbin directories on PATH.
	Run func(ctx context.Context, name string, args ...string) error
}

var _ Host = System{}

func (s System) path(p string) string { return filepath.Join(s.Root, p) }

// Preflight requires root, and useradd unless the account already exists.
func (s System) Preflight() error {
	if os.Geteuid() != 0 {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "sm join must run as root (use sudo)")
	}
	if _, found, err := s.LookupAccount(config.DefaultSSHUser); err == nil && found {
		return nil
	}
	if _, err := lookPathWithSbin("useradd"); err != nil {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "useradd was not found: sm join supports Linux with the shadow-utils tools")
	}
	return nil
}

func lookPathWithSbin(name string) (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH") + sbinPath) {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 { //nolint:gosec // candidate is a PATH entry joined with a constant program name
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func (s System) Hostname() (string, error) { return os.Hostname() }

// Addresses lists the node's global unicast addresses, for the operator's
// reference; the server decides for itself where it reaches the node.
func (s System) Addresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.IsGlobalUnicast() && len(out) < maxAddresses {
			out = append(out, ipNet.IP.String())
		}
	}
	return out
}

func (s System) ReadFile(path string) ([]byte, error) { return os.ReadFile(s.path(path)) }

// LookupAccount reads /etc/passwd and /etc/group directly: the entry must be
// exactly what useradd wrote, and nothing here depends on the name service.
func (s System) LookupAccount(name string) (Account, bool, error) {
	passwd, err := os.ReadFile(s.path("/etc/passwd"))
	if err != nil {
		return Account{}, false, err
	}
	fields, found := entryNamed(passwd, name, 7)
	if !found {
		return Account{}, false, nil
	}
	uid, uidErr := strconv.Atoi(fields[2])
	gid, gidErr := strconv.Atoi(fields[3])
	if uidErr != nil || gidErr != nil {
		return Account{}, false, fmt.Errorf("malformed passwd entry for %s", name)
	}
	account := Account{UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}
	if group, err := os.ReadFile(s.path("/etc/group")); err == nil {
		account.PrimaryGroup = groupNamed(group, gid)
	}
	return account, true, nil
}

func entryNamed(db []byte, name string, minFields int) ([]string, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(db))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= minFields && fields[0] == name {
			return fields, true
		}
	}
	return nil, false
}

func groupNamed(db []byte, gid int) string {
	scanner := bufio.NewScanner(bytes.NewReader(db))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 3 && fields[2] == strconv.Itoa(gid) {
			return fields[0]
		}
	}
	return ""
}

func (s System) AddAccount(ctx context.Context, name string) error {
	return s.run(ctx, "useradd", "--system", "--user-group", "--home-dir", templates.HomeDir, "--create-home", "--shell", "/bin/sh", name)
}

func (s System) DisablePassword(ctx context.Context, name string) error {
	return s.run(ctx, "usermod", "-p", "*", name)
}

func (s System) run(ctx context.Context, name string, args ...string) error {
	if s.Run != nil {
		return s.Run(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // name is useradd or usermod, chosen by this package
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+sbinPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureDir makes path a directory with the given mode and owner. A symlink in
// its place is refused: everything below the home directory belongs to the
// dedicated user, who could otherwise redirect root's writes.
func (s System) EnsureDir(path string, mode fs.FileMode, owner string) error {
	account, err := s.owner(owner)
	if err != nil {
		return err
	}
	real := s.path(path)
	info, err := os.Lstat(real)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(real, mode); err != nil {
			return err
		}
	case err != nil:
		return err
	case !info.IsDir():
		return smerr.New(smerr.CodeConflict, "", path+" exists and is not a directory")
	}
	if err := os.Chmod(real, mode); err != nil {
		return err
	}
	return os.Lchown(real, account.UID, account.GID)
}

// InstallFile writes data to a fresh sibling file (never through a symlink)
// and renames it over path.
func (s System) InstallFile(path string, data []byte, mode fs.FileMode, owner string) error {
	account, err := s.owner(owner)
	if err != nil {
		return err
	}
	real := s.path(path)
	staged := real + templates.StagingSuffix
	if err := os.Remove(staged); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := writeStaged(staged, data, mode, account); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, real); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return nil
}

func writeStaged(staged string, data []byte, mode fs.FileMode, owner Account) error {
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode) //nolint:gosec // staged is a fixed node path; O_EXCL|O_NOFOLLOW refuse planted links
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Chown(owner.UID, owner.GID); err != nil {
		return err
	}
	return f.Sync()
}

func (s System) owner(name string) (Account, error) {
	account, found, err := s.LookupAccount(name)
	if err != nil {
		return Account{}, err
	}
	if !found {
		return Account{}, fmt.Errorf("account %s does not exist", name)
	}
	return account, nil
}
