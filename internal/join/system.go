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
	"time"

	"github.com/autarquico/supermgmt/internal/config"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	maxAddresses = 16
	// asUserTimeout bounds one step run as the service user; the Host methods take no context.
	asUserTimeout = time.Minute
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
	// AsUser runs a sh script as the named user with args as $1...; the default
	// uses runuser, as node.setup does.
	AsUser func(ctx context.Context, user string, stdin []byte, script string, args ...string) error
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

// EnsureDir makes path a directory with the given mode and owner. The home
// directory itself is root's to check (its parent is root-owned); everything
// below it belongs to the dedicated user, who could redirect root's writes
// with a symlink, so those steps run as that user (ADR-0009).
func (s System) EnsureDir(path string, mode fs.FileMode, owner string) error {
	if path != templates.HomeDir {
		return s.asUser(owner, nil, ensureOwnDirScript, s.path(path), fmt.Sprintf("%04o", mode.Perm()))
	}
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

// InstallFile has the dedicated user write data to a fresh sibling file and
// rename it over path: root never touches the user's directories.
func (s System) InstallFile(path string, data []byte, mode fs.FileMode, owner string) error {
	real := s.path(path)
	return s.asUser(owner, data, installOwnFileScript, real, real+templates.StagingSuffix, fmt.Sprintf("%04o", mode.Perm()))
}

// The scripts mirror the setup.own_* templates of node.setup. A symlink swapped
// in after the check can only redirect the dedicated user's own privileges.
const (
	ensureOwnDirScript   = `test ! -L "$1" && install -d -m "$2" -- "$1" && chmod "$2" "$1"`
	installOwnFileScript = `umask 077; rm -f -- "$2"; if (set -C; cat >"$2") && chmod "$3" "$2" && mv -f -- "$2" "$1"; then :; else rm -f -- "$2"; exit 1; fi`
)

func (s System) asUser(user string, stdin []byte, script string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), asUserTimeout)
	defer cancel()
	if s.AsUser != nil {
		return s.AsUser(ctx, user, stdin, script, args...)
	}
	cmd := exec.CommandContext(ctx, "runuser", append([]string{"-u", user, "--", "sh", "-c", script, "sh"}, args...)...) //nolint:gosec // script is a constant of this package
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+sbinPath)
	cmd.Stdin = bytes.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("as %s: %w: %s", user, err, strings.TrimSpace(string(out)))
	}
	return nil
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
