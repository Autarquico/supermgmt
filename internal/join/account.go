package join

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Account is a passwd entry.
type Account struct {
	UID, GID     int
	Home, Shell  string
	PrimaryGroup string
}

// Host is the node as join sees it. The system implementation runs as root;
// tests substitute a recording fake.
type Host interface {
	// Preflight fails, before anything is asked of the server, when this
	// process cannot finish joining (not root, no useradd).
	Preflight() error
	Hostname() (string, error)
	Addresses() []string
	ReadFile(path string) ([]byte, error)
	LookupAccount(name string) (Account, bool, error)
	AddAccount(ctx context.Context, name string) error
	// DisablePassword sets the password field to "*": no password, but not
	// locked, so sshd with UsePAM no still accepts keys (ADR-0009).
	DisablePassword(ctx context.Context, name string) error
	EnsureDir(path string, mode fs.FileMode, owner string) error
	// InstallFile replaces path atomically: the node holds the old file or the
	// new one, never a part.
	InstallFile(path string, data []byte, mode fs.FileMode, owner string) error
}

const (
	maxSystemUID = 999
	homeMode     = 0o750
	privateMode  = 0o700
	keysMode     = 0o600
)

// Provision runs the ADR-0009 user steps for an enrolled node as root: the
// dedicated account (created, or kept only if it is exactly ours), its
// directories, and the single restricted authorized_keys line. Nothing else:
// no sudoers and no group membership (ADR-0022).
func Provision(ctx context.Context, host Host, e wire.Enrolled) error {
	user := e.SSHUser
	if user != config.DefaultSSHUser {
		return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("the server named the account %q; only %q can be provisioned", user, config.DefaultSSHUser))
	}
	line, err := systemd.AuthorizedKeys(user, e.AuthorizedKey, e.InstanceID.String())
	if err != nil {
		return fmt.Errorf("the server sent an unusable key: %w", err)
	}
	if err := ensureAccount(ctx, host, user); err != nil {
		return err
	}
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{{templates.HomeDir, homeMode}, {templates.MarkerDir, privateMode}, {templates.SSHDir, privateMode}} {
		if err := host.EnsureDir(d.path, d.mode, user); err != nil {
			return fmt.Errorf("prepare %s: %w", d.path, err)
		}
	}
	if err := host.InstallFile(templates.AuthorizedKeysPath, []byte(line), keysMode, user); err != nil {
		return fmt.Errorf("install %s: %w", templates.AuthorizedKeysPath, err)
	}
	return nil
}

// ensureAccount creates the account or keeps one that is exactly ours; any
// other account of that name is a CONFLICT, never hijacked. The password field
// is set on every run, so a run interrupted between creation and that step
// converges.
func ensureAccount(ctx context.Context, host Host, user string) error {
	found, err := checkAccount(host, user)
	if err != nil {
		return err
	}
	if !found {
		if err := host.AddAccount(ctx, user); err != nil {
			return fmt.Errorf("create %s: %w", user, err)
		}
	}
	if err := host.DisablePassword(ctx, user); err != nil {
		return fmt.Errorf("set the password field of %s: %w", user, err)
	}
	return nil
}

// checkAccount reports whether the account exists, and refuses one that is not
// exactly ours. It changes nothing.
func checkAccount(host Host, user string) (found bool, err error) {
	account, found, err := host.LookupAccount(user)
	if err != nil {
		return false, fmt.Errorf("look up %s: %w", user, err)
	}
	if found && !isOurs(account, user) {
		return false, smerr.New(smerr.CodeConflict, "", fmt.Sprintf("account %s already exists and is not the SuperMgmt service account", user))
	}
	return found, nil
}

func isOurs(a Account, user string) bool {
	return a.UID >= 1 && a.UID <= maxSystemUID && a.Home == templates.HomeDir && a.Shell == "/bin/sh" && a.PrimaryGroup == user
}
