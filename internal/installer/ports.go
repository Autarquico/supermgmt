package installer

import (
	"context"
	"io"
	"io/fs"
	"strconv"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Owner names the account that owns a file; the zero value leaves ownership alone.
type Owner struct{ User, Group string }

// Files is the file system seam. Writes are atomic (temp file and rename).
type Files interface {
	Exists(path string) bool
	ReadFile(path string) ([]byte, error)
	MkdirAll(path string, mode fs.FileMode, owner Owner) error
	WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error
	CopyFile(src, dst string, mode fs.FileMode, owner Owner) error
	RemoveAll(path string) error
	// AppendSync appends line to path (created 0600 if absent) and fsyncs the file.
	AppendSync(path string, line []byte) error
	// SyncDir fsyncs a directory, making creations and renames inside it durable.
	SyncDir(dir string) error
	// Rename replaces newPath with oldPath atomically (same file system).
	Rename(oldPath, newPath string) error
	// Link creates newPath as a hard link to oldPath.
	Link(oldPath, newPath string) error
	// Hash returns the lowercase hex SHA-256 of a file's contents.
	Hash(path string) (string, error)
	// Lock takes an exclusive, non-blocking lock on path and returns its release.
	Lock(path string) (release func(), err error)
	// Canonical makes path absolute and resolves symlinks in its directory; the file itself may not exist.
	Canonical(path string) (string, error)
	// FreeBytes is the space available to an unprivileged writer under dir.
	FreeBytes(dir string) (uint64, error)
	// FileSize is the size in bytes of a file.
	FileSize(path string) (int64, error)
	// ListDir lists the entry names of dir; a missing directory is empty.
	ListDir(dir string) ([]string, error)
	// Lstat describes path itself, without following a final symlink.
	Lstat(path string) (EntryInfo, error)
}

// Accounts manages the service user.
type Accounts interface {
	UserExists(name string) (bool, error)
	CreateServiceUser(ctx context.Context, name, home string) error
}

// Unit is a service definition on disk.
type Unit struct{ Name, Path string }

// ServiceManager manages a unit (systemd system or user scope, or a launchd
// agent). Register makes the manager load and enable the unit; Load only makes
// it known, not enabled (`sm install server --no-start`, ADR-0026).
type ServiceManager interface {
	Register(ctx context.Context, unit Unit) error
	Load(ctx context.Context, unit Unit) error
	Start(ctx context.Context, unit Unit) error
	Stop(ctx context.Context, unit Unit) error
	Disable(ctx context.Context, unit Unit) error
	// WaitStopped returns once the unit is inactive and its main process is
	// gone, or an error after timeout (ADR-0027).
	WaitStopped(ctx context.Context, unit Unit, timeout time.Duration) error
}

// Command is one subprocess. User, when set, is the account it runs as.
// Stdin is passed through untouched, so a passphrase prompt reaches the terminal.
// Sensitive commands carry a secret on their output: stdout and stderr are
// captured in memory, never streamed, and a failure is reported without them
// (ADR-0026).
type Command struct {
	Name      string
	Args      []string
	User      string
	Stdin     io.Reader
	Sensitive bool
}

// Runner runs subprocesses and returns their stdout. A non-zero exit is an *ExitStatus.
type Runner interface {
	Run(ctx context.Context, cmd Command) ([]byte, error)
}

// ExitStatus is the failure of a subprocess that ran and exited non-zero.
type ExitStatus struct {
	Command string
	Code    int
}

func (e *ExitStatus) Error() string {
	return e.Command + " exited with status " + strconv.Itoa(e.Code)
}

// Probe says where and how to ask for readiness.
type Probe struct {
	URL        string
	ServerName string // TLS server name; empty for plain HTTP
	RootPEM    []byte // trust anchor for direct TLS; nil for plain HTTP
	// ForwardedProto is sent as X-Forwarded-Proto: a proxy-mode server refuses requests that do not
	// say TLS ended at the proxy, and the probe stands in for that proxy.
	ForwardedProto string
}

// Health waits for GET /health/ready to answer 200.
type Health interface {
	WaitReady(ctx context.Context, probe Probe, timeout time.Duration) error
}

// Prompter asks the operator; it is used only when a terminal is attached.
type Prompter interface {
	Confirm(question string) (bool, error)
	Ask(question string) (string, error)
}

// Host is what the installer knows about the machine without side effects.
type Host struct {
	GOOS       string
	GOARCH     string
	UID        int
	Home       string
	Env        map[string]string
	HasSystemd bool
}

// Deps bundles the seams. UserServices manages the resident local daemon.
type Deps struct {
	Host         Host
	Files        Files
	Accounts     Accounts
	Services     ServiceManager
	UserServices ServiceManager
	Runner       Runner
	Health       Health
	PVE          PVE      // the Proxmox host tools; nil when not on a Proxmox host
	Prompter     Prompter // nil when no terminal is attached
	Clock        domain.Clock
	Out          io.Writer
}
