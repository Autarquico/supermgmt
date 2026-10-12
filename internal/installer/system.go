package installer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// SystemDeps wires the real host. prompts is the terminal to ask on, or nil
// for non-interactive runs. env is the process environment ("KEY=value").
func SystemDeps(out io.Writer, prompts io.Reader, env []string) Deps {
	values := make(map[string]string, len(env))
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			values[k] = v
		}
	}
	runner := execRunner{stderr: os.Stderr}
	d := Deps{
		Host: Host{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, UID: os.Geteuid(), Home: values["HOME"], Env: values,
			HasSystemd: dirExists("/run/systemd/system"),
		},
		Files:    osFiles{},
		Accounts: osAccounts{runner: runner},
		Services: systemd{runner: runner},
		Runner:   runner,
		Health:   httpHealth{},
		Clock:    domain.SystemClock{},
		Out:      out,
	}
	if runtime.GOOS == "darwin" {
		d.UserServices = launchd{runner: runner, uid: os.Geteuid()}
	} else {
		d.UserServices = systemd{runner: runner, user: true}
	}
	if fileExecutable(pveVersionTool) {
		d.PVE = newExecPVE(runner)
	}
	if prompts != nil {
		d.Prompter = linePrompter{in: bufio.NewReader(prompts), out: out}
	}
	return d
}

func fileExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// ---- files ----

type osFiles struct{}

func (osFiles) Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Lstat describes path itself: a symlink is reported as neither a directory nor a regular file.
func (osFiles) Lstat(path string) (EntryInfo, error) {
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return EntryInfo{}, err
	}
	uid := -1
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(st.Uid)
	}
	return EntryInfo{Dir: info.IsDir(), Regular: info.Mode().IsRegular(), UID: uid, Mode: info.Mode().Perm()}, nil
}

func (osFiles) ReadFile(path string) ([]byte, error) { return os.ReadFile(filepath.Clean(path)) }

func (osFiles) RemoveAll(path string) error { return os.RemoveAll(path) }

func (osFiles) MkdirAll(path string, mode fs.FileMode, owner Owner) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return chown(path, owner)
}

func (osFiles) WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error {
	return writeAtomic(path, mode, owner, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func (osFiles) CopyFile(src, dst string, mode fs.FileMode, owner Owner) error {
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	return writeAtomic(dst, mode, owner, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

func (osFiles) AppendSync(path string, line []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (osFiles) SyncDir(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

func (osFiles) Rename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

func (osFiles) Link(oldPath, newPath string) error { return os.Link(oldPath, newPath) }

func (osFiles) Hash(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Lock takes an exclusive, non-blocking advisory lock on path and returns its
// release. The lock dies with the process, so a crash never leaves it stale.
func (osFiles) Lock(path string) (func(), error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

// ListDir returns the names in dir; a missing directory is empty.
func (osFiles) ListDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func writeAtomic(path string, mode fs.FileMode, owner Owner, fill func(io.Writer) error) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sm-install-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if err = chown(tmp.Name(), owner); err != nil {
		return err
	}
	if err = fill(tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func chown(path string, owner Owner) error {
	uid, gid := -1, -1
	if owner.User != "" {
		u, err := user.Lookup(owner.User)
		if err != nil {
			return err
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if owner.Group != "" {
		g, err := user.LookupGroup(owner.Group)
		if err != nil {
			return err
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	if uid == -1 && gid == -1 {
		return nil
	}
	return os.Chown(path, uid, gid)
}

// ---- accounts, services, subprocesses ----

type osAccounts struct{ runner Runner }

func (osAccounts) UserExists(name string) (bool, error) {
	_, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return false, nil
	}
	return err == nil, err
}

func (a osAccounts) CreateServiceUser(ctx context.Context, name, home string) error {
	_, err := a.runner.Run(ctx, Command{Name: "useradd", Args: []string{
		"--system", "--user-group", "--home-dir", home, "--no-create-home", "--shell", "/usr/sbin/nologin", name,
	}})
	return err
}

type systemd struct {
	runner Runner
	user   bool
}

func (s systemd) systemctl(ctx context.Context, args ...string) ([]byte, error) {
	if s.user {
		args = append([]string{"--user"}, args...)
	}
	return s.runner.Run(ctx, Command{Name: "systemctl", Args: args})
}

func (s systemd) Register(ctx context.Context, u Unit) error {
	if err := s.Load(ctx, u); err != nil {
		return err
	}
	_, err := s.systemctl(ctx, "enable", u.Name)
	return err
}

// Load makes systemd read the unit file; the unit stays disabled.
func (s systemd) Load(ctx context.Context, _ Unit) error {
	_, err := s.systemctl(ctx, "daemon-reload")
	return err
}

// Start restarts, so a reinstall picks up the new binary.
func (s systemd) Start(ctx context.Context, u Unit) error {
	_, err := s.systemctl(ctx, "restart", u.Name)
	return err
}

func (s systemd) Stop(ctx context.Context, u Unit) error {
	_, err := s.systemctl(ctx, "stop", u.Name)
	return err
}

func (s systemd) Disable(ctx context.Context, u Unit) error {
	_, err := s.systemctl(ctx, "disable", u.Name)
	return err
}

// WaitStopped polls until the unit is inactive and its main process is gone.
func (s systemd) WaitStopped(ctx context.Context, u Unit, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		out, err := s.systemctl(ctx, "show", "--property=ActiveState", "--property=MainPID", u.Name)
		if err == nil && stoppedState(string(out)) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("unit %s did not stop within %s", u.Name, timeout)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func stoppedState(show string) bool {
	state, pid := "", ""
	for _, line := range strings.Split(show, "\n") {
		switch k, v, _ := strings.Cut(strings.TrimSpace(line), "="); k {
		case "ActiveState":
			state = v
		case "MainPID":
			pid = v
		}
	}
	return (state == "inactive" || state == "failed") && (pid == "0" || pid == "")
}

type launchd struct {
	runner Runner
	uid    int
}

func (launchd) Register(context.Context, Unit) error { return nil }

func (launchd) Load(context.Context, Unit) error { return nil }

func (launchd) Disable(context.Context, Unit) error { return nil }

// Stop boots the agent out; bootout returns once the job is gone.
func (l launchd) Stop(ctx context.Context, u Unit) error {
	_, err := l.runner.Run(ctx, Command{Name: "launchctl", Args: []string{"bootout", "gui/" + strconv.Itoa(l.uid), u.Path}})
	return err
}

func (launchd) WaitStopped(context.Context, Unit, time.Duration) error { return nil }

func (l launchd) Start(ctx context.Context, u Unit) error {
	target := "gui/" + strconv.Itoa(l.uid)
	_, _ = l.runner.Run(ctx, Command{Name: "launchctl", Args: []string{"bootout", target, u.Path}}) // absent on first install
	_, err := l.runner.Run(ctx, Command{Name: "launchctl", Args: []string{"bootstrap", target, u.Path}})
	return err
}

type execRunner struct{ stderr io.Writer }

func (r execRunner) Run(ctx context.Context, c Command) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...) //nolint:gosec // fixed argument vectors, never shell strings
	cmd.Stdin = c.Stdin
	var stdout, hidden bytes.Buffer
	cmd.Stdout = &stdout
	if c.Sensitive {
		cmd.Stderr = &hidden // may carry a secret: kept in memory, never shown
	} else {
		cmd.Stderr = r.stderr
	}
	if c.User != "" {
		cred, err := credentialOf(c.User)
		if err != nil {
			return nil, err
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		out := stdout.Bytes()
		if c.Sensitive {
			out = nil
		}
		return out, &ExitStatus{Command: c.Name, Code: exit.ExitCode()}
	case err != nil && c.Sensitive:
		return nil, errors.New(c.Name + " could not run")
	}
	return stdout.Bytes(), err
}

func credentialOf(name string) (*syscall.Credential, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, nil
}

// ---- health and prompts ----

type httpHealth struct{}

func (httpHealth) WaitReady(ctx context.Context, p Probe, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := probeClient(p)
	if err != nil {
		return err
	}
	var last error
	for {
		if last = getReady(ctx, client, p); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %w)", ctx.Err(), last)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// probeClient trusts exactly the configured certificate for direct TLS.
func probeClient(p Probe) (*http.Client, error) {
	transport := &http.Transport{}
	if p.RootPEM != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(p.RootPEM) {
			return nil, errors.New("certificate file holds no PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: p.ServerName}
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, nil
}

func getReady(ctx context.Context, client *http.Client, p Probe) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return err
	}
	if p.ForwardedProto != "" {
		req.Header.Set("X-Forwarded-Proto", p.ForwardedProto)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

type linePrompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p linePrompter) Ask(question string) (string, error) {
	_, _ = fmt.Fprintf(p.out, "%s: ", question)
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (p linePrompter) Confirm(question string) (bool, error) {
	answer, err := p.Ask(question + " [y/N]")
	if err != nil {
		return false, err
	}
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}
