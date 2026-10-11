package installer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
			GOOS: runtime.GOOS, UID: os.Geteuid(), Home: values["HOME"], Env: values,
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
	if prompts != nil {
		d.Prompter = linePrompter{in: bufio.NewReader(prompts), out: out}
	}
	return d
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

func (s systemd) systemctl(ctx context.Context, args ...string) error {
	if s.user {
		args = append([]string{"--user"}, args...)
	}
	_, err := s.runner.Run(ctx, Command{Name: "systemctl", Args: args})
	return err
}

func (s systemd) Register(ctx context.Context, u Unit) error {
	if err := s.systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	return s.systemctl(ctx, "enable", u.Name)
}

// Start restarts, so a reinstall picks up the new binary.
func (s systemd) Start(ctx context.Context, u Unit) error { return s.systemctl(ctx, "restart", u.Name) }

type launchd struct {
	runner Runner
	uid    int
}

func (launchd) Register(context.Context, Unit) error { return nil }

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
	cmd.Stderr = r.stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if c.User != "" {
		cred, err := credentialOf(c.User)
		if err != nil {
			return nil, err
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.Bytes(), &ExitStatus{Command: c.Name, Code: exit.ExitCode()}
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
		if last = getReady(ctx, client, p.URL); last == nil {
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

func getReady(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
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
