//go:build e2e

// Package harness drives the M2 acceptance e2e tests: Docker containers (a Debian systemd host,
// Dex, a TLS proxy, a release mirror), a throwaway PKI, a signed release and the `sm` client
// on the test machine. Everything shells out to the docker CLI, like test/fixtures.
package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RepoRoot is the repository root, derived from this file's location.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// Result is a finished command.
type Result struct {
	Stdout, Stderr string
	Code           int
}

// commandError describes a command that failed to start or exited non-zero; nil when it succeeded.
func commandError(what string, res Result, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w\n%s", what, err, res.Output())
	case res.Code != 0:
		return fmt.Errorf("%s: exit %d\n%s", what, res.Code, res.Output())
	}
	return nil
}

// Output is stdout and stderr together, for failure messages.
func (r Result) Output() string { return strings.TrimSpace(r.Stdout + r.Stderr) }

// Run executes a command and returns its result; the error is set only when it could not start.
func Run(ctx context.Context, dir string, env []string, stdin string, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errOut.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.Code = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}

// Docker runs the docker CLI.
func Docker(ctx context.Context, stdin string, args ...string) (Result, error) {
	return Run(ctx, "", nil, stdin, "docker", args...)
}

// MustDocker runs docker and fails the test on any non-zero exit.
func MustDocker(t testing.TB, args ...string) string {
	t.Helper()
	res, err := Docker(context.Background(), "", args...)
	if err != nil || res.Code != 0 {
		t.Fatalf("docker %s: %v (exit %d)\n%s", strings.Join(args, " "), err, res.Code, res.Output())
	}
	return strings.TrimSpace(res.Stdout)
}

// Suffix returns a short random name suffix.
func Suffix() string { return strings.ToLower(rand.Text()[:8]) }

// Network is a user-defined docker bridge: its members get private, non-loopback addresses and
// resolve each other by name.
type Network struct{ Name string }

// NewNetwork creates a network removed at the end of the test.
func NewNetwork(t testing.TB) *Network {
	t.Helper()
	n := &Network{Name: "sm-e2e-" + Suffix()}
	MustDocker(t, "network", "create", n.Name)
	t.Cleanup(func() { _, _ = Docker(context.Background(), "", "network", "rm", n.Name) })
	return n
}

// Container is a running container.
type Container struct {
	Name string
	t    testing.TB
}

// RunOptions describe docker run.
type RunOptions struct {
	Image      string
	Name       string
	Network    string   // network name, or "container:<name>" to share a network namespace
	Aliases    []string // network aliases
	Publish    []string // container ports published on 127.0.0.1 with a random host port
	Privileged bool     // systemd as PID 1
	Cmd        []string
	// Files are copied into the container before it starts: container path -> host path.
	Files map[string]string
}

// Start creates, populates and starts a container removed at the end of the test.
func Start(t testing.TB, o RunOptions) *Container {
	t.Helper()
	name := o.Name
	if name == "" {
		name = "sm-e2e-" + Suffix()
	}
	args := []string{"create", "--name", name}
	if o.Privileged {
		args = append(args, "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock")
	}
	if o.Network != "" {
		args = append(args, "--network", o.Network)
	}
	for _, a := range o.Aliases {
		args = append(args, "--network-alias", a)
	}
	for _, p := range o.Publish {
		args = append(args, "--publish", "127.0.0.1::"+p)
	}
	args = append(args, o.Image)
	args = append(args, o.Cmd...)
	MustDocker(t, args...)
	c := &Container{Name: name, t: t}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("container %s logs:\n%s", name, tail(c.Logs(), 4000))
		}
		_, _ = Docker(context.Background(), "", "rm", "--force", "--volumes", name)
	})
	for dst, src := range o.Files {
		c.Copy(src, dst)
	}
	MustDocker(t, "start", name)
	return c
}

// Adopt wraps a container somebody else started (and will remove), such as a node fixture.
func Adopt(t testing.TB, name string) *Container { return &Container{Name: name, t: t} }

// Connect attaches a container to a network, with optional aliases.
func (c *Container) Connect(net *Network, aliases ...string) {
	c.t.Helper()
	args := []string{"network", "connect"}
	for _, a := range aliases {
		args = append(args, "--alias", a)
	}
	MustDocker(c.t, append(args, net.Name, c.Name)...)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// Logs returns the console output.
func (c *Container) Logs() string {
	res, _ := Docker(context.Background(), "", "logs", c.Name)
	return res.Output()
}

// Exec runs a command as root inside the container.
func (c *Container) Exec(ctx context.Context, stdin string, argv ...string) Result {
	c.t.Helper()
	args := []string{"exec"}
	if stdin != "" {
		args = append(args, "-i")
	}
	res, err := Docker(ctx, stdin, append(append(args, c.Name), argv...)...)
	if err != nil {
		c.t.Fatalf("docker exec %v: %v", argv, err)
	}
	return res
}

// Env runs a command with extra environment variables.
func (c *Container) Env(ctx context.Context, stdin string, env map[string]string, argv ...string) Result {
	c.t.Helper()
	args := []string{"exec"}
	if stdin != "" {
		args = append(args, "-i")
	}
	for k, v := range env {
		args = append(args, "--env", k+"="+v)
	}
	res, err := Docker(ctx, stdin, append(append(args, c.Name), argv...)...)
	if err != nil {
		c.t.Fatalf("docker exec %v: %v", argv, err)
	}
	return res
}

// MustExec runs a command and fails the test on a non-zero exit.
func (c *Container) MustExec(ctx context.Context, argv ...string) string {
	c.t.Helper()
	res := c.Exec(ctx, "", argv...)
	if res.Code != 0 {
		c.t.Fatalf("%s: %v exited %d\n%s", c.Name, argv, res.Code, res.Output())
	}
	return strings.TrimSpace(res.Stdout)
}

// Copy copies a host file into the container (docker cp keeps the host owner's numeric ids, so
// the file is chowned to root).
func (c *Container) Copy(src, dst string) {
	c.t.Helper()
	MustDocker(c.t, "cp", src, c.Name+":"+dst)
}

// CopyRoot copies a host file and makes it root-owned.
func (c *Container) CopyRoot(ctx context.Context, src, dst string) {
	c.t.Helper()
	c.Copy(src, dst)
	c.MustExec(ctx, "chown", "-R", "0:0", dst)
}

// Fetch returns a file's content.
func (c *Container) Fetch(ctx context.Context, path string) (string, error) {
	res := c.Exec(ctx, "", "cat", path)
	if res.Code != 0 {
		return "", fmt.Errorf("cat %s: %s", path, res.Output())
	}
	return res.Stdout, nil
}

// Address is the container's IP on the named network.
func (c *Container) Address(network string) string {
	c.t.Helper()
	return MustDocker(c.t, "inspect", "--format", fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", network), c.Name)
}

// HostPort is the host port a container port is published on (127.0.0.1).
func (c *Container) HostPort(containerPort string) int {
	c.t.Helper()
	out := MustDocker(c.t, "port", c.Name, containerPort+"/tcp")
	line := strings.Fields(strings.Split(out, "\n")[0])
	addr := line[len(line)-1]
	port, err := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
	if err != nil {
		c.t.Fatalf("parse published port %q: %v", out, err)
	}
	return port
}

// WaitSystemd blocks until systemd reports a settled state.
func (c *Container) WaitSystemd(ctx context.Context) {
	c.t.Helper()
	deadline := Now().Add(2 * time.Minute)
	for Now().Before(deadline) {
		res := c.Exec(ctx, "", "systemctl", "is-system-running")
		if state := strings.TrimSpace(res.Stdout); state == "running" || state == "degraded" {
			return
		}
		time.Sleep(time.Second)
	}
	c.t.Fatalf("%s: systemd did not settle\n%s", c.Name, tail(c.Logs(), 2000))
}

// WriteFile puts content at a container path with the given mode, owned by root.
func (c *Container) WriteFile(ctx context.Context, path string, content []byte, mode string) {
	c.t.Helper()
	dir := c.t.TempDir()
	src := filepath.Join(dir, filepath.Base(path))
	if err := os.WriteFile(src, content, 0o600); err != nil {
		c.t.Fatal(err)
	}
	c.MustExec(ctx, "mkdir", "-p", filepath.Dir(path))
	c.CopyRoot(ctx, src, path)
	c.MustExec(ctx, "chmod", mode, path)
}
