package pvesim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DockerEngine runs each guest as a privileged systemd container on Network, the way the e2e
// harness runs every Debian host. Guests carry Label so a crashed run can be swept.
type DockerEngine struct {
	Image   string
	Network string
	Label   string
	// AfterStart are commands run in a guest right after it booted: a hook for hosts that need a
	// workaround (the e2e suite uses it for emulated amd64 binaries).
	AfterStart [][]string
}

const systemdAttempts = 120 // one second apart

func (d DockerEngine) docker(ctx context.Context, stdin []byte, args ...string) (ExecResult, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // the docker CLI with arguments built by the harness
	cmd.Stdin = bytes.NewReader(stdin)                 // always a pipe, never a terminal: the tools run without one
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	res := ExecResult{Stdout: out.Bytes(), Stderr: errOut.Bytes()}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		res.Code = exit.ExitCode()
		return res, nil
	}
	return res, err
}

func (d DockerEngine) must(ctx context.Context, args ...string) error {
	res, err := d.docker(ctx, nil, args...)
	switch {
	case err != nil:
		return fmt.Errorf("docker %s: %w", args[0], err)
	case res.Code != 0:
		return fmt.Errorf("docker %s: exit %d: %s", args[0], res.Code, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Create makes the container without starting it.
func (d DockerEngine) Create(ctx context.Context, name string, spec ContainerSpec) error {
	args := []string{
		"create", "--name", name, "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock",
		"--hostname", spec.Hostname, "--network", d.Network, "--label", d.Label,
	}
	if spec.IP != "" {
		args = append(args, "--ip", spec.IP)
	}
	return d.must(ctx, append(args, d.Image)...)
}

// Start boots the container and waits for systemd to settle, as `pct start` returns when the
// container is up.
func (d DockerEngine) Start(ctx context.Context, name string) error {
	if err := d.must(ctx, "start", name); err != nil {
		return err
	}
	for range systemdAttempts {
		res, err := d.docker(ctx, nil, "exec", name, "systemctl", "is-system-running")
		if err != nil {
			return err
		}
		if state := strings.TrimSpace(string(res.Stdout)); state == "running" || state == "degraded" {
			return d.afterStart(ctx, name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("systemd of %s did not settle", name)
}

func (d DockerEngine) afterStart(ctx context.Context, name string) error {
	for _, argv := range d.AfterStart {
		if err := d.must(ctx, append([]string{"exec", name}, argv...)...); err != nil {
			return err
		}
	}
	return nil
}

// Stop halts the container (systemd receives its clean-shutdown signal).
func (d DockerEngine) Stop(ctx context.Context, name string) error {
	return d.must(ctx, "stop", "--time", "60", name)
}

// Remove deletes the container and its anonymous volumes.
func (d DockerEngine) Remove(ctx context.Context, name string) error {
	return d.must(ctx, "rm", "--force", "--volumes", name)
}

// Exec runs argv as root in the container, never through a shell.
func (d DockerEngine) Exec(ctx context.Context, name string, argv []string, stdin []byte) (ExecResult, error) {
	return d.docker(ctx, stdin, append([]string{"exec", "-i", name}, argv...)...)
}

// RemoveLabelled deletes every guest container left behind with Label.
func (d DockerEngine) RemoveLabelled(ctx context.Context) {
	res, err := d.docker(ctx, nil, "ps", "--all", "--quiet", "--filter", "label="+d.Label)
	if err != nil {
		return
	}
	for _, id := range strings.Fields(string(res.Stdout)) {
		_ = d.must(ctx, "rm", "--force", "--volumes", id)
	}
}
