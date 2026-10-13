package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Host-mutating tests (ADR-0036) install SuperMgmt on the machine that runs them. This guard makes
// that safe: it refuses unless the machine is disposable and holds no installation yet, and it
// removes whatever the test left behind, also when the test failed.

// HostProbe is the view of the machine the guard judges. Production code uses OSHostProbe.
type HostProbe struct {
	Getenv func(string) string
	Exists func(path string) bool
	GOOS   string
	Home   string
	// PID1 is the name of the process with PID 1 ("" when unknown).
	PID1 func() string
}

// OSHostProbe probes the real machine.
func OSHostProbe() HostProbe {
	home, _ := os.UserHomeDir()
	return HostProbe{
		Getenv: os.Getenv,
		Exists: func(path string) bool { _, err := os.Lstat(path); return err == nil },
		GOOS:   runtime.GOOS,
		Home:   home,
		PID1:   linuxPID1,
	}
}

func linuxPID1() string {
	name, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(name))
}

// installMarkers are the paths whose existence means a SuperMgmt installation is present. The
// installer prefers a system installation whenever its binary or unit exists, so any leftover
// would change what later steps operate on.
func (p HostProbe) installMarkers() []string {
	markers := []string{
		"/usr/local/bin/sm",
		"/etc/systemd/system/supermgmt.service",
		"/etc/supermgmt",
		"/var/lib/supermgmt",
		filepath.Join(p.Home, ".local", "bin", "sm"),
		filepath.Join(p.Home, ".config", "systemd", "user", "supermgmt.service"),
		filepath.Join(p.Home, ".config", "supermgmt"),
		filepath.Join(p.Home, ".local", "share", "supermgmt"),
		filepath.Join(p.Home, "Library", "LaunchAgents", "dev.supermgmt.daemon.plist"),
		filepath.Join(p.Home, "Library", "Application Support", "SuperMgmt"),
	}
	if xdg := p.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		markers = append(markers,
			filepath.Join(xdg, "systemd", "user", "supermgmt.service"),
			filepath.Join(xdg, "supermgmt"))
	}
	return markers
}

// RequireDisposable fails unless the machine may be mutated: SM_E2E_VM=1 plus either a GitHub-hosted
// runner identity or systemd as PID 1 (the e2e container).
func (p HostProbe) RequireDisposable() error {
	if p.Getenv("SM_E2E_VM") != "1" {
		return errors.New("host-mutating tests need SM_E2E_VM=1")
	}
	githubHosted := p.Getenv("GITHUB_ACTIONS") == "true" && p.Getenv("RUNNER_ENVIRONMENT") == "github-hosted"
	systemdContainer := p.GOOS == "linux" && p.PID1 != nil && p.PID1() == "systemd"
	if !githubHosted && !systemdContainer {
		return errors.New("host-mutating tests need a disposable runner " +
			"(GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted) or systemd as PID 1 in the e2e container")
	}
	return nil
}

// RequireNoInstall fails when any server layout, user layout, unit or launchd plist exists.
func (p HostProbe) RequireNoInstall() error {
	var found []string
	for _, path := range p.installMarkers() {
		if p.Exists(path) {
			found = append(found, path)
		}
	}
	if len(found) > 0 {
		return fmt.Errorf("an installation already exists, refusing to mutate the host: %s", strings.Join(found, ", "))
	}
	return nil
}

// HostGuard proves the disposable-host checks passed; only it can clean the host up.
type HostGuard struct {
	probe HostProbe
	run   func(name string, args ...string)
	rm    func(path string) error
}

// AcquireHost checks that the host is disposable and clean.
func AcquireHost(p HostProbe) (*HostGuard, error) {
	if err := p.RequireDisposable(); err != nil {
		return nil, err
	}
	if err := p.RequireNoInstall(); err != nil {
		return nil, err
	}
	return &HostGuard{probe: p, run: bestEffort, rm: os.RemoveAll}, nil
}

// Cleanup stops the services and removes every installation path.
func (g *HostGuard) Cleanup() error {
	g.stopServices()
	var errs []error
	for _, path := range g.probe.installMarkers() {
		if g.probe.Exists(path) {
			errs = append(errs, g.rm(path))
		}
	}
	return errors.Join(errs...)
}

func (g *HostGuard) stopServices() {
	if g.probe.GOOS == "darwin" {
		g.run("launchctl", "bootout", "gui/"+g.probe.Getenv("UID"), "dev.supermgmt.daemon")
		return
	}
	g.run("systemctl", "disable", "--now", "supermgmt.service")
	g.run("systemctl", "--user", "disable", "--now", "supermgmt.service")
}

func bestEffort(name string, args ...string) {
	_ = exec.CommandContext(context.Background(), name, args...).Run() //nolint:gosec // fixed teardown commands of the guard, never test input
}

// RequireHostLifecycle is the entry point of every host-mutating test: it fails the test unless the
// host is disposable and clean, and registers the cleanup that runs even when the test fails.
func RequireHostLifecycle(t testing.TB) *HostGuard {
	t.Helper()
	g, err := AcquireHost(OSHostProbe())
	if err != nil {
		t.Fatalf("host-mutation guard: %v", err)
	}
	t.Cleanup(func() {
		if err := g.Cleanup(); err != nil {
			t.Errorf("host cleanup: %v", err)
		}
	})
	return g
}
