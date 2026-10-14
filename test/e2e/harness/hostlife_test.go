package harness

import (
	"slices"
	"strings"
	"testing"
)

type fakeHost struct {
	env   map[string]string
	files map[string]bool
	pid1  string
	goos  string
	runs  []string
}

func (f *fakeHost) probe() HostProbe {
	return HostProbe{
		Getenv: func(k string) string { return f.env[k] },
		Exists: func(p string) bool { return f.files[p] },
		GOOS:   f.goos,
		Home:   "/home/runner",
		UID:    501,
		PID1:   func() string { return f.pid1 },
	}
}

func githubRunner() *fakeHost {
	return &fakeHost{
		env:   map[string]string{"SM_E2E_VM": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
		files: map[string]bool{}, pid1: "init", goos: "linux",
	}
}

func wantHostRefusal(t *testing.T, f *fakeHost, fragment string) {
	t.Helper()
	_, err := AcquireHost(f.probe())
	if err == nil || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("AcquireHost error = %v, want it to contain %q", err, fragment)
	}
}

func TestHostGuardAllowsACleanGitHubHostedRunner(t *testing.T) {
	if _, err := AcquireHost(githubRunner().probe()); err != nil {
		t.Fatalf("AcquireHost: %v", err)
	}
}

func TestHostGuardAllowsASystemdE2EContainer(t *testing.T) {
	f := githubRunner()
	f.env = map[string]string{"SM_E2E_VM": "1"}
	f.pid1 = "systemd"
	if _, err := AcquireHost(f.probe()); err != nil {
		t.Fatalf("AcquireHost: %v", err)
	}
}

func TestHostGuardRefusesWithoutTheOptInEnv(t *testing.T) {
	f := githubRunner()
	delete(f.env, "SM_E2E_VM")
	wantHostRefusal(t, f, "SM_E2E_VM=1")
}

func TestHostGuardRefusesWithoutRunnerIdentity(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no identity":      {"SM_E2E_VM": "1"},
		"github self-host": {"SM_E2E_VM": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
		"hosted only":      {"SM_E2E_VM": "1", "RUNNER_ENVIRONMENT": "github-hosted"},
	} {
		t.Run(name, func(t *testing.T) {
			f := githubRunner()
			f.env = env
			wantHostRefusal(t, f, "disposable runner")
		})
	}
}

func TestHostGuardRefusesSystemdPID1OnMacOS(t *testing.T) {
	f := githubRunner()
	f.env = map[string]string{"SM_E2E_VM": "1"}
	f.pid1, f.goos = "systemd", "darwin"
	wantHostRefusal(t, f, "disposable runner")
}

func TestHostGuardRefusesAnExistingInstallation(t *testing.T) {
	for _, path := range []string{
		"/usr/local/bin/sm",
		"/etc/systemd/system/supermgmt.service",
		"/var/lib/supermgmt",
		"/home/runner/.local/bin/sm",
		"/home/runner/.config/systemd/user/supermgmt.service",
		"/home/runner/Library/LaunchAgents/dev.supermgmt.daemon.plist",
	} {
		t.Run(path, func(t *testing.T) {
			f := githubRunner()
			f.files[path] = true
			wantHostRefusal(t, f, path)
		})
	}
}

func TestHostGuardRefusesAnInstallationUnderXDGConfigHome(t *testing.T) {
	f := githubRunner()
	f.env["XDG_CONFIG_HOME"] = "/xdg"
	f.files["/xdg/systemd/user/supermgmt.service"] = true
	wantHostRefusal(t, f, "/xdg/systemd/user/supermgmt.service")
}

func TestHostCleanupRemovesWhatTheTestInstalledAndStopsServices(t *testing.T) {
	f := githubRunner()
	g, err := AcquireHost(f.probe())
	if err != nil {
		t.Fatal(err)
	}
	f.files["/usr/local/bin/sm"] = true
	f.files["/var/lib/supermgmt"] = true
	var removed []string
	g.rm = func(p string) error { removed = append(removed, p); return nil }
	g.run = func(name string, args ...string) { f.runs = append(f.runs, name+" "+strings.Join(args, " ")) }

	if err := g.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(removed) != 2 || removed[0] != "/usr/local/bin/sm" || removed[1] != "/var/lib/supermgmt" {
		t.Errorf("removed = %v, want the two installed paths", removed)
	}
	if len(f.runs) != 2 || !strings.HasPrefix(f.runs[0], "systemctl disable --now") {
		t.Errorf("service stops = %v, want system and user unit disabled", f.runs)
	}
}

func TestHostCleanupBootsOutTheLaunchdAgentOfTheRealUser(t *testing.T) {
	f := githubRunner()
	f.goos = "darwin"
	g, err := AcquireHost(f.probe())
	if err != nil {
		t.Fatal(err)
	}
	g.run = func(name string, args ...string) { f.runs = append(f.runs, name+" "+strings.Join(args, " ")) }
	g.rm = func(string) error { return nil }
	if err := g.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"launchctl bootout gui/501 dev.supermgmt.daemon"}; !slices.Equal(f.runs, want) {
		t.Fatalf("teardown commands = %q, want %q", f.runs, want)
	}
}
