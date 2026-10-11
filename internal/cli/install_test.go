package cli

import (
	"bytes"
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/installer"
)

// stubHost is a minimal in-memory installer host.
type stubHost struct {
	files map[string][]byte
}

func (h *stubHost) Exists(p string) bool { _, ok := h.files[p]; return ok }
func (h *stubHost) ReadFile(p string) ([]byte, error) {
	if b, ok := h.files[p]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}
func (h *stubHost) MkdirAll(string, fs.FileMode, installer.Owner) error { return nil }
func (h *stubHost) WriteFile(p string, d []byte, _ fs.FileMode, _ installer.Owner) error {
	h.files[p] = d
	return nil
}

func (h *stubHost) CopyFile(_, dst string, _ fs.FileMode, _ installer.Owner) error {
	h.files[dst] = []byte("bin")
	return nil
}
func (h *stubHost) RemoveAll(string) error                                  { return nil }
func (h *stubHost) UserExists(string) (bool, error)                         { return true, nil }
func (h *stubHost) CreateServiceUser(context.Context, string, string) error { return nil }
func (h *stubHost) Register(context.Context, installer.Unit) error          { return nil }
func (h *stubHost) Start(context.Context, installer.Unit) error             { return nil }
func (h *stubHost) Run(context.Context, installer.Command) ([]byte, error) {
	return []byte("CODE-9\n"), nil
}

func (h *stubHost) WaitReady(context.Context, installer.Probe, time.Duration) error {
	return nil
}

type stubClock struct{}

func (stubClock) Now() time.Time { return time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC) }

func runInstall(t *testing.T, host *stubHost, uid int, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	deps := func(cmd *cobra.Command, _ bool) installer.Deps {
		return installer.Deps{
			Host:  installer.Host{GOOS: "linux", UID: uid, Home: "/home/t", Env: map[string]string{}, HasSystemd: true},
			Files: host, Accounts: host, Services: host, UserServices: host, Runner: host, Health: host,
			Clock: stubClock{}, Out: cmd.OutOrStdout(),
		}
	}
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.AddCommand(newInstallCmdWith([]string{"HOME=/home/t"}, deps))
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"install"}, args...))
	err := root.Execute()
	if err != nil {
		reportError(&errOut, err, false)
	}
	return exitCode(err), out.String(), errOut.String()
}

func TestInstallServerExitsZeroAndPrintsTheBootstrapCode(t *testing.T) {
	host := &stubHost{files: map[string][]byte{}}
	code, out, errOut := runInstall(t, host, 0, "server", "--public-url", "https://mgmt.example.com", "--non-interactive")
	if code != 0 || !strings.Contains(out, "CODE-9") {
		t.Fatalf("code %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
}

func TestInstallExitCodesFollowThePlatformContract(t *testing.T) {
	cases := []struct {
		name string
		uid  int
		args []string
		want int
	}{
		{"not root", 1000, []string{"server", "--public-url", "https://m.example.com"}, installer.ExitPrerequisite},
		{"http public url", 0, []string{"server", "--public-url", "http://m.example.com"}, installer.ExitInvalid},
		{"direct without certificate", 0, []string{"server", "--public-url", "https://m.example.com", "--tls", "direct"}, installer.ExitInvalid},
		{"missing public url", 0, []string{"server"}, installer.ExitInvalid},
		{"later mode", 0, []string{"upgrade"}, installer.ExitUnsupported},
		{"proxmox mode", 0, []string{"proxmox-lxc"}, installer.ExitUnsupported},
		{"unknown mode", 0, []string{"bogus"}, exitUsage},
		{"unknown flag", 0, []string{"server", "--bogus"}, exitUsage},
		{"restore without inputs", 0, []string{"restore", "--public-url", "https://m.example.com"}, installer.ExitInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runInstall(t, &stubHost{files: map[string][]byte{}}, tc.uid, tc.args...)
			if code != tc.want {
				t.Fatalf("exit %d, want %d (stderr %q)", code, tc.want, errOut)
			}
			if errOut == "" {
				t.Error("a failure must be reported")
			}
		})
	}
}

func TestInstallExistingInstallFailsNonInteractive(t *testing.T) {
	host := &stubHost{files: map[string][]byte{"/usr/local/bin/sm": []byte("old")}}
	code, _, errOut := runInstall(t, host, 0, "server", "--public-url", "https://m.example.com")
	if code != installer.ExitPrerequisite || !strings.Contains(errOut, "refusing to guess") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestInstallClientNeedsNoPrivileges(t *testing.T) {
	host := &stubHost{files: map[string][]byte{}}
	if code, _, errOut := runInstall(t, host, 1000, "client"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !host.Exists("/home/t/.config/supermgmt/profiles.yaml") {
		t.Error("client profile not written")
	}
}

func TestInstallAcceptsNoSecretFlags(t *testing.T) {
	for _, mode := range newInstallCmd(nil).Commands() {
		usage := mode.LocalFlags().FlagUsages()
		for _, secret := range []string{"pass", "token", "secret", "password"} {
			if strings.Contains(usage, secret) {
				t.Errorf("sm install %s has a secret-looking flag mentioning %q:\n%s", mode.Name(), secret, usage)
			}
		}
	}
}

func TestInstallRestoreFlagsCarryPathsOnly(t *testing.T) {
	var restore *cobra.Command
	for _, c := range newInstallCmd(nil).Commands() {
		if c.Name() == "restore" {
			restore = c
		}
	}
	for _, name := range []string{"archive", "key-export", "tls", "public-url"} {
		if restore.Flags().Lookup(name) == nil {
			t.Errorf("restore lacks --%s", name)
		}
	}
}
