package cli

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/join"
)

// joinHost is a Host that is root, has a host key and records nothing else.
type joinHost struct{ installed []string }

func (h *joinHost) Preflight() error          { return nil }
func (h *joinHost) Hostname() (string, error) { return "edge-1", nil }
func (h *joinHost) Addresses() []string       { return nil }
func (h *joinHost) ReadFile(string) ([]byte, error) {
	return []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/0rZjuLbOAYMUDGUQxdU6VZp13y6BXawIDIRfDnJPc root@edge-1\n"), nil
}

func (h *joinHost) LookupAccount(string) (join.Account, bool, error) {
	return join.Account{UID: 998, GID: 998, Home: "/var/lib/supermgmt", Shell: "/bin/sh", PrimaryGroup: "supermgmt"}, true, nil
}
func (h *joinHost) AddAccount(context.Context, string) error      { return nil }
func (h *joinHost) DisablePassword(context.Context, string) error { return nil }
func (h *joinHost) EnsureDir(string, fs.FileMode, string) error   { return nil }
func (h *joinHost) InstallFile(path string, _ []byte, _ fs.FileMode, _ string) error {
	h.installed = append(h.installed, path)
	return nil
}

type recordingEnroller struct{ got []wire.EnrollRequest }

func (e *recordingEnroller) Enroll(_ context.Context, r wire.EnrollRequest) (wire.Enrolled, error) {
	e.got = append(e.got, r)
	return wire.Enrolled{
		NodeID: "node-1", InstanceID: "instance-1", SSHUser: "supermgmt", KeyVersion: 1, FingerprintSHA256: "SHA256:instance",
		AuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/0rZjuLbOAYMUDGUQxdU6VZp13y6BXawIDIRfDnJPc",
	}, nil
}

func runJoin(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string, host *joinHost, enroller *recordingEnroller) {
	t.Helper()
	host, enroller = &joinHost{}, &recordingEnroller{}
	factory := func(string, []byte) (join.Joiner, error) { return join.Joiner{Host: host, Enroller: enroller}, nil }
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().Bool("json", false, "")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.AddCommand(newJoinCmdWith(factory))
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"join"}, args...))
	err := root.Execute()
	if err != nil {
		reportError(&errOut, err, false)
	}
	return exitCode(err), out.String(), errOut.String(), host, enroller
}

func TestJoinReadsTheTokenFromStdin(t *testing.T) {
	code, out, _, host, enroller := runJoin(t, "smj_fromstdin\n", "--server", "https://mgmt.example.com", "--token-stdin")

	if code != 0 || len(enroller.got) != 1 || enroller.got[0].Token != "smj_fromstdin" {
		t.Fatalf("code = %d, requests = %+v", code, enroller.got)
	}
	if !strings.Contains(out, "node-1") || !strings.Contains(out, "SHA256:instance") {
		t.Errorf("stdout = %q, want the node id and the key fingerprint", out)
	}
	if len(host.installed) != 1 {
		t.Errorf("installed = %v, want authorized_keys", host.installed)
	}
}

func TestJoinReadsTheTokenFromAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("smj_fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, _, _, enroller := runJoin(t, "", "--server", "https://mgmt.example.com", "--token-file", file, "--hostname", "web-9", "--ssh-port", "2222")

	if code != 0 || enroller.got[0].Token != "smj_fromfile" || enroller.got[0].Hostname != "web-9" || enroller.got[0].SSHPort != 2222 {
		t.Fatalf("code = %d, requests = %+v", code, enroller.got)
	}
}

func TestJoinNeverTakesTheTokenAsAnArgument(t *testing.T) {
	code, _, errOut, _, enroller := runJoin(t, "", "smj_inargv", "--server", "https://mgmt.example.com")

	if code != exitUsage || len(enroller.got) != 0 {
		t.Fatalf("code = %d, requests = %d", code, len(enroller.got))
	}
	if strings.Contains(errOut, "smj_inargv") {
		t.Errorf("stderr echoes the token: %q", errOut)
	}
}

func TestJoinRejectsInvalidFlagCombinations(t *testing.T) {
	tests := map[string][]string{
		"no server":        {"--token-stdin"},
		"no token source":  {"--server", "https://mgmt.example.com"},
		"two token source": {"--server", "https://mgmt.example.com", "--token-stdin", "--token-file", "/dev/null"},
		"missing file":     {"--server", "https://mgmt.example.com", "--token-file", "/nonexistent/token"},
		"missing CA file":  {"--server", "https://mgmt.example.com", "--token-stdin", "--ca-file", "/nonexistent/ca.pem"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			code, _, _, _, enroller := runJoin(t, "smj_x\n", args...)

			if code != exitUsage || len(enroller.got) != 0 {
				t.Fatalf("code = %d, requests = %d; want a usage error before the server is asked", code, len(enroller.got))
			}
		})
	}
}

func TestJoinPrintsJSONWhenAsked(t *testing.T) {
	_, out, _, _, _ := runJoin(t, "smj_x\n", "--server", "https://mgmt.example.com", "--token-stdin", "--json")

	if !strings.Contains(out, `"node_id":"node-1"`) {
		t.Fatalf("stdout = %q, want JSON", out)
	}
}

func TestTheSystemJoinCommandRefusesAPlainHTTPServer(t *testing.T) {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(newJoinCmd(nil))
	root.SetIn(strings.NewReader("smj_x\n"))
	root.SetArgs([]string{"join", "--server", "http://mgmt.example.com", "--token-stdin"})

	err := root.Execute()

	if exitCode(err) != exitUsage {
		t.Fatalf("err = %v, want a usage error", err)
	}
}
