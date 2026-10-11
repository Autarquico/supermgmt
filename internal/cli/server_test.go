package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
)

// runServerCmds runs args against a root that carries the server commands, as
// root.go will once it registers them.
func runServerCmds(env []string, args ...string) result {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true}
	flags := root.PersistentFlags()
	flags.String("config", "", "")
	flags.Bool("json", false, "")
	flags.String("log-level", "info", "")
	root.AddCommand(newServerCmd(env), newAdminCmd(env))
	var out, errOut bytes.Buffer
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&errOut)
	err := root.Execute()
	if err != nil {
		reportError(&errOut, err, false)
	}
	return result{exitCode(err), out.String(), errOut.String()}
}

func serverConfig(t *testing.T) (file, root string) {
	t.Helper()
	root, err := os.MkdirTemp("", "smc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	body := "version: 1\ninstance:\n  mode: server\n  data_dir: " + filepath.Join(root, "data") + "\n" +
		"server:\n  listen: 127.0.0.1:0\n  admin_socket: " + filepath.Join(root, "run", "admin.sock") + "\n  trusted_proxies: [10.0.0.0/8]\n"
	file = filepath.Join(root, "config.yaml")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return file, root
}

func TestServerNeedsAServerConfiguration(t *testing.T) {
	env := []string{"HOME=" + t.TempDir()}
	missing := runServerCmds(env, "server", "--config", filepath.Join(t.TempDir(), "absent.yaml"))
	local := filepath.Join(t.TempDir(), "local.yaml")
	if err := os.WriteFile(local, []byte("version: 1\ninstance:\n  mode: local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongMode := runServerCmds(env, "server", "--config", local)
	invalid := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("version: 1\ninstance:\n  mode: server\nserver:\n  tls:\n    mode: direct\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := runServerCmds(env, "server", "--config", invalid)

	for name, r := range map[string]result{"missing": missing, "local mode": wrongMode, "invalid": broken} {
		if r.code != exitUsage {
			t.Errorf("%s: exit %d, stderr %q; want a usage error", name, r.code, r.stderr)
		}
	}
	if !strings.Contains(wrongMode.stderr, "sm daemon") {
		t.Errorf("local mode: %q does not point at sm daemon", wrongMode.stderr)
	}
}

func TestAdminCommandsDriveARunningServerThroughItsAdminSocket(t *testing.T) {
	file, root := serverConfig(t)
	env := []string{"HOME=" + root}
	loaded, err := config.Load(file, env)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serving := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.RunServer(ctx, daemon.Options{Config: loaded.Config, ConfigFile: file, OnServing: func(daemon.Endpoints) { close(serving) }})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-serving:
	case err := <-done:
		t.Fatalf("the server stopped: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not start")
	}

	code := runServerCmds(env, "admin", "bootstrap-code", "--config", file)

	if code.code != 0 || !regexp.MustCompile(`^smb_[A-Za-z0-9_-]{43}\n$`).MatchString(code.stdout) {
		t.Fatalf("bootstrap-code: exit %d, stdout %q, stderr %q; stdout must be the code alone", code.code, code.stdout, code.stderr)
	}
	if !strings.Contains(code.stderr, "valid until") {
		t.Errorf("stderr = %q, want the expiry", code.stderr)
	}
	bad := runServerCmds(env, "admin", "grant", "not-an-id", "admin", "--config", file)
	if bad.code != exitUsage {
		t.Errorf("grant with a malformed id: exit %d", bad.code)
	}
	unknown := runServerCmds(env, "admin", "grant", "01970000-0000-7000-8000-0000000000ff", "admin", "--config", file)
	if unknown.code == 0 {
		t.Errorf("grant to an identity that does not exist succeeded: %q", unknown.stdout)
	}
	complete := runServerCmds(env, "admin", "restore-complete", "--config", file)
	if complete.code != 0 {
		t.Errorf("restore-complete without a hold: exit %d %q", complete.code, complete.stderr)
	}
}

func TestAdminCommandsFailAsAPrerequisiteWhenNoServerRuns(t *testing.T) {
	file, root := serverConfig(t)

	r := runServerCmds([]string{"HOME=" + root}, "admin", "bootstrap-code", "--config", file)

	if r.code != exitPrerequisite || r.stdout != "" || !strings.Contains(r.stderr, "admin socket") {
		t.Errorf("exit %d, stdout %q, stderr %q; want a prerequisite failure naming the socket", r.code, r.stdout, r.stderr)
	}
}
