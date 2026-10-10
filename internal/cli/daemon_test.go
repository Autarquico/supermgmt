package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/version"
)

func daemonConfig(t *testing.T, mode string) (configFile string, env []string, dbPath string) {
	t.Helper()
	root, err := os.MkdirTemp("", "smc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	configFile = filepath.Join(root, "config.yaml")
	body := "version: 1\ninstance:\n  mode: " + mode + "\n  data_dir: " + filepath.Join(root, "data") + "\ndaemon:\n  socket: " + filepath.Join(root, "run", "s") + "\n"
	if err := os.WriteFile(configFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return configFile, []string{"HOME=" + root}, filepath.Join(root, "data", "supermgmt.db")
}

// runDaemonCmd runs sm with the daemon command whether or not root.go
// registers it yet, and returns the exit code.
func runDaemonCmd(args, env []string, stderr *bytes.Buffer) int {
	root := newRootCmd(version.Info(), env)
	if found, _, _ := root.Find([]string{"daemon"}); found == root {
		root.AddCommand(newDaemonCmd(env))
	}
	root.SetArgs(args)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(stderr)
	err := root.Execute()
	if err != nil {
		reportError(stderr, err, false)
	}
	return exitCode(err)
}

func TestASecondDaemonExitsWithCode2NamingThePID(t *testing.T) {
	configFile, env, dbPath := daemonConfig(t, "local")
	lock, err := database.AcquireDatabaseLock(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()

	var stderr bytes.Buffer
	code := runDaemonCmd([]string{"daemon", "--config", configFile}, env, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), strconv.Itoa(os.Getpid())) {
		t.Errorf("stderr does not name PID %d: %s", os.Getpid(), stderr.String())
	}
}

func TestTheDaemonRefusesServerModeInM1(t *testing.T) {
	configFile, env, _ := daemonConfig(t, "server")
	var stderr bytes.Buffer
	code := runDaemonCmd([]string{"daemon", "--config", configFile}, env, &stderr)
	if code != 3 || !strings.Contains(stderr.String(), "M2") {
		t.Errorf("code %d, stderr %q; want 3 (unsupported) mentioning M2", code, stderr.String())
	}
}
