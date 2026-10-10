package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// buildSM compiles ./cmd/sm into a temporary directory.
func buildSM(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sm")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/sm")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/sm: %v\n%s", err, out)
	}
	return bin
}

type result struct {
	stdout, stderr string
	exit           int
}

// runSM runs the binary from the repository root with only the given environment.
func runSM(t *testing.T, bin string, env []string, args ...string) result {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := result{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		res.exit = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("run sm %v: %v", args, err)
	}
	return res
}

func TestSMBinarySmoke(t *testing.T) {
	bin := buildSM(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "xdg"), "PATH=" + os.Getenv("PATH")}

	t.Run("version --json prints the build metadata", func(t *testing.T) {
		res := runSM(t, bin, env, "version", "--json")
		var got map[string]any
		if err := json.Unmarshal([]byte(res.stdout), &got); res.exit != 0 || err != nil {
			t.Fatalf("exit %d, %v, stdout %q", res.exit, err, res.stdout)
		}
		for _, key := range []string{"version", "commit", "date", "go_version", "platform"} {
			if _, ok := got[key]; !ok {
				t.Errorf("version --json lacks %q: %s", key, res.stdout)
			}
		}
	})

	t.Run("config validate accepts the shipped examples with exit 0", func(t *testing.T) {
		res := runSM(t, bin, env, "config", "validate", "--config", "examples/config.yaml", "--policy", "examples/policies.yaml")
		if res.exit != 0 {
			t.Fatalf("exit %d\n%s%s", res.exit, res.stdout, res.stderr)
		}
	})

	t.Run("config validate rejects an unknown field with exit 2 naming it", func(t *testing.T) {
		valid, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		bad := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(bad, append(valid, []byte("\nno_such_field: 1\n")...), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runSM(t, bin, env, "config", "validate", "--config", bad)

		if res.exit != 2 {
			t.Fatalf("exit %d, want 2\n%s%s", res.exit, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout+res.stderr, "no_such_field") {
			t.Errorf("output does not name the unknown field:\n%s%s", res.stdout, res.stderr)
		}
	})

	t.Run("doctor --offline on a fresh HOME exits 0 and does not create the database", func(t *testing.T) {
		data := filepath.Join(home, "data")
		cfg := filepath.Join(home, "config.yaml")
		body := "version: 1\ninstance:\n  name: smoke\n  mode: local\n  data_dir: " + data + "\n"
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runSM(t, bin, env, "doctor", "--offline", "--config", cfg)

		if res.exit != 0 {
			t.Fatalf("exit %d\n%s%s", res.exit, res.stdout, res.stderr)
		}
		if _, err := os.Stat(filepath.Join(data, "supermgmt.db")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("doctor --offline created the database: %v", err)
		}
	})
}
