package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/version"
)

var update = flag.Bool("update", false, "rewrite golden files")

var testBuild = version.Build{
	Version:   "v1.2.3",
	Commit:    "deadbeef",
	Date:      "2026-01-02T03:04:05Z",
	GoVersion: "go1.27.0",
	Platform:  "linux/arm64",
}

type result struct {
	code   int
	stdout string
	stderr string
}

func run(args ...string) result {
	var out, errOut bytes.Buffer
	code := execute(args, &out, &errOut, testBuild)
	return result{code, out.String(), errOut.String()}
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch\n got:\n%s\nwant:\n%s", name, got, want)
	}
}

func TestVersionOutput(t *testing.T) {
	tests := []struct {
		golden string
		args   []string
	}{
		{"version.human.golden", []string{"version"}},
		{"version.json.golden", []string{"version", "--json"}},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			r := run(tt.args...)
			if r.code != 0 || r.stderr != "" {
				t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
			}
			assertGolden(t, tt.golden, r.stdout)
		})
	}
}

func TestVersionJSONKeys(t *testing.T) {
	var got map[string]string
	if err := json.Unmarshal([]byte(run("version", "--json").stdout), &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "commit", "date", "go_version", "platform"} {
		if got[key] == "" {
			t.Errorf("missing key %q in %v", key, got)
		}
	}
}

func TestBareSM(t *testing.T) {
	r := run()
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	if !strings.HasSuffix(r.stdout, "\n"+tuiNotice+"\n") {
		t.Errorf("missing TUI notice:\n%s", r.stdout)
	}
	assertGolden(t, "bare.golden", r.stdout)
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
	}{
		{"unknown command", []string{"frobnicate"}, 2},
		{"bad flag", []string{"--nope"}, 2},
		{"bad flag on subcommand", []string{"version", "--nope"}, 2},
		{"unexpected arg", []string{"version", "extra"}, 2},
		{"bad shell", []string{"completion", "tcsh"}, 2},
		{"missing shell", []string{"completion"}, 2},
		{"bad log level", []string{"--log-level", "loud", "version"}, 2},
		{"good log level", []string{"--log-level", "debug", "version"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(tt.args...)
			if r.code != tt.code {
				t.Fatalf("code = %d, want %d (stderr %q)", r.code, tt.code, r.stderr)
			}
			if tt.code != 0 && !strings.HasPrefix(r.stderr, "error: ") {
				t.Errorf("stderr = %q, want one-line 'error: ...'", r.stderr)
			}
			if tt.code != 0 && strings.Count(r.stderr, "\n") != 1 {
				t.Errorf("stderr should be one line: %q", r.stderr)
			}
		})
	}
}

func TestJSONErrors(t *testing.T) {
	r := run("--json", "frobnicate")
	if r.code != 2 {
		t.Fatalf("code = %d", r.code)
	}
	var got jsonError
	if err := json.Unmarshal([]byte(r.stderr), &got); err != nil {
		t.Fatalf("stderr not JSON: %q", r.stderr)
	}
	if got.Error.Code != "INVALID_ARGUMENT" || got.Error.Message == "" {
		t.Errorf("got %+v", got)
	}
}

func TestErrorMapping(t *testing.T) {
	plain := os.ErrNotExist
	if exitCode(plain) != 1 || errorCode(plain) != "INTERNAL" {
		t.Errorf("plain error: code=%d %s", exitCode(plain), errorCode(plain))
	}
	usage := usageErrorf("bad")
	if exitCode(usage) != 2 || errorCode(usage) != "INVALID_ARGUMENT" {
		t.Errorf("usage error: code=%d %s", exitCode(usage), errorCode(usage))
	}
	if exitCode(nil) != 0 {
		t.Error("nil error must map to 0")
	}
}

func TestCompletionScripts(t *testing.T) {
	markers := map[string]string{
		"bash":       "# bash completion V2 for sm",
		"zsh":        "#compdef sm",
		"fish":       "# fish completion for sm",
		"powershell": "# powershell completion for sm",
	}
	for shell, marker := range markers {
		t.Run(shell, func(t *testing.T) {
			r := run("completion", shell)
			if r.code != 0 || r.stderr != "" {
				t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
			}
			if !strings.HasPrefix(r.stdout, marker) {
				head, _, _ := strings.Cut(r.stdout, "\n")
				t.Errorf("first line = %q, want prefix %q", head, marker)
			}
		})
	}
}
