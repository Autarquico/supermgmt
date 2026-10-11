package join

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	installScript = "../../install.sh"
	joinScript    = "../../scripts/join.sh"
)

// sharedFunctions are the verification steps join.sh copies from install.sh.
// A copy that drifted could verify less than the installer does.
var sharedFunctions = []string{
	"write_trust_roots", "have", "verify_signature", "verify_the_verifier", "fetch", "fetch_verified",
	"is_version", "sha256_of", "json_field", "epoch", "resolve_channel_version", "check_header", "download_archive",
}

func TestJoinScriptVerifiesExactlyLikeTheInstaller(t *testing.T) {
	install, joinText := readScript(t, installScript), readScript(t, joinScript)

	for _, name := range sharedFunctions {
		want, found := functionText(install, name)
		if !found {
			t.Fatalf("install.sh has no function %s", name)
		}
		got, found := functionText(joinText, name)
		if !found {
			t.Fatalf("join.sh has no function %s", name)
		}
		if got != want {
			t.Errorf("function %s differs between install.sh and join.sh", name)
		}
	}
	for _, constant := range []string{"NAMESPACE='supermgmt-release'", "PRINCIPAL='release@supermgmt'", "DEFAULT_BASE_URL='https://github.com/autarquico/supermgmt/releases/download'"} {
		if !strings.Contains(install, constant) || !strings.Contains(joinText, constant) {
			t.Errorf("%s is not in both scripts", constant)
		}
	}
}

func TestJoinScriptRefusesBadArgumentsBeforeTouchingTheNetwork(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	tests := map[string][]string{
		"token as argument":    {"--server", "https://mgmt.example.com", "--token", "smj_secret"},
		"bare token argument":  {"--server", "https://mgmt.example.com", "smj_secret"},
		"no server":            {"--token-stdin"},
		"two token sources":    {"--server", "https://mgmt.example.com", "--token-stdin", "--token-file", "f"},
		"option without value": {"--server"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), sh, append([]string{joinScript}, args...)...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SUPERMGMT_RELEASE_BASE_URL=http://127.0.0.1:1"}
			out, err := cmd.CombinedOutput()

			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("err = %v, want exit status 2; output %q", err, out)
			}
			if strings.Contains(string(out), "smj_secret") {
				t.Errorf("the output echoes the token: %q", out)
			}
		})
	}
}

func readScript(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// functionText returns the lines of a shell function, from "name() {" to the
// closing "}" at column 0, or the single line of a one-line function.
func functionText(script, name string) (string, bool) {
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, name+"() {") {
			continue
		}
		if strings.HasSuffix(line, "}") {
			return line, true
		}
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == "}" {
				return strings.Join(lines[i:j+1], "\n"), true
			}
		}
	}
	return "", false
}
