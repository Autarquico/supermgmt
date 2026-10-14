package install_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const requireChecksScript = "../../packaging/release/require-checks.sh"

// checkRun renders one check-run as the GitHub API reports it for a finished GitHub Actions job.
func checkRun(name, status, conclusion string) string {
	return checkRunBy(name, status, conclusion, "github-actions")
}

func checkRunBy(name, status, conclusion, app string) string {
	outcome := "null"
	if conclusion != "" {
		outcome = fmt.Sprintf("%q", conclusion)
	}
	return fmt.Sprintf(`{"name":%q,"status":%q,"conclusion":%s,"app":{"slug":%q}}`, name, status, outcome, app)
}

func checkRunsPage(runs ...string) string {
	return `{"total_count":` + fmt.Sprint(len(runs)) + `,"check_runs":[` + strings.Join(runs, ",") + `]}`
}

// runRequireChecks returns the script's exit code and stderr+stdout for the given inputs.
func runRequireChecks(t *testing.T, required, checks string) (int, string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not on PATH")
	}
	dir := t.TempDir()
	requiredPath := filepath.Join(dir, "required-checks.txt")
	checksPath := filepath.Join(dir, "check-runs.json")
	for path, content := range map[string]string{requiredPath: required, checksPath: checks} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.CommandContext(t.Context(), "sh", requireChecksScript, requiredPath, checksPath).CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("require-checks.sh did not run: %v", err)
	return -1, ""
}

func TestRequireChecks_PassesWhenEveryRequiredCheckSucceeded(t *testing.T) {
	required := "# comment\n\nfmt\n  test (ubuntu-latest)  \nnightly\n"
	checks := checkRunsPage(
		checkRun("fmt", "completed", "success"),
		checkRun("test (ubuntu-latest)", "completed", "success"),
		checkRun("unrelated", "completed", "failure"),
	) + checkRunsPage(checkRun("nightly", "completed", "success"))

	code, out := runRequireChecks(t, required, checks)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
}

func TestRequireChecks_RejectsEveryOutcomeThatIsNotSuccess(t *testing.T) {
	tests := []struct {
		name string
		run  string
		want string
	}{
		{"queued", checkRun("fmt", "queued", ""), "not finished (queued)"},
		{"in progress", checkRun("fmt", "in_progress", ""), "not finished (in_progress)"},
		{"skipped", checkRun("fmt", "completed", "skipped"), "fmt: skipped"},
		{"neutral", checkRun("fmt", "completed", "neutral"), "fmt: neutral"},
		{"cancelled", checkRun("fmt", "completed", "cancelled"), "fmt: cancelled"},
		{"failed", checkRun("fmt", "completed", "failure"), "fmt: failure"},
		{"timed out", checkRun("fmt", "completed", "timed_out"), "fmt: timed_out"},
		{"action required", checkRun("fmt", "completed", "action_required"), "fmt: action_required"},
		{"completed without a conclusion", checkRun("fmt", "completed", ""), "no conclusion"},
		{"another run of the same name failed", checkRun("fmt", "completed", "success") + "," + checkRun("fmt", "completed", "failure"), "fmt: failure"},
		{"another run of the same name still runs", checkRun("fmt", "completed", "success") + "," + checkRun("fmt", "in_progress", ""), "not finished"},
		{"a check run not created by GitHub Actions", checkRunBy("fmt", "completed", "success", "some-app"), "fmt: missing"},
		{"a check run without an app", `{"name":"fmt","status":"completed","conclusion":"success"}`, "fmt: missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out := runRequireChecks(t, "fmt\n", checkRunsPage(tt.run))
			if code != 1 || !strings.Contains(out, tt.want) {
				t.Fatalf("exit %d, want 1 with %q\n%s", code, tt.want, out)
			}
		})
	}
}

func TestRequireChecks_RejectsAMissingCheckEvenWhenOthersSucceeded(t *testing.T) {
	code, out := runRequireChecks(t, "fmt\nvet\n", checkRunsPage(checkRun("fmt", "completed", "success")))
	if code != 1 || !strings.Contains(out, "vet: missing") || strings.Contains(out, "fmt:") {
		t.Fatalf("exit %d, want 1 naming only vet\n%s", code, out)
	}
}

func TestRequireChecks_ReportsEveryOffendingCheck(t *testing.T) {
	checks := checkRunsPage(checkRun("fmt", "completed", "failure"), checkRun("vet", "queued", ""))
	code, out := runRequireChecks(t, "fmt\nvet\nlint\n", checks)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	for _, want := range []string{"fmt: failure", "vet: not finished", "lint: missing"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

func TestRequireChecks_FailsClosedOnAnAnswerThatIsNotAListOfChecks(t *testing.T) {
	tests := []struct {
		name     string
		required string
		checks   string
		code     int
	}{
		{"an API error body has no check runs", "fmt\n", `{"message":"Not Found"}`, 1},
		{"an empty page", "fmt\n", checkRunsPage(), 1},
		{"not JSON", "fmt\n", "<html>", 2},
		{"empty answer", "fmt\n", "", 1},
		{"no required checks", "# nothing\n\n", checkRunsPage(checkRun("fmt", "completed", "success")), 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code, out := runRequireChecks(t, tt.required, tt.checks); code != tt.code {
				t.Fatalf("exit %d, want %d\n%s", code, tt.code, out)
			}
		})
	}
}

func TestRequireChecks_RefusesMissingArguments(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "sh", requireChecksScript).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "usage") {
		t.Fatalf("want exit 2 with usage, got %v\n%s", err, out)
	}
}
