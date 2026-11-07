package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const retiredPolicy = `version: 1
rules:
  - name: old
    subjects: ["role:admin"]
    allow: ["app_target.move", "app_target.*"]
    deny: ["app_target.cleanup_source", "app_target.write"]
`

func TestConfigValidateWarnsAboutRetiredActionsAndPasses(t *testing.T) {
	s := newSandbox(t)
	policyFile := filepath.Join(s.dir, "policy.yaml")
	writeFile(t, policyFile, retiredPolicy)

	r := s.run("config", "validate", "--policy", policyFile)
	if r.code != 0 {
		t.Fatalf("code = %d, stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	for _, want := range []string{"ADR-0043", "app_target.move", "app_target.cleanup_source"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q: %q", want, r.stdout)
		}
	}
	if got := strings.Count(r.stdout, "warning: "); got != 2 {
		t.Errorf("%d warnings printed, want one per retired action (2): %q", got, r.stdout)
	}

	r = s.run("config", "validate", "--policy", policyFile, "--json")
	var report validateReport
	if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if r.code != 0 || !report.Valid || len(report.Policy.Warnings) != 2 {
		t.Errorf("code=%d valid=%v warnings=%v", r.code, report.Valid, report.Policy.Warnings)
	}
}

func TestConfigValidateStillRejectsATypoInARetiredName(t *testing.T) {
	s := newSandbox(t)
	policyFile := filepath.Join(s.dir, "policy.yaml")
	writeFile(t, policyFile, "version: 1\nrules:\n  - {name: r, subjects: ['*'], allow: ['app_target.moev']}\n")
	if r := s.run("config", "validate", "--policy", policyFile); r.code != 2 {
		t.Fatalf("code = %d, stdout %q", r.code, r.stdout)
	}
}
