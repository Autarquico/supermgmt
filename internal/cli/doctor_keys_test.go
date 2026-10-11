package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func doctorCheckNamed(t *testing.T, r result, name string) (check, bool) {
	t.Helper()
	var report doctorReport
	if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v\n%s\nstderr: %s", err, r.stdout, r.stderr)
	}
	for _, c := range report.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return check{}, false
}

func TestDoctorWarnsAboutKeyFilesNothingReferences(t *testing.T) {
	s, _ := keyedSandbox(t)
	const stray = "0192a000-0000-7000-8000-00000000f0aa.key"
	if err := os.WriteFile(filepath.Join(keysDirOf(t, s), stray), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}

	r := s.run("doctor", "--offline", "--json")

	c, found := doctorCheckNamed(t, r, "orphan_keys")
	if !found || c.Status != statusWarn || !strings.Contains(c.Detail, stray) {
		t.Errorf("orphan_keys = %+v (found %v), want a warning naming %s", c, found, stray)
	}
	if r.code != 0 {
		t.Errorf("a warning must not fail doctor: exit %d", r.code)
	}
}

func TestDoctorAcceptsAKeyDirectoryWhereEveryKeyIsReferenced(t *testing.T) {
	s, _ := keyedSandbox(t)

	r := s.run("doctor", "--offline", "--json")

	if c, found := doctorCheckNamed(t, r, "orphan_keys"); !found || c.Status != statusOK {
		t.Errorf("orphan_keys = %+v (found %v), want ok", c, found)
	}
}
