package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hostMutatingHelpers are the harness entry points that mutate the machine (ADR-0036).
var hostMutatingHelpers = []string{"RequireHostLifecycle", "AcquireHost"}

func TestHostMutatingCallersCarryTheHostlifecycleBuildTag(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file == "hostlife_tags_test.go" {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if callsHostMutatingHelper(string(src)) && !hasHostlifecycleTag(string(src)) {
			t.Errorf("%s calls a host-mutating helper but lacks //go:build hostlifecycle", file)
		}
	}
}

func callsHostMutatingHelper(src string) bool {
	for _, name := range hostMutatingHelpers {
		if strings.Contains(src, "harness."+name+"(") {
			return true
		}
	}
	return false
}

func hasHostlifecycleTag(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return false
		}
		if strings.HasPrefix(line, "//go:build") {
			return strings.Contains(line, "hostlifecycle") && !strings.Contains(line, "!hostlifecycle")
		}
	}
	return false
}

func TestHostlifecycleTagDetector(t *testing.T) {
	cases := map[string]bool{
		"//go:build hostlifecycle\n\npackage e2e\n":        true,
		"//go:build e2e && hostlifecycle\n\npackage e2e\n": true,
		"//go:build e2e\n\npackage e2e\n":                  false,
		"//go:build !hostlifecycle\n\npackage e2e\n":       false,
		"package e2e\n// //go:build hostlifecycle\n":       false,
	}
	for src, want := range cases {
		if got := hasHostlifecycleTag(src); got != want {
			t.Errorf("hasHostlifecycleTag(%q) = %v, want %v", src, got, want)
		}
	}
	if !callsHostMutatingHelper("g := harness.RequireHostLifecycle(t)") {
		t.Error("a RequireHostLifecycle call is not detected")
	}
}
