//go:build e2e

package harness

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func withScratchWorkDir(t *testing.T) {
	t.Helper()
	saved := workDir
	workDir = t.TempDir()
	t.Cleanup(func() { workDir = saved })
}

func TestMilestoneSourceExportsTheTreeOfTheCommitOnce(t *testing.T) {
	withScratchWorkDir(t)
	src := MilestoneSource(t, "nminus1-head", "HEAD")
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Fatalf("exported tree has no go.mod: %v", err)
	}
	if again := MilestoneSource(t, "nminus1-head", "HEAD"); again != src {
		t.Fatalf("second export = %q, want the memoized %q", again, src)
	}
}

func TestBuildSMBuildsTheCommandForThePlatformOnce(t *testing.T) {
	withScratchWorkDir(t)
	src := MilestoneSource(t, "nminus1-build", "HEAD")
	bin := BuildSM(t, "nminus1-test", src, runtime.GOOS, runtime.GOARCH, "v9.9.9", "")
	if info, err := os.Stat(bin); err != nil || info.IsDir() {
		t.Fatalf("binary %q: %v", bin, err)
	}
	if again := BuildSM(t, "nminus1-test", src, runtime.GOOS, runtime.GOARCH, "v9.9.9", ""); again != bin {
		t.Fatalf("second build = %q, want the memoized %q", again, bin)
	}
}
