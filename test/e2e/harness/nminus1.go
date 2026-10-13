//go:build e2e

package harness

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const versionPackage = "github.com/autarquico/supermgmt/internal/version"

// MilestoneSource is the source tree of commit, exported with git archive (the working tree is
// untouched) into the work directory. It is exported once per name.
func MilestoneSource(t testing.TB, name, commit string) string {
	t.Helper()
	src := filepath.Join(workDir, "src-"+name)
	_, err := once("src-"+name, func() (string, error) {
		if err := os.MkdirAll(src, 0o755); err != nil {
			return "", err
		}
		tarball := src + ".tar"
		ctx := context.Background()
		res, err := Run(ctx, RepoRoot(), nil, "", "git", "archive", "--format=tar", "--output", tarball, commit)
		if e := commandError("git archive "+commit+" (CI needs fetch-depth: 0)", res, err); e != nil {
			return "", e
		}
		res, err = Run(ctx, "", nil, "", "tar", "-xf", tarball, "-C", src)
		return src, commandError("extract "+commit, res, err)
	})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// BuildSM builds ./cmd/sm of srcDir for goos/goarch as version, with the given comma-separated
// build tags ("" for none). The binary is built once per key.
func BuildSM(t testing.TB, key, srcDir, goos, goarch, version, tags string) string {
	t.Helper()
	path, err := once("sm-"+key, func() (string, error) {
		out := filepath.Join(workDir, "sm-"+key)
		env := append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
		args := []string{"build", "-trimpath", "-ldflags", "-X " + versionPackage + ".Version=" + version}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		res, err := Run(context.Background(), srcDir, env, "", "go", append(args, "-o", out, "./cmd/sm")...)
		return out, commandError("go build "+out, res, err)
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}
