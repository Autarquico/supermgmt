package install_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const reproFakeDeterministic = `
for t in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  mkdir -p dist/sm_${t}_v1
  echo "binary $t" > dist/sm_${t}_v1/sm
  echo "archive $t" > dist/sm_0.0.1_$t.tar.gz
done`

// A binary that embeds the temp dir differs between the two clean roots.
const reproFakeLeaksTempDir = `
for t in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  mkdir -p dist/sm_${t}_v1
  echo "binary $t $TMPDIR" > dist/sm_${t}_v1/sm
  echo "archive $t" > dist/sm_0.0.1_$t.tar.gz
done`

const reproFakeBuildsOneTarget = `
mkdir -p dist/sm_linux_amd64_v1
echo binary > dist/sm_linux_amd64_v1/sm
echo archive > dist/sm_0.0.1_linux_amd64.tar.gz`

func runReproducible(t *testing.T, build string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "../../packaging/release/reproducible.sh")
	if build != "" {
		cmd.Env = append(os.Environ(), "SM_REPRO_BUILD="+build)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestReproducibleAcceptsIdenticalBuilds(t *testing.T) {
	out, err := runReproducible(t, reproFakeDeterministic)
	if err != nil {
		t.Fatalf("identical builds rejected: %v\n%s", err, out)
	}
	if !strings.Contains(out, "4 binaries and 4 archives identical") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestReproducibleRejectsABuildThatDependsOnItsRoot(t *testing.T) {
	out, err := runReproducible(t, reproFakeLeaksTempDir)
	if err == nil {
		t.Fatalf("differing binaries accepted:\n%s", out)
	}
	if !strings.Contains(out, "not reproducible") {
		t.Fatalf("failure does not say why:\n%s", out)
	}
}

func TestReproducibleRejectsABuildMissingTargets(t *testing.T) {
	out, err := runReproducible(t, reproFakeBuildsOneTarget)
	if err == nil {
		t.Fatalf("a build with 1 of 4 targets accepted:\n%s", out)
	}
	if !strings.Contains(out, "expected at least 4 binaries") {
		t.Fatalf("failure does not say why:\n%s", out)
	}
}

func TestReproducibleRealGoReleaserConfig(t *testing.T) {
	for _, tool := range []string{"goreleaser", "syft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; CI job `reproducible` runs this", tool)
		}
	}
	if out, err := runReproducible(t, ""); err != nil {
		t.Fatalf("real config is not reproducible: %v\n%s", err, out)
	}
}
