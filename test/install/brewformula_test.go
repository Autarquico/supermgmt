package install_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const brewScript = "../../packaging/release/brew-formula.sh"

const (
	brewDarwinArm = "1111111111111111111111111111111111111111111111111111111111111111"
	brewDarwinAmd = "2222222222222222222222222222222222222222222222222222222222222222"
	brewLinuxArm  = "3333333333333333333333333333333333333333333333333333333333333333"
	brewLinuxAmd  = "4444444444444444444444444444444444444444444444444444444444444444"
	brewSBOM      = "5555555555555555555555555555555555555555555555555555555555555555"
)

func brewChecksums(version, channel string, drop string) string {
	lines := []string{"version: " + version, "channel: " + channel}
	bare := strings.TrimPrefix(version, "v")
	entries := []struct{ digest, target string }{
		{brewDarwinArm, "darwin_arm64"},
		{brewDarwinAmd, "darwin_amd64"},
		{brewLinuxArm, "linux_arm64"},
		{brewLinuxAmd, "linux_amd64"},
	}
	for _, e := range entries {
		if e.target == drop {
			continue
		}
		lines = append(lines, e.digest+"  sm_"+bare+"_"+e.target+".tar.gz")
	}
	lines = append(lines, brewSBOM+"  sm_"+bare+"_linux_amd64.tar.gz.spdx.json")
	return strings.Join(lines, "\n") + "\n"
}

func renderBrewFormula(t *testing.T, checksums string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "checksums.txt")
	if err := os.WriteFile(path, []byte(checksums), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sh", brewScript, path)
	cmd.Env = append(os.Environ(), "SM_RELEASE_BASE_URL=https://example.test/dl")
	out, err := cmd.Output()
	return string(out), err
}

const wantBrewFormula = `class Supermgmt < Formula
  desc "Self-hosted management for personal infrastructure"
  homepage "https://github.com/autarquico/supermgmt"
  version "1.2.3"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://example.test/dl/v1.2.3/sm_1.2.3_darwin_arm64.tar.gz"
      sha256 "` + brewDarwinArm + `"
    end
    on_intel do
      url "https://example.test/dl/v1.2.3/sm_1.2.3_darwin_amd64.tar.gz"
      sha256 "` + brewDarwinAmd + `"
    end
  end

  on_linux do
    on_arm do
      url "https://example.test/dl/v1.2.3/sm_1.2.3_linux_arm64.tar.gz"
      sha256 "` + brewLinuxArm + `"
    end
    on_intel do
      url "https://example.test/dl/v1.2.3/sm_1.2.3_linux_amd64.tar.gz"
      sha256 "` + brewLinuxAmd + `"
    end
  end

  def install
    bin.install "sm"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sm version")
  end
end
`

func TestBrewFormulaRenders(t *testing.T) {
	got, err := renderBrewFormula(t, brewChecksums("v1.2.3", "stable", ""))
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if got != wantBrewFormula {
		t.Fatalf("formula differs from golden:\n%s", got)
	}
	if strings.Contains(got, "@") {
		t.Error("unreplaced placeholder in formula")
	}
}

func TestBrewFormulaIsValidRuby(t *testing.T) {
	ruby, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not installed")
	}
	formula := filepath.Join(t.TempDir(), "supermgmt.rb")
	if err := os.WriteFile(formula, []byte(wantBrewFormula), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), ruby, "-c", formula).CombinedOutput(); err != nil {
		t.Fatalf("ruby -c: %v\n%s", err, out)
	}
}

func TestBrewFormulaRefusesUnsafeInput(t *testing.T) {
	cases := []struct {
		name      string
		checksums string
	}{
		{"beta channel", brewChecksums("v1.2.3", "beta", "")},
		{"prerelease version", brewChecksums("v1.2.3-beta.1", "stable", "")},
		{"missing archive", brewChecksums("v1.2.3", "stable", "linux_arm64")},
		{"duplicate archive", brewChecksums("v1.2.3", "stable", "") + brewDarwinArm + "  sm_1.2.3_darwin_arm64.tar.gz\n"},
		{"short digest", strings.Replace(brewChecksums("v1.2.3", "stable", ""), brewLinuxAmd, "abcd", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := renderBrewFormula(t, tc.checksums); err == nil {
				t.Fatalf("expected failure, got formula:\n%s", got)
			}
		})
	}
}

func TestBrewFormulaRefusesBadSignature(t *testing.T) {
	dir := t.TempDir()
	checksums := filepath.Join(dir, "checksums.txt")
	trust := filepath.Join(dir, "allowed_signers")
	for path, body := range map[string]string{
		checksums:          brewChecksums("v1.2.3", "stable", ""),
		checksums + ".sig": "not a signature\n",
		trust:              "# none\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.CommandContext(t.Context(), "sh", brewScript, checksums, trust).Output(); err == nil {
		t.Fatalf("expected signature failure, got:\n%s", out)
	}
}
