package install_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// noticesFixture is a tiny vendored program whose build info lists fake modules, plus a fake module
// cache holding their licence files, so the scripts run without network or the real dependency set.
type noticesFixture struct {
	modcache string
	binary   string
}

type fakeModule struct {
	path, version string
	files         map[string]string // file name -> content, written to the fake module cache
}

var (
	depModule   = fakeModule{"example.com/dep", "v1.0.0", map[string]string{"LICENSE": "dep licence text\n", "NOTICE": "dep notice text\n"}}
	otherModule = fakeModule{"example.com/other", "v1.2.3", map[string]string{"LICENSE": "other licence text\n"}}
	bareModule  = fakeModule{"example.com/bare", "v0.1.0", map[string]string{"README": "no licence here\n"}}
)

func noticesRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func noticesScript(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(noticesRepoRoot(t), "packaging", "release", name)
}

func noticesWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func noticesRun(t *testing.T, env []string, dir, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func noticesMustRun(t *testing.T, env []string, dir, name string, args ...string) string {
	t.Helper()
	out, err := noticesRun(t, env, dir, name, args...)
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func noticesGoVersion(t *testing.T) string {
	t.Helper()
	return strings.TrimPrefix(strings.TrimSpace(noticesMustRun(t, nil, "", "go", "env", "GOVERSION")), "go")
}

// newNoticesFixture builds a binary for goos/goarch whose build info lists mods.
func newNoticesFixture(t *testing.T, goos, goarch string, mods ...fakeModule) noticesFixture {
	t.Helper()
	src := t.TempDir()
	modcache := t.TempDir()
	var gomod, vendor, imports strings.Builder
	fmt.Fprintf(&gomod, "module example.com/app\n\ngo %s\n\n", noticesGoVersion(t))
	for i, m := range mods {
		fmt.Fprintf(&gomod, "require %s %s\n", m.path, m.version)
		fmt.Fprintf(&vendor, "# %s %s\n## explicit\n%s\n", m.path, m.version, m.path)
		fmt.Fprintf(&imports, "\t_ %q\n", m.path)
		noticesWrite(t, filepath.Join(src, "vendor", m.path, "dep.go"), fmt.Sprintf("package dep%d\n", i))
		for name, content := range m.files {
			noticesWrite(t, filepath.Join(modcache, m.path+"@"+m.version, name), content)
		}
	}
	noticesWrite(t, filepath.Join(src, "go.mod"), gomod.String())
	noticesWrite(t, filepath.Join(src, "vendor", "modules.txt"), vendor.String())
	noticesWrite(t, filepath.Join(src, "main.go"), "package main\n\nimport (\n"+imports.String()+")\n\nfunc main() {}\n")
	binary := filepath.Join(t.TempDir(), "sm")
	env := []string{"GOFLAGS=-mod=vendor", "GOWORK=off", "CGO_ENABLED=0", "GOOS=" + goos, "GOARCH=" + goarch}
	// Package names differ per directory, so the blank imports above need a distinct name each.
	noticesMustRun(t, env, src, "go", "build", "-o", binary, ".")
	return noticesFixture{modcache: modcache, binary: binary}
}

func (f noticesFixture) env(extra ...string) []string {
	return append([]string{"GOMODCACHE=" + f.modcache}, extra...)
}

func (f noticesFixture) generate(t *testing.T, extra ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "THIRD_PARTY_LICENSES")
	noticesMustRun(t, f.env(extra...), "", noticesScript(t, "notices.sh"), "generate", f.binary, out)
	return out
}

func (f noticesFixture) verify(t *testing.T, notices string, extra ...string) (string, error) {
	t.Helper()
	return noticesRun(t, f.env(extra...), "", noticesScript(t, "notices.sh"), "verify", f.binary, notices)
}

func noticesRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func wantNoticesRejected(t *testing.T, out string, err error, mention string) {
	t.Helper()
	if err == nil {
		t.Fatalf("verification passed; want failure mentioning %q", mention)
	}
	if !strings.Contains(out, mention) {
		t.Fatalf("failure does not mention %q:\n%s", mention, out)
	}
}

func TestNotices_GeneratedFileCarriesEveryLicenceAndNotice(t *testing.T) {
	f := newNoticesFixture(t, runtime.GOOS, runtime.GOARCH, depModule, otherModule)
	notices := f.generate(t)
	text := noticesRead(t, notices)
	for _, want := range []string{
		"=== example.com/dep v1.0.0 ===", "dep licence text", "--- NOTICE ---", "dep notice text",
		"=== example.com/other v1.2.3 ===", "other licence text", "=== go-stdlib go" + noticesGoVersion(t) + " ===",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("notices lack %q", want)
		}
	}
	if out, err := f.verify(t, notices); err != nil {
		t.Fatalf("verify rejected the file just generated: %v\n%s", err, out)
	}
}

func TestNotices_DroppedModuleNoticeFailsVerification(t *testing.T) {
	f := newNoticesFixture(t, runtime.GOOS, runtime.GOARCH, depModule, otherModule)
	notices := f.generate(t)
	text := noticesRead(t, notices)
	start := strings.Index(text, "=== example.com/other")
	end := strings.Index(text, "=== go-stdlib")
	noticesWrite(t, notices, text[:start]+text[end:])
	out, err := f.verify(t, notices)
	wantNoticesRejected(t, out, err, "example.com/other v1.2.3")
}

func TestNotices_MissingNoticeFileFailsVerification(t *testing.T) {
	f := newNoticesFixture(t, runtime.GOOS, runtime.GOARCH, depModule, otherModule)
	notices := f.generate(t)
	noticesWrite(t, notices, strings.Replace(noticesRead(t, notices), "--- NOTICE ---\ndep notice text\n", "", 1))
	out, err := f.verify(t, notices)
	wantNoticesRejected(t, out, err, "differs")
}

func TestNotices_ComponentOfAnotherBinaryFailsVerification(t *testing.T) {
	f := newNoticesFixture(t, runtime.GOOS, runtime.GOARCH, depModule)
	notices := f.generate(t)
	stale := noticesRead(t, notices) + "\n=== example.com/gone v9.9.9 ===\n--- LICENSE ---\ngone\n"
	noticesWrite(t, notices, stale)
	out, err := f.verify(t, notices)
	wantNoticesRejected(t, out, err, "example.com/gone v9.9.9")
}

func TestNotices_ModuleWithoutLicenceNeedsAReviewedOverride(t *testing.T) {
	f := newNoticesFixture(t, runtime.GOOS, runtime.GOARCH, bareModule)
	bare := filepath.Join(f.modcache, bareModule.path+"@"+bareModule.version)
	noticesWrite(t, filepath.Join(bare, "docs", "TERMS"), "reviewed terms\n")
	out := filepath.Join(t.TempDir(), "out")
	script := noticesScript(t, "notices.sh")

	noOverrides := filepath.Join(t.TempDir(), "overrides.txt")
	noticesWrite(t, noOverrides, "")
	o, err := noticesRun(t, f.env("SM_LICENSE_OVERRIDES="+noOverrides), "", script, "generate", f.binary, out)
	wantNoticesRejected(t, o, err, "no licence file")

	hash := noticesSHA256(t, filepath.Join(bare, "docs", "TERMS"))
	good := filepath.Join(t.TempDir(), "good.txt")
	noticesWrite(t, good, fmt.Sprintf("# reviewed\n%s\t%s\tMIT\tdocs/TERMS\t%s\n", bareModule.path, bareModule.version, hash))
	o, err = noticesRun(t, f.env("SM_LICENSE_OVERRIDES="+good), "", script, "generate", f.binary, out)
	if err != nil {
		t.Fatalf("reviewed override rejected: %v\n%s", err, o)
	}
	if text := noticesRead(t, out); !strings.Contains(text, "SPDX-License-Identifier: MIT (reviewed override)") || !strings.Contains(text, "reviewed terms") {
		t.Errorf("override section incomplete:\n%s", text)
	}

	stale := filepath.Join(t.TempDir(), "stale.txt")
	noticesWrite(t, stale, fmt.Sprintf("%s\t%s\tMIT\tdocs/TERMS\t%064d\n", bareModule.path, bareModule.version, 0))
	o, err = noticesRun(t, f.env("SM_LICENSE_OVERRIDES="+stale), "", script, "generate", f.binary, out)
	wantNoticesRejected(t, o, err, "review it again")
}

func noticesSHA256(t *testing.T, path string) string {
	t.Helper()
	out := noticesMustRun(t, nil, "", "sh", "-c", `if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi`, "sh", path)
	return strings.Fields(out)[0]
}

func TestNotices_RealOverridesCoverTheShippedBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds cmd/sm")
	}
	root := noticesRepoRoot(t)
	binary := filepath.Join(t.TempDir(), "sm")
	noticesMustRun(t, []string{"CGO_ENABLED=0"}, root, "go", "build", "-trimpath", "-o", binary, "./cmd/sm")
	out := filepath.Join(t.TempDir(), "THIRD_PARTY_LICENSES")
	script := noticesScript(t, "notices.sh")
	noticesMustRun(t, nil, root, script, "generate", binary, out)
	noticesMustRun(t, nil, root, script, "verify", binary, out)
	for _, module := range []string{"github.com/in-toto/attestation", "github.com/in-toto/in-toto-golang", "github.com/cyberphone/json-canonicalization"} {
		if !strings.Contains(noticesRead(t, out), "=== "+module+" ") {
			t.Errorf("notices lack %s", module)
		}
	}
}

// spdxFor renders a minimal SPDX document listing the binary's modules, applying edit to each "path version" line.
func (f noticesFixture) spdxFor(t *testing.T, edit func(line string) string) string {
	t.Helper()
	modules := noticesMustRun(t, f.env(), "", noticesScript(t, "notices.sh"), "modules", f.binary)
	var packages []string
	for _, line := range strings.Split(strings.TrimSpace(modules), "\n") {
		if line = edit(line); line == "" {
			continue
		}
		name, version, _ := strings.Cut(line, " ")
		packages = append(packages, fmt.Sprintf(`{"name":%q,"versionInfo":%q}`, name, version))
	}
	return `{"spdxVersion":"SPDX-2.3","packages":[` + strings.Join(packages, ",") + `]}`
}

func (f noticesFixture) checkSBOM(t *testing.T, document string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbom.spdx.json")
	noticesWrite(t, path, document)
	return noticesRun(t, f.env(), "", noticesScript(t, "sbom-check.sh"), f.binary, path)
}

func TestSBOMCheck(t *testing.T) {
	f := newNoticesFixture(t, runtime.GOOS, runtime.GOARCH, depModule, otherModule)
	keep := func(line string) string { return line }
	cases := []struct {
		name    string
		edit    func(string) string
		mention string
	}{
		{"complete document passes", keep, ""},
		{"a module missing", func(l string) string {
			if strings.HasPrefix(l, "example.com/other ") {
				return ""
			}
			return l
		}, "example.com/other v1.2.3"},
		{"a module at the wrong version", func(l string) string { return strings.Replace(l, "v1.2.3", "v1.2.4", 1) }, "example.com/other v1.2.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := f.checkSBOM(t, f.spdxFor(t, tc.edit))
			if tc.mention == "" {
				if err != nil {
					t.Fatalf("complete SBOM rejected: %v\n%s", err, out)
				}
				return
			}
			wantNoticesRejected(t, out, err, tc.mention)
		})
	}
	t.Run("not an SPDX document", func(t *testing.T) {
		out, err := f.checkSBOM(t, `{"hello":"world"}`)
		wantNoticesRejected(t, out, err, "not an SPDX document")
	})
}

var releaseTargets = []struct{ goos, goarch string }{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}}

// releaseOptions lets a test damage one archive of an otherwise valid release.
type releaseOptions struct {
	notices func(text string) string
	sbom    func(line string) string
}

// buildFinalizedRelease writes a signed dist with four archives of the fixture binary and returns dist, the trust file and the fake module cache.
func buildFinalizedRelease(t *testing.T, damage releaseOptions) (dist, trust, modcache string) {
	t.Helper()
	dist = t.TempDir()
	keys := filepath.Join(t.TempDir(), "keys")
	noticesMustRun(t, nil, "", noticesScript(t, "testkey.sh"), keys)
	const version = "1.0.0"
	for _, target := range releaseTargets {
		f := newNoticesFixture(t, target.goos, target.goarch, depModule, otherModule)
		modcache = f.modcache
		notices := noticesRead(t, f.generate(t))
		document := f.spdxFor(t, func(l string) string { return l })
		if damage.notices != nil && target.goos == "darwin" && target.goarch == "arm64" {
			notices = damage.notices(notices)
		}
		if damage.sbom != nil && target.goos == "linux" && target.goarch == "arm64" {
			document = f.spdxFor(t, damage.sbom)
		}
		name := fmt.Sprintf("sm_%s_%s_%s.tar.gz", version, target.goos, target.goarch)
		noticesWriteArchive(t, filepath.Join(dist, name), f.binary, notices)
		noticesWrite(t, filepath.Join(dist, name+".spdx.json"), document)
	}
	noticesMustRun(t, []string{"SM_SIGNING_KEY_FILE=" + filepath.Join(keys, "key")}, "", noticesScript(t, "finalize.sh"), dist, "v"+version)
	return dist, filepath.Join(keys, "allowed_signers"), modcache
}

func noticesWriteArchive(t *testing.T, path, binary, notices string) {
	t.Helper()
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, file := range []struct {
		name string
		data []byte
		mode int64
	}{{"sm", body, 0o755}, {"THIRD_PARTY_LICENSES", []byte(notices), 0o644}} {
		if err := tw.WriteHeader(&tar.Header{Name: file.name, Mode: file.mode, Size: int64(len(file.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseCheck_SupplyChain(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is needed to sign the fixture release")
	}
	dropOther := func(text string) string {
		start := strings.Index(text, "=== example.com/other")
		stdlib := strings.Index(text, "=== go-stdlib")
		return text[:start] + text[stdlib:]
	}
	cases := []struct {
		name    string
		damage  releaseOptions
		mention string
	}{
		{"complete release passes", releaseOptions{}, ""},
		{"an archive dropped a module notice", releaseOptions{notices: dropOther}, "notices do not match"},
		{"an archive lost a NOTICE text", releaseOptions{notices: func(s string) string {
			return strings.Replace(s, "--- NOTICE ---\ndep notice text\n", "", 1)
		}}, "notices do not match"},
		{"an SBOM misses a module", releaseOptions{sbom: func(l string) string {
			if strings.HasPrefix(l, "example.com/dep ") {
				return ""
			}
			return l
		}}, "SBOM does not match"},
		{"an SBOM has a wrong version", releaseOptions{sbom: func(l string) string { return strings.Replace(l, "v1.0.0", "v1.0.1", 1) }}, "SBOM does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dist, trust, modcache := buildFinalizedRelease(t, tc.damage)
			out, err := noticesRun(t, []string{"GOMODCACHE=" + modcache}, "", noticesScript(t, "check.sh"), dist, trust)
			if tc.mention == "" {
				if err != nil {
					t.Fatalf("release-check rejected a complete release: %v\n%s", err, out)
				}
				return
			}
			wantNoticesRejected(t, out, err, tc.mention)
		})
	}
}
