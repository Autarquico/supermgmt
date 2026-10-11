//go:build e2e

package harness

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Release is a signed release set (spec §3.2) signed with a throwaway key: archives, SBOMs,
// checksums.txt with its version/channel header, install.sh, join.sh and a signed channel pointer.
type Release struct {
	// Dir is laid out like the release host: <Dir>/<version>/* and <Dir>/channels/<channel>.json.
	Dir     string
	Version string
	Channel string
	// TrustDir holds key, key.pub and allowed_signers of the throwaway release key.
	TrustDir string
	// Source says how the archives were made.
	Source string
}

// AllowedSigners is the path of the trust root that matches the release signature.
func (r *Release) AllowedSigners() string { return filepath.Join(r.TrustDir, "allowed_signers") }

// VersionDir is where the signed files of the version live.
func (r *Release) VersionDir() string { return filepath.Join(r.Dir, r.Version) }

const snapshotVersion = "v0.0.0-e2e.1"

// BuildRelease prepares the signed release once per process.
//
// With SM_E2E_DIST=<dist> (CI: after `make snapshot`, which runs GoReleaser and Syft and signs
// with a throwaway key into dist/test-trust) it serves that dist as is. Without it, the
// archive is made from `go build` of this tree for the docker architecture, packed like
// GoReleaser does (sm at the archive root), and signed by the same packaging/release scripts;
// the other three platform archives are copies, present only because finalize.sh requires all four.
func BuildRelease(t testing.TB) *Release {
	t.Helper()
	dir, err := once("release", func() (string, error) { return prepareRelease(t) })
	if err != nil {
		t.Fatal(err)
	}
	return loadRelease(t, dir)
}

func prepareRelease(t testing.TB) (string, error) {
	root := filepath.Join(workDir, "release")
	if dist := os.Getenv("SM_E2E_DIST"); dist != "" {
		return root, fromDist(dist, root)
	}
	return root, fromLocalBuild(t, root)
}

func loadRelease(t testing.TB, root string) *Release {
	raw, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(raw))
	return &Release{
		Dir: filepath.Join(root, "served"), Version: fields[0], Channel: fields[1], Source: fields[2],
		TrustDir: filepath.Join(root, "trust"),
	}
}

func fromDist(dist, root string) error {
	dist, err := filepath.Abs(dist)
	if err != nil {
		return err
	}
	checksums, err := os.ReadFile(filepath.Join(dist, "checksums.txt"))
	if err != nil {
		return fmt.Errorf("SM_E2E_DIST=%s has no checksums.txt (run make snapshot): %w", dist, err)
	}
	lines := strings.Split(string(checksums), "\n")
	version := strings.TrimPrefix(lines[0], "version: ")
	channel := strings.TrimPrefix(lines[1], "channel: ")
	served := filepath.Join(root, "served")
	if err := copyReleaseFiles(dist, filepath.Join(served, version)); err != nil {
		return err
	}
	if err := copyTree(filepath.Join(dist, "test-trust"), filepath.Join(root, "trust")); err != nil {
		return err
	}
	if err := publishChannel(root, served, channel, version); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "VERSION"), []byte(version+" "+channel+" goreleaser-snapshot\n"), 0o644)
}

func fromLocalBuild(t testing.TB, root string) error {
	sm := LinuxSM(t)
	stage := filepath.Join(root, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	archive, err := packSM(sm, nil)
	if err != nil {
		return err
	}
	for _, target := range []string{"linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"} {
		name := fmt.Sprintf("sm_%s_%s.tar.gz", strings.TrimPrefix(snapshotVersion, "v"), target)
		if err := os.WriteFile(filepath.Join(stage, name), archive, 0o644); err != nil {
			return err
		}
		sbom := fmt.Sprintf(`{"spdxVersion":"SPDX-2.3","name":%q}`+"\n", target)
		if err := os.WriteFile(filepath.Join(stage, name+".spdx.json"), []byte(sbom), 0o644); err != nil {
			return err
		}
	}
	trust := filepath.Join(root, "trust")
	if err := script(nil, "packaging/release/testkey.sh", trust); err != nil {
		return err
	}
	key := []string{"SM_SIGNING_KEY_FILE=" + filepath.Join(trust, "key")}
	if err := script(key, "packaging/release/finalize.sh", stage, snapshotVersion); err != nil {
		return err
	}
	served := filepath.Join(root, "served")
	if err := copyTree(stage, filepath.Join(served, snapshotVersion)); err != nil {
		return err
	}
	if err := publishChannel(root, served, "beta", snapshotVersion); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "VERSION"), []byte(snapshotVersion+" beta local-build\n"), 0o644)
}

func publishChannel(root, served, channel, version string) error {
	issued := Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05Z")
	until := Now().UTC().Add(20 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")
	env := []string{"SM_SIGNING_KEY_FILE=" + filepath.Join(root, "trust", "key")}
	return script(env, "packaging/release/channel.sh", channel, version, issued, until, filepath.Join(served, "channels"))
}

// script runs one of the repository's packaging scripts.
func script(env []string, path string, args ...string) error {
	res, err := Run(context.Background(), RepoRoot(), append(os.Environ(), env...), "", filepath.Join(RepoRoot(), path), args...)
	return commandError(path, res, err)
}

// packSM makes a .tar.gz whose only member is sm (mode 0755). With body set, that script is
// packed instead of the binary at path.
func packSM(path string, body []byte) ([]byte, error) {
	if body == nil {
		var err error
		if body, err = os.ReadFile(path); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "sm", Mode: 0o755, Size: int64(len(body)), ModTime: time.Unix(0, 0)}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(body); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PackScript is an archive whose sm is a shell script: what an attacker would swap in.
func PackScript(script string) ([]byte, error) { return packSM("", []byte(script)) }

// copyTree copies the regular files of a directory tree.
func copyTree(from, to string) error {
	return filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), raw, info.Mode().Perm())
	})
}

// copyReleaseFiles copies the release set out of a GoReleaser dist (not its build directories).
func copyReleaseFiles(dist, to string) error {
	if err := os.MkdirAll(to, 0o755); err != nil {
		return err
	}
	for _, pattern := range []string{"sm_*.tar.gz*", "checksums.txt*", "install.sh*", "join.sh*"} {
		matches, err := filepath.Glob(filepath.Join(dist, pattern))
		if err != nil {
			return err
		}
		for _, m := range matches {
			raw, err := os.ReadFile(m)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(to, filepath.Base(m)), raw, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// CopyServed makes an editable copy of the served tree.
func (r *Release) CopyServed(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	if err := copyTree(r.Dir, dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// RenderScript replaces the trust-root blocks of install.sh or join.sh with the throwaway key
// (the markers test/install/lib.sh uses). The result is what a test mirror serves as "the script
// on the main branch"; the production script keeps its placeholder.
func RenderScript(t testing.TB, source string, allowedSigners string, revoked string) []byte {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := os.ReadFile(allowedSigners)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	skip := false
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		trimmed := strings.TrimRight(line, "\n")
		switch {
		case trimmed == "# BEGIN allowed_signers":
			out.WriteString(line)
			out.Write(allowed)
			skip = true
		case trimmed == "# BEGIN revoked_keys":
			out.WriteString(line)
			out.WriteString(revoked)
			skip = true
		case trimmed == "# END allowed_signers" || trimmed == "# END revoked_keys":
			skip = false
			out.WriteString(line)
		case !skip:
			out.WriteString(line)
		}
	}
	return out.Bytes()
}
