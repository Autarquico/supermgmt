package install_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	provRepo  = "autarquico/supermgmt"
	provTag   = "v1.2.3"
	provSHA   = "0123456789abcdef0123456789abcdef01234567"
	provOther = "fedcba9876543210fedcba9876543210fedcba98"
)

var provFiles = map[string]string{
	"sm_1.2.3_linux_amd64.tar.gz":  "linux amd64 archive",
	"sm_1.2.3_darwin_arm64.tar.gz": "darwin arm64 archive",
	"checksums.txt":                "signed checksums",
}

type provStatement struct {
	subjects map[string]string // name -> sha256
	sha      string
	builder  string
}

func provDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func provBuilder(workflow, ref string) string {
	return "https://github.com/" + provRepo + "/.github/workflows/" + workflow + "@" + ref
}

func provGood() provStatement {
	subjects := map[string]string{}
	for name, content := range provFiles {
		subjects[name] = provDigest(content)
	}
	return provStatement{subjects: subjects, sha: provSHA, builder: provBuilder("release.yml", "refs/tags/"+provTag)}
}

func (s provStatement) json(t *testing.T) []byte {
	t.Helper()
	var subjects []map[string]any
	for name, digest := range s.subjects {
		subjects = append(subjects, map[string]any{"name": name, "digest": map[string]string{"sha256": digest}})
	}
	b, err := json.Marshal(map[string]any{
		"_type":   "https://in-toto.io/Statement/v1",
		"subject": subjects,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"resolvedDependencies": []map[string]any{{"digest": map[string]string{"gitCommit": s.sha}}},
			},
			"runDetails": map[string]any{"builder": map[string]string{"id": s.builder}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runVerifyProvenance(t *testing.T, statement []byte, files map[string]string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not on PATH")
	}
	dir := t.TempDir()
	dist := filepath.Join(dir, "dist")
	if err := os.Mkdir(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "statement.json")
	if err := os.WriteFile(path, statement, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "../../packaging/release/verify-provenance.sh", path, dist, provSHA, provRepo, provTag).CombinedOutput()
	return string(out), err
}

func TestProvenanceAcceptsAMatchingStatement(t *testing.T) {
	out, err := runVerifyProvenance(t, provGood().json(t), provFiles)
	if err != nil {
		t.Fatalf("matching statement rejected: %v\n%s", err, out)
	}
}

func TestProvenanceRejectsWhatDoesNotMatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*provStatement)
		want   string
	}{
		{"wrong archive digest", func(s *provStatement) { s.subjects["sm_1.2.3_linux_amd64.tar.gz"] = provDigest("tampered") }, "has digest"},
		{"wrong checksums.txt digest", func(s *provStatement) { s.subjects["checksums.txt"] = strings.Repeat("0", 64) }, "has digest"},
		{"wrong source SHA", func(s *provStatement) { s.sha = provOther }, "source commit"},
		{"empty source SHA", func(s *provStatement) { s.sha = "" }, "source commit"},
		{"wrong builder workflow", func(s *provStatement) { s.builder = provBuilder("ci.yml", "refs/tags/"+provTag) }, "builder"},
		{"wrong builder ref", func(s *provStatement) { s.builder = provBuilder("release.yml", "refs/heads/main") }, "builder"},
		{"wrong builder repo", func(s *provStatement) {
			s.builder = "https://github.com/evil/fork/.github/workflows/release.yml@refs/tags/" + provTag
		}, "builder"},
		{"missing archive subject", func(s *provStatement) { delete(s.subjects, "sm_1.2.3_darwin_arm64.tar.gz") }, "is not a subject"},
		{"missing checksums subject", func(s *provStatement) { delete(s.subjects, "checksums.txt") }, "is not a subject"},
		{"subject without a file", func(s *provStatement) { s.subjects["sm_9.9.9_linux_amd64.tar.gz"] = provDigest("x") }, "is not in"},
		{"no subjects", func(s *provStatement) { s.subjects = map[string]string{} }, "no subjects"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := provGood()
			tt.mutate(&s)
			out, err := runVerifyProvenance(t, s.json(t), provFiles)
			if err == nil {
				t.Fatalf("statement accepted:\n%s", out)
			}
			if !strings.Contains(out, tt.want) {
				t.Fatalf("want %q in output:\n%s", tt.want, out)
			}
		})
	}
}

func TestProvenanceRejectsAPublishedFileTheStatementDoesNotCover(t *testing.T) {
	files := maps.Clone(provFiles)
	files["sm_1.2.3_linux_arm64.tar.gz"] = "an archive nobody attested"
	out, err := runVerifyProvenance(t, provGood().json(t), files)
	if err == nil || !strings.Contains(out, "sm_1.2.3_linux_arm64.tar.gz is not a subject") {
		t.Fatalf("uncovered archive accepted (err=%v):\n%s", err, out)
	}
}

func TestProvenanceRejectsAFileSwappedAfterAttestation(t *testing.T) {
	files := maps.Clone(provFiles)
	files["sm_1.2.3_linux_amd64.tar.gz"] = "swapped after attestation"
	out, err := runVerifyProvenance(t, provGood().json(t), files)
	if err == nil || !strings.Contains(out, "has digest") {
		t.Fatalf("swapped archive accepted (err=%v):\n%s", err, out)
	}
}
