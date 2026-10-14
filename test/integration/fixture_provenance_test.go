//go:build migrationfixtures

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
)

// The migration fixtures were written by real older binaries (ADR-0035). These tests keep them
// honest: a pinned commit must be a full SHA reachable from HEAD, the schema and version must be
// the milestone's, and every byte on disk must be the byte PROVENANCE.md hashed.

const migrationFixtureRoot = "../fixtures/migrations"

var migrationFixtureNames = []string{"m1", "m2", "m3", "m4", "m5"}

// provenanceSection is one `## mN` section of PROVENANCE.md.
type provenanceSection struct {
	name    string
	commit  string
	version string
	schema  int
	keyID   string
	hashes  map[string]string // path relative to the fixture root -> sha256
}

// pinnedMilestone is a row of test/e2e/milestones_test.go, the source of truth for what a
// milestone is. Its commit is empty until the milestone is merged on main.
type pinnedMilestone struct {
	name, commit, version string
	schema                int
}

var (
	provenanceCommitLine  = regexp.MustCompile("^- commit: `([^`]*)`$")
	provenanceVersionLine = regexp.MustCompile("^- synthetic version: `([^`]*)`$")
	provenanceSchemaLine  = regexp.MustCompile(`^- schema version: (\d+)$`)
	provenanceKeyIDLine   = regexp.MustCompile("^- master key id: `([^`]*)`$")
	provenanceHashRow     = regexp.MustCompile("^\\| `([^`]+)` \\| `([0-9a-f]{64})` \\|$")
	pinnedMilestoneRow    = regexp.MustCompile(`\{"(m\d+)", "([0-9a-f]*)", "(v[^"]+)", (\d+)\}`)
	fullCommitSHA         = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func parseProvenance(text string) ([]provenanceSection, error) {
	var sections []provenanceSection
	for _, line := range strings.Split(text, "\n") {
		if name, ok := strings.CutPrefix(line, "## "); ok {
			sections = append(sections, provenanceSection{name: strings.TrimSpace(name), hashes: map[string]string{}})
			continue
		}
		if len(sections) == 0 {
			continue
		}
		cur := &sections[len(sections)-1]
		if m := provenanceCommitLine.FindStringSubmatch(line); m != nil {
			cur.commit = m[1]
		} else if m := provenanceVersionLine.FindStringSubmatch(line); m != nil {
			cur.version = m[1]
		} else if m := provenanceSchemaLine.FindStringSubmatch(line); m != nil {
			cur.schema, _ = strconv.Atoi(m[1])
		} else if m := provenanceKeyIDLine.FindStringSubmatch(line); m != nil {
			cur.keyID = m[1]
		} else if m := provenanceHashRow.FindStringSubmatch(line); m != nil {
			cur.hashes[m[1]] = m[2]
		}
	}
	if len(sections) == 0 {
		return nil, errors.New("no `## mN` section")
	}
	return sections, nil
}

func readProvenance(t *testing.T) map[string]provenanceSection {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(migrationFixtureRoot, "PROVENANCE.md"))
	if err != nil {
		t.Fatalf("read PROVENANCE.md: %v", err)
	}
	sections, err := parseProvenance(string(data))
	if err != nil {
		t.Fatalf("PROVENANCE.md: %v", err)
	}
	byName := map[string]provenanceSection{}
	for _, s := range sections {
		byName[s.name] = s
	}
	return byName
}

func readPinnedMilestones(t *testing.T) map[string]pinnedMilestone {
	t.Helper()
	data, err := os.ReadFile("../e2e/milestones_test.go")
	if err != nil {
		t.Fatalf("read the milestone table: %v", err)
	}
	table := map[string]pinnedMilestone{}
	for _, m := range pinnedMilestoneRow.FindAllStringSubmatch(string(data), -1) {
		schema, _ := strconv.Atoi(m[4])
		table[m[1]] = pinnedMilestone{name: m[1], commit: m[2], version: m[3], schema: schema}
	}
	if len(table) != len(migrationFixtureNames) {
		t.Fatalf("test/e2e/milestones_test.go lists %d milestones, want %d", len(table), len(migrationFixtureNames))
	}
	return table
}

// commitProblems applies the commit rules: a full SHA that is an ancestor of HEAD in repo.
func commitProblems(ctx context.Context, repo, commit string) []string {
	if !fullCommitSHA.MatchString(commit) {
		return []string{fmt.Sprintf("commit %q is not a full 40-hex SHA", commit)}
	}
	ancestor, err := isAncestorOfHead(ctx, repo, commit)
	switch {
	case err != nil:
		return []string{fmt.Sprintf("cannot decide whether %s is an ancestor of HEAD (full history needed): %v", commit, err)}
	case !ancestor:
		return []string{fmt.Sprintf("commit %s is not an ancestor of HEAD", commit)}
	}
	return nil
}

// isAncestorOfHead tells "not an ancestor" (git exit 1) from every other failure, such as a
// shallow clone that lacks the object (exit 128).
func isAncestorOfHead(ctx context.Context, repo, commit string) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "merge-base", "--is-ancestor", commit, "HEAD")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false, nil
	default:
		return false, fmt.Errorf("git merge-base: %w: %s", err, strings.TrimSpace(string(out)))
	}
}

// identityProblems compares a section with the milestone table and the schema its database holds.
func identityProblems(s provenanceSection, want pinnedMilestone, databaseSchema int) []string {
	var problems []string
	if s.version != want.version {
		problems = append(problems, fmt.Sprintf("synthetic version %q, the milestone table says %q", s.version, want.version))
	}
	if s.schema != want.schema {
		problems = append(problems, fmt.Sprintf("schema %d, the milestone table says %d", s.schema, want.schema))
	}
	if databaseSchema != s.schema {
		problems = append(problems, fmt.Sprintf("sm.db holds schema %d, PROVENANCE says %d", databaseSchema, s.schema))
	}
	if want.commit != "" && s.commit != want.commit {
		problems = append(problems, fmt.Sprintf("commit %s, the milestone table says %s", s.commit, want.commit))
	}
	return problems
}

// fileProblems checks that the files of dir are exactly the listed ones, byte for byte.
func fileProblems(root, name string, listed map[string]string) []string {
	var problems []string
	onDisk, err := filesBelow(root, name)
	if err != nil {
		return []string{err.Error()}
	}
	for path, want := range listed {
		got, err := fileSHA256(filepath.Join(root, path))
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
		case got != want:
			problems = append(problems, fmt.Sprintf("%s: sha256 %s, PROVENANCE says %s", path, got, want))
		}
	}
	for _, path := range onDisk {
		if _, ok := listed[path]; !ok {
			problems = append(problems, fmt.Sprintf("%s is on disk but not in PROVENANCE", path))
		}
	}
	sort.Strings(problems)
	return problems
}

func filesBelow(root, name string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, name))
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		files = append(files, name+"/"+e.Name())
	}
	return files, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// schemaOfDatabaseCopy reads the schema version of a copy, so the committed file is never opened.
func schemaOfDatabaseCopy(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "sm.db")
	if err := os.WriteFile(copyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := database.Inspect(t.Context(), copyPath)
	if err != nil || !found.HasSchema {
		t.Fatalf("inspect %s: %+v, %v", path, found, err)
	}
	return found.SchemaVersion
}

func TestMigrationFixtures_Provenance(t *testing.T) {
	provenance := readProvenance(t)
	pinned := readPinnedMilestones(t)
	repo := repoRoot(t)

	for _, name := range migrationFixtureNames {
		t.Run(name, func(t *testing.T) {
			section, ok := provenance[name]
			if !ok {
				t.Fatalf("PROVENANCE.md has no section %q", name)
			}
			problems := commitProblems(t.Context(), repo, section.commit)
			problems = append(problems, identityProblems(section, pinned[name], schemaOfDatabaseCopy(t, filepath.Join(migrationFixtureRoot, name, "sm.db")))...)
			problems = append(problems, fileProblems(migrationFixtureRoot, name, section.hashes)...)
			for _, p := range problems {
				t.Error(p)
			}
		})
	}
}

func TestMigrationFixtures_ProvenanceHasNoSectionForAnUnknownMilestone(t *testing.T) {
	for name := range readProvenance(t) {
		if !contains(migrationFixtureNames, name) {
			t.Errorf("PROVENANCE.md has a section for %q, which has no fixtures", name)
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ---- the rules themselves, against inputs that must be rejected ----------------------------

func TestFixtureProvenanceRules_RejectAnAbbreviatedCommit(t *testing.T) {
	for _, commit := range []string{"", "0c31ac1", "main", strings.Repeat("G", 40), strings.Repeat("a", 41)} {
		if got := commitProblems(t.Context(), ".", commit); len(got) != 1 || !strings.Contains(got[0], "full 40-hex SHA") {
			t.Errorf("commit %q: problems = %v, want the full-SHA rule", commit, got)
		}
	}
}

func TestFixtureProvenanceRules_RejectACommitThatIsNotAnAncestorOfHead(t *testing.T) {
	repo, base, side := ancestryRepo(t)

	if got := commitProblems(t.Context(), repo, base); len(got) != 0 {
		t.Errorf("an ancestor of HEAD is rejected: %v", got)
	}
	if got := commitProblems(t.Context(), repo, side); len(got) != 1 || !strings.Contains(got[0], "not an ancestor of HEAD") {
		t.Errorf("a commit on another branch: problems = %v, want the ancestry rule", got)
	}
}

func TestFixtureProvenanceRules_ReportAMissingObjectAsMissingHistoryNotAsAVerdict(t *testing.T) {
	repo, _, _ := ancestryRepo(t)

	got := commitProblems(t.Context(), repo, strings.Repeat("1", 40))

	if len(got) != 1 || !strings.Contains(got[0], "full history needed") {
		t.Errorf("problems = %v, want a full-history message, not an ancestry verdict", got)
	}
}

func TestFixtureProvenanceRules_RejectAMilestoneThatDisagreesWithTheTableOrTheDatabase(t *testing.T) {
	section := provenanceSection{name: "m3", commit: strings.Repeat("a", 40), version: "v0.3.0", schema: 4}
	table := pinnedMilestone{name: "m3", commit: strings.Repeat("a", 40), version: "v0.3.0", schema: 4}
	if got := identityProblems(section, table, 4); len(got) != 0 {
		t.Fatalf("a consistent milestone is rejected: %v", got)
	}

	cases := map[string]struct {
		section  provenanceSection
		table    pinnedMilestone
		database int
		want     string
	}{
		"version":         {section, pinnedMilestone{"m3", table.commit, "v0.9.0", 4}, 4, "synthetic version"},
		"table schema":    {section, pinnedMilestone{"m3", table.commit, "v0.3.0", 5}, 4, "milestone table says 5"},
		"database schema": {section, table, 5, "sm.db holds schema 5"},
		"merged commit":   {section, pinnedMilestone{"m3", strings.Repeat("b", 40), "v0.3.0", 4}, 4, "milestone table says " + strings.Repeat("b", 40)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := identityProblems(c.section, c.table, c.database)
			if len(got) != 1 || !strings.Contains(got[0], c.want) {
				t.Errorf("problems = %v, want one containing %q", got, c.want)
			}
		})
	}
}

func TestFixtureProvenanceRules_AnUnmergedMilestoneAcceptsAnyCommitInTheTable(t *testing.T) {
	section := provenanceSection{name: "m4", commit: strings.Repeat("c", 40), version: "v0.4.0", schema: 5}
	table := pinnedMilestone{name: "m4", version: "v0.4.0", schema: 5}

	if got := identityProblems(section, table, 5); len(got) != 0 {
		t.Errorf("problems = %v, want none while the table has no commit", got)
	}
}

func TestFixtureProvenanceRules_RejectAChangedOrUnlistedFile(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "m9/sm.db", "database")
	writeFixtureFile(t, root, "m9/master.key", "key")
	good := map[string]string{
		"m9/sm.db":      mustSHA256(t, filepath.Join(root, "m9/sm.db")),
		"m9/master.key": mustSHA256(t, filepath.Join(root, "m9/master.key")),
	}
	if got := fileProblems(root, "m9", good); len(got) != 0 {
		t.Fatalf("matching files are rejected: %v", got)
	}

	writeFixtureFile(t, root, "m9/sm.db", "tampered")
	writeFixtureFile(t, root, "m9/stray.tar.zst", "stray")
	got := strings.Join(fileProblems(root, "m9", good), "\n")

	for _, want := range []string{"m9/sm.db: sha256", "m9/stray.tar.zst is on disk but not in PROVENANCE"} {
		if !strings.Contains(got, want) {
			t.Errorf("problems %q lack %q", got, want)
		}
	}
}

func TestFixtureProvenanceRules_RejectAListedFileThatIsMissing(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "m9/sm.db", "database")

	got := fileProblems(root, "m9", map[string]string{"m9/sm.db": strings.Repeat("0", 64), "m9/gone.key": strings.Repeat("1", 64)})

	if joined := strings.Join(got, "\n"); !strings.Contains(joined, "m9/gone.key") {
		t.Errorf("problems %q do not name the missing file", joined)
	}
}

func TestParseProvenance_ReadsEverySectionField(t *testing.T) {
	text := "# title\n\n## m1\n\n- commit: `" + strings.Repeat("a", 40) + "`\n- synthetic version: `v0.1.0`\n- Go version: `go1.27.2`\n" +
		"- schema version: 2\n- master key id: `key-1`\n\n| file | sha256 |\n|---|---|\n| `m1/sm.db` | `" + strings.Repeat("e", 64) + "` |\n"

	sections, err := parseProvenance(text)

	if err != nil || len(sections) != 1 {
		t.Fatalf("sections = %+v, %v", sections, err)
	}
	s := sections[0]
	if s.name != "m1" || s.commit != strings.Repeat("a", 40) || s.version != "v0.1.0" || s.schema != 2 || s.keyID != "key-1" || s.hashes["m1/sm.db"] != strings.Repeat("e", 64) {
		t.Errorf("section = %+v", s)
	}
}

func TestParseProvenance_RejectsADocumentWithoutSections(t *testing.T) {
	if _, err := parseProvenance("# only a title\n"); err == nil {
		t.Error("a document without a section is accepted")
	}
}

// ancestryRepo is a throw-away repository: base is an ancestor of HEAD, side lives on another branch.
func ancestryRepo(t *testing.T) (repo, base, side string) {
	t.Helper()
	repo = t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	run("commit", "-q", "--allow-empty", "-m", "base")
	base = run("rev-parse", "HEAD")
	run("checkout", "-q", "-b", "side")
	run("commit", "-q", "--allow-empty", "-m", "side")
	side = run("rev-parse", "HEAD")
	run("checkout", "-q", "main")
	run("commit", "-q", "--allow-empty", "-m", "main")
	return repo, base, side
}

func writeFixtureFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSHA256(t *testing.T, path string) string {
	t.Helper()
	sum, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}
