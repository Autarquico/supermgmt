//go:build fixturegen && fixtures

package main

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ---- ancestry: no fixture is ever pinned to a branch head -------------------------------------

// genRepo is a repository whose main holds one commit and whose branch "feature" holds one more.
type genRepo struct {
	dir           string
	onMain, onTip string
}

func newGenRepo(t *testing.T) genRepo {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "--quiet", "-b", "main")
	git("commit", "--quiet", "--allow-empty", "-m", "merged milestone")
	onMain := git("rev-parse", "HEAD")
	git("checkout", "--quiet", "-b", "feature")
	git("commit", "--quiet", "--allow-empty", "-m", "branch head")
	return genRepo{dir: dir, onMain: onMain, onTip: git("rev-parse", "HEAD")}
}

func TestRequireMergedCommit_AcceptsACommitOnMain(t *testing.T) {
	repo := newGenRepo(t)
	if err := requireMergedCommit(t.Context(), repo.dir, "main", repo.onMain); err != nil {
		t.Fatal(err)
	}
}

func TestRequireMergedCommit_RefusesABranchHead(t *testing.T) {
	repo := newGenRepo(t)
	err := requireMergedCommit(t.Context(), repo.dir, "main", repo.onTip)
	if err == nil || !strings.Contains(err.Error(), "not an ancestor of main") {
		t.Fatalf("a commit that is not on main was accepted or misreported: %v", err)
	}
}

func TestRequireMergedCommit_RefusesAnAbbreviatedSHA(t *testing.T) {
	repo := newGenRepo(t)
	err := requireMergedCommit(t.Context(), repo.dir, "main", repo.onMain[:7])
	if err == nil || !strings.Contains(err.Error(), "full 40-hex SHA") {
		t.Fatalf("an abbreviated SHA was accepted or misreported: %v", err)
	}
}

func TestRequireMergedCommit_ReportsAMissingHistoryAsAnError(t *testing.T) {
	repo := newGenRepo(t)
	unknown := strings.Repeat("ab", 20)
	err := requireMergedCommit(t.Context(), repo.dir, "main", unknown)
	if err == nil || strings.Contains(err.Error(), "not an ancestor") {
		t.Fatalf("an unknown commit must be a git failure (shallow clone?), not a verdict: %v", err)
	}
}

// ---- the milestone table ----------------------------------------------------------------------

var e2eMilestoneRow = regexp.MustCompile(`\{"(m[0-9]+)", "([0-9a-f]*)", "(v[0-9.]+)", ([0-9]+)\}`)

func TestMilestoneTable_MatchesTheE2ETable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "e2e", "milestones_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := e2eMilestoneRow.FindAllStringSubmatch(string(raw), -1)
	if len(rows) != len(milestones) {
		t.Fatalf("test/e2e/milestones_test.go lists %d milestones, the generator %d", len(rows), len(milestones))
	}
	for i, row := range rows {
		schema, _ := strconv.Atoi(row[4])
		want := milestones[i]
		if row[1] != want.name || row[3] != want.version || schema != want.schema {
			t.Errorf("%s: e2e table says version %s schema %d, generator says %s schema %d", row[1], row[3], schema, want.version, want.schema)
		}
		if row[2] != "" && row[2] != want.commit {
			t.Errorf("%s: e2e table pins %s, generator %s", row[1], row[2], want.commit)
		}
	}
}

func TestMilestoneTable_IsOrderedFullSHAsEndingAtTheLatestSchema(t *testing.T) {
	for i, m := range milestones {
		if m.number() != i+1 || m.name != "m"+strconv.Itoa(i+1) || m.version != "v0."+strconv.Itoa(i+1)+".0" {
			t.Errorf("%s: position %d, version %s", m.name, i+1, m.version)
		}
		if !fullSHA.MatchString(m.commit) {
			t.Errorf("%s: %q is not a full SHA", m.name, m.commit)
		}
		if i > 0 && m.schema <= milestones[i-1].schema {
			t.Errorf("%s: schema %d does not follow %d", m.name, m.schema, milestones[i-1].schema)
		}
	}
	ups, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "*.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	last := milestones[len(milestones)-1]
	switch {
	case last.schema == len(ups):
	case pendingSchema == len(ups) && last.schema < len(ups):
	default:
		t.Errorf("%s: schema %d, but the tree has %d migrations (pending: %d)", last.name, last.schema, len(ups), pendingSchema)
	}
}

// ---- the world --------------------------------------------------------------------------------

func stepTexts(n int) []string {
	var texts []string
	for _, s := range stepsFor(n) {
		texts = append(texts, s.text)
	}
	return texts
}

func hasStepAbout(texts []string, fragment string) bool {
	return slices.ContainsFunc(texts, func(text string) bool { return strings.Contains(text, fragment) })
}

func TestWorld_EachMilestoneRunsOnlyTheCommandsItsBinaryHas(t *testing.T) {
	cases := []struct {
		milestone  int
		has, lacks []string
	}{
		{1, []string{"SSH node", "cancelled", "paused"}, []string{"secrets", "token", "backup", "app fixture-web", "MCP"}},
		{2, []string{"secrets", "token", "backup", "node.setup"}, []string{"app fixture-web", "MCP"}},
		{3, []string{"secrets", "backup"}, []string{"app fixture-web", "MCP"}},
		{4, []string{"app fixture-web"}, []string{"MCP"}},
		{5, []string{"app fixture-web", "MCP client"}, nil},
	}
	for _, c := range cases {
		texts := stepTexts(c.milestone)
		for _, fragment := range c.has {
			if !hasStepAbout(texts, fragment) {
				t.Errorf("m%d: no step about %q", c.milestone, fragment)
			}
		}
		for _, fragment := range c.lacks {
			if hasStepAbout(texts, fragment) {
				t.Errorf("m%d: has a step about %q, which its binary cannot run", c.milestone, fragment)
			}
		}
	}
}

func TestWorld_TheBackupComesLastSoTheArchiveHoldsTheWholeWorld(t *testing.T) {
	for n := 2; n <= len(milestones); n++ {
		texts := stepTexts(n)
		if last := texts[len(texts)-1]; !strings.Contains(last, "backup") {
			t.Errorf("m%d: last step is %q", n, last)
		}
	}
}

func TestWorld_CoversEveryTerminalJobState(t *testing.T) {
	texts := stepTexts(1)
	for _, state := range []string{"succeeded", "failed", "cancelled"} {
		if !hasStepAbout(texts, "-> "+state) {
			t.Errorf("m1: no step ends a job %s", state)
		}
	}
}

func TestJobIn_ReadsASubmissionAPendingDirectAnswerAndAnAppliedOne(t *testing.T) {
	cases := map[string]struct {
		output  string
		want    jobView
		wantJob bool
		wantErr bool
	}{
		"submission": {`{"job":{"id":"j1","state":"awaiting_approval","plan_hash":"h"},"policy":{}}`, jobView{"j1", "awaiting_approval", "h"}, true, false},
		"pending":    {`{"applied":null,"pending":{"job":{"id":"j2","state":"queued","plan_hash":"p"}}}`, jobView{"j2", "queued", "p"}, true, false},
		"applied":    {`{"applied":{"id":"n1"},"pending":null}`, jobView{}, false, false},
		"not json":   {`error: boom`, jobView{}, false, true},
	}
	for name, c := range cases {
		got, ok, err := jobIn(c.output)
		if (err != nil) != c.wantErr || ok != c.wantJob || got != c.want {
			t.Errorf("%s: got %+v, %v, %v", name, got, ok, err)
		}
	}
}

func TestConfiguration_ConfiguresTheBackupDirectoryOnlyWhereTheMilestoneHasBackups(t *testing.T) {
	for _, m := range milestones {
		in := &installation{m: m, dir: "/tmp/smg-x", dataDir: "/tmp/smg-x/data", keysDir: "/tmp/smg-x/keys", backups: "/tmp/smg-x/backups"}
		text := in.configuration()
		if got, want := strings.Contains(text, "backups"), m.number() >= 2; got != want {
			t.Errorf("%s: backup directory configured = %v, want %v", m.name, got, want)
		}
		for _, environment := range []string{"staging", "production"} {
			if !strings.Contains(text, "name: "+environment) {
				t.Errorf("%s: environment %s missing", m.name, environment)
			}
		}
	}
}

// ---- provenance -------------------------------------------------------------------------------

func provenanceRecord(m milestone, files ...fileHash) record {
	return record{
		milestone: m, goVersion: "go1.27.2", schema: m.schema, kekID: "kek-" + m.name,
		transcript: []string{"first step", "second step"}, files: files,
	}
}

func TestProvenance_IsDeterministicForTheSameRecord(t *testing.T) {
	r := provenanceRecord(milestones[1], fileHash{"m2/sm.db", "aa"}, fileHash{"m2/master.key", "bb"})
	reversed := r
	reversed.files = []fileHash{r.files[1], r.files[0]}
	if r.markdown() != reversed.markdown() {
		t.Fatal("the order the files were collected in changes the document")
	}
	first, second := mergeProvenance("", []record{r}), mergeProvenance("", []record{r})
	if first != second {
		t.Fatal("the same record renders differently")
	}
}

func TestProvenance_StatesCommitVersionGoSchemaTranscriptAndEveryFileHash(t *testing.T) {
	m := milestones[2]
	doc := mergeProvenance("", []record{provenanceRecord(m, fileHash{"m3/sm.db", "deadbeef"})})
	for _, want := range []string{
		"## m3", "commit: `" + m.commit + "`", "synthetic version: `v0.3.0`", "Go version: `go1.27.2`", "schema version: 4",
		"| `m3/sm.db` | `deadbeef` |", "1. first step", "2. second step", "Volatile fields",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("document lacks %q:\n%s", want, doc)
		}
	}
}

func TestProvenance_RegeneratingSomeMilestonesKeepsTheOthersInOrder(t *testing.T) {
	first := mergeProvenance("", []record{provenanceRecord(milestones[2], fileHash{"m3/sm.db", "old3"}), provenanceRecord(milestones[0], fileHash{"m1/sm.db", "old1"})})
	merged := mergeProvenance(first, []record{provenanceRecord(milestones[3], fileHash{"m4/sm.db", "new4"}), provenanceRecord(milestones[2], fileHash{"m3/sm.db", "new3"})})
	sections := regexp.MustCompile(`(?m)^## (m[0-9]+)$`).FindAllStringSubmatch(merged, -1)
	var order []string
	for _, s := range sections {
		order = append(order, s[1])
	}
	if want := []string{"m1", "m3", "m4"}; !slices.Equal(order, want) {
		t.Fatalf("sections %v, want %v", order, want)
	}
	for _, want := range []string{"`old1`", "`new3`", "`new4`"} {
		if !strings.Contains(merged, want) {
			t.Errorf("merged document lacks %s", want)
		}
	}
	if strings.Contains(merged, "old3") {
		t.Error("a regenerated milestone kept its previous hash")
	}
}

func TestProvenance_MergingTwiceChangesNothing(t *testing.T) {
	records := []record{provenanceRecord(milestones[0], fileHash{"m1/sm.db", "h1"}), provenanceRecord(milestones[1], fileHash{"m2/sm.db", "h2"})}
	once := mergeProvenance("", records)
	if twice := mergeProvenance(once, records); twice != once {
		t.Fatalf("merging the same records again changed the document:\n%s\n---\n%s", once, twice)
	}
}

func TestHashFile_IsTheSha256OfTheContentWithASlashPath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "m1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "m1", "sm.db"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := hashFile(root, filepath.Join("m1", "sm.db"))
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "m1/sm.db" || got.sha256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("got %+v", got)
	}
}

// ---- the database -----------------------------------------------------------------------------

func TestCheckpointedSchemaVersion_FoldsTheWALSoTheDatabaseFileAloneIsComplete(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "sm.db")
	writer, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	writer.SetMaxOpenConns(1) // keep the connection (and its WAL) open while the checkpoint runs
	for _, stmt := range []string{
		`PRAGMA journal_mode=WAL`,
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)`,
		`INSERT INTO schema_migrations VALUES (1, 'x'), (2, 'x'), (3, 'x')`,
	} {
		if _, err := writer.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	version, err := checkpointedSchemaVersion(ctx, path)
	if err != nil || version != 3 {
		t.Fatalf("version %d, %v; want 3", version, err)
	}
	alone := filepath.Join(t.TempDir(), "copy.db")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alone, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	copied, err := sql.Open("sqlite", "file:"+alone+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = copied.Close() }()
	var rows int
	if err := copied.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&rows); err != nil || rows != 3 {
		t.Fatalf("the copy of the main file alone has %d rows (%v), want 3", rows, err)
	}
}

func TestCheckpointedSchemaVersion_FailsOnADatabaseWithoutMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sm.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE other (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := checkpointedSchemaVersion(t.Context(), path); err == nil {
		t.Fatal("a database without schema_migrations was accepted")
	}
}

// ---- options ----------------------------------------------------------------------------------

func TestParseOptions_SelectsMilestonesAndRefusesUnknownOnes(t *testing.T) {
	o, err := parseOptions([]string{"-only", "m2,m4", "-repo", "/r"})
	if err != nil {
		t.Fatal(err)
	}
	if o.selected(milestones[0]) || !o.selected(milestones[1]) || !o.selected(milestones[3]) {
		t.Errorf("selection %v", o.only)
	}
	if o.ref != "main" || o.out != filepath.Join("/r", "test", "fixtures", "migrations") {
		t.Errorf("defaults: ref %q out %q", o.ref, o.out)
	}
	if _, err := parseOptions([]string{"-only", "m9"}); err == nil {
		t.Error("an unknown milestone was accepted")
	}
}

// ---- the whole generator ----------------------------------------------------------------------

// TestGenerate_M1ProducesFixturesThatMatchTheirProvenance runs the generator for real: it builds
// the M1 binary, starts a docker node and a daemon. It is opt-in (SM_FIXTUREGEN_E2E=1).
func TestGenerate_M1ProducesFixturesThatMatchTheirProvenance(t *testing.T) {
	if os.Getenv("SM_FIXTUREGEN_E2E") != "1" {
		t.Skip("set SM_FIXTUREGEN_E2E=1 to build M1 and drive it against a docker node")
	}
	out := t.TempDir()
	repo, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := generate(t.Context(), options{repo: repo, out: out, ref: "HEAD", only: map[string]bool{"m1": true}}); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(out, "PROVENANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"m1/sm.db", "m1/master.key"} {
		h, err := hashFile(out, rel)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(doc), "| `"+h.path+"` | `"+h.sha256+"` |") {
			t.Errorf("PROVENANCE.md does not state the hash of %s", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "m1", "sm.db-wal")); err == nil {
		t.Error("a write-ahead log was left next to the database")
	}
}
