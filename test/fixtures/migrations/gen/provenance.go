//go:build fixturegen && fixtures

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	_ "modernc.org/sqlite" // the driver that reads the schema version of a generated database
)

// milestone is a historical build the generator runs as a real older binary (ADR-0035): its merge
// commit on main, the synthetic version it is built as and the schema it leaves behind. The table
// mirrors test/e2e/milestones_test.go; TestMilestoneTable_MatchesTheE2ETable keeps them equal.
type milestone struct {
	name    string
	commit  string
	version string
	schema  int
}

var milestones = []milestone{
	{"m1", "0c31ac148e3b78668c1e9425eb34d089700a6eba", "v0.1.0", 2},
	{"m2", "e6d5577bb51e8837a58d9d48cd06e9c2bfd2641a", "v0.2.0", 3},
	{"m3", "e13d021a09a796d50527a92b8f2a9832fbe01c99", "v0.3.0", 4},
	{"m4", "f4195937b25e1570e49f63158e3bcca83ee42e54", "v0.4.0", 5},
	{"m5", "658078b15d68846ed67b80d4e2f463c114be27cf", "v0.5.0", 6},
}

// pendingSchema is the highest migration merged after the last milestone and not yet released:
// its fixture can only be generated from a merge commit on main (ADR-0035), so it is listed here
// until a milestone with that schema is added, then set back to 0. Every migration between the
// last milestone and it is pending too. 7: 000007_cloudflare_tunnels, 8: 000008_tunnel_enrollments.
const pendingSchema = 8

// number is the N of mN.
func (m milestone) number() int {
	for i, other := range milestones {
		if other.name == m.name {
			return i + 1
		}
	}
	return 0
}

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// requireMergedCommit refuses a commit that is not a full SHA or not an ancestor of ref in the
// repository at repo. A branch head that a squash merge will orphan fails here, so no fixture can
// be generated from one.
func requireMergedCommit(ctx context.Context, repo, ref, commit string) error {
	if !fullSHA.MatchString(commit) {
		return fmt.Errorf("commit %q is not a full 40-hex SHA", commit)
	}
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "merge-base", "--is-ancestor", commit, ref)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return fmt.Errorf("commit %s is not an ancestor of %s: a fixture is never pinned to a branch head", commit, ref)
	default:
		return fmt.Errorf("git merge-base --is-ancestor %s %s (full history needed): %w: %s", commit, ref, err, strings.TrimSpace(stderr.String()))
	}
}

// checkpointedSchemaVersion checkpoints the write-ahead log of the database at path into the main file,
// so that a copy of sm.db alone is complete, and returns the schema version it records.
func checkpointedSchemaVersion(ctx context.Context, path string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rw")
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return 0, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	var version int
	if err := db.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read the schema version of %s: %w", path, err)
	}
	return version, nil
}

// fileHash is one generated file: its path relative to the fixtures directory and its sha256.
type fileHash struct {
	path   string
	sha256 string
}

func hashFile(root, rel string) (fileHash, error) {
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return fileHash{}, err
	}
	sum := sha256.Sum256(raw)
	return fileHash{path: filepath.ToSlash(rel), sha256: hex.EncodeToString(sum[:])}, nil
}

// record is what PROVENANCE.md says about one milestone.
type record struct {
	milestone  milestone
	goVersion  string
	schema     int
	kekID      string
	transcript []string
	files      []fileHash
}

const provenanceHeader = `# Migration fixtures provenance (ADR-0035)

Each section records a fixture set produced by the **real binary** of one milestone: built from the
full merge commit on ` + "`main`" + ` (` + "`git archive`" + `, synthetic version) and driven through the scripted world
of ` + "`test/fixtures/migrations/gen`" + `. Regenerate with ` + "`make migration-fixtures`" + `; pull-request CI does not.

Volatile fields: the generator is deterministic in its steps, its transcript and the file names. These
differ on every run and are not reproducible: the bytes of ` + "`sm.db`" + ` (row ids, timestamps, wrapped keys), the
master key and its id, the bytes of the archive, and the host key of the node. Files are therefore pinned by
hash, and a changed hash is a regeneration, not a drift.

CI checks per section: the commit is a full SHA and an ancestor of HEAD, the schema equals
` + "`test/e2e/milestones_test.go`" + `, and every file hash below equals the file on disk.
`

// markdown renders the section of one milestone. The file table rows are the contract of
// TestMigrationFixtures_Provenance: | `path` | `sha256` |.
func (r record) markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", r.milestone.name)
	fmt.Fprintf(&b, "- commit: `%s`\n- synthetic version: `%s`\n- Go version: `%s`\n- schema version: %d\n- master key id: `%s`\n\n",
		r.milestone.commit, r.milestone.version, r.goVersion, r.schema, r.kekID)
	b.WriteString("| file | sha256 |\n|---|---|\n")
	files := append([]fileHash(nil), r.files...)
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	for _, f := range files {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", f.path, f.sha256)
	}
	b.WriteString("\nTranscript:\n\n")
	for i, line := range r.transcript {
		fmt.Fprintf(&b, "%d. %s\n", i+1, line)
	}
	return b.String()
}

var sectionStart = regexp.MustCompile(`(?m)^## (m[0-9]+)$`)

// splitSections returns the "## mN" sections of a PROVENANCE.md by milestone name.
func splitSections(doc string) map[string]string {
	sections := map[string]string{}
	starts := sectionStart.FindAllStringSubmatchIndex(doc, -1)
	for i, loc := range starts {
		end := len(doc)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		sections[doc[loc[2]:loc[3]]] = strings.TrimRight(doc[loc[0]:end], "\n") + "\n"
	}
	return sections
}

// mergeProvenance replaces the sections of the regenerated milestones and keeps the others, so
// generating M1-M3 and later M4-M5 yields one document in milestone order.
func mergeProvenance(existing string, fresh []record) string {
	sections := splitSections(existing)
	for _, r := range fresh {
		sections[r.milestone.name] = r.markdown()
	}
	var b strings.Builder
	b.WriteString(provenanceHeader)
	for _, m := range milestones {
		if section, ok := sections[m.name]; ok {
			b.WriteString("\n" + section)
		}
	}
	return b.String()
}
