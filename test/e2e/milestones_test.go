//go:build e2e

package e2e_test

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// milestone is a historical build that upgrade and migration tests run as a real older binary
// (ADR-0035). No release tag exists yet, so each one is its merge commit on main, built as a
// synthetic semantic version; schema is the schema version that build leaves behind.
type milestone struct {
	name    string
	commit  string
	version string
	schema  int
}

// merged reports whether the milestone has its merge commit on main. Until it does, nothing may
// pin a branch head in its place: a squash merge would orphan that commit.
func (m milestone) merged() bool { return m.commit != "" }

// milestones lists M1..M5 in merge order.
var milestones = []milestone{
	{"m1", "0c31ac148e3b78668c1e9425eb34d089700a6eba", "v0.1.0", 2},
	{"m2", "e6d5577bb51e8837a58d9d48cd06e9c2bfd2641a", "v0.2.0", 3},
	{"m3", "e13d021a09a796d50527a92b8f2a9832fbe01c99", "v0.3.0", 4},
	{"m4", "f4195937b25e1570e49f63158e3bcca83ee42e54", "v0.4.0", 5},
	{"m5", "658078b15d68846ed67b80d4e2f463c114be27cf", "v0.5.0", 6},
}

var (
	fullCommit     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	syntheticMinor = regexp.MustCompile(`^v0\.([1-9][0-9]*)\.0$`)
)

// minor is the milestone number a synthetic version v0.N.0 encodes, or 0 when it is not one.
func (m milestone) minor() int {
	match := syntheticMinor.FindStringSubmatch(m.version)
	if match == nil {
		return 0
	}
	n, _ := strconv.Atoi(match[1])
	return n
}

func TestMilestones_AreOrderedAndEndAtTheLatestSchema(t *testing.T) {
	for i, m := range milestones {
		if m.minor() != i+1 {
			t.Errorf("%s: version %q, want v0.%d.0", m.name, m.version, i+1)
		}
		if i == 0 {
			continue
		}
		if prev := milestones[i-1]; m.schema <= prev.schema {
			t.Errorf("%s: schema %d does not follow %d", m.name, m.schema, prev.schema)
		}
	}
	ups, err := filepath.Glob(filepath.Join(harness.RepoRoot(), "migrations", "*.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if last := milestones[len(milestones)-1]; last.schema != len(ups) {
		t.Errorf("%s: schema %d, but the tree has %d migrations", last.name, last.schema, len(ups))
	}
}

func TestMilestones_MergedCommitsAreFullAncestorsOfHead(t *testing.T) {
	for _, m := range milestones {
		if !m.merged() {
			continue
		}
		if !fullCommit.MatchString(m.commit) {
			t.Errorf("%s: commit %q is not a full SHA", m.name, m.commit)
			continue
		}
		res, err := harness.Run(context.Background(), harness.RepoRoot(), nil, "", "git", "merge-base", "--is-ancestor", m.commit, "HEAD")
		if e := commandFailure("git merge-base --is-ancestor "+m.commit+" HEAD (CI needs fetch-depth: 0)", res, err); e != nil {
			t.Errorf("%s: %v", m.name, e)
		}
	}
}
