// Package docs_test keeps the documentation honest (ADR-0036): what a page cites must exist, and a
// platform may be called supported only when CI runs every operation on it. Standard library and
// the YAML decoder only; nothing here builds or runs the product.
package docs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// repoRoot is the directory holding go.mod, found from the test's working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// docPages are the Markdown pages whose citations are checked: docs/*.md and the manual checklists.
func docPages(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var pages []string
	for _, pattern := range []string{"docs/*.md", "docs/manual-checks/*.md"} {
		found, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, found...)
	}
	if len(pages) == 0 {
		t.Fatal("no documentation pages found")
	}
	sort.Strings(pages)
	return pages
}

func relativeTo(t *testing.T, path string) string {
	t.Helper()
	rel, err := filepath.Rel(repoRoot(t), path)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// ---- cited tests exist -------------------------------------------------------------------------

var (
	declaredTestFunc = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]*)\(`)
	backtickSpan     = regexp.MustCompile("`([^`\n]+)`")
	citedTestName    = regexp.MustCompile(`\b((?:Test|Fuzz)[A-Za-z0-9_]*)(\*?)`)
)

// declaredTests lists every Test and Fuzz function declared in a _test.go file of the repository.
func declaredTests(t *testing.T) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(repoRoot(t), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "node_modules", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range declaredTestFunc.FindAllSubmatch(src, -1) {
			names = append(names, string(m[1]))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// citedTests returns the test names a page quotes in code spans. A trailing `*` or `_` means a
// family (TestM3_Uninstall*, TestM4_), which needs at least one declared test with that prefix.
func citedTests(page string) map[string]bool {
	cited := map[string]bool{}
	for _, span := range backtickSpan.FindAllStringSubmatch(page, -1) {
		for _, m := range citedTestName.FindAllStringSubmatch(span[1], -1) {
			name := m[1] + m[2]
			if name == "Test" || name == "Fuzz" || name == "Test*" || name == "Fuzz*" {
				continue
			}
			cited[name] = true
		}
	}
	return cited
}

func isDeclared(name string, declared []string) bool {
	prefix, family := strings.CutSuffix(name, "*")
	family = family || strings.HasSuffix(name, "_")
	for _, d := range declared {
		if d == prefix || family && strings.HasPrefix(d, prefix) {
			return true
		}
	}
	return false
}

func TestEveryCitedTestExists(t *testing.T) {
	declared := declaredTests(t)
	for _, path := range docPages(t) {
		page, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for name := range citedTests(string(page)) {
			if !isDeclared(name, declared) {
				t.Errorf("%s cites %s, which no _test.go file declares", relativeTo(t, path), name)
			}
		}
	}
}

func TestCitedTestNamesAreParsedAsFamiliesOrExactNames(t *testing.T) {
	declared := []string{"TestUpgrade_Resumes", "TestM3_UninstallKeepsData", "FuzzReadArchive"}
	tests := []struct {
		cited string
		want  bool
	}{
		{"TestUpgrade_Resumes", true},
		{"TestUpgrade_Resume", false},
		{"TestUpgrade_*", true},
		{"TestM3_Uninstall*", true},
		{"TestM3_", true},
		{"TestM4_", false},
		{"FuzzReadArchive", true},
		{"TestMissing", false},
	}
	for _, tc := range tests {
		if got := isDeclared(tc.cited, declared); got != tc.want {
			t.Errorf("isDeclared(%q) = %v, want %v", tc.cited, got, tc.want)
		}
	}
}

// ---- cited jobs exist --------------------------------------------------------------------------

// A job is cited as "CI job `x`", "CI jobs `x`, `y` and `z`" or "(job `x`". Other uses of the word
// (job states such as `running`) are not citations.
var (
	citedJobList = regexp.MustCompile("(?:CI jobs?|\\(jobs?) ((?:`[a-z][a-z0-9-]*`(?:, and |, | and | or )?)+)")
	quotedName   = regexp.MustCompile("`([^`]+)`")
)

// workflowJobs returns the job ids of every workflow file.
func workflowJobs(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	jobs := map[string]bool{}
	for _, f := range files {
		var wf struct {
			Jobs map[string]yaml.Node `yaml:"jobs"`
		}
		decodeYAMLFile(t, f, &wf)
		for id := range wf.Jobs {
			jobs[id] = true
		}
	}
	return jobs
}

func decodeYAMLFile(t *testing.T, path string, out any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v", relativeTo(t, path), err)
	}
}

func TestEveryCitedJobExists(t *testing.T) {
	jobs := workflowJobs(t)
	for _, path := range docPages(t) {
		page, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, list := range citedJobList.FindAllStringSubmatch(string(page), -1) {
			for _, name := range quotedName.FindAllStringSubmatch(list[1], -1) {
				if !jobs[name[1]] {
					t.Errorf("%s cites job %q, which no workflow defines", relativeTo(t, path), name[1])
				}
			}
		}
	}
}

// ---- links resolve -----------------------------------------------------------------------------

var (
	markdownLink = regexp.MustCompile(`\[[^\]\n]*\]\(([^)\s]+)\)`)
	headingLine  = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*$`)
	slugDrop     = regexp.MustCompile(`[^a-z0-9 _-]`)
	linkInHead   = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
)

// anchorsOf lists the GitHub-style heading anchors of a Markdown page, ignoring fenced code.
func anchorsOf(page string) map[string]bool {
	anchors := map[string]bool{}
	seen := map[string]int{}
	inFence := false
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		m := headingLine.FindStringSubmatch(line)
		if inFence || m == nil {
			continue
		}
		slug := strings.ReplaceAll(slugDrop.ReplaceAllString(strings.ToLower(headingText(m[1])), ""), " ", "-")
		if n := seen[slug]; n > 0 {
			anchors[fmt.Sprintf("%s-%d", slug, n)] = true
		} else {
			anchors[slug] = true
		}
		seen[slug]++
	}
	return anchors
}

// headingText drops the Markdown markup GitHub ignores when it builds an anchor.
func headingText(h string) string {
	h = linkInHead.ReplaceAllString(h, "$1")
	return strings.NewReplacer("`", "", "*", "").Replace(h)
}

// linksOf returns the link targets of a page outside fenced code and code spans.
func linksOf(page string) []string {
	var links []string
	inFence := false
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		line = backtickSpan.ReplaceAllString(line, "")
		for _, m := range markdownLink.FindAllStringSubmatch(line, -1) {
			links = append(links, m[1])
		}
	}
	return links
}

func TestEveryRelativeLinkResolves(t *testing.T) {
	for _, path := range docPages(t) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, link := range linksOf(string(b)) {
			if strings.Contains(link, "://") || strings.HasPrefix(link, "mailto:") {
				continue
			}
			file, fragment, _ := strings.Cut(link, "#")
			target := path
			if file != "" {
				target = filepath.Join(filepath.Dir(path), file)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Errorf("%s links to %s, which does not exist", relativeTo(t, path), link)
				continue
			}
			if fragment == "" || info.IsDir() || !strings.HasSuffix(target, ".md") {
				continue
			}
			content, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if !anchorsOf(string(content))[fragment] {
				t.Errorf("%s links to %s, but %s has no heading with that anchor", relativeTo(t, path), link, relativeTo(t, target))
			}
		}
	}
}

func TestAnchorsFollowTheGitHubRule(t *testing.T) {
	page := "# Proxmox VE (M3)\n## `sm join`: a node\n## Same\n## Same\n```\n# not a heading\n```\n"
	got := anchorsOf(page)
	for _, want := range []string{"proxmox-ve-m3", "sm-join-a-node", "same", "same-1"} {
		if !got[want] {
			t.Errorf("anchor %q missing from %v", want, got)
		}
	}
	if got["not-a-heading"] {
		t.Error("a heading inside a code fence produced an anchor")
	}
}

// ---- the platform matrix -----------------------------------------------------------------------

const matrixPage = "docs/compatibility.md"

// operations are the four cells a supported platform must fill, in column order.
var operations = []string{"install", "upgrade", "backup and restore", "uninstall"}

// statuses are the only labels a row may carry (spec section 35, ADR-0036).
var statuses = map[string]bool{
	"supported": true, "container-verified": true, "fake-verified": true, "manual": true, "not claimed": true,
}

// mustBeProven are the statuses whose operations all need a test and a job.
var mustBeProven = map[string]bool{"supported": true, "container-verified": true}

// runnerArch is the CPU architecture of each GitHub-hosted runner label the workflows use. A new
// label must be added here on purpose: a guess would let a row claim an architecture nothing runs.
var runnerArch = map[string]string{
	"ubuntu-latest":    "amd64",
	"ubuntu-24.04":     "amd64",
	"ubuntu-24.04-arm": "arm64",
	"macos-15":         "arm64",
	"macos-latest":     "arm64",
}

type matrixRow struct {
	platform, arch, mode, status string
	cells                        [4]string
}

var (
	cellTest = regexp.MustCompile(`\b(Test[A-Za-z0-9_]+)`)
	cellJob  = regexp.MustCompile("\\bjob `([a-z][a-z0-9-]*)`")
)

// matrixRows reads the table under the heading "Platforms and operations" of the compatibility page.
func matrixRows(t *testing.T, page string) []matrixRow {
	t.Helper()
	_, section, found := strings.Cut(page, "\n## Platforms and operations")
	if !found {
		t.Fatalf("%s has no \"Platforms and operations\" section", matrixPage)
	}
	if end := strings.Index(section[1:], "\n#"); end >= 0 {
		section = section[:end+1]
	}
	var rows []matrixRow
	for _, line := range strings.Split(section, "\n") {
		cols := tableCells(line)
		if len(cols) == 0 || cols[0] == "Platform" || strings.HasPrefix(cols[0], "---") {
			continue
		}
		if len(cols) != 8 {
			t.Fatalf("%s: matrix row has %d columns, want 8: %s", matrixPage, len(cols), line)
		}
		rows = append(rows, matrixRow{
			platform: cols[0], arch: cols[1], mode: cols[2], status: cols[3],
			cells: [4]string{cols[4], cols[5], cols[6], cols[7]},
		})
	}
	if len(rows) == 0 {
		t.Fatalf("%s: the platform matrix has no rows", matrixPage)
	}
	return rows
}

func tableCells(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") {
		return nil
	}
	var cells []string
	for _, c := range strings.Split(strings.Trim(line, "|"), "|") {
		cells = append(cells, strings.TrimSpace(c))
	}
	return cells
}

// jobCoverage says which architectures and modes a CI job runs on, from its runs-on and matrix.
type jobCoverage struct {
	arches map[string]bool
	modes  map[string]bool // nil when the job has no mode axis
}

type ciMatrix map[string]any

func (m ciMatrix) strings(t *testing.T, job, axis string) []string {
	t.Helper()
	list, ok := m[axis].([]any)
	if !ok {
		t.Fatalf("job %q: matrix axis %q is not a list", job, axis)
	}
	var out []string
	for _, v := range list {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

type ciJob struct {
	RunsOn   string `yaml:"runs-on"`
	Strategy struct {
		Matrix ciMatrix `yaml:"matrix"`
	} `yaml:"strategy"`
}

func ciJobs(t *testing.T) map[string]ciJob {
	t.Helper()
	var wf struct {
		Jobs map[string]ciJob `yaml:"jobs"`
	}
	decodeYAMLFile(t, filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"), &wf)
	return wf.Jobs
}

func coverageOf(t *testing.T, jobs map[string]ciJob, id string) jobCoverage {
	t.Helper()
	job, ok := jobs[id]
	if !ok {
		t.Fatalf("job %q is not in ci.yml", id)
	}
	runners := []string{job.RunsOn}
	if axis, ok := strings.CutSuffix(strings.TrimPrefix(job.RunsOn, "${{ matrix."), " }}"); ok && axis != job.RunsOn {
		runners = job.Strategy.Matrix.strings(t, id, axis)
	}
	cov := jobCoverage{arches: map[string]bool{}}
	for _, r := range runners {
		arch, known := runnerArch[r]
		if !known {
			t.Fatalf("job %q runs on %q, which runnerArch does not know: add its architecture to test/docs", id, r)
		}
		cov.arches[arch] = true
	}
	if _, ok := job.Strategy.Matrix["mode"]; ok {
		cov.modes = map[string]bool{}
		for _, m := range job.Strategy.Matrix.strings(t, id, "mode") {
			cov.modes[m] = true
		}
	}
	return cov
}

// matrixProblems returns every way the rows fail the ADR-0036 rule.
func matrixProblems(rows []matrixRow, declared []string, jobs map[string]ciJob, cover func(string) jobCoverage) []string {
	var problems []string
	for _, r := range rows {
		name := fmt.Sprintf("%s %s %s", r.platform, r.arch, r.mode)
		if !statuses[r.status] {
			problems = append(problems, fmt.Sprintf("%s: status %q is not one of supported, container-verified, fake-verified, manual, not claimed", name, r.status))
		}
		for i, cell := range r.cells {
			if cell == "" || cell == "-" || cell == "none" {
				if mustBeProven[r.status] {
					problems = append(problems, fmt.Sprintf("%s is %s but has no test and job for %s", name, r.status, operations[i]))
				}
				continue
			}
			problems = append(problems, cellProblems(name, operations[i], cell, r, declared, jobs, cover)...)
		}
	}
	return problems
}

func cellProblems(name, op, cell string, r matrixRow, declared []string, jobs map[string]ciJob, cover func(string) jobCoverage) []string {
	var problems []string
	test, job := cellTest.FindString(cell), cellJob.FindStringSubmatch(cell)
	if test == "" || job == nil {
		return []string{fmt.Sprintf("%s, %s: the cell must name a Test and a job `x`, got %q", name, op, cell)}
	}
	if !isDeclared(test, declared) {
		problems = append(problems, fmt.Sprintf("%s, %s: %s is not declared in any _test.go file", name, op, test))
	}
	if _, ok := jobs[job[1]]; !ok {
		return append(problems, fmt.Sprintf("%s, %s: job %q is not in ci.yml", name, op, job[1]))
	}
	cov := cover(job[1])
	if !cov.arches[r.arch] {
		problems = append(problems, fmt.Sprintf("%s, %s: job %q does not run on %s", name, op, job[1], r.arch))
	}
	if cov.modes != nil && !cov.modes[r.mode] {
		problems = append(problems, fmt.Sprintf("%s, %s: job %q does not run mode %s", name, op, job[1], r.mode))
	}
	return problems
}

func TestPlatformMatrixClaimsOnlyWhatCIRuns(t *testing.T) {
	rows := matrixRows(t, readRepoFile(t, matrixPage))
	jobs := ciJobs(t)
	cover := func(id string) jobCoverage { return coverageOf(t, jobs, id) }
	for _, p := range matrixProblems(rows, declaredTests(t), jobs, cover) {
		t.Error(p)
	}
}

func TestPlatformMatrixRuleRejectsWhatItShould(t *testing.T) {
	jobs := map[string]ciJob{"lifecycle": {}, "other": {}}
	cover := func(id string) jobCoverage {
		if id == "lifecycle" {
			return jobCoverage{arches: map[string]bool{"amd64": true}, modes: map[string]bool{"server": true}}
		}
		return jobCoverage{arches: map[string]bool{"amd64": true}}
	}
	declared := []string{"TestLifecycle"}
	cell := "`TestLifecycle` job `lifecycle`"
	full := [4]string{cell, cell, cell, cell}
	tests := []struct {
		name string
		row  matrixRow
		want string // substring of the expected problem; empty means none
	}{
		{"complete supported row", matrixRow{"Ubuntu", "amd64", "server", "supported", full}, ""},
		{"missing cell", matrixRow{"Ubuntu", "amd64", "server", "supported", [4]string{cell, cell, "", cell}}, "no test and job for backup and restore"},
		{"unknown test", matrixRow{"Ubuntu", "amd64", "server", "supported", [4]string{"`TestNope` job `lifecycle`", cell, cell, cell}}, "TestNope is not declared"},
		{"unknown job", matrixRow{"Ubuntu", "amd64", "server", "supported", [4]string{"`TestLifecycle` job `ghost`", cell, cell, cell}}, `job "ghost" is not in ci.yml`},
		{"wrong architecture", matrixRow{"Ubuntu", "arm64", "server", "supported", full}, "does not run on arm64"},
		{"wrong mode", matrixRow{"Ubuntu", "amd64", "local-client", "supported", full}, "does not run mode local-client"},
		{"invented status", matrixRow{"Ubuntu", "amd64", "server", "works great", full}, "is not one of"},
		{"container-verified needs all four", matrixRow{"Debian", "amd64", "server", "container-verified", [4]string{cell, "", "", ""}}, "no test and job for upgrade"},
		{"manual row may be empty", matrixRow{"Intel Mac", "amd64", "local-client", "manual", [4]string{}}, ""},
		{"cell without a job", matrixRow{"Ubuntu", "amd64", "server", "fake-verified", [4]string{"`TestLifecycle`", "", "", ""}}, "must name a Test and a job"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matrixProblems([]matrixRow{tc.row}, declared, jobs, cover)
			switch {
			case tc.want == "" && len(got) != 0:
				t.Errorf("unexpected problems: %v", got)
			case tc.want != "" && !strings.Contains(strings.Join(got, "\n"), tc.want):
				t.Errorf("problems %v do not contain %q", got, tc.want)
			}
		})
	}
}

// ---- the release checklist ---------------------------------------------------------------------

// checklistPages are written by the docs-B task; the rule applies as soon as they exist.
var checklistPages = []string{"docs/release-checklist.md", "docs/manual-checks/m6-release.md"}

var (
	humanRow     = regexp.MustCompile(`\[human\]`)
	uncheckedBox = regexp.MustCompile(`^\s*[-*]\s*\[ \]`)
	rowOwner     = regexp.MustCompile(`(?i)\bowner:\s*\S`)
	rowProcedure = regexp.MustCompile(`(?i)\bprocedure:\s*\S`)
)

// humanRowProblems checks the lines tagged [human]: each is an unchecked box with an owner and a
// procedure, because a human check that is already ticked or has nobody to run it proves nothing.
func humanRowProblems(page string) []string {
	var problems []string
	for i, line := range strings.Split(page, "\n") {
		if !humanRow.MatchString(line) {
			continue
		}
		switch {
		case !uncheckedBox.MatchString(line):
			problems = append(problems, fmt.Sprintf("line %d: a [human] row must start with an unchecked box \"- [ ]\"", i+1))
		case !rowOwner.MatchString(line):
			problems = append(problems, fmt.Sprintf("line %d: a [human] row must say \"owner: <who>\"", i+1))
		case !rowProcedure.MatchString(line):
			problems = append(problems, fmt.Sprintf("line %d: a [human] row must say \"procedure: <where>\"", i+1))
		}
	}
	return problems
}

func TestHumanChecklistRowsAreUncheckedWithOwnerAndProcedure(t *testing.T) {
	for _, rel := range checklistPages {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range humanRowProblems(string(b)) {
			t.Errorf("%s: %s", rel, p)
		}
	}
}

func TestHumanRowRule(t *testing.T) {
	good := "- [ ] [human] Fresh Debian VM install. owner: release owner. procedure: manual-checks/m6-release.md#debian"
	bad := map[string]string{
		"ticked":         "- [x] [human] Fresh Debian VM install. owner: me. procedure: here",
		"no owner":       "- [ ] [human] Fresh Debian VM install. procedure: here",
		"no procedure":   "- [ ] [human] Fresh Debian VM install. owner: me",
		"not a checkbox": "[human] Fresh Debian VM install. owner: me. procedure: here",
	}
	if got := humanRowProblems(good); len(got) != 0 {
		t.Errorf("good row rejected: %v", got)
	}
	for name, row := range bad {
		if len(humanRowProblems(row)) == 0 {
			t.Errorf("%s: row accepted: %s", name, row)
		}
	}
}
