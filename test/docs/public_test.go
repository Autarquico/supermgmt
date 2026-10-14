package docs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ---- the manifest of public pages --------------------------------------------------------------

const manifestPath = "docs/public-pages.txt"

// internalPages are the files of docs/ that are never published on the website.
var internalPages = []string{"STATUS.md", "release-checklist.md", "releasing.md"}

type publicPage struct{ section, file string }

// parseManifest reads "[Section]" lines and the docs/ file names under them, and reports every
// rule the format breaks. It does not touch the file system.
func parseManifest(text string) ([]publicPage, []string) {
	var pages []publicPage
	var problems []string
	section := ""
	seen := map[string]bool{}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" {
				problems = append(problems, fmt.Sprintf("line %d: empty section name", i+1))
			}
			continue
		}
		for _, p := range pageProblems(line, section, seen) {
			problems = append(problems, fmt.Sprintf("line %d: %s", i+1, p))
		}
		seen[line] = true
		pages = append(pages, publicPage{section, line})
	}
	return pages, problems
}

func pageProblems(file, section string, seen map[string]bool) []string {
	var problems []string
	if section == "" {
		problems = append(problems, file+" is listed before any [Section]")
	}
	if seen[file] {
		problems = append(problems, file+" is listed twice")
	}
	if strings.ContainsAny(file, `/\`) {
		problems = append(problems, file+" is not a flat file name")
	}
	if !strings.HasSuffix(file, ".md") {
		problems = append(problems, file+" is not a Markdown page")
	}
	if slices.Contains(internalPages, file) {
		problems = append(problems, file+" is internal and must not be published")
	}
	return problems
}

func publicPages(t *testing.T) []publicPage {
	t.Helper()
	pages, problems := parseManifest(readRepoFile(t, manifestPath))
	for _, p := range problems {
		t.Errorf("%s: %s", manifestPath, p)
	}
	if len(pages) == 0 {
		t.Fatalf("%s lists no pages", manifestPath)
	}
	return pages
}

func TestManifestListsOnlyExistingPages(t *testing.T) {
	root := repoRoot(t)
	for _, p := range publicPages(t) {
		if _, err := os.Stat(filepath.Join(root, "docs", p.file)); err != nil {
			t.Errorf("%s lists %s, which does not exist in docs/", manifestPath, p.file)
		}
	}
}

func TestEveryDocsPageIsPublicOrDeclaredInternal(t *testing.T) {
	listed := map[string]bool{}
	for _, p := range publicPages(t) {
		listed[p.file] = true
	}
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		name := filepath.Base(f)
		if !listed[name] && !slices.Contains(internalPages, name) {
			t.Errorf("docs/%s is neither in %s nor a known internal page", name, manifestPath)
		}
	}
}

func TestManifestRuleRejectsWhatItShould(t *testing.T) {
	tests := []struct{ name, manifest, want string }{
		{"page before any section", "overview.md\n", "before any [Section]"},
		{"duplicate page", "[A]\noverview.md\noverview.md\n", "listed twice"},
		{"subfolder", "[A]\nadr/0001.md\n", "not a flat file name"},
		{"not markdown", "[A]\nlogo.svg\n", "not a Markdown page"},
		{"internal page", "[A]\nSTATUS.md\n", "internal"},
		{"empty section", "[]\noverview.md\n", "empty section name"},
	}
	for _, tc := range tests {
		_, problems := parseManifest(tc.manifest)
		if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
			t.Errorf("%s: problems %v do not mention %q", tc.name, problems, tc.want)
		}
	}
	if _, problems := parseManifest("# comment\n\n[A]\noverview.md\n[B]\nconcepts.md\n"); len(problems) != 0 {
		t.Errorf("a valid manifest was rejected: %v", problems)
	}
}

// ---- no internal vocabulary in public prose ----------------------------------------------------

// internalVocabulary matches milestone codes, finding IDs, spec section numbers and ADR numbers.
// It is case-sensitive on purpose: manual-check file names use lower-case m1..m6, and those only
// appear in link targets, which are stripped anyway.
var internalVocabulary = regexp.MustCompile(`\bM[0-6]\b|\bSEC-\d|\bCODE-\d|§\s?\d|\bADR-\d`)

var (
	linkTarget     = regexp.MustCompile(`\]\([^)\s]*\)`)
	referencesHead = regexp.MustCompile(`^## References\s*$`)
)

// vocabularyHits returns "line: match" for each line of prose that uses internal vocabulary.
// Fenced code, code spans, link targets and the final "## References" section are not prose.
func vocabularyHits(page string) []string {
	var hits []string
	inFence := false
	for i, line := range strings.Split(page, "\n") {
		if referencesHead.MatchString(line) {
			break
		}
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		line = linkTarget.ReplaceAllString(backtickSpan.ReplaceAllString(line, ""), "]")
		if m := internalVocabulary.FindString(line); m != "" {
			hits = append(hits, fmt.Sprintf("%d: %q", i+1, m))
		}
	}
	return hits
}

func TestPublicPagesUseNoInternalVocabularyInProse(t *testing.T) {
	for _, p := range publicPages(t) {
		for _, hit := range vocabularyHits(readRepoFile(t, "docs/"+p.file)) {
			t.Errorf("docs/%s:%s", p.file, hit)
		}
	}
}

func TestVocabularyRuleRejectsWhatItShould(t *testing.T) {
	bad := []string{
		"Built in M3.", "See SEC-12.", "Finding CODE-4 is fixed.", "Spec §11.5 says so.",
		"Decided in ADR-0036.", "## Platforms (M6)",
	}
	for _, line := range bad {
		if len(vocabularyHits(line)) == 0 {
			t.Errorf("%q was accepted", line)
		}
	}
	good := []string{
		"Read the [checklist](manual-checks/m3-real-pve.md).",
		"The `TestM3_Appliance*` family covers it.",
		"```\nM3 inside code\n```",
		"A model M7 or a form like XM3 is fine.",
		"Body.\n\n## References\n\n- [ADR-0036](adr/0036-x.md) and §30",
	}
	for _, page := range good {
		if hits := vocabularyHits(page); len(hits) != 0 {
			t.Errorf("%q was rejected: %v", page, hits)
		}
	}
}

// ---- the web version of the command reference is published -------------------------------------

func TestTheGeneratedCommandReferenceIsPublic(t *testing.T) {
	for _, p := range publicPages(t) {
		if p.file == "cli.md" {
			return
		}
	}
	t.Errorf("%s does not list cli.md", manifestPath)
}

// ---- the claims table of the status page ------------------------------------------------------

const statusPage = "docs/project-status.md"

var (
	claimsHeader = []string{"Claim", "Scope", "Evidence", "Level", "Limitation"}
	claimLevels  = []string{
		"implemented and tested in CI", "tested against fakes", "configured, not yet run", "not verified",
	}
	passedAtCommit = regexp.MustCompile("passed at `[0-9a-f]{7,40}`")
	citedJob       = regexp.MustCompile("job `[a-z][a-z0-9-]*`")
)

// claimsTableProblems checks the shape of the table under "## Claims": exact header, five
// non-empty cells per row, one of four levels, and for a CI-tested claim a job and a recorded commit.
func claimsTableProblems(page string) []string {
	_, section, found := strings.Cut(page, "\n## Claims\n")
	if !found {
		return []string{"no \"## Claims\" section"}
	}
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	var rows [][]string
	var problems []string
	for _, line := range strings.Split(section, "\n") {
		if cells := tableCells(line); cells != nil {
			rows = append(rows, cells)
		}
	}
	if len(rows) < 3 {
		return []string{"the claims table needs a header, a separator and at least one row"}
	}
	if !slices.Equal(rows[0], claimsHeader) {
		problems = append(problems, fmt.Sprintf("header is %v, want %v", rows[0], claimsHeader))
	}
	for _, row := range rows[2:] {
		problems = append(problems, claimRowProblems(row)...)
	}
	return problems
}

func claimRowProblems(row []string) []string {
	if len(row) != len(claimsHeader) {
		return []string{fmt.Sprintf("row has %d cells, want %d (a \"|\" inside a cell?): %.60s", len(row), len(claimsHeader), strings.Join(row, " | "))}
	}
	var problems []string
	name := row[0]
	for i, cell := range row {
		if cell == "" {
			problems = append(problems, fmt.Sprintf("claim %q: empty %s cell", name, claimsHeader[i]))
		}
	}
	level, evidence := row[3], row[2]
	if !slices.Contains(claimLevels, level) {
		problems = append(problems, fmt.Sprintf("claim %q: level %q is not one of %v", name, level, claimLevels))
	}
	if level == "implemented and tested in CI" && (!citedJob.MatchString(evidence) || !passedAtCommit.MatchString(evidence)) {
		problems = append(problems, fmt.Sprintf("claim %q: a CI-tested claim must cite a job and \"passed at `<commit>`\"", name))
	}
	if level == "tested against fakes" && !citedJob.MatchString(evidence) {
		problems = append(problems, fmt.Sprintf("claim %q: a claim tested against fakes must cite the job that runs the fake", name))
	}
	return problems
}

func TestStatusClaimsTableIsWellFormed(t *testing.T) {
	for _, p := range claimsTableProblems(readRepoFile(t, statusPage)) {
		t.Errorf("%s: %s", statusPage, p)
	}
}

func TestClaimsRuleRejectsWhatItShould(t *testing.T) {
	header := "| Claim | Scope | Evidence | Level | Limitation |\n|---|---|---|---|---|\n"
	row := func(evidence, level string) string {
		return "\n## Claims\n\n" + header + "| c | s | " + evidence + " | " + level + " | l |\n"
	}
	tests := []struct{ name, page, want string }{
		{"no section", "# Status\n", "no \"## Claims\""},
		{"wrong header", "\n## Claims\n\n| Claim | Evidence |\n|---|---|\n| a | b |\n", "header is"},
		{"extra cell", "\n## Claims\n\n" + header + "| c | s | e | not verified | l | x |\n", "6 cells"},
		{"empty cell", "\n## Claims\n\n" + header + "| c | | e | not verified | l |\n", "empty Scope"},
		{"unknown level", row("e", "works"), "not one of"},
		{"CI claim without commit", row("job `test`", "implemented and tested in CI"), "passed at"},
		{"fake claim without job", row("a test", "tested against fakes"), "cite the job"},
	}
	for _, tc := range tests {
		if got := strings.Join(claimsTableProblems(tc.page), "\n"); !strings.Contains(got, tc.want) {
			t.Errorf("%s: problems %q do not mention %q", tc.name, got, tc.want)
		}
	}
	valid := row("job `test`, passed at `6f89609`", "implemented and tested in CI")
	if problems := claimsTableProblems(valid); len(problems) != 0 {
		t.Errorf("a valid table was rejected: %v", problems)
	}
}

// ---- links and anchors of the files at the repository root -------------------------------------

var rootPages = []string{"README.md", "ROADMAP.md", "SECURITY.md", "CONTRIBUTING.md", "GOVERNANCE.md"}

// brokenLinks lists the relative links of a page whose file or heading anchor does not exist.
func brokenLinks(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var broken []string
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
			broken = append(broken, link+" (no such file)")
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
			broken = append(broken, link+" (no such heading)")
		}
	}
	return broken
}

func TestRootPagesLinkToExistingFilesAndHeadings(t *testing.T) {
	for _, name := range rootPages {
		for _, link := range brokenLinks(t, filepath.Join(repoRoot(t), name)) {
			t.Errorf("%s links to %s", name, link)
		}
	}
}
