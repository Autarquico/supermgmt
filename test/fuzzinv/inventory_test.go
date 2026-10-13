// Package fuzzinv_test keeps the fuzz inventory honest (ADR-0034). Names alone cannot find a parser
// that has no fuzz target, so the test discovers parsers from the syntax tree of internal/ and
// requires each one to appear in scripts/fuzz-inventory.txt, mapped to a real Fuzz target or
// exempted with a reason.
package fuzzinv_test

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/autarquico/supermgmt"

var parserNamePrefixes = []string{"parse", "decode", "read", "load", "unmarshal"}

// parsingCalls are the package-qualified calls that make a function a parser, whatever its name.
var parsingCalls = map[string]map[string]bool{
	"json":       {"Unmarshal": true},
	"yaml":       {"Unmarshal": true},
	"yamlstrict": {"Decode": true},
	"tar":        {"NewReader": true},
	"zstd":       {"NewReader": true},
}

// parsingCallPrefixes match every parse entry point of a token library (jwt.Parse, jose.ParseSigned, ...).
var parsingCallPrefixes = map[string]string{"jwt": "Parse", "jose": "Parse"}

var fuzzTargetDecl = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(\w+ \*testing\.F\)`)

type row struct {
	function string
	target   string // empty when exempt
	exempt   string // reason; empty when mapped
	line     int
}

func TestFuzzInventory_DiscoversEveryParser(t *testing.T) {
	root := repoRoot(t)
	problems := checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt"))
	for _, p := range problems {
		t.Error(p)
	}
}

func TestFuzzInventory_FailsOnAnUnmappedParser(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"internal/feed/feed.go": "package feed\n\nfunc parseFeed(b []byte) error { return nil }\n",
	}, "")
	got := checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt"))
	wantProblem(t, got, "internal/feed.parseFeed is a parser missing from the inventory")
}

func TestFuzzInventory_FailsOnAParserFoundOnlyByItsBody(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"internal/feed/feed.go": "package feed\n\nimport \"encoding/json\"\n\nfunc Open(b []byte) (v any, err error) { err = json.Unmarshal(b, &v); return }\n",
	}, "")
	got := checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt"))
	wantProblem(t, got, "internal/feed.Open is a parser missing from the inventory")
}

func TestFuzzInventory_FailsOnAParserMethod(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"internal/feed/feed.go": "package feed\n\ntype Feed struct{}\n\nfunc (Feed) decodeEntry(b []byte) error { return nil }\n",
	}, "")
	got := checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt"))
	wantProblem(t, got, "internal/feed.Feed.decodeEntry is a parser missing from the inventory")
}

func TestFuzzInventory_IgnoresTestFiles(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"internal/feed/feed_test.go": "package feed\n\nfunc parseHelper() {}\n",
	}, "")
	if got := checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt")); len(got) != 0 {
		t.Fatalf("test helpers are not parsers, got %q", got)
	}
}

func TestFuzzInventory_AcceptsMappedAndExemptRows(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"internal/feed/feed.go":      "package feed\n\nfunc parseFeed(b []byte) error { return nil }\n\nfunc readClock() int { return 0 }\n",
		"internal/feed/feed_test.go": "package feed\n\nimport \"testing\"\n\nfunc FuzzParseFeed(f *testing.F) {}\n",
	}, modulePath+"/internal/feed.parseFeed  FuzzParseFeed\n"+modulePath+"/internal/feed.readClock  exempt: reads the clock, not input\n")
	if got := checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt")); len(got) != 0 {
		t.Fatalf("unexpected problems: %q", got)
	}
}

func TestFuzzInventory_FailsOnAnUnmappedTarget(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"internal/feed/feed_test.go": "package feed\n\nimport \"testing\"\n\nfunc FuzzOrphan(f *testing.F) {}\n",
	}, "")
	got := checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt"))
	wantProblem(t, got, "FuzzOrphan is a fuzz target that no inventory row maps")
}

func TestFuzzInventory_FailsOnABrokenRow(t *testing.T) {
	tests := []struct {
		name string
		rows string
		want string
	}{
		{"unknown function", modulePath + "/internal/feed.parseGone  FuzzParseFeed\n", "names no function"},
		{"unknown target", modulePath + "/internal/feed.parseFeed  FuzzNothing\n", "FuzzNothing is not a fuzz target"},
		{"exemption without a reason", modulePath + "/internal/feed.parseFeed  exempt:\n", "needs a reason"},
		{"duplicate row", modulePath + "/internal/feed.parseFeed  FuzzParseFeed\n" + modulePath + "/internal/feed.parseFeed  FuzzParseFeed\n", "listed twice"},
		{"malformed row", "parseFeed\n", "want \"<import path>.<Func>  <FuzzTarget>"},
		{"foreign module", "example.com/other/internal/feed.parseFeed  FuzzParseFeed\n", "outside the module"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fixtureTree(t, map[string]string{
				"internal/feed/feed.go":      "package feed\n\nfunc parseFeed(b []byte) error { return nil }\n",
				"internal/feed/feed_test.go": "package feed\n\nimport \"testing\"\n\nfunc FuzzParseFeed(f *testing.F) {}\n",
			}, tt.rows)
			wantProblem(t, checkInventory(root, filepath.Join(root, "scripts", "fuzz-inventory.txt")), tt.want)
		})
	}
}

// checkInventory returns one sentence per way the inventory disagrees with the tree under root.
func checkInventory(root, inventoryPath string) []string {
	rows, problems := readInventory(inventoryPath)
	declared := declaredFunctions(root)
	targets := fuzzTargets(root)
	var out []string
	out = append(out, problems...)

	seen := map[string]bool{}
	pairs := map[string]bool{}
	mapped := map[string]bool{}
	for _, r := range rows {
		pair := r.function + " " + r.target
		if pairs[pair] {
			out = append(out, fmt.Sprintf("line %d: %s is listed twice", r.line, strings.TrimSpace(pair)))
		}
		pairs[pair] = true
		seen[r.function] = true
		mapped[r.target] = true
		if !declared[r.function] {
			out = append(out, fmt.Sprintf("line %d: %s names no function in the tree", r.line, r.function))
		}
		if r.target != "" && !targets[r.target] {
			out = append(out, fmt.Sprintf("line %d: %s is not a fuzz target in any test file", r.line, r.target))
		}
	}
	for _, target := range sortedTargets(targets) {
		if !mapped[target] {
			out = append(out, target+" is a fuzz target that no inventory row maps (the nightly run would skip it)")
		}
	}
	for _, fn := range discoverParsers(root) {
		if !seen[fn] {
			out = append(out, fn+" is a parser missing from the inventory (map it to a Fuzz target or exempt it with a reason)")
		}
	}
	return out
}

// readInventory parses `<import path>.<Func>  <FuzzTarget>` and `<import path>.<Func>  exempt: <reason>`
// lines; blank lines and # comments are ignored. A missing file is an empty inventory.
func readInventory(path string) ([]row, []string) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = file.Close() }()
	var rows []row
	var problems []string
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		r, problem := parseRow(text, line)
		if problem != "" {
			problems = append(problems, problem)
			continue
		}
		rows = append(rows, r)
	}
	return rows, problems
}

func parseRow(text string, line int) (row, string) {
	fields := strings.Fields(text)
	if len(fields) < 2 {
		return row{}, fmt.Sprintf("line %d: want \"<import path>.<Func>  <FuzzTarget>\" or \"<import path>.<Func>  exempt: <reason>\", got %q", line, text)
	}
	fn := fields[0]
	if !strings.HasPrefix(fn, modulePath+"/") {
		return row{}, fmt.Sprintf("line %d: %s is outside the module", line, fn)
	}
	r := row{function: strings.TrimPrefix(fn, modulePath+"/"), line: line}
	rest := strings.TrimSpace(strings.TrimPrefix(text, fn))
	if reason, ok := strings.CutPrefix(rest, "exempt:"); ok {
		r.exempt = strings.TrimSpace(reason)
		if r.exempt == "" {
			return row{}, fmt.Sprintf("line %d: the exemption of %s needs a reason", line, fn)
		}
		return r, ""
	}
	if len(fields) != 2 {
		return row{}, fmt.Sprintf("line %d: want a single target after %s, got %q", line, fn, rest)
	}
	r.target = fields[1]
	return r, ""
}

// discoverParsers lists "<package dir>.<Func>" or "<package dir>.<Type>.<Method>" for every function
// under internal/ that is named like a parser or whose body calls a parsing entry point.
func discoverParsers(root string) []string {
	var found []string
	walkFunctions(root, func(key string, fn *ast.FuncDecl, imports map[string]string) {
		if isParser(fn, imports) {
			found = append(found, key)
		}
	})
	sort.Strings(found)
	return found
}

func declaredFunctions(root string) map[string]bool {
	declared := map[string]bool{}
	walkFunctions(root, func(key string, _ *ast.FuncDecl, _ map[string]string) { declared[key] = true })
	return declared
}

func walkFunctions(root string, visit func(key string, fn *ast.FuncDecl, imports map[string]string)) {
	internal := filepath.Join(root, "internal")
	_ = filepath.WalkDir(internal, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return nil
		}
		dir, _ := filepath.Rel(root, filepath.Dir(path))
		imports := importNames(file)
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				visit(filepath.ToSlash(dir)+"."+functionName(fn), fn, imports)
			}
		}
		return nil
	})
}

func functionName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if index, ok := expr.(*ast.IndexExpr); ok {
		expr = index.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// importNames maps the local name of every import to its path's last element, so that an
// aliased import still resolves to the package it names.
func importNames(file *ast.File) map[string]string {
	names := map[string]string{}
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		base := filepath.Base(path)
		if strings.HasPrefix(base, "v") && len(base) <= 3 && strings.Contains(path, "/") {
			base = filepath.Base(filepath.Dir(path))
		}
		local := base
		if spec.Name != nil {
			local = spec.Name.Name
		}
		names[local] = base
	}
	return names
}

func isParser(fn *ast.FuncDecl, imports map[string]string) bool {
	lower := strings.ToLower(fn.Name.Name)
	for _, prefix := range parserNamePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return callsParsingEntryPoint(fn.Body, imports)
}

func callsParsingEntryPoint(body *ast.BlockStmt, imports map[string]string) bool {
	decodes := imports["json"] != "" || imports["yaml"] != ""
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok {
			if parsingCall(imports[pkg.Name], sel.Sel.Name) {
				found = true
			}
		}
		if decodes && sel.Sel.Name == "Decode" {
			found = true
		}
		return !found
	})
	return found
}

func parsingCall(pkg, name string) bool {
	if parsingCalls[pkg][name] {
		return true
	}
	prefix, ok := parsingCallPrefixes[pkg]
	return ok && strings.HasPrefix(name, prefix)
}

// fuzzTargets collects every Fuzz function declared in a test file anywhere in the tree.
func fuzzTargets(root string) map[string]bool {
	targets := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, m := range fuzzTargetDecl.FindAllSubmatch(data, -1) {
			targets[string(m[1])] = true
		}
		return nil
	})
	return targets
}

func sortedTargets(targets map[string]bool) []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func wantProblem(t *testing.T, got []string, want string) {
	t.Helper()
	for _, p := range got {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("want a problem containing %q, got %q", want, got)
}

// fixtureTree writes files and the inventory under a temporary root and returns it.
func fixtureTree(t *testing.T, files map[string]string, inventory string) string {
	t.Helper()
	root := t.TempDir()
	files["scripts/fuzz-inventory.txt"] = inventory
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("not the repository root: %v", err)
	}
	return root
}
