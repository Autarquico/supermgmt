package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	firstStep = 1
	lastStep  = 10
)

var (
	stepCaseName = regexp.MustCompile(`^step(\d+)/`)
	stepTestName = regexp.MustCompile(`^TestEvaluate_Step(\d+)_`)
)

// stepCoverage counts the cases found for one step of spec §11.3: positive
// ones end in allow, negative ones in deny or capability_unavailable.
type stepCoverage struct{ positive, negative int }

// scanStepCoverage reads Go test source and tallies, per step, the table rows
// named "step<N>/..." (verdict taken from the row's fourth field) and, for a
// TestEvaluate_Step<N>_ function without such rows, the verdicts it refers to.
func scanStepCoverage(t *testing.T, filename string, src []byte) map[int]stepCoverage {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	coverage := map[int]stepCoverage{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		rows := tallyTableRows(fn, coverage)
		if m := stepTestName.FindStringSubmatch(fn.Name.Name); m != nil && !rows {
			step, _ := strconv.Atoi(m[1])
			tallyReferencedVerdicts(fn, step, coverage)
		}
	}
	return coverage
}

// tallyTableRows reports whether fn holds any "step<N>/" row.
func tallyTableRows(fn *ast.FuncDecl, coverage map[int]stepCoverage) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		row, ok := n.(*ast.CompositeLit)
		if !ok || len(row.Elts) < 4 {
			return true
		}
		name, ok := row.Elts[0].(*ast.BasicLit)
		if !ok || name.Kind != token.STRING {
			return true
		}
		text, err := strconv.Unquote(name.Value)
		if err != nil {
			return true
		}
		m := stepCaseName.FindStringSubmatch(text)
		if m == nil {
			return true
		}
		found = true
		step, _ := strconv.Atoi(m[1])
		c := coverage[step]
		switch verdict(row.Elts[3]) {
		case DecisionAllow:
			c.positive++
		case DecisionDeny, DecisionCapabilityUnavailable:
			c.negative++
		}
		coverage[step] = c
		return false
	})
	return found
}

func tallyReferencedVerdicts(fn *ast.FuncDecl, step int, coverage map[int]stepCoverage) {
	c := coverage[step]
	ast.Inspect(fn, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			switch id.Name {
			case "DecisionAllow":
				c.positive++
			case "DecisionDeny", "DecisionCapabilityUnavailable":
				c.negative++
			}
		}
		return true
	})
	coverage[step] = c
}

// verdict resolves a row's expected decision from its identifier, or "".
func verdict(expr ast.Expr) Decision {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	switch id.Name {
	case "DecisionAllow":
		return DecisionAllow
	case "DecisionDeny":
		return DecisionDeny
	case "DecisionCapabilityUnavailable":
		return DecisionCapabilityUnavailable
	}
	return ""
}

// uncoveredSteps lists every step of §11.3 lacking a positive or negative case.
func uncoveredSteps(coverage map[int]stepCoverage) []string {
	var gaps []string
	for step := firstStep; step <= lastStep; step++ {
		c := coverage[step]
		if c.positive == 0 {
			gaps = append(gaps, "step "+strconv.Itoa(step)+": no positive case")
		}
		if c.negative == 0 {
			gaps = append(gaps, "step "+strconv.Itoa(step)+": no negative case")
		}
	}
	return gaps
}

func TestPolicyCoversEveryStepOf11_3WithPositiveAndNegativeCases(t *testing.T) {
	const file = "evaluate_test.go"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	coverage := scanStepCoverage(t, file, src)
	t.Logf("cases per step: %+v", coverage)
	if gaps := uncoveredSteps(coverage); len(gaps) > 0 {
		t.Fatalf("spec §11.3 steps without coverage in %s:\n  %s", file, strings.Join(gaps, "\n  "))
	}
}

func TestStepCoverageMetaTestReportsMissingCases(t *testing.T) {
	const src = `package policy
func TestEvaluate_Step1_Catalog() {
	_ = []evalCase{
		{"step1/known", p, req, DecisionAllow, "", false, 0},
		{"step1/unknown", p, req, DecisionDeny, "", false, 0},
	}
}
func TestEvaluate_Step2_Capability() {
	_ = []evalCase{
		{"step2/missing", p, req, DecisionCapabilityUnavailable, "", false, 0},
	}
}
func TestEvaluate_Step3_Match() {
	_ = []evalCase{
		{"step3/matches", p, req, DecisionAllow, "", false, 0},
	}
}
`
	got := strings.Join(uncoveredSteps(scanStepCoverage(t, "synthetic_test.go", []byte(src))), "\n")
	for _, want := range []string{
		"step 2: no positive case",
		"step 3: no negative case",
		"step 4: no positive case",
		"step 10: no negative case",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in report:\n%s", want, got)
		}
	}
	for _, unexpected := range []string{"step 1:", "step 2: no negative", "step 3: no positive"} {
		if strings.Contains(got, unexpected) {
			t.Errorf("unexpected %q in report:\n%s", unexpected, got)
		}
	}
}
