package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func parseWarnings(t *testing.T, rules ...string) (*Policy, []Warning, error) {
	t.Helper()
	return ParseWithWarnings([]byte("version: 1\nrules:\n  - " + strings.Join(rules, "\n  - ") + "\n"))
}

func writeTarget() Request {
	return Request{
		Actor: human(), Action: "app_target.write",
		Targets: []Target{target(domain.ResourceAppTarget, "t", stagingAttrs)},
	}
}

func TestRetiredExactNameLoadsWithWarningAndGrantsNothing(t *testing.T) {
	p, warnings, err := parseWarnings(t, `{name: old, subjects: ['*'], allow: ['app_target.move']}`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Warning{{Action: "app_target.move", ADR: "ADR-0043", Rules: []string{"old"}}}
	if !reflect.DeepEqual(warnings, want) {
		t.Errorf("warnings = %+v, want %+v", warnings, want)
	}
	if rule := p.Rules()[0]; len(rule.Allow) != 0 || len(rule.Deny) != 0 {
		t.Errorf("rule still has patterns: %+v", rule)
	}
	for _, spec := range Catalog() {
		got := p.Evaluate(Request{Actor: human(), Action: spec.Name, Targets: []Target{target(spec.Resource, "t", stagingAttrs)}})
		if got.Decision == DecisionAllow {
			t.Errorf("%s: an exhausted rule allows it", spec.Name)
		}
	}
}

func TestRetiredOnlyWildcardIsDropped(t *testing.T) {
	p, warnings, err := parseWarnings(t, `{name: old, subjects: ['*'], allow: ['app_target.*_move']}`)
	if err == nil {
		t.Fatalf("segment %q is not a wildcard form and must stay an error; got %+v %+v", "*_move", p, warnings)
	}
	p, warnings, err = parseWarnings(t, `{name: old, subjects: ['*'], allow: ['*.cleanup_source', '*.abandon_move']}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 || warnings[0].Action != "app_target.abandon_move" || warnings[1].Action != "app_target.cleanup_source" {
		t.Errorf("warnings = %+v", warnings)
	}
	if rule := p.Rules()[0]; len(rule.Allow) != 0 {
		t.Errorf("allow = %v, want none (never a wildcard)", rule.Allow)
	}
}

func TestRetiredMixedWithLiveKeepsLiveOnAllowAndDeny(t *testing.T) {
	p, warnings, err := parseWarnings(t,
		`{name: first, subjects: ['*'], allow: ['app_target.move']}`,
		`{name: wide, subjects: ['*'], allow: ['app_target.*']}`,
		`{name: stop, subjects: ['*'], deny: ['app_target.cleanup_source', 'app_target.write']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	for _, w := range warnings {
		actions = append(actions, w.Action)
	}
	if !reflect.DeepEqual(actions, []string{"app_target.cleanup_source", "app_target.move"}) {
		t.Errorf("warned actions = %v", actions)
	}
	rules := p.Rules()
	if len(rules[0].Allow) != 0 || !reflect.DeepEqual(rules[1].Allow, []string{"app_target.*"}) || !reflect.DeepEqual(rules[2].Deny, []string{"app_target.write"}) {
		t.Errorf("rules = %+v", rules)
	}
	read := Request{Actor: human(), Action: "app_target.read", Targets: []Target{target(domain.ResourceAppTarget, "t", stagingAttrs)}}
	if got := p.Evaluate(read); got.Decision != DecisionAllow {
		t.Errorf("app_target.read = %s, want allow", got.Decision)
	}
	if got := p.Evaluate(writeTarget()); got.Decision != DecisionDeny {
		t.Errorf("app_target.write = %s, want the live deny preserved", got.Decision)
	}
}

func TestRetiredAllowAndDenyInOneRuleAreFilteredIndependently(t *testing.T) {
	p, _, err := parseWarnings(t, `{name: r, subjects: ['*'], allow: ['app_target.move', 'app_target.read'], deny: ['app_target.abandon_move', 'app_target.write']}`)
	if err != nil {
		t.Fatal(err)
	}
	r := p.Rules()[0]
	if !reflect.DeepEqual(r.Allow, []string{"app_target.read"}) || !reflect.DeepEqual(r.Deny, []string{"app_target.write"}) {
		t.Errorf("rule = %+v", r)
	}
}

func TestRetiredKeepsEverythingElseOfTheRule(t *testing.T) {
	p, _, err := parseWarnings(t, `{name: r, subjects: ['role:admin'], resources: ['environment:staging'], allow: ['app_target.move', 'node.remove'], allow_destructive: true, approvals: 2}`)
	if err != nil {
		t.Fatal(err)
	}
	r := p.Rules()[0]
	if !reflect.DeepEqual(r.Subjects, []string{"role:admin"}) || !reflect.DeepEqual(r.Resources, []string{"environment:staging"}) ||
		!r.AllowDestructive || r.quorum() != 2 || !reflect.DeepEqual(r.Allow, []string{"node.remove"}) {
		t.Errorf("rule = %+v", r)
	}
}

func TestRetiredWarningsAreDeduplicatedPerAction(t *testing.T) {
	_, warnings, err := parseWarnings(t,
		`{name: a, subjects: ['*'], allow: ['app_target.move', 'app_target.move']}`,
		`{name: b, subjects: ['*'], deny: ['app_target.move']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []Warning{{Action: "app_target.move", ADR: "ADR-0043", Rules: []string{"a", "b"}}}
	if !reflect.DeepEqual(warnings, want) {
		t.Errorf("warnings = %+v, want %+v", warnings, want)
	}
}

func TestRetiredNeverExcusesATypoOrAnEmptyRule(t *testing.T) {
	for name, rule := range map[string]string{
		"typo":               `{name: r, subjects: ['*'], allow: ['app_target.moev']}`,
		"bad segment":        `{name: r, subjects: ['*'], allow: ['app_target.Move']}`,
		"wildcard no match":  `{name: r, subjects: ['*'], allow: ['nothing.*']}`,
		"empty rule":         `{name: r, subjects: ['*']}`,
		"bad subject":        `{name: r, subjects: ['team:x'], allow: ['app_target.move']}`,
		"live name mistyped": `{name: r, subjects: ['*'], allow: ['app_target.writ']}`,
	} {
		if _, _, err := parseWarnings(t, rule); err == nil {
			t.Errorf("%s: loaded, want an error", name)
		}
	}
}

func TestLiveOnlyPolicyHasNoWarnings(t *testing.T) {
	_, warnings, err := ParseWithWarnings(DefaultYAML())
	if err != nil || len(warnings) != 0 {
		t.Fatalf("default: warnings=%v err=%v", warnings, err)
	}
	for name := range retiredActions {
		if strings.Contains(string(DefaultYAML()), name) {
			t.Errorf("default.yaml names retired action %s", name)
		}
	}
}

// Every live action decides as it would in the same file with the retired
// names deleted by hand.
func TestRetiredNamesDoNotChangeAnyLiveDecision(t *testing.T) {
	withRetired := []string{
		`{name: a, subjects: ['*'], allow: ['app_target.move', 'app_target.*'], deny: ['app_target.cleanup_source', 'app_target.write']}`,
		`{name: b, subjects: ['role:admin'], allow: ['app_target.abandon_move', 'node.*', '*.read'], allow_destructive: true}`,
		`{name: c, subjects: ['*'], allow: ['app_target.move']}`,
	}
	by := []string{
		`{name: a, subjects: ['*'], allow: ['app_target.*'], deny: ['app_target.write']}`,
		`{name: b, subjects: ['role:admin'], allow: ['node.*', '*.read'], allow_destructive: true}`,
	}
	before, after := pol(t, withRetired...), pol(t, by...)
	for _, spec := range Catalog() {
		for _, actor := range []domain.Actor{human(), human("admin"), mcp()} {
			for _, attrs := range []Attributes{stagingAttrs, prodAttrs} {
				req := Request{Actor: actor, Action: spec.Name, Targets: []Target{target(spec.Resource, "t", attrs)}}
				if a, b := before.Evaluate(req), after.Evaluate(req); !reflect.DeepEqual(a, b) {
					t.Errorf("%s as %v in %s: %+v vs %+v", spec.Name, actor.Roles, attrs.Environment, a, b)
				}
			}
		}
	}
}

func TestRetiredActionsAreNotInTheCatalog(t *testing.T) {
	for name := range retiredActions {
		if _, ok := Lookup(name); ok {
			t.Errorf("%s is retired and still in the catalog", name)
		}
	}
}
