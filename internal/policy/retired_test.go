package policy

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func parseWarnings(t *testing.T, rules ...string) (*Policy, []Warning, error) {
	t.Helper()
	return ParseWithWarnings([]byte("version: 1\nrules:\n  - " + strings.Join(rules, "\n  - ") + "\n"))
}

func nodeRequest(action string) Request {
	return Request{Actor: human(), Action: action, Targets: []Target{nodeT(stagingAttrs)}}
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
		`{name: wide, subjects: ['*'], allow: ['*.read']}`,
		`{name: stop, subjects: ['*'], deny: ['app_target.cleanup_source', 'node.remove']}`,
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
	if len(rules[0].Allow) != 0 || !reflect.DeepEqual(rules[1].Allow, []string{"*.read"}) || !reflect.DeepEqual(rules[2].Deny, []string{"node.remove"}) {
		t.Errorf("rules = %+v", rules)
	}
	if got := p.Evaluate(nodeRequest("node.read")); got.Decision != DecisionAllow {
		t.Errorf("node.read = %s, want allow", got.Decision)
	}
	if got := p.Evaluate(nodeRequest("node.remove")); got.Decision != DecisionDeny {
		t.Errorf("node.remove = %s, want the live deny preserved", got.Decision)
	}
}

func TestRetiredAllowAndDenyInOneRuleAreFilteredIndependently(t *testing.T) {
	p, _, err := parseWarnings(t, `{name: r, subjects: ['*'], allow: ['app_target.move', 'node.read'], deny: ['app_target.abandon_move', 'node.remove']}`)
	if err != nil {
		t.Fatal(err)
	}
	r := p.Rules()[0]
	if !reflect.DeepEqual(r.Allow, []string{"node.read"}) || !reflect.DeepEqual(r.Deny, []string{"node.remove"}) {
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

func TestRetiredRouteActionsPointToTheirReplacement(t *testing.T) {
	_, warnings, err := parseWarnings(t, `{name: old, subjects: ['*'], allow: ['app_route.expose', 'app_route.unexpose']}`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Warning{
		{Action: "app_route.expose", ADR: "ADR-0043", Replacement: "node_route.expose", Rules: []string{"old"}},
		{Action: "app_route.unexpose", ADR: "ADR-0043", Replacement: "node_route.unexpose", Rules: []string{"old"}},
	}
	if !reflect.DeepEqual(warnings, want) {
		t.Fatalf("warnings = %+v, want %+v", warnings, want)
	}
	if got := warnings[0].String(); !strings.Contains(got, "use node_route.expose") {
		t.Errorf("warning %q does not name the replacement", got)
	}
}

func nodeRoute(action string) Request {
	params := map[string]any{ParamHostname: "a.example.com"}
	if action == ActionNodeRouteExpose {
		params[ParamPort] = "8080"
	}
	return Request{Actor: human(), Action: action, Targets: []Target{target(domain.ResourceNode, "n", stagingAttrs)}, Params: params}
}

func TestRetiredRouteDenyBecomesDenyOfReplacement(t *testing.T) {
	p, warnings, err := parseWarnings(t,
		`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
		`{name: carve, subjects: ['*'], deny: ['app_route.expose']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Evaluate(nodeRoute("node_route.expose")); got.Decision != DecisionDeny {
		t.Errorf("node_route.expose = %s, want deny", got.Decision)
	}
	if got := p.Evaluate(nodeRoute("node_route.unexpose")); got.Decision == DecisionDeny {
		t.Errorf("node_route.unexpose = deny, want the broad allow untouched")
	}
	if len(warnings) != 1 || !reflect.DeepEqual(warnings[0].Denied, []string{"carve"}) || len(warnings[0].AllNodes) != 0 {
		t.Fatalf("warnings = %+v", warnings)
	}
	if got := warnings[0].String(); !strings.Contains(got, `deny now denies node_route.expose in rules: "carve"`) {
		t.Errorf("warning %q does not say the deny was carried over", got)
	}
}

func TestRetiredRouteAllowGrantsNothing(t *testing.T) {
	p, _, err := parseWarnings(t, `{name: old, subjects: ['*'], allow: ['app_route.expose', 'app_route.unexpose']}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"node_route.expose", "node_route.unexpose"} {
		if got := p.Evaluate(nodeRoute(action)); got.Decision == DecisionAllow {
			t.Errorf("%s = allow, want nothing granted", action)
		}
	}
}

func TestRetiredRouteWildcardDenyDeniesBothReplacements(t *testing.T) {
	p, warnings, err := parseWarnings(t,
		`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
		`{name: carve, subjects: ['*'], deny: ['app_route.*']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"node_route.expose", "node_route.unexpose"} {
		if got := p.Evaluate(nodeRoute(action)); got.Decision != DecisionDeny {
			t.Errorf("%s = %s, want deny", action, got.Decision)
		}
	}
	if len(warnings) != 2 {
		t.Errorf("warnings = %+v", warnings)
	}
}

func TestRetiredRouteDenyScopedToAppsDeniesEveryNode(t *testing.T) {
	p, warnings, err := parseWarnings(t,
		`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
		`{name: carve, subjects: ['*'], resources: ['app:web', 'environment:production'], deny: ['app_route.expose']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Evaluate(nodeRoute("node_route.expose")); got.Decision != DecisionDeny {
		t.Errorf("node_route.expose on a staging node = %s, want deny", got.Decision)
	}
	if !reflect.DeepEqual(warnings[0].AllNodes, []string{"carve"}) || !strings.Contains(warnings[0].String(), "on every node") {
		t.Errorf("warning = %+v", warnings[0])
	}
}

func TestRetiredRouteDenyScopedToAppsLeavesLiveActionsScoped(t *testing.T) {
	const rule = `{name: carve, subjects: ['*'], resources: ['app:shop'], allow: ['service.restart'], deny: ['app_route.expose']}`
	p, _, err := parseWarnings(t, rule)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := parseWarnings(t, `{name: carve, subjects: ['*'], resources: ['app:shop'], allow: ['service.restart']}`)
	if err != nil {
		t.Fatal(err)
	}
	restart := Request{Actor: human(), Action: "service.restart", Targets: []Target{target(domain.ResourceNode, "n", stagingAttrs)}}
	scoped := restart
	scoped.Targets = []Target{target(domain.ResourceNode, "n", Attributes{App: "shop"})}
	for _, req := range []Request{restart, scoped} {
		if got, want := p.Evaluate(req).Decision, before.Evaluate(req).Decision; got != want {
			t.Errorf("service.restart on %+v = %s, want %s as without the retired deny", req.Targets[0], got, want)
		}
	}
	if got := p.Evaluate(nodeRoute("node_route.expose")); got.Decision != DecisionDeny {
		t.Errorf("node_route.expose = %s, want deny on every node", got.Decision)
	}
	rules := p.Rules()
	if len(rules) != 2 || !reflect.DeepEqual(rules[0].Resources, []string{"app:shop"}) || !reflect.DeepEqual(rules[0].Allow, []string{"service.restart"}) || len(rules[0].Deny) != 0 {
		t.Errorf("rules = %+v, want the original untouched", rules)
	}
}

func TestRetiredRouteDenyUnscopedJoinsTheSameRule(t *testing.T) {
	p, _, err := parseWarnings(t, `{name: carve, subjects: ['*'], allow: ['service.restart'], deny: ['app_route.expose']}`)
	if err != nil {
		t.Fatal(err)
	}
	if rules := p.Rules(); len(rules) != 1 || !reflect.DeepEqual(rules[0].Deny, []string{"node_route.expose"}) {
		t.Errorf("rules = %+v, want one rule denying the replacement", rules)
	}
}

func TestRetiredRouteDenyKeepsNodeScopedResources(t *testing.T) {
	p, warnings, err := parseWarnings(t,
		`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
		`{name: carve, subjects: ['*'], resources: ['tag:edge'], deny: ['app_route.expose']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Evaluate(nodeRoute("node_route.expose")); got.Decision == DecisionDeny {
		t.Errorf("untagged node = deny, want the tag scope kept")
	}
	edge := nodeRoute("node_route.expose")
	edge.Targets = []Target{target(domain.ResourceNode, "n", Attributes{Tags: []string{"edge"}})}
	if got := p.Evaluate(edge); got.Decision != DecisionDeny {
		t.Errorf("edge node = %s, want deny", got.Decision)
	}
	if len(warnings[0].AllNodes) != 0 {
		t.Errorf("AllNodes = %v, want none", warnings[0].AllNodes)
	}
}

func TestRetiredRouteDenyEnvironmentScopeDeniesOnEveryNode(t *testing.T) {
	p, warnings, err := parseWarnings(t,
		`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
		`{name: carve, subjects: ['*'], resources: ['environment:production'], deny: ['app_route.expose']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	staging := nodeRoute("node_route.expose")
	staging.Targets = []Target{target(domain.ResourceNode, "n", Attributes{Environment: "staging"})}
	for name, req := range map[string]Request{"no environment": nodeRoute("node_route.expose"), "staging": staging} {
		if got := p.Evaluate(req); got.Decision != DecisionDeny {
			t.Errorf("%s node = %s, want deny", name, got.Decision)
		}
	}
	if got := p.Evaluate(nodeRoute("node_route.unexpose")); got.Decision == DecisionDeny {
		t.Errorf("node_route.unexpose = deny, want it decided as before")
	}
	if len(warnings[0].AllNodes) != 1 {
		t.Errorf("AllNodes = %v, want the carve rule", warnings[0].AllNodes)
	}
}

func TestRetiredRouteDenyKeepsSubjects(t *testing.T) {
	p, _, err := parseWarnings(t,
		`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
		`{name: carve, subjects: ['role:admin'], deny: ['app_route.expose']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Evaluate(nodeRoute("node_route.expose")); got.Decision == DecisionDeny {
		t.Errorf("a non-admin = deny, want the rule's subjects kept")
	}
	admin := nodeRoute("node_route.expose")
	admin.Actor = human("admin")
	if got := p.Evaluate(admin); got.Decision != DecisionDeny {
		t.Errorf("admin = %s, want deny", got.Decision)
	}
}

func TestRetiredMoveDenyStaysDropped(t *testing.T) {
	p, warnings, err := parseWarnings(t, `{name: r, subjects: ['*'], deny: ['app_target.move']}`)
	if err != nil {
		t.Fatal(err)
	}
	if rule := p.Rules()[0]; len(rule.Deny) != 0 || len(warnings[0].Denied) != 0 {
		t.Errorf("rule = %+v, warning = %+v", rule, warnings[0])
	}
}

func TestRetiredWarningSanitisesRuleNames(t *testing.T) {
	w := Warning{
		Action: "app_route.expose", ADR: "ADR-0043", Replacement: "node_route.expose",
		Rules: []string{"a\nb"}, Denied: []string{"a\nb"}, AllNodes: []string{"a\nb"},
	}
	if got := w.String(); strings.ContainsAny(got, "\n\r") {
		t.Errorf("warning %q has a raw newline", got)
	}
}

func TestRetiredRouteWildcardDenyScopedToAppsOrEnvironmentsDeniesEveryNode(t *testing.T) {
	staging := nodeRoute("node_route.expose")
	staging.Targets = []Target{target(domain.ResourceNode, "n", Attributes{Environment: "staging"})}
	for _, pattern := range []string{"*.expose", "*.*", "*"} {
		for _, scope := range []string{"environment:production", "app:shop"} {
			p, warnings, err := parseWarnings(t,
				`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
				`{name: carve, subjects: ['*'], resources: ['`+scope+`'], deny: ['`+pattern+`']}`,
			)
			if err != nil {
				t.Fatal(err)
			}
			for name, req := range map[string]Request{"no environment": nodeRoute("node_route.expose"), "staging": staging} {
				if got := p.Evaluate(req); got.Decision != DecisionDeny {
					t.Errorf("%s %s: node_route.expose on %s node = %s, want deny", pattern, scope, name, got.Decision)
				}
			}
			restart := Request{Actor: human(), Action: "service.restart", Targets: []Target{target(domain.ResourceNode, "n", stagingAttrs)}}
			if got := p.Evaluate(restart); got.Decision == DecisionDeny {
				t.Errorf("%s %s: service.restart = deny, want it decided as before", pattern, scope)
			}
			if len(warnings) == 0 || !reflect.DeepEqual(warnings[0].AllNodes, []string{"carve"}) {
				t.Errorf("%s %s: warnings = %+v, want carve denying on every node", pattern, scope, warnings)
			}
			if rules := p.Rules(); len(rules) != 3 || !slices.Contains(rules[1].Deny, pattern) {
				t.Errorf("%s %s: rules = %+v, want the pattern kept plus one synthetic rule", pattern, scope, rules)
			}
		}
	}
}

func TestRetiredRouteWildcardDenyBothCasesShareOneSyntheticRule(t *testing.T) {
	p, _, err := parseWarnings(t, `{name: carve, subjects: ['*'], resources: ['app:shop'], deny: ['*.expose', 'app_route.unexpose']}`)
	if err != nil {
		t.Fatal(err)
	}
	if rules := p.Rules(); len(rules) != 2 || !reflect.DeepEqual(rules[1].Deny, []string{"node_route.unexpose", "node_route.expose"}) {
		t.Errorf("rules = %+v, want one synthetic rule denying both replacements", rules)
	}
}

func TestRetiredRouteWildcardDenyUnscopedNeedsNoSyntheticRule(t *testing.T) {
	p, warnings, err := parseWarnings(t,
		`{name: broad, subjects: ['*'], allow: ['*.*'], allow_destructive: true}`,
		`{name: carve, subjects: ['*'], deny: ['*.expose']}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Evaluate(nodeRoute("node_route.expose")); got.Decision != DecisionDeny {
		t.Errorf("node_route.expose = %s, want deny", got.Decision)
	}
	if rules := p.Rules(); len(rules) != 2 {
		t.Errorf("rules = %+v, want no synthetic rule", rules)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %+v, want none", warnings)
	}
}

func TestRetiredDeploymentAndAppActionsLoadWithOneWarningEachAndGrantNothing(t *testing.T) {
	retired := []string{"app.read", "app.write", "app_target.read", "app_target.write", "deployment.create", "deployment.read", "deployment.rollback"}
	quoted := "'" + strings.Join(retired, "', '") + "'"
	p, warnings, err := parseWarnings(t, `{name: deployer, subjects: ['role:deployer'], allow: [`+quoted+`]}`, `{name: live, subjects: ['*'], allow: ['*.read']}`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, w := range warnings {
		got = append(got, w.Action)
		if w.Replacement != "" {
			t.Errorf("%s names replacement %q, want none", w.Action, w.Replacement)
		}
	}
	if !slices.Equal(got, retired) {
		t.Errorf("warned actions = %v, want %v", got, retired)
	}
	if allow := p.Rules()[0].Allow; len(allow) != 0 {
		t.Errorf("allow = %v, want none", allow)
	}
	if res := p.Evaluate(nodeRequest("node.read")); res.Decision != DecisionAllow {
		t.Errorf("a wildcard live action = %s, want allow", res.Decision)
	}
}

func TestDefaultPolicyGrantsAdminTheBackupTemplate(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	admin := Request{
		Actor: human("admin"), Action: "node.probe", Targets: []Target{nodeT(stagingAttrs, "node.read")},
		SubActions: []SubAction{{Action: ActionNodeBackupTemplateRun, Target: nodeT(stagingAttrs, "node.exec.template")}},
	}
	if res := p.Evaluate(admin); res.Decision != DecisionAllow {
		t.Errorf("admin node.backup_template.run = %s, want allow", res.Decision)
	}
	admin.Actor = human("operator")
	if res := p.Evaluate(admin); res.Decision != DecisionDeny {
		t.Errorf("operator node.backup_template.run = %s, want deny", res.Decision)
	}
}
