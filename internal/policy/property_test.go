package policy

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Property tests for spec §11.3. Every case is generated from its own seed
// (propertySeed + case index), printed on failure, so a failing case replays
// with newPropGen(<printed seed>).
const (
	propertyCases = 10_000
	propertySeed  = uint64(0x5eed11a3)
)

type propGen struct{ r *rand.Rand }

func newPropGen(seed uint64) *propGen {
	return &propGen{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

func (g *propGen) chance(p float64) bool { return g.r.Float64() < p }

func pick[T any](g *propGen, xs []T) T { return xs[g.r.IntN(len(xs))] }

func nonEmptySubset[T any](g *propGen, xs []T) []T {
	var out []T
	for len(out) == 0 {
		for _, x := range xs {
			if g.chance(0.15) {
				out = append(out, x)
			}
		}
	}
	return out
}

func subset[T any](g *propGen, xs []T) []T {
	if g.chance(0.4) {
		return nil
	}
	return nonEmptySubset(g, xs)
}

var (
	propActorIDs = []string{"0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88", "0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f99"}
	propRoles    = []string{"viewer", "operator", "deployer", "admin"}
	propTypes    = []domain.ActorType{domain.ActorHuman, domain.ActorAutomation, domain.ActorMCP}

	propSubjects = []string{
		"*", "type:human", "type:automation", "type:mcp",
		"role:viewer", "role:operator", "role:deployer", "role:admin",
		"identity:" + propActorIDs[0], "identity:" + propActorIDs[1],
	}
	propResources = []string{
		"*", "environment:staging", "environment:production", "environment:dev",
		"tag:docker", "tag:db", "provider:p1", "provider:p2", "node:n1", "node:n2", "app:a1",
	}
	propEnvironments = []struct {
		name string
		risk domain.EnvironmentRiskLevel
	}{
		{"dev", domain.EnvironmentDevelopment},
		{"staging", domain.EnvironmentStaging},
		{"production", domain.EnvironmentProduction},
	}
	propTags      = []string{"docker", "db"}
	propProviders = []string{"p1", "p2"}
	propNodes     = []string{"n1", "n2"}
)

// propActions are the catalog names plus a few names the catalog lacks.
var propActions = func() []string {
	var names []string
	for _, spec := range Catalog() {
		names = append(names, spec.Name)
	}
	return append(names, "node.explode", "")
}()

// propPatterns are action patterns that pass rule validation.
var propPatterns = func() []string {
	patterns := []string{"*", "*.read", "*.write", "*.*"}
	firstSegments := map[string]struct{}{}
	for _, spec := range Catalog() {
		patterns = append(patterns, spec.Name)
		first, _, _ := strings.Cut(spec.Name, ".")
		firstSegments[first] = struct{}{}
	}
	for first := range firstSegments {
		if wildcard := first + ".*"; validateActionPattern(wildcard) == nil {
			patterns = append(patterns, wildcard)
		}
	}
	slices.Sort(patterns)
	return slices.Compact(patterns)
}()

var propCredentialActions = func() []string {
	var names []string
	for _, spec := range Catalog() {
		if spec.CredentialIssuing {
			names = append(names, spec.Name)
		}
	}
	return names
}()

type ruleKind int

const (
	anyRule ruleKind = iota
	denyOnlyRule
	allowOnlyRule
)

func (g *propGen) rule(name string, kind ruleKind) Rule {
	r := Rule{Name: name, Subjects: nonEmptySubset(g, propSubjects), Resources: subset(g, propResources)}
	switch kind {
	case denyOnlyRule:
		r.Deny = nonEmptySubset(g, propPatterns)
	case allowOnlyRule:
		r.Allow = nonEmptySubset(g, propPatterns)
	case anyRule:
		r.Allow, r.Deny = subset(g, propPatterns), subset(g, propPatterns)
		if len(r.Allow)+len(r.Deny) == 0 {
			r.Allow = []string{pick(g, propPatterns)}
		}
	}
	if kind != denyOnlyRule && g.chance(0.3) {
		b := g.chance(0.5)
		r.RequireApproval = &b
	}
	if kind != denyOnlyRule && g.chance(0.3) {
		n := 1 + g.r.IntN(5)
		r.Approvals = &n
	}
	r.AllowDestructive = kind != denyOnlyRule && g.chance(0.4)
	if r.requiresApproval() && coversCredentialIssuingAction(r.Allow) {
		r.RequireApproval = nil // rejected by validation (§11.2)
	}
	return r
}

func coversCredentialIssuingAction(patterns []string) bool {
	return slices.ContainsFunc(propCredentialActions, func(action string) bool { return matchesAnyAction(patterns, action) })
}

// broadAllow keeps a good share of generated requests allowed, so the
// properties exercise approval and quorum and not only denials.
func (g *propGen) broadAllow() Rule {
	r := Rule{Name: "broad", Subjects: []string{"*"}, Allow: []string{"*"}, AllowDestructive: g.chance(0.5)}
	if g.chance(0.3) {
		r.Resources = []string{pick(g, propResources)}
	}
	if g.chance(0.3) {
		n := 1 + g.r.IntN(5)
		r.Approvals = &n
	}
	return r
}

func (g *propGen) rules(n int) []Rule {
	rules := make([]Rule, n)
	for i := range rules {
		rules[i] = g.rule(fmt.Sprintf("r%d", i), anyRule)
	}
	return rules
}

func (g *propGen) actor() domain.Actor {
	a := domain.Actor{
		ID:    domain.ID(pick(g, propActorIDs)),
		Type:  pick(g, propTypes),
		Roles: subset(g, propRoles),
	}
	if g.chance(0.2) {
		a.Credential.Scopes = nonEmptySubset(g, propPatterns)
	}
	return a
}

func (g *propGen) target(spec ActionSpec, id string) Target {
	env := pick(g, propEnvironments)
	attrs := Attributes{
		Tags:              subset(g, propTags),
		Environment:       env.name,
		EnvironmentRisk:   env.risk,
		ApprovalsRequired: g.r.IntN(4),
		Provider:          pick(g, propProviders),
		Node:              pick(g, propNodes),
		App:               "a1",
	}
	var caps []string
	if spec.Capability != "" && g.chance(0.9) {
		caps = append(caps, spec.Capability)
	}
	resource := spec.Resource
	if resource == "" {
		resource = domain.ResourceNode
	}
	return target(resource, id, attrs, caps...)
}

func (g *propGen) params(spec ActionSpec) map[string]any {
	params := map[string]any{}
	for _, p := range spec.Params {
		if len(p.Values) > 0 {
			params[p.Name] = pick(g, p.Values)
		}
	}
	return params
}

func (g *propGen) subAction(id string) SubAction {
	action := pick(g, []string{ActionSnapshotCreate, ActionNodeBackupTemplateRun})
	spec, _ := Lookup(action)
	return SubAction{Action: action, Target: g.target(spec, id)}
}

func (g *propGen) request() Request {
	action := pick(g, propActions)
	spec, known := Lookup(action)
	if !known {
		spec = ActionSpec{Resource: domain.ResourceNode}
	}
	req := Request{Actor: g.actor(), Action: action, Params: g.params(spec)}
	for i := range 1 + g.r.IntN(3) {
		req.Targets = append(req.Targets, g.target(spec, fmt.Sprintf("t%d", i)))
	}
	for i := range g.r.IntN(3) {
		req.SubActions = append(req.SubActions, g.subAction(fmt.Sprintf("s%d", i)))
	}
	return req
}

type scenario struct {
	seed   uint64
	doc    Document
	policy *Policy
	req    Request
}

func (s scenario) describe() string {
	text, _ := yaml.Marshal(s.doc)
	return fmt.Sprintf("seed=%#x\npolicy:\n%srequest: %+v", s.seed, text, s.req)
}

func newScenario(t *testing.T, i int) (*propGen, scenario) {
	t.Helper()
	seed := propertySeed + uint64(i)
	g := newPropGen(seed)
	doc := Document{Version: SupportedVersion, Rules: g.rules(g.r.IntN(7))}
	if g.chance(0.75) {
		doc.Rules = append(doc.Rules, g.broadAllow())
	}
	return g, scenario{seed: seed, doc: doc, policy: mustPolicy(t, doc), req: g.request()}
}

// mustPolicy skips validation for speed: generated rules are valid by
// construction, which TestPolicyProperty_GeneratedPoliciesAreValid pins.
func mustPolicy(t *testing.T, doc Document) *Policy {
	t.Helper()
	return &Policy{rules: doc.Rules}
}

func TestPolicyProperty_GeneratedPoliciesAreValid(t *testing.T) {
	for i := range 2_000 {
		_, s := newScenario(t, i)
		if _, err := New(s.doc); err != nil {
			t.Fatalf("seed=%#x generates an invalid policy: %v\n%s", s.seed, err, s.describe())
		}
	}
}

func forEachScenario(t *testing.T, check func(t *testing.T, g *propGen, s scenario)) {
	t.Helper()
	for i := range propertyCases {
		g, s := newScenario(t, i)
		check(t, g, s)
	}
}

// withExtraRules returns doc with extra inserted at random positions.
func withExtraRules(g *propGen, doc Document, extra ...Rule) Document {
	rules := slices.Clone(doc.Rules)
	for _, r := range extra {
		rules = slices.Insert(rules, g.r.IntN(len(rules)+1), r)
	}
	return Document{Version: doc.Version, Rules: rules}
}

// strictness orders decisions from most to least permissive.
func strictness(d Decision) int {
	switch d {
	case DecisionAllow:
		return 0
	case DecisionCapabilityUnavailable:
		return 1
	case DecisionDeny:
		return 2
	}
	return 2
}

// relaxation explains how after is more permissive than before, or returns "".
func relaxation(before, after Result) string {
	switch {
	case strictness(after.Decision) < strictness(before.Decision):
		return fmt.Sprintf("decision %s became %s", before.Decision, after.Decision)
	case before.Decision != DecisionAllow || after.Decision != DecisionAllow:
		return ""
	case before.ApprovalRequired && !after.ApprovalRequired:
		return "approval_required dropped"
	case after.Quorum < before.Quorum:
		return fmt.Sprintf("quorum dropped from %d to %d", before.Quorum, after.Quorum)
	}
	return ""
}

func TestPolicyProperty_NoAllowOverridesAMatchingDeny(t *testing.T) {
	t.Run("deny_all_rule_wins_over_any_allow", func(t *testing.T) {
		forEachScenario(t, func(t *testing.T, g *propGen, s scenario) {
			denyAll := Rule{Name: "deny-all", Subjects: []string{"*"}, Deny: []string{"*"}}
			allows := []Rule{g.rule("extra-allow-1", allowOnlyRule), g.rule("extra-allow-2", allowOnlyRule), {Name: "allow-all", Subjects: []string{"*"}, Allow: []string{"*"}, AllowDestructive: true}}
			doc := withExtraRules(g, s.doc, append(allows, denyAll)...)
			if got := mustPolicy(t, doc).Evaluate(s.req); got.Decision == DecisionAllow {
				t.Fatalf("allow overrode a deny-all rule\n%s", s.describe())
			}
		})
	})
	t.Run("deny_rule_matching_actor_and_action_wins_over_any_allow", func(t *testing.T) {
		forEachScenario(t, func(t *testing.T, g *propGen, s scenario) {
			deny := Rule{Name: "deny-this", Subjects: []string{"type:" + string(s.req.Actor.Type)}, Deny: []string{pick(g, []string{"*", s.req.Action})}}
			if validate(Document{Version: SupportedVersion, Rules: []Rule{deny}}) != nil {
				return // the action is not a catalog action: nothing to deny by name
			}
			allowAll := Rule{Name: "allow-all", Subjects: []string{"*"}, Allow: []string{"*"}, AllowDestructive: true}
			doc := withExtraRules(g, s.doc, allowAll, deny)
			if got := mustPolicy(t, doc).Evaluate(s.req); got.Decision == DecisionAllow {
				t.Fatalf("allow overrode a deny rule matching the actor and action\n%s", s.describe())
			}
		})
	})
	t.Run("adding_allow_rules_never_lifts_a_denial_by_a_deny_rule", func(t *testing.T) {
		forEachScenario(t, func(t *testing.T, g *propGen, s scenario) {
			before := s.policy.Evaluate(s.req)
			if !slices.ContainsFunc(before.PerTarget, func(r TargetResult) bool { return r.Reason == smerr.ReasonDenyRule }) {
				return
			}
			extra := []Rule{g.rule("extra-allow-1", allowOnlyRule), {Name: "allow-all", Subjects: []string{"*"}, Allow: []string{"*"}, AllowDestructive: true}}
			after := mustPolicy(t, withExtraRules(g, s.doc, extra...)).Evaluate(s.req)
			if after.Decision != DecisionDeny {
				t.Fatalf("decision %s after adding allow rules to a denial by a deny rule\n%s", after.Decision, s.describe())
			}
		})
	})
}

func TestPolicyProperty_AddingTargetsNeverRelaxesTheDecision(t *testing.T) {
	forEachScenario(t, func(t *testing.T, g *propGen, s scenario) {
		spec, known := Lookup(s.req.Action)
		if !known {
			spec = ActionSpec{Resource: domain.ResourceNode}
		}
		before := s.policy.Evaluate(s.req)

		moreTargets := s.req
		moreTargets.Targets = slices.Insert(slices.Clone(s.req.Targets), g.r.IntN(len(s.req.Targets)+1), g.target(spec, "added"))
		if why := relaxation(before, s.policy.Evaluate(moreTargets)); why != "" {
			t.Fatalf("adding a target relaxed the result: %s\n%s", why, s.describe())
		}

		moreSubActions := s.req
		moreSubActions.SubActions = slices.Insert(slices.Clone(s.req.SubActions), g.r.IntN(len(s.req.SubActions)+1), g.subAction("added"))
		if why := relaxation(before, s.policy.Evaluate(moreSubActions)); why != "" {
			t.Fatalf("adding a sub-action relaxed the result: %s\n%s", why, s.describe())
		}
	})
}

func TestPolicyProperty_AddingADenyRuleNeverRelaxesTheDecision(t *testing.T) {
	forEachScenario(t, func(t *testing.T, g *propGen, s scenario) {
		before := s.policy.Evaluate(s.req)
		after := mustPolicy(t, withExtraRules(g, s.doc, g.rule("extra-deny", denyOnlyRule))).Evaluate(s.req)
		if why := relaxation(before, after); why != "" {
			t.Fatalf("adding a deny rule relaxed the result: %s\n%s", why, s.describe())
		}
		if before.Decision == DecisionAllow && after.Decision == DecisionAllow &&
			(before.ApprovalRequired != after.ApprovalRequired || before.Quorum != after.Quorum) {
			t.Fatalf("a deny rule that did not match changed approval or quorum: %+v -> %+v\n%s", before, after, s.describe())
		}
	})
}

func TestPolicyProperty_DecisionIsIndependentOfRuleOrder(t *testing.T) {
	forEachScenario(t, func(t *testing.T, g *propGen, s scenario) {
		shuffled := slices.Clone(s.doc.Rules)
		g.r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := mustPolicy(t, Document{Version: s.doc.Version, Rules: shuffled}).Evaluate(s.req)
		want := s.policy.Evaluate(s.req)
		if diff := orderFreeDiff(want, got); diff != "" {
			t.Fatalf("rule order changed the result: %s\n%s", diff, s.describe())
		}
	})
}

func TestPolicyProperty_DecisionIsIndependentOfTargetOrder(t *testing.T) {
	forEachScenario(t, func(t *testing.T, g *propGen, s scenario) {
		shuffled := s.req
		shuffled.Targets = slices.Clone(s.req.Targets)
		g.r.Shuffle(len(shuffled.Targets), func(i, j int) { shuffled.Targets[i], shuffled.Targets[j] = shuffled.Targets[j], shuffled.Targets[i] })
		shuffled.SubActions = slices.Clone(s.req.SubActions)
		g.r.Shuffle(len(shuffled.SubActions), func(i, j int) {
			shuffled.SubActions[i], shuffled.SubActions[j] = shuffled.SubActions[j], shuffled.SubActions[i]
		})
		want, got := s.policy.Evaluate(s.req), s.policy.Evaluate(shuffled)
		if got.Decision != want.Decision || got.ApprovalRequired != want.ApprovalRequired || got.Quorum != want.Quorum {
			t.Fatalf("target order changed the result: %+v vs %+v\n%s", want, got, s.describe())
		}
	})
}

// orderFreeDiff compares two results ignoring the order of matched rule names.
func orderFreeDiff(want, got Result) string {
	if got.Decision != want.Decision || got.Reason != want.Reason ||
		got.ApprovalRequired != want.ApprovalRequired || got.Quorum != want.Quorum {
		return fmt.Sprintf("%+v vs %+v", want, got)
	}
	if len(got.PerTarget) != len(want.PerTarget) {
		return "per-target result count differs"
	}
	for i := range want.PerTarget {
		w, g := want.PerTarget[i], got.PerTarget[i]
		if w.Decision != g.Decision || w.Reason != g.Reason || w.ApprovalRequired != g.ApprovalRequired || w.Quorum != g.Quorum ||
			!slices.Equal(sorted(w.MatchedRules), sorted(g.MatchedRules)) {
			return fmt.Sprintf("target %d: %+v vs %+v", i, w, g)
		}
	}
	return ""
}

func sorted(xs []string) []string {
	out := slices.Clone(xs)
	slices.Sort(out)
	return out
}
