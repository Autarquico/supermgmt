package policy

import (
	"fmt"
	"slices"
	"strings"
)

// retirement says which ADR removed an action and, when the capability lives on, under which action.
type retirement struct {
	ADR         string
	Replacement string
}

// retiredActions maps an action removed from the catalog to its retirement.
// Policy files written before the removal still load: the name is
// accepted, warned about once, and grants or denies nothing.
var retiredActions = map[string]retirement{
	"app_target.move":           {ADR: "ADR-0043"},
	"app_target.cleanup_source": {ADR: "ADR-0043"},
	"app_target.abandon_move":   {ADR: "ADR-0043"},
	"app_route.expose":          {ADR: "ADR-0043", Replacement: ActionNodeRouteExpose},
	"app_route.unexpose":        {ADR: "ADR-0043", Replacement: ActionNodeRouteUnexpose},
}

// Warning reports that a policy file names a retired action.
type Warning struct {
	Action      string
	ADR         string
	Replacement string   // the action that took over, empty when none did
	Rules       []string // names of the rules that mention it, in document order
	Denied      []string // rules whose deny of it now denies Replacement, in document order
	AllNodes    []string // the Denied rules whose resource scope could not carry over, so they deny Replacement on every node
}

func (w Warning) String() string {
	rules := make([]string, len(w.Rules))
	for i, r := range w.Rules {
		rules[i] = fmt.Sprintf("%q", r)
	}
	replaced := ""
	if w.Replacement != "" {
		replaced = "; use " + w.Replacement
	}
	return fmt.Sprintf("action %s was retired by %s and grants nothing%s (rules: %s)%s%s",
		w.Action, w.ADR, replaced, strings.Join(rules, ", "),
		quotedRules("; deny now denies "+w.Replacement+" in rules: ", w.Denied),
		quotedRules("; their resources name apps or environments, whose scope could not be carried over to nodes, so they deny it on every node: ", w.AllNodes))
}

func quotedRules(prefix string, names []string) string {
	if len(names) == 0 {
		return ""
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return prefix + strings.Join(quoted, ", ")
}

// retiredMatches lists the retired actions pattern covers.
func retiredMatches(pattern string) []string {
	var names []string
	for name := range retiredActions {
		if matchAction(pattern, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func coversLiveAction(pattern string) bool {
	return slices.ContainsFunc(Catalog(), func(s ActionSpec) bool { return matchAction(pattern, s.Name) })
}

// withoutRetired drops, from a validated document, every pattern that covers
// only retired actions. A dropped allow grants nothing. A dropped deny whose
// action lives on as a replacement is replaced by a deny of the replacement,
// so a carve-out never turns into a grant; the rule's resources carry over
// unless they name apps or environments, which do not carry over to nodes: then a separate deny-only rule
// with the same subjects denies it on every node and the rule itself is untouched.
// A pattern that also covers live actions stays as it
// is: the evaluator never sees a retired action, so it already keeps exactly
// its live matches, and it denies the replacement with the same meaning unless
// the rule's resources name apps or environments: then the same all-nodes deny applies. A rule left with no pattern at all is inert, never a
// wildcard. Subjects, resources, approvals and gates are untouched.
func withoutRetired(doc Document) (Document, []Warning) {
	found := map[string]*Warning{}
	note := func(rule string, names []string) {
		for _, name := range names {
			w, ok := found[name]
			if !ok {
				w = &Warning{Action: name, ADR: retiredActions[name].ADR, Replacement: retiredActions[name].Replacement}
				found[name] = w
			}
			if !slices.Contains(w.Rules, rule) {
				w.Rules = append(w.Rules, rule)
			}
		}
	}
	var replacements []string // of the retired-only deny patterns keep dropped
	var covered []string      // retired route actions kept deny patterns also match
	keep := func(rule string, patterns []string, denies bool) []string {
		var kept []string
		for _, p := range patterns {
			names := retiredMatches(p)
			if len(names) > 0 && !coversLiveAction(p) {
				note(rule, names)
				if denies {
					replacements = addReplacements(replacements, names)
				}
				continue
			}
			if denies {
				for _, name := range names {
					if retiredActions[name].Replacement != "" {
						covered = append(covered, name)
					}
				}
			}
			kept = append(kept, p)
		}
		return kept
	}
	noteDenied := func(rule string, replacements []string, widened bool) {
		for _, name := range deniedNames(replacements) {
			w := found[name]
			w.Denied = append(w.Denied, rule)
			if widened {
				w.AllNodes = append(w.AllNodes, rule)
			}
		}
	}
	taken := map[string]bool{}
	for _, r := range doc.Rules {
		taken[r.Name] = true
	}
	out := Document{Version: doc.Version, Rules: make([]Rule, 0, len(doc.Rules))}
	for _, r := range doc.Rules {
		replacements, covered = nil, nil
		r.Allow = keep(r.Name, r.Allow, false)
		r.Deny = keep(r.Name, r.Deny, true)
		widened := scopeLostOnNodes(r.Resources)
		carry := replacements
		if widened {
			note(r.Name, covered)
			carry = addReplacements(slices.Clone(replacements), covered)
		}
		if len(carry) == 0 {
			out.Rules = append(out.Rules, r)
			continue
		}
		noteDenied(r.Name, carry, widened)
		if !widened {
			for _, rep := range carry {
				if !slices.Contains(r.Deny, rep) {
					r.Deny = append(r.Deny, rep)
				}
			}
			out.Rules = append(out.Rules, r)
			continue
		}
		out.Rules = append(out.Rules, r, allNodesDeny(r, carry, taken))
	}
	warnings := make([]Warning, 0, len(found))
	for _, w := range found {
		warnings = append(warnings, *w)
	}
	slices.SortFunc(warnings, func(a, b Warning) int { return strings.Compare(a.Action, b.Action) })
	return out, warnings
}

// addReplacements appends the replacement of each named retired action that has one.
func addReplacements(replacements, names []string) []string {
	for _, name := range names {
		if r := retiredActions[name].Replacement; r != "" && !slices.Contains(replacements, r) {
			replacements = append(replacements, r)
		}
	}
	return replacements
}

// allNodesDeny is the deny-only rule that carries replacements over for a rule
// whose app: or environment: resources cannot apply to nodes. The original rule keeps its
// resources, because dropping them would widen its live actions to every resource.
func allNodesDeny(r Rule, replacements []string, taken map[string]bool) Rule {
	name := r.Name + " (retired app_route deny)"
	for n := 2; taken[name]; n++ {
		name = fmt.Sprintf("%s (retired app_route deny %d)", r.Name, n)
	}
	taken[name] = true
	return Rule{Name: name, Subjects: slices.Clone(r.Subjects), Deny: slices.Clone(replacements)}
}

// scopeLostOnNodes reports whether a resource selector has an app: or
// environment: entry. No node satisfies app:, and a node's environment is its
// own, not that of the app targets it hosts, so neither scope carries over.
func scopeLostOnNodes(resources []string) bool {
	return slices.ContainsFunc(resources, func(e string) bool {
		return strings.HasPrefix(e, "app:") || strings.HasPrefix(e, "environment:")
	})
}

// deniedNames lists the retired actions whose replacement is in replacements.
func deniedNames(replacements []string) []string {
	var names []string
	for name, ret := range retiredActions {
		if slices.Contains(replacements, ret.Replacement) {
			names = append(names, name)
		}
	}
	return names
}
