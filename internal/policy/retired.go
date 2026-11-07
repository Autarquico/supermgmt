package policy

import (
	"fmt"
	"slices"
	"strings"
)

// retiredActions maps an action removed from the catalog to the ADR that
// retired it. Policy files written before the removal still load: the name is
// accepted, warned about once, and grants or denies nothing.
var retiredActions = map[string]string{
	"app_target.move":           "ADR-0043",
	"app_target.cleanup_source": "ADR-0043",
	"app_target.abandon_move":   "ADR-0043",
}

// Warning reports that a policy file names a retired action.
type Warning struct {
	Action string
	ADR    string
	Rules  []string // names of the rules that mention it, in document order
}

func (w Warning) String() string {
	rules := make([]string, len(w.Rules))
	for i, r := range w.Rules {
		rules[i] = fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf("action %s was retired by %s and grants or denies nothing (rules: %s)",
		w.Action, w.ADR, strings.Join(rules, ", "))
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
// only retired actions. A pattern that also covers live actions stays as it
// is: the evaluator never sees a retired action, so it already keeps exactly
// its live matches. A rule left with no pattern at all is inert, never a
// wildcard. Subjects, resources, approvals and gates are untouched.
func withoutRetired(doc Document) (Document, []Warning) {
	found := map[string]*Warning{}
	note := func(rule string, names []string) {
		for _, name := range names {
			w, ok := found[name]
			if !ok {
				w = &Warning{Action: name, ADR: retiredActions[name]}
				found[name] = w
			}
			if !slices.Contains(w.Rules, rule) {
				w.Rules = append(w.Rules, rule)
			}
		}
	}
	keep := func(rule string, patterns []string) []string {
		var kept []string
		for _, p := range patterns {
			if names := retiredMatches(p); len(names) > 0 && !coversLiveAction(p) {
				note(rule, names)
				continue
			}
			kept = append(kept, p)
		}
		return kept
	}
	out := Document{Version: doc.Version, Rules: make([]Rule, len(doc.Rules))}
	for i, r := range doc.Rules {
		r.Allow = keep(r.Name, r.Allow)
		r.Deny = keep(r.Name, r.Deny)
		out.Rules[i] = r
	}
	warnings := make([]Warning, 0, len(found))
	for _, w := range found {
		warnings = append(warnings, *w)
	}
	slices.SortFunc(warnings, func(a, b Warning) int { return strings.Compare(a.Action, b.Action) })
	return out, warnings
}
