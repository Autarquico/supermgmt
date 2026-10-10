package policy

import (
	"slices"
)

// RuleChange pairs the two versions of a rule present in both policies.
type RuleChange struct {
	Name   string
	Before Rule
	After  Rule
}

// Diff is the rule-level difference between a base policy and another one,
// matched by rule name. Lists are ordered as in their source policy.
type Diff struct {
	Added   []Rule
	Removed []Rule
	Changed []RuleChange
}

// Empty reports whether the policies are equivalent.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// DiffPolicies compares other against base (typically the built-in default).
func DiffPolicies(base, other *Policy) Diff {
	var d Diff
	baseByName := indexByName(base.rules)
	otherByName := indexByName(other.rules)
	for _, r := range other.rules {
		before, found := baseByName[r.Name]
		switch {
		case !found:
			d.Added = append(d.Added, r)
		case !sameRule(before, r):
			d.Changed = append(d.Changed, RuleChange{Name: r.Name, Before: before, After: r})
		}
	}
	for _, r := range base.rules {
		if _, found := otherByName[r.Name]; !found {
			d.Removed = append(d.Removed, r)
		}
	}
	return d
}

func indexByName(rules []Rule) map[string]Rule {
	index := make(map[string]Rule, len(rules))
	for _, r := range rules {
		index[r.Name] = r
	}
	return index
}

// sameRule compares rules by meaning: list order and duplicates do not matter.
func sameRule(a, b Rule) bool {
	return sameSet(a.Subjects, b.Subjects) &&
		sameSet(a.Resources, b.Resources) &&
		sameSet(a.Allow, b.Allow) &&
		sameSet(a.Deny, b.Deny) &&
		a.AllowDestructive == b.AllowDestructive &&
		samePtr(a.RequireApproval, b.RequireApproval) &&
		samePtr(a.Approvals, b.Approvals)
}

func sameSet(a, b []string) bool {
	return slices.Equal(sortedUnique(a), sortedUnique(b))
}

func sortedUnique(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

func samePtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
