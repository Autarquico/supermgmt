package policy

import (
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	wildcard         = "*"
	segmentSeparator = "."
)

// matchAction reports whether the dot-separated pattern covers action. A "*"
// segment matches exactly one segment; a bare "*" matches any action.
func matchAction(pattern, action string) bool {
	if pattern == wildcard {
		return true
	}
	patternSegments := strings.Split(pattern, segmentSeparator)
	actionSegments := strings.Split(action, segmentSeparator)
	if len(patternSegments) != len(actionSegments) {
		return false
	}
	for i, segment := range patternSegments {
		if segment != wildcard && segment != actionSegments[i] {
			return false
		}
	}
	return true
}

func matchesAnyAction(patterns []string, action string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return matchAction(p, action) })
}

// matchSubject reports whether a subject entry ("type:", "role:",
// "identity:" or "*") designates actor.
func matchSubject(entry string, actor domain.Actor) bool {
	if entry == wildcard {
		return true
	}
	kind, value, ok := strings.Cut(entry, ":")
	if !ok || value == "" {
		return false
	}
	switch kind {
	case "type":
		return string(actor.Type) == value
	case "role":
		return slices.Contains(actor.Roles, value)
	case "identity":
		return string(actor.ID) == value
	}
	return false
}

// Attributes are the effective, control-plane-owned attributes of a target
// (spec §11.3). The caller computes them; the engine only consumes them.
type Attributes struct {
	Tags              []string
	Environment       string
	EnvironmentRisk   domain.EnvironmentRiskLevel
	ApprovalsRequired int // the environment's approvals_required; 0 when unset
	Provider          string
	Node              string
	App               string
}

// matchResource reports whether a resource entry ("tag:", "environment:",
// "provider:", "node:", "app:" or "*") matches attrs.
func matchResource(entry string, attrs Attributes) bool {
	if entry == wildcard {
		return true
	}
	kind, value, ok := strings.Cut(entry, ":")
	if !ok || value == "" {
		return false
	}
	switch kind {
	case "tag":
		return slices.Contains(attrs.Tags, value)
	case "environment":
		return attrs.Environment == value
	case "provider":
		return attrs.Provider == value
	case "node":
		return attrs.Node == value
	case "app":
		return attrs.App == value
	}
	return false
}

func (r Rule) matchesActor(actor domain.Actor) bool {
	return slices.ContainsFunc(r.Subjects, func(s string) bool { return matchSubject(s, actor) })
}

// matchesResource: an omitted resources list matches everything; entries are OR'ed.
func (r Rule) matchesResource(attrs Attributes) bool {
	if len(r.Resources) == 0 {
		return true
	}
	return slices.ContainsFunc(r.Resources, func(e string) bool { return matchResource(e, attrs) })
}

// matchedRules are the rules of a policy that apply to one actor, target and
// action (spec §11.3 step 3), in policy order.
type matchedRules struct {
	allow []Rule
	deny  []Rule
}

func (m matchedRules) names() []string {
	seen := make(map[string]struct{}, len(m.allow)+len(m.deny))
	var names []string
	for _, rules := range [][]Rule{m.allow, m.deny} {
		for _, r := range rules {
			if _, dup := seen[r.Name]; !dup {
				seen[r.Name] = struct{}{}
				names = append(names, r.Name)
			}
		}
	}
	return names
}

func (p *Policy) match(actor domain.Actor, action string, attrs Attributes) matchedRules {
	var m matchedRules
	for _, r := range p.rules {
		if !r.matchesActor(actor) || !r.matchesResource(attrs) {
			continue
		}
		if matchesAnyAction(r.Allow, action) {
			m.allow = append(m.allow, r)
		}
		if matchesAnyAction(r.Deny, action) {
			m.deny = append(m.deny, r)
		}
	}
	return m
}
