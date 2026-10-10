package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	minApprovals = 1
	maxApprovals = 5
)

var (
	segmentPattern = regexp.MustCompile(`^[a-z0-9_]+$`)
	valuePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

	subjectKinds  = []string{"type", "role", "identity"}
	resourceKinds = []string{"tag", "environment", "provider", "node", "app"}
)

func validate(doc Document) error {
	if doc.Version != SupportedVersion {
		return invalidPolicy(fmt.Sprintf("unsupported policy version %d (want %d)", doc.Version, SupportedVersion), nil)
	}
	names := make(map[string]struct{}, len(doc.Rules))
	for i, rule := range doc.Rules {
		if err := validateRule(rule); err != nil {
			return invalidPolicy(fmt.Sprintf("rule %d (%q)", i+1, rule.Name), err)
		}
		if _, dup := names[rule.Name]; dup {
			return invalidPolicy(fmt.Sprintf("rule %d: duplicate rule name %q", i+1, rule.Name), nil)
		}
		names[rule.Name] = struct{}{}
	}
	return nil
}

func validateRule(r Rule) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(r.Subjects) == 0 {
		return fmt.Errorf("subjects must not be empty")
	}
	for _, s := range r.Subjects {
		if err := validateSubject(s); err != nil {
			return err
		}
	}
	for _, res := range r.Resources {
		if err := validateResource(res); err != nil {
			return err
		}
	}
	if len(r.Allow)+len(r.Deny) == 0 {
		return fmt.Errorf("a rule needs at least one allow or deny pattern")
	}
	for _, p := range slices.Concat(r.Allow, r.Deny) {
		if err := validateActionPattern(p); err != nil {
			return err
		}
	}
	if r.Approvals != nil && (*r.Approvals < minApprovals || *r.Approvals > maxApprovals) {
		return fmt.Errorf("approvals must be between %d and %d", minApprovals, maxApprovals)
	}
	return validateApprovalSupport(r)
}

func validateSubject(entry string) error {
	if entry == wildcard {
		return nil
	}
	kind, value, err := splitEntry(entry, subjectKinds, "subject")
	if err != nil {
		return err
	}
	switch kind {
	case "type":
		if _, err := domain.ParseActorType(value); err != nil {
			return fmt.Errorf("subject %q: %w", entry, err)
		}
	case "identity":
		if _, err := domain.ParseID(value); err != nil {
			return fmt.Errorf("subject %q: %w", entry, err)
		}
	}
	return nil
}

func validateResource(entry string) error {
	if entry == wildcard {
		return nil
	}
	_, _, err := splitEntry(entry, resourceKinds, "resource")
	return err
}

func splitEntry(entry string, kinds []string, what string) (kind, value string, err error) {
	kind, value, ok := strings.Cut(entry, ":")
	if !ok || !slices.Contains(kinds, kind) {
		return "", "", fmt.Errorf("%s %q: prefix must be one of %s", what, entry, strings.Join(kinds, ", "))
	}
	if !valuePattern.MatchString(value) {
		return "", "", fmt.Errorf("%s %q: invalid value", what, entry)
	}
	return kind, value, nil
}

// validateActionPattern checks an allow/deny pattern against the catalog. An
// exact name must be a catalog action; a wildcard pattern must be well formed
// per segment and cover at least one catalog action.
func validateActionPattern(pattern string) error {
	if pattern == wildcard {
		return nil
	}
	segments := strings.Split(pattern, segmentSeparator)
	hasWildcard := false
	for _, segment := range segments {
		switch {
		case segment == wildcard:
			hasWildcard = true
		case !segmentPattern.MatchString(segment):
			return fmt.Errorf("action pattern %q: invalid segment %q", pattern, segment)
		}
	}
	if !hasWildcard {
		if _, ok := Lookup(pattern); !ok {
			return unknownAction(pattern)
		}
		return nil
	}
	if !slices.ContainsFunc(Catalog(), func(s ActionSpec) bool { return matchAction(pattern, s.Name) }) {
		return fmt.Errorf("action pattern %q matches no catalog action", pattern)
	}
	return nil
}

// validateApprovalSupport rejects require_approval: true on any pattern that
// covers a credential-issuing action: those are never approval-gated (§11.2).
func validateApprovalSupport(r Rule) error {
	if !r.requiresApproval() {
		return nil
	}
	for _, spec := range Catalog() {
		if spec.CredentialIssuing && matchesAnyAction(r.Allow, spec.Name) {
			return fmt.Errorf("require_approval: true is not supported for credential-issuing action %q", spec.Name)
		}
	}
	return nil
}
