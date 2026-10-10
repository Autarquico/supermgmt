package policy

import "slices"

// SupportedVersion is the only policy document version.
const SupportedVersion = 1

// Rule is one entry of a policy document (spec §11.2, §11.6).
type Rule struct {
	Name      string   `yaml:"name"`
	Subjects  []string `yaml:"subjects"`
	Resources []string `yaml:"resources"`
	Allow     []string `yaml:"allow"`
	Deny      []string `yaml:"deny"`
	// RequireApproval is tri-state: nil (unset), true, or false.
	RequireApproval  *bool `yaml:"require_approval"`
	Approvals        *int  `yaml:"approvals"`
	AllowDestructive bool  `yaml:"allow_destructive"`
}

// Document is the policy file as written.
type Document struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Policy is a validated policy document ready for evaluation.
type Policy struct {
	rules []Rule
}

// Rules returns the policy's rules in document order.
func (p *Policy) Rules() []Rule { return slices.Clone(p.rules) }

// requiresApproval reports whether the rule explicitly sets require_approval: true.
func (r Rule) requiresApproval() bool { return r.RequireApproval != nil && *r.RequireApproval }

// optsOutOfApproval reports whether the rule explicitly sets require_approval: false.
func (r Rule) optsOutOfApproval() bool { return r.RequireApproval != nil && !*r.RequireApproval }

// quorum is the rule's approvals value, 0 when unset.
func (r Rule) quorum() int {
	if r.Approvals == nil {
		return 0
	}
	return *r.Approvals
}
