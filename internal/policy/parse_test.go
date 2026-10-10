package policy

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestParse_Invalid(t *testing.T) {
	const uuid = "0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88"
	cases := []struct {
		name string
		yaml string
	}{
		{"empty_file", ""},
		{"wrong_version", "version: 2\nrules: []\n"},
		{"missing_version", "rules: []\n"},
		{"unknown_top_level_field", "version: 1\nrules: []\nextra: 1\n"},
		{"unknown_rule_field", "version: 1\nrules:\n  - name: a\n    subjects: ['*']\n    allow: ['node.read']\n    alow: ['x']\n"},
		{"duplicate_key", "version: 1\nrules:\n  - name: a\n    name: b\n    subjects: ['*']\n    allow: ['node.read']\n"},
		{"two_documents", "version: 1\nrules: []\n---\nversion: 1\nrules: []\n"},
		{"not_yaml_mapping", "- a\n- b\n"},
		{"missing_name", "version: 1\nrules:\n  - subjects: ['*']\n    allow: ['node.read']\n"},
		{"duplicate_rule_names", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [node.read]}\n  - {name: a, subjects: ['*'], allow: [node.read]}\n"},
		{"empty_subjects", "version: 1\nrules:\n  - {name: a, allow: [node.read]}\n"},
		{"unknown_subject_prefix", "version: 1\nrules:\n  - {name: a, subjects: ['group:x'], allow: [node.read]}\n"},
		{"subject_without_value", "version: 1\nrules:\n  - {name: a, subjects: ['role:'], allow: [node.read]}\n"},
		{"subject_unknown_actor_type", "version: 1\nrules:\n  - {name: a, subjects: ['type:robot'], allow: [node.read]}\n"},
		{"subject_identity_not_uuid", "version: 1\nrules:\n  - {name: a, subjects: ['identity:bob'], allow: [node.read]}\n"},
		{"subject_identity_uppercase", "version: 1\nrules:\n  - {name: a, subjects: ['identity:" + strings.ToUpper(uuid) + "'], allow: [node.read]}\n"},
		{"unknown_resource_prefix", "version: 1\nrules:\n  - {name: a, subjects: ['*'], resources: ['region:eu'], allow: [node.read]}\n"},
		{"resource_without_value", "version: 1\nrules:\n  - {name: a, subjects: ['*'], resources: ['tag:'], allow: [node.read]}\n"},
		{"no_allow_nor_deny", "version: 1\nrules:\n  - {name: a, subjects: ['*']}\n"},
		{"unknown_exact_action", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['node.explode']}\n"},
		{"unknown_exact_action_in_deny", "version: 1\nrules:\n  - {name: a, subjects: ['*'], deny: ['node.explode']}\n"},
		{"wildcard_matching_nothing", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*.reed']}\n"},
		{"partial_wildcard_segment", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['node.re*']}\n"},
		{"empty_segment", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['node..read']}\n"},
		{"uppercase_segment", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['Node.read']}\n"},
		{"approvals_zero", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [node.read], approvals: 0}\n"},
		{"approvals_six", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [node.read], approvals: 6}\n"},
		{"require_approval_not_bool", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [node.read], require_approval: maybe}\n"},
		{"require_approval_on_credential_action", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [token.create], require_approval: true}\n"},
		{"require_approval_on_issue_token", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [mcp_client.issue_token], require_approval: true}\n"},
		{"require_approval_on_wildcard_covering_credential_action", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['token.*'], require_approval: true}\n"},
		{"require_approval_on_bare_wildcard", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*'], require_approval: true}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("Parse succeeded, rules = %+v", p.Rules())
			}
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Fatalf("code = %s, want INVALID_ARGUMENT (err: %v)", smerr.CodeOf(err), err)
			}
		})
	}
}

func TestParse_UnknownActionKeepsReason(t *testing.T) {
	_, err := Parse([]byte("version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['node.explode']}\n"))
	if !errors.Is(err, smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "")) {
		t.Fatalf("err = %v, want it to wrap UNKNOWN_ACTION", err)
	}
}

func TestParse_Valid(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"no_rules", "version: 1\nrules: []\n"},
		{"bare_wildcard_action", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*']}\n"},
		{"deny_only_rule", "version: 1\nrules:\n  - {name: a, subjects: ['type:mcp'], deny: [node.shutdown]}\n"},
		{"require_approval_false_on_credential_action", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [token.create], require_approval: false}\n"},
		{"require_approval_true_on_non_credential_wildcard", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*.write'], require_approval: true}\n"},
		{"approvals_bounds", "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: [node.reboot], approvals: 1}\n  - {name: b, subjects: ['*'], allow: [node.reboot], approvals: 5}\n"},
		{"all_resource_kinds", "version: 1\nrules:\n  - {name: a, subjects: ['*'], resources: ['tag:db', 'environment:staging', 'provider:pve', 'node:pve-1', 'app:shop', '*'], allow: [node.read]}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err != nil {
				t.Fatalf("Parse: %v", err)
			}
		})
	}
}

func TestParse_RequireApprovalIsTriState(t *testing.T) {
	p, err := Parse([]byte(`version: 1
rules:
  - {name: unset, subjects: ['*'], allow: [node.read]}
  - {name: yes, subjects: ['*'], allow: [node.read], require_approval: true}
  - {name: no, subjects: ['*'], allow: [node.read], require_approval: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	rules := p.Rules()
	if rules[0].RequireApproval != nil {
		t.Error("unset must stay nil")
	}
	if rules[1].RequireApproval == nil || !*rules[1].RequireApproval {
		t.Error("true must decode as true")
	}
	if rules[2].RequireApproval == nil || *rules[2].RequireApproval {
		t.Error("false must decode as non-nil false")
	}
}

func TestDefaultPolicy_ParsesAndNamesOnlyCatalogActions(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if len(p.Rules()) != 6 {
		t.Fatalf("default has %d rules, want 6", len(p.Rules()))
	}
	for _, r := range p.Rules() {
		for _, pattern := range append(append([]string{}, r.Allow...), r.Deny...) {
			if strings.Contains(pattern, "*") {
				continue
			}
			if _, ok := Lookup(pattern); !ok {
				t.Errorf("rule %s names %q, which is not in the catalog", r.Name, pattern)
			}
		}
	}
}

func TestDefaultYAML_ReturnsACopy(t *testing.T) {
	first := DefaultYAML()
	first[0] = 'X'
	if DefaultYAML()[0] == 'X' {
		t.Fatal("DefaultYAML exposes the embedded buffer")
	}
}

func TestDefaultPolicy_MatchesSpecBlock(t *testing.T) {
	blocks := specPolicyBlocks(t)
	if got := strings.TrimSpace(string(DefaultYAML())); got != strings.TrimSpace(blocks[0]) {
		t.Fatal("default.yaml differs from the §11.2 block in the spec")
	}
}

func TestExamplePolicy_MatchesSpecBlockAndValidates(t *testing.T) {
	blocks := specPolicyBlocks(t)
	data, err := os.ReadFile("../../examples/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != strings.TrimSpace(blocks[1]) {
		t.Fatal("examples/policies.yaml differs from the §11.6 block in the spec")
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("example policy does not validate: %v", err)
	}
}

// specPolicyBlocks extracts the two policy YAML blocks (§11.2, §11.6) from the spec.
func specPolicyBlocks(t *testing.T) []string {
	t.Helper()
	spec, err := os.ReadFile("../../docs/spec/SUPERMGMT-SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile("(?s)```yaml\n(version: 1\nrules:\n.*?)```")
	var blocks []string
	for _, m := range re.FindAllStringSubmatch(string(spec), -1) {
		if _, err := Parse([]byte(m[1])); err != nil {
			t.Fatalf("spec policy block does not validate: %v", err)
		}
		blocks = append(blocks, m[1])
	}
	if len(blocks) != 2 {
		t.Fatalf("found %d policy blocks in the spec, want 2", len(blocks))
	}
	return blocks
}

func TestParse_ErrorsNameYAMLPathAndLine(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"unknown rule field", "version: 1\nrules:\n  - name: a\n    subjects: ['*']\n    allow: [node.read]\n    bogus: 1\n", "rules[0].bogus (line 6): unknown field"},
		{"unknown top-level field", "version: 1\nrules: []\nextra: 1\n", "extra (line 3): unknown field"},
		{"duplicate key", "version: 1\nrules:\n  - name: a\n    name: b\n", "rules[0].name (line 4): duplicate key"},
		{"anchor", "version: 1\nrules:\n  - name: &n a\n    subjects: ['*']\n", "anchors are not supported"},
		{"alias", "version: 1\nrules:\n  - name: &n a\n    subjects: [*n]\n", "aliases are not supported"},
		{"merge key", "version: 1\nrules:\n  - <<: {name: a}\n", "merge keys are not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
