package policy

import (
	"testing"
)

func TestDiffPolicies_AgainstDefault(t *testing.T) {
	base, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if d := DiffPolicies(base, base); !d.Empty() {
		t.Fatalf("a policy differs from itself: %+v", d)
	}

	user := pol(t,
		`{name: builtin-read, subjects: ['role:admin', 'role:viewer', 'role:deployer', 'role:operator'], allow: ['node.connect', 'plan.create', 'service.logs', '*.read']}`,
		`{name: builtin-operator, subjects: ['role:operator'], allow: ['service.restart']}`,
		`{name: custom, subjects: ['role:ops'], allow: ['node.read']}`)
	d := DiffPolicies(base, user)

	if len(d.Added) != 1 || d.Added[0].Name != "custom" {
		t.Errorf("added = %+v, want [custom]", d.Added)
	}
	if len(d.Changed) != 1 || d.Changed[0].Name != "builtin-operator" {
		t.Errorf("changed = %+v, want [builtin-operator] (builtin-read only reordered)", d.Changed)
	}
	if d.Changed[0].Before.Allow[0] != "service.start" || d.Changed[0].After.Allow[0] != "service.restart" {
		t.Errorf("changed rule carries wrong versions: %+v", d.Changed[0])
	}
	wantRemoved := []string{"builtin-deployer", "builtin-approver", "builtin-admin", "builtin-mcp-read"}
	if len(d.Removed) != len(wantRemoved) {
		t.Fatalf("removed = %+v", d.Removed)
	}
	for i, name := range wantRemoved {
		if d.Removed[i].Name != name {
			t.Errorf("removed[%d] = %s, want %s", i, d.Removed[i].Name, name)
		}
	}
	if d.Empty() {
		t.Error("Empty() must be false")
	}
}

func TestDiffPolicies_FieldsThatChangeMeaning(t *testing.T) {
	const base = `{name: r, subjects: ['*'], allow: ['node.read']}`
	cases := map[string]string{
		"deny_added":             `{name: r, subjects: ['*'], allow: ['node.read'], deny: ['node.reboot']}`,
		"resources_added":        `{name: r, subjects: ['*'], resources: ['tag:x'], allow: ['node.read']}`,
		"require_approval_true":  `{name: r, subjects: ['*'], allow: ['node.read'], require_approval: true}`,
		"require_approval_false": `{name: r, subjects: ['*'], allow: ['node.read'], require_approval: false}`,
		"approvals":              `{name: r, subjects: ['*'], allow: ['node.read'], approvals: 2}`,
		"allow_destructive":      `{name: r, subjects: ['*'], allow: ['node.read'], allow_destructive: true}`,
		"subjects_changed":       `{name: r, subjects: ['type:mcp'], allow: ['node.read']}`,
	}
	for name, changed := range cases {
		t.Run(name, func(t *testing.T) {
			d := DiffPolicies(pol(t, base), pol(t, changed))
			if len(d.Changed) != 1 || len(d.Added) != 0 || len(d.Removed) != 0 {
				t.Fatalf("diff = %+v, want exactly one changed rule", d)
			}
		})
	}
}

func TestDiffPolicies_RequireApprovalUnsetDiffersFromFalse(t *testing.T) {
	unset := pol(t, `{name: r, subjects: ['*'], allow: ['node.read']}`)
	explicitFalse := pol(t, `{name: r, subjects: ['*'], allow: ['node.read'], require_approval: false}`)
	if DiffPolicies(unset, explicitFalse).Empty() {
		t.Fatal("unset and explicit false are different policies (opt-out semantics)")
	}
}
