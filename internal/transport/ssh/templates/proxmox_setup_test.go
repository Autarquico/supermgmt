package templates

import (
	"slices"
	"strings"
	"testing"
)

func TestSecretOutputIsForSetupTemplatesOnly(t *testing.T) {
	tpl := Template{Name: "t", Body: "echo", MaxBytes: 1, SecretOutput: true}
	if _, err := newRegistry([]Template{tpl}); err == nil {
		t.Error("a read template with secret output was accepted")
	}
	tpl.Setup = true
	if _, err := newRegistry([]Template{tpl}); err != nil {
		t.Errorf("a setup template with secret output was refused: %v", err)
	}
}

func TestOnlyTheTokenAddStepHasSecretOutput(t *testing.T) {
	all, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	var secret []string
	for _, tpl := range all {
		if tpl.SecretOutput {
			secret = append(secret, tpl.Name)
		}
	}
	want := []string{PVETokenAddStep, PVETokenAddStep + SudoVariantSuffix}
	slices.Sort(want)
	if !slices.Equal(secret, want) {
		t.Errorf("secret output templates = %v, want %v", secret, want)
	}
}

func TestSecretOutputReachesTheRenderedCommand(t *testing.T) {
	args := map[string]string{"user": "sm-ab12cd34@pve", "id": "sm", "comment": "supermgmt install ab12cd34"}
	for _, name := range []string{PVETokenAddStep, PVETokenAddStep + SudoVariantSuffix} {
		c, err := RenderSetup(name, args, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !c.SecretOutput {
			t.Errorf("%s: SecretOutput lost", name)
		}
		for _, want := range []string{"--privsep 1", "--output-format json", "'sm-ab12cd34@pve' 'sm'"} {
			if !strings.Contains(c.Line, want) {
				t.Errorf("%s: %q lacks %q", name, c.Line, want)
			}
		}
	}
	c, err := RenderSetup(PVETokenListStep, map[string]string{"user": "sm-ab12cd34@pve"}, nil)
	if err != nil || c.SecretOutput {
		t.Errorf("token list: %+v, %v", c, err)
	}
}

func TestEveryProxmoxStepHasARootAndASudoVariant(t *testing.T) {
	for _, s := range proxmoxSteps {
		root, errRoot := lookupTemplate(s.name)
		sudo, errSudo := lookupTemplate(s.name + SudoVariantSuffix)
		if errRoot != nil || errSudo != nil {
			t.Fatalf("%s: %v / %v", s.name, errRoot, errSudo)
		}
		if !root.Setup || !sudo.Setup || !strings.HasPrefix(sudo.Body, "sudo -n ") {
			t.Errorf("%s bodies: %q / %q", s.name, root.Body, sudo.Body)
		}
	}
}

func TestProxmoxStepsRenderTheInstallersArgumentVectors(t *testing.T) {
	const prefix = "sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/sbin/pveum "
	tests := []struct {
		name string
		args map[string]string
		want string
	}{
		{PVEUserAddStep, map[string]string{"user": "sm-ab@pve", "comment": "supermgmt install ab"}, prefix + "user add 'sm-ab@pve' --comment 'supermgmt install ab'"},
		{PVERoleAddStep, map[string]string{"role": "SMAudit-ab", "privs": "VM.Audit,Sys.Audit"}, prefix + "role add 'SMAudit-ab' --privs 'VM.Audit,Sys.Audit'"},
		{PVEACLAddUserStep, map[string]string{"path": "/vms", "role": "SMPower-ab", "user": "sm-ab@pve"}, prefix + "acl modify '/vms' --roles 'SMPower-ab' --users 'sm-ab@pve'"},
		{PVETokenRemoveStep, map[string]string{"user": "sm-ab@pve", "id": "sm"}, prefix + "user token remove 'sm-ab@pve' 'sm'"},
	}
	for _, tt := range tests {
		c, err := RenderSetup(tt.name+SudoVariantSuffix, tt.args, nil)
		if err != nil || c.Line != tt.want {
			t.Errorf("%s: %q, %v; want %q", tt.name, c.Line, err, tt.want)
		}
	}
}

func TestProxmoxStepsRefuseHostileArguments(t *testing.T) {
	good := map[string]string{
		"user": "sm-ab@pve", "role": "SMAudit-ab", "privs": "VM.Audit,Sys.Audit", "comment": "supermgmt install ab",
		"path": "/vms", "token": "sm-ab@pve!sm", "id": "sm",
	}
	hostile := map[string][]string{
		"user":    {"sm-ab", "a@pve;id", "a@pve b", "$(id)@pve", "a@pve\n", "@pve"},
		"role":    {"a b", "a;id", "a`id`", "a/b"},
		"privs":   {"VM.Audit,", "VM.Audit;id", "vm.audit", "VM.Audit, Sys.Audit", strings.Repeat("VM.Audit,", 40) + "VM.Audit"},
		"comment": {"x\ny", "é", "a\x00b"},
		"path":    {"vms", "/../etc", "/a b", "/a;id", "/a$(id)"},
		"token":   {"sm-ab@pve", "sm-ab@pve!", "sm-ab@pve!a b", "x!sm", "sm-ab@pve!sm;id"},
		"id":      {"a b", "a;id", "a!b"},
	}
	for _, s := range proxmoxSteps {
		tpl, err := lookupTemplate(s.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range tpl.Params {
			for _, bad := range hostile[p.Name] {
				args := map[string]string{}
				for _, q := range tpl.Params {
					args[q.Name] = good[q.Name]
				}
				args[p.Name] = bad
				if c, err := RenderSetup(s.name, args, nil); err == nil {
					t.Errorf("%s accepted %s=%q: %q", s.name, p.Name, bad, c.Line)
				}
			}
		}
	}
}

func TestProxmoxReadsTakeNoArguments(t *testing.T) {
	for _, name := range []string{HostnameRead, SocatPathRead} {
		c, err := Render(name, nil)
		if err != nil || c.Line == "" {
			t.Errorf("%s: %q, %v", name, c.Line, err)
		}
		if _, err := Render(name, map[string]string{"x": "y"}); err == nil {
			t.Errorf("%s accepted an argument", name)
		}
	}
}
