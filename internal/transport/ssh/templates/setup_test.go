package templates

import (
	"strings"
	"testing"
)

func lookupTemplate(name string) (Template, error) {
	r, err := catalog()
	if err != nil {
		return Template{}, err
	}
	return r.lookup(name)
}

func TestEverySetupStepHasARootAndASudoVariant(t *testing.T) {
	for _, s := range privilegedSteps {
		root, errRoot := lookupTemplate(s.name)
		sudo, errSudo := lookupTemplate(s.name + SudoVariantSuffix)
		if errRoot != nil || errSudo != nil {
			t.Fatalf("%s: %v / %v", s.name, errRoot, errSudo)
		}
		if !root.Setup || !sudo.Setup || root.Mutating || sudo.Mutating {
			t.Errorf("%s must be a setup, non-marker template", s.name)
		}
		if !strings.HasPrefix(sudo.Body, "sudo -n ") || strings.HasPrefix(root.Body, "sudo") || !strings.HasPrefix(root.Body, rootPath) {
			t.Errorf("%s bodies: %q / %q", s.name, root.Body, sudo.Body)
		}
	}
}

func TestSetupStepsRenderOnlyThroughRenderSetupWithContentOnStdin(t *testing.T) {
	content := []byte("restrict ssh-ed25519 AAAA supermgmt@i\n")
	args := map[string]string{"mode": "0440", "owner": "root", "group": "root", "path": SudoersPath + StagingSuffix}
	c, err := RenderSetup("setup.file_stage.sudo", args, content)
	if err != nil {
		t.Fatal(err)
	}
	want := "sudo -n install -m '0440' -o 'root' -g 'root' /dev/stdin '/etc/sudoers.d/supermgmt.new'"
	if c.Line != want || string(c.Stdin) != string(content) || c.Mutating {
		t.Errorf("command = %+v", c)
	}
	if _, err := Render("setup.file_stage", args); err == nil {
		t.Error("Render served a setup template")
	}
	if _, err := RenderMutating("setup.file_stage", "m1", args); err == nil {
		t.Error("RenderMutating served a setup template")
	}
}

func TestSetupTemplatesTouchOnlyManagedPaths(t *testing.T) {
	stage := func(path string) error {
		_, err := RenderSetup("setup.file_stage", map[string]string{"mode": "0600", "owner": "root", "group": "root", "path": path}, nil)
		return err
	}
	if err := stage(SudoersPath + StagingSuffix); err != nil {
		t.Errorf("managed staging path: %v", err)
	}
	for _, bad := range []string{"/etc/passwd", "/etc/sudoers", SudoersPath, "/etc/sudoers.d/other.new", "/etc/sudoers.d/supermgmt.new/../../passwd", "/root/.ssh/authorized_keys.new"} {
		if err := stage(bad); err == nil {
			t.Errorf("staging path %q accepted", bad)
		}
	}
	if _, err := RenderSetup("setup.file_commit", map[string]string{"from": "/etc/passwd.new", "to": SudoersPath}, nil); err == nil {
		t.Error("commit from an unmanaged path accepted")
	}
	if _, err := RenderSetup("setup.file_commit", map[string]string{"from": SudoersPath + StagingSuffix, "to": "/etc/passwd"}, nil); err == nil {
		t.Error("commit to an unmanaged path accepted")
	}
	if _, err := RenderSetup("setup.dir", map[string]string{"mode": "0777", "owner": "root", "group": "root", "path": "/etc"}, nil); err == nil {
		t.Error("directory outside the managed set accepted")
	}
	for _, mode := range []string{"777", "0o77", "0888", "00600", "a", "0600; id"} {
		if _, err := RenderSetup("setup.dir", map[string]string{"mode": mode, "owner": "root", "group": "root", "path": HomeDir}, nil); err == nil {
			t.Errorf("mode %q accepted", mode)
		}
	}
}

func TestSetupAccountsAndGroupsAreAllowlisted(t *testing.T) {
	c, err := RenderSetup("setup.user_add", map[string]string{"user": "supermgmt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--system", "--user-group", "--home-dir /var/lib/supermgmt", "--create-home", "--shell /bin/sh"} {
		if !strings.Contains(c.Line, flag) {
			t.Errorf("useradd lacks %s: %s", flag, c.Line)
		}
	}
	if c, _ := RenderSetup("setup.user_unlock", map[string]string{"user": "supermgmt"}, nil); !strings.HasSuffix(c.Line, "usermod -p '*' 'supermgmt'") {
		t.Errorf("unlock = %s", c.Line)
	}
	for _, bad := range []string{"root; id", "Root", "a b", "-r", ""} {
		if _, err := RenderSetup("setup.user_add", map[string]string{"user": bad}, nil); err == nil {
			t.Errorf("user %q accepted", bad)
		}
	}
	for _, group := range []string{"systemd-journal", "adm", "docker"} {
		if _, err := RenderSetup("setup.group_add", map[string]string{"user": "supermgmt", "group": group}, nil); err != nil {
			t.Errorf("group %s: %v", group, err)
		}
	}
	for _, group := range []string{"sudo", "wheel", "root", "shadow"} {
		if _, err := RenderSetup("setup.group_add", map[string]string{"user": "supermgmt", "group": group}, nil); err == nil {
			t.Errorf("privileged group %q accepted", group)
		}
	}
}

func TestSetupReadsAreNotSetupTemplates(t *testing.T) {
	for _, name := range []string{"setup.user_entry", "setup.user_groups", "setup.systemctl_path", "setup.verify_id", "setup.verify_markers", "setup.verify_sudo"} {
		args := map[string]string{}
		if name == "setup.user_entry" || name == "setup.user_groups" {
			args["user"] = "supermgmt"
		}
		if _, err := Render(name, args); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c, _ := Render("setup.verify_sudo", nil); c.Line != "sudo -n -l" {
		t.Errorf("verify_sudo = %q", c.Line)
	}
}

func TestRootNeverReceivesPathsBelowTheServiceUsersHome(t *testing.T) {
	for _, path := range []string{AuthorizedKeysPath, SSHDir, MarkerDir, HomeDir + "/anything"} {
		if _, err := RenderSetup("setup.file_stage", map[string]string{"mode": "0600", "owner": "root", "group": "root", "path": StagingPath(path)}, nil); err == nil {
			t.Errorf("root file_stage accepted %s", path)
		}
		if _, err := RenderSetup("setup.dir", map[string]string{"mode": "0700", "owner": "root", "group": "root", "path": path}, nil); path != HomeDir+"/anything" && err == nil {
			t.Errorf("root dir accepted %s", path)
		}
	}
	if _, err := RenderSetup("setup.file_commit", map[string]string{"from": StagingPath(AuthorizedKeysPath), "to": AuthorizedKeysPath}, nil); err == nil {
		t.Error("root file_commit accepted authorized_keys")
	}
	home, err := RenderSetup("setup.dir", map[string]string{"mode": "0750", "owner": "supermgmt", "group": "supermgmt", "path": HomeDir}, nil)
	if err != nil || !strings.Contains(home.Line, "test ! -L '"+HomeDir+"' && ") {
		t.Errorf("home step must refuse a symlink: %q, %v", home.Line, err)
	}
}

func TestOwnStepsRunAsTheDedicatedUser(t *testing.T) {
	dir := map[string]string{"user": "supermgmt", "mode": "0700", "path": SSHDir}
	root, err := RenderSetup("setup.own_dir", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(root.Line, "runuser -u 'supermgmt' -- sh -c 'test ! -L \"$1\" && install -d") {
		t.Errorf("root variant = %s", root.Line)
	}
	viaSudo, err := RenderSetup("setup.own_dir.sudo", dir, nil)
	if err != nil || !strings.HasPrefix(viaSudo.Line, "sudo -n runuser -u 'supermgmt' -- sh -c ") {
		t.Errorf("sudo variant = %q, %v", viaSudo.Line, err)
	}
	stage, err := RenderSetup("setup.own_file_stage", map[string]string{"user": "supermgmt", "mode": "0600", "path": StagingPath(AuthorizedKeysPath)}, []byte("key"))
	if err != nil || !strings.Contains(stage.Line, "runuser -u 'supermgmt' -- sh -c 'cat | install -m \"$2\" /dev/stdin \"$1\"' sh '"+AuthorizedKeysPath+".new' '0600'") {
		t.Errorf("stage = %q, %v", stage.Line, err)
	}
	for _, bad := range []string{"/etc/passwd", HomeDir, HomeDir + "/other", SudoersPath} {
		if _, err := RenderSetup("setup.own_dir", map[string]string{"user": "supermgmt", "mode": "0700", "path": bad}, nil); err == nil {
			t.Errorf("own_dir accepted %s", bad)
		}
	}
}
