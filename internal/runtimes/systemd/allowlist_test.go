package systemd

import (
	"context"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestUnlistedInterpretersMakeTheUnitIneligible(t *testing.T) {
	refused := [][]string{
		{"/usr/bin/zsh", "-c", "source /home/x/f"},
		{"/usr/bin/zsh", "/srv/app/run.zsh"},
		{"/bin/ksh", "/srv/app/run.ksh"},
		{"/bin/mksh", "-c", "id"},
		{"/bin/busybox", "sh", "/srv/app/run.sh"},
		{"/usr/bin/fish", "-c", "id"},
		{"/usr/bin/awk", "-f", "/srv/app/run.awk"},
		{"/usr/bin/gawk", "BEGIN{system(\"id\")}"},
		{"/usr/bin/mawk", "/srv/app/run.awk"},
		{"/usr/bin/lua5.4", "/srv/app/run.lua"},
		{"/usr/bin/tclsh8.6", "/srv/app/run.tcl"},
		{"/usr/bin/deno", "run", "/srv/app/run.ts"},
		{"/usr/bin/sed", "-e", "s/a/b/"},
	}
	for _, argv := range refused {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			show := goodShow("ExecStartPre=" + execLine(argv[0], argv...))
			assertNotEligible(t, CheckTrust(context.Background(), trustNode(t, show, nil, nil), "app.service"), argv[0])
		})
	}
	for _, argv := range [][]string{
		{"/usr/local/bin/tool", "-c", "x"},
		{"/usr/local/bin/tool", "-e"},
		{"/usr/local/bin/tool", "--eval=x"},
	} {
		show := goodShow("ExecStartPre=" + execLine(argv[0], argv...))
		assertNotEligible(t, CheckTrust(context.Background(), trustNode(t, show, nil, nil), "app.service"), argv[0])
	}
	ok := goodShow("ExecStartPre=" + execLine("/usr/local/bin/tool", "/usr/local/bin/tool", "--serve", "-v"))
	if err := CheckTrust(context.Background(), trustNode(t, ok, nil, nil), "app.service"); err != nil {
		t.Errorf("plain program refused: %v", err)
	}
	versioned := goodShow("ExecStartPre=" + execLine("/usr/bin/perl5.36.0", "/usr/bin/perl5.36.0", "-w", "/srv/app/run.pl"))
	if err := CheckTrust(context.Background(), trustNode(t, versioned, nil, nil), "app.service"); err != nil {
		t.Errorf("listed interpreter with a version suffix refused: %v", err)
	}
}

func TestSetupRefusesAnAccountInUnmanagedGroupsBeforeChangingIt(t *testing.T) {
	for _, members := range []string{"supermgmt sudo", "supermgmt wheel docker", "supermgmt systemd-journal lxd"} {
		node := newSetupNode(t)
		node.account, node.members = ownAccount, members
		if _, err := Setup(context.Background(), node, setupParams()); smerr.CodeOf(err) != smerr.CodeConflict {
			t.Fatalf("%q: got %v", members, err)
		}
		for _, mutating := range []string{"setup.user_unlock", "setup.group_add", "setup.group_remove", "setup.dir", "setup.own_dir"} {
			if node.count(mutating) != 0 {
				t.Errorf("%q: %s ran before the account was refused", members, mutating)
			}
		}
	}
}
