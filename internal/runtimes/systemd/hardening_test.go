package systemd

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func TestInterpretersRunOnlyWithListedOptions(t *testing.T) {
	refused := [][]string{
		{"/usr/bin/python3", `-cprint("INLINE")`, "/usr/bin/true"},
		{"/usr/bin/python3", "-c=print(1)", "/usr/bin/true"},
		{"/usr/bin/python3", "-mhttp.server", "/usr/bin/true"},
		{"/usr/bin/python3", "-Wignore", "/usr/bin/true"},
		{"/usr/bin/python3.11", "--check-hash-based-pycs=always", "/usr/bin/true"},
		{"/bin/sh", "-cid", "/usr/bin/true"},
		{"/bin/bash", "-lc", "/usr/bin/true"},
		{"/bin/bash", "--command=id", "/usr/bin/true"},
		{"/bin/bash", "--rcfile=/tmp/x", "/usr/bin/true"},
		{"/usr/bin/perl", `-eprint"x"`, "/usr/bin/true"},
		{"/usr/bin/perl", "-Mstrict", "/usr/bin/true"},
		{"/usr/bin/ruby", "-ep", "/usr/bin/true"},
		{"/usr/bin/node", "--eval=1", "/usr/bin/true"},
		{"/usr/bin/node", "--require=/tmp/x.js", "/usr/bin/true"},
		{"/usr/bin/php", "-rphpinfo();", "/usr/bin/true"},
		{"/usr/bin/php", "-d", "auto_prepend_file=/tmp/x", "/usr/bin/true"},
	}
	for _, argv := range refused {
		name := strings.Join(argv, " ")
		t.Run(name, func(t *testing.T) {
			show := goodShow("ExecStartPre=" + execLine(argv[0], argv...))
			assertNotEligible(t, CheckTrust(context.Background(), trustNode(t, show, nil, nil), "app.service"), argv[0])
		})
	}

	accepted := [][]string{
		{"/usr/bin/python3", "-u", "-B", "/srv/app/run.py", "--flag"},
		{"/usr/bin/python3", "--", "/srv/app/run.py"},
		{"/bin/bash", "--norc", "--noprofile", "-eu", "/srv/app/run.sh"},
		{"/usr/bin/perl", "-w", "/srv/app/run.pl"},
		{"/usr/bin/node", "--no-warnings", "/srv/app/run.js"},
	}
	for _, argv := range accepted {
		show := goodShow("ExecStartPre=" + execLine(argv[0], argv...))
		if err := CheckTrust(context.Background(), trustNode(t, show, nil, nil), "app.service"); err != nil {
			t.Errorf("%v refused: %v", argv, err)
		}
	}
}

func TestSystemctlMustBeRootOwnedOnEveryComponent(t *testing.T) {
	tests := map[string]map[string]string{
		"owned by the service user":     {"/var/lib/supermgmt/bin/systemctl": "998 755"},
		"group-writable":                {"/var/lib/supermgmt/bin/systemctl": "0 775"},
		"service-user-owned parent":     {"/var/lib/supermgmt/bin": "998 755"},
		"world-writable grandparent":    {"/var/lib/supermgmt": "0 757"},
		"user-owned directory up to /":  {"/var/lib": "1000 755"},
		"root-owned but other-writable": {"/var/lib/supermgmt/bin/systemctl": "0 757"},
	}
	for name, bad := range tests {
		t.Run(name, func(t *testing.T) {
			node := trustNode(t, goodShow(), bad, nil)
			err := CheckSystemctlTrust(context.Background(), node, "/var/lib/supermgmt/bin/systemctl")
			if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable || !strings.Contains(err.Error(), "systemctl is not trusted") {
				t.Fatalf("got %v", err)
			}
		})
	}
	if err := CheckSystemctlTrust(context.Background(), trustNode(t, goodShow(), nil, nil), testSystemctl); err != nil {
		t.Errorf("root-owned systemctl refused: %v", err)
	}
	unreadable := newFakeNode(t).fail("systemd.path_chain", 1)
	if err := CheckSystemctlTrust(context.Background(), unreadable, testSystemctl); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("uninspectable systemctl accepted: %v", err)
	}
}

func TestSetupRefusesAServiceUserWritableSystemctlBeforeChangingAnything(t *testing.T) {
	node := newSetupNode(t)
	inner := node.handlers["systemd.path_chain"]
	node.on("systemd.path_chain", func(c templates.Command) transport.Result {
		if strings.Contains(c.Line, "/var/lib/supermgmt/bin/systemctl") {
			return transport.Result{Stdout: []byte("998 755 /var/lib/supermgmt/bin/systemctl\n")}
		}
		return inner(c)
	})
	p := setupParams()
	p.SystemctlPath = "/var/lib/supermgmt/bin/systemctl"
	if _, err := Setup(context.Background(), node, p); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Fatalf("got %v", err)
	}
	for _, name := range node.ran() {
		if strings.HasPrefix(name, "setup.") {
			t.Errorf("%s ran although systemctl is untrusted", name)
		}
	}
}

func TestSetupResolvedSystemctlFromTheAdminPathIsCheckedToo(t *testing.T) {
	node := newSetupNode(t)
	node.reply("setup.systemctl_path", "/var/lib/supermgmt/bin/systemctl\n")
	node.on("systemd.path_chain", func(templates.Command) transport.Result {
		return transport.Result{Stdout: []byte("998 755 /var/lib/supermgmt/bin/systemctl\n")}
	})
	p := setupParams()
	p.SystemctlPath = ""
	if _, err := Setup(context.Background(), node, p); err == nil || !strings.Contains(err.Error(), "systemctl is not trusted") {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRefusesAnUntrustedSystemctl(t *testing.T) {
	node := verifyNode(t, "supermgmt", "writable\n", sudoListing, 0)
	node.on("systemd.path_chain", func(templates.Command) transport.Result {
		return transport.Result{Stdout: []byte("998 755 /usr/bin/systemctl\n")}
	})
	if err := Verify(context.Background(), node, verifyParams()); err == nil || !strings.Contains(err.Error(), "systemctl is not trusted") {
		t.Fatalf("got %v", err)
	}
}

func TestSetupRefusesForeignAccountsBeforeAnyCredentialIsInstalled(t *testing.T) {
	tests := map[string]struct {
		account, primary, members string
	}{
		"uid 0":                       {"supermgmt:x:0:0::/var/lib/supermgmt:/bin/sh\n", "supermgmt", "supermgmt"},
		"login uid":                   {"supermgmt:x:1000:1000::/var/lib/supermgmt:/bin/sh\n", "supermgmt", "supermgmt"},
		"primary group docker":        {ownAccount, "docker", "docker"},
		"primary group of another id": {ownAccount, "users", "users"},
		"member of sudo":              {ownAccount, "supermgmt", "supermgmt sudo"},
		"member of wheel":             {ownAccount, "supermgmt", "supermgmt wheel"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			node := newSetupNode(t)
			node.account, node.primary, node.members = tt.account, tt.primary, tt.members
			_, err := Setup(context.Background(), node, setupParams())
			if smerr.CodeOf(err) != smerr.CodeConflict {
				t.Fatalf("got %v, want CONFLICT", err)
			}
			if _, installed := node.files[templates.AuthorizedKeysPath]; installed || node.count("setup.own_file_stage") != 0 {
				t.Error("the instance key was installed for a foreign account")
			}
			if _, installed := node.files[templates.SudoersPath]; installed {
				t.Error("sudoers was installed for a foreign account")
			}
		})
	}
}

func TestSetupInstallsTheKeyLast(t *testing.T) {
	node := newSetupNode(t)
	if _, err := Setup(context.Background(), node, setupParams()); err != nil {
		t.Fatal(err)
	}
	ran := node.ran()
	if last := ran[len(ran)-1]; last != "setup.own_file_commit" {
		t.Fatalf("last step = %s; want the authorized_keys commit", last)
	}
	for _, before := range []string{"setup.group_add", "setup.sudoers_check", "setup.file_commit", "setup.tmpfiles_apply"} {
		if i, j := slices.Index(ran, before), slices.Index(ran, "setup.own_file_stage"); i < 0 || i > j {
			t.Errorf("%s must precede the key (at %d, key at %d)", before, i, j)
		}
	}
}

func TestSetupConvergesAfterACutBetweenUserAddAndUserUnlock(t *testing.T) {
	node := newSetupNode(t)
	node.account = ownAccount // useradd ran, usermod -p '*' did not
	if _, err := Setup(context.Background(), node, setupParams()); err != nil {
		t.Fatal(err)
	}
	if node.count("setup.user_unlock") != 1 || node.count("setup.user_add") != 0 {
		t.Errorf("ran %v", node.ran())
	}
}

func TestSetupNeverLetsRootTouchServiceUserPaths(t *testing.T) {
	node := newSetupNode(t)
	if _, err := Setup(context.Background(), node, setupParams()); err != nil {
		t.Fatal(err)
	}
	for _, c := range node.calls {
		if !strings.HasPrefix(c.Template, "setup.") || !strings.Contains(c.Line, "/var/lib/supermgmt/") {
			continue
		}
		if !strings.Contains(c.Line, "runuser -u 'supermgmt' --") {
			t.Errorf("%s touches the service user's tree as root: %s", c.Template, c.Line)
		}
	}
	node = newSetupNode(t)
	p := setupParams()
	p.AdminIsRoot = false
	if _, err := Setup(context.Background(), node, p); err != nil {
		t.Fatal(err)
	}
	for _, c := range node.calls {
		if strings.HasPrefix(c.Template, "setup.") && strings.Contains(c.Line, "/var/lib/supermgmt/") && !strings.Contains(c.Line, "sudo -n runuser -u 'supermgmt' -- ") {
			t.Errorf("%s touches the service user's tree as root: %s", c.Template, c.Line)
		}
	}
}

func TestObserveAfterATimeoutKilledClientWaitsForSystemd(t *testing.T) {
	// timeout(1) exits 124/137 after killing only the systemctl client; the
	// job keeps running in systemd. The adapter must not conclude.
	const pre = `{"invocation_id":"inv-1","active_state":"active","sub_state":"running"}`
	busy := newFakeNode(t).reply("systemd.list_jobs", "7 a.service stop running\n")
	_, err := New().Observe(context.Background(), busy, ref("a.service"), domain.VerbStop, "m1", json.RawMessage(pre), time.Time{})
	if !errors.Is(err, ErrSettling) {
		t.Fatalf("got %v, want ErrSettling", err)
	}
	done := newFakeNode(t).reply("systemd.list_jobs", "").reply("systemd.show", showReply("inv-1", "active", "running"))
	ev, err := New().Observe(context.Background(), done, ref("a.service"), domain.VerbRestart, "m1", json.RawMessage(pre), time.Time{})
	if err != nil || ev.Proof != ProofNoJobs || ev.Classification != jobs.ClassNotStarted || len(ev.Fingerprint) == 0 || string(ev.Pre) != pre {
		t.Errorf("evidence = %+v, %v", ev, err)
	}
}
