package systemd

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	testKey      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbc"
	ownAccount   = "supermgmt:x:998:998::/var/lib/supermgmt:/bin/sh\n"
	staged       = "staged"
	sudoersStage = "/etc/sudoers.d/supermgmt.new"
)

func setupParams() SetupParams {
	return SetupParams{
		User: "supermgmt", InstanceID: "inst-1", AuthorizedKey: testKey, SystemctlPath: testSystemctl,
		Grants:   []runtimes.UnitGrant{{Unit: "app.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}}},
		LogsMode: runtimes.LogsJournalGroup, AdminIsRoot: true,
	}
}

// setupNode simulates the node commands Setup issues. account is what getent
// returns (exit 2 when empty); members is `id -nG`; groups exist on the node.
type setupNode struct {
	*fakeNode
	account, members string
	primary          string
	groups           []string
	sudoersInvalid   bool
	files            map[string]string // destination -> content committed
	staging          map[string]string
}

func newSetupNode(t *testing.T) *setupNode {
	n := &setupNode{fakeNode: newFakeNode(t), groups: []string{"systemd-journal", "docker"}, primary: "supermgmt", files: map[string]string{}, staging: map[string]string{}}
	trusted := trustNode(t, goodShow(), nil, nil)
	for name, h := range trusted.handlers {
		n.on(name, h)
	}
	n.on("setup.user_entry", func(templates.Command) transport.Result {
		if n.account == "" {
			return transport.Result{ExitStatus: 2}
		}
		return transport.Result{Stdout: []byte(n.account)}
	})
	n.on("setup.group_entry", func(c templates.Command) transport.Result {
		for _, g := range n.groups {
			if strings.Contains(c.Line, "'"+g+"'") {
				return transport.Result{Stdout: []byte(g + ":x:1:\n")}
			}
		}
		return transport.Result{ExitStatus: 2}
	})
	n.on("setup.user_groups", func(templates.Command) transport.Result { return transport.Result{Stdout: []byte(n.members)} })
	n.on("setup.user_primary_group", func(templates.Command) transport.Result { return transport.Result{Stdout: []byte(n.primary + "\n")} })
	for _, base := range []string{"setup.user_add", "setup.user_unlock", "setup.dir", "setup.own_dir", "setup.tmpfiles_apply"} {
		n.on(base, ok)
		n.on(base+templates.SudoVariantSuffix, ok)
	}
	for _, suffix := range []string{"", templates.SudoVariantSuffix} {
		n.on("setup.group_add"+suffix, func(c templates.Command) transport.Result {
			n.members += " " + argument(c.Line, 0)
			return transport.Result{}
		})
		n.on("setup.group_remove"+suffix, func(c templates.Command) transport.Result {
			group := argument(c.Line, -1)
			n.members = strings.Join(slices.DeleteFunc(strings.Fields(n.members), func(g string) bool { return g == group }), " ")
			return transport.Result{}
		})
		for _, kind := range []string{"setup.file_", "setup.own_file_"} {
			n.on(kind+"stage"+suffix, func(c templates.Command) transport.Result {
				path := argument(c.Line, -1)
				if strings.Contains(c.Line, "cat | install") {
					path = argument(c.Line, -2) // the mode follows the path
				}
				n.staging[path] = string(c.Stdin)
				return transport.Result{}
			})
			n.on(kind+"commit"+suffix, func(c templates.Command) transport.Result {
				n.files[argument(c.Line, -1)] = n.staging[argument(c.Line, -2)]
				return transport.Result{}
			})
			n.on(kind+"discard"+suffix, func(c templates.Command) transport.Result {
				delete(n.staging, argument(c.Line, -1))
				return transport.Result{}
			})
		}
		n.on("setup.sudoers_check"+suffix, func(templates.Command) transport.Result {
			if n.sudoersInvalid {
				return transport.Result{ExitStatus: 1, Stderr: []byte("\x1b[31mparse error near line 2\n")}
			}
			return transport.Result{}
		})
	}
	return n
}

func ok(templates.Command) transport.Result { return transport.Result{} }

// argument returns the i-th single-quoted argument of a rendered line (negative: from the end).
func argument(line string, i int) string {
	parts := strings.Split(line, "'")
	var args []string
	for j := 1; j < len(parts); j += 2 {
		args = append(args, parts[j])
	}
	if i < 0 {
		i += len(args)
	}
	return args[i]
}

func TestSetupProvisionsANewNodeAsRoot(t *testing.T) {
	node := newSetupNode(t)
	out, err := Setup(context.Background(), node, setupParams())
	if err != nil {
		t.Fatal(err)
	}
	if out.SystemctlPath != testSystemctl {
		t.Errorf("outcome = %+v", out)
	}
	want := []string{"user_add", "user_unlock"}
	for _, w := range want {
		if node.count("setup."+w) != 1 {
			t.Errorf("setup.%s ran %d times", w, node.count("setup."+w))
		}
	}
	if node.count("setup.dir") != 1 || node.count("setup.own_dir") != 2 {
		t.Errorf("root dirs = %d, own dirs = %d; only the home directory is set by root", node.count("setup.dir"), node.count("setup.own_dir"))
	}
	if got := node.files[templates.AuthorizedKeysPath]; got != "restrict "+testKey+" supermgmt@inst-1\n" {
		t.Errorf("authorized_keys = %q", got)
	}
	sudoers := node.files[templates.SudoersPath]
	if !strings.Contains(sudoers, "supermgmt ALL=(root) NOPASSWD: /usr/bin/systemctl restart app.service\n") {
		t.Errorf("sudoers = %q", sudoers)
	}
	if got := node.files[templates.TmpfilesPath]; got != "d /run/supermgmt/locks 0700 supermgmt supermgmt -\n" {
		t.Errorf("tmpfiles = %q", got)
	}
	if node.count("setup.group_add") != 1 || !strings.Contains(node.lines(), "usermod -aG 'systemd-journal' 'supermgmt'") {
		t.Errorf("groups: %s", node.lines())
	}
	if len(node.files) != 3 || len(node.staging) != 3 {
		t.Errorf("unexpected files: %v", node.files)
	}
}

func TestSetupKeepsContentOffTheCommandLineAndInstallsBeforeValidating(t *testing.T) {
	node := newSetupNode(t)
	if _, err := Setup(context.Background(), node, setupParams()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(node.lines(), "AAAAC3") || strings.Contains(node.lines(), "NOPASSWD") {
		t.Error("file content reached a command line")
	}
	ran := strings.Join(node.ran(), " ")
	if !strings.Contains(ran, "setup.file_stage setup.sudoers_check setup.file_commit") {
		t.Errorf("sudoers must be staged, checked, then committed: %s", ran)
	}
	for _, c := range node.calls {
		if c.Template == "setup.sudoers_check" && !strings.Contains(c.Line, "visudo -cf '"+sudoersStage+"'") {
			t.Errorf("check line = %s", c.Line)
		}
	}
}

func TestSetupUsesSudoVariantsWhenAdminIsNotRoot(t *testing.T) {
	node := newSetupNode(t)
	p := setupParams()
	p.AdminIsRoot = false
	if _, err := Setup(context.Background(), node, p); err != nil {
		t.Fatal(err)
	}
	for _, c := range node.calls {
		if strings.HasPrefix(c.Template, "setup.") && c.Mutating {
			t.Errorf("setup step %s is marker-wrapped", c.Template)
		}
		privileged := strings.HasSuffix(c.Template, templates.SudoVariantSuffix)
		if privileged && !strings.HasPrefix(c.Line, "sudo -n ") {
			t.Errorf("%s line = %s", c.Template, c.Line)
		}
		if !privileged && strings.HasPrefix(c.Template, "setup.") && strings.Contains(c.Line, "useradd") {
			t.Errorf("unprivileged useradd: %s", c.Line)
		}
	}
	if node.count("setup.user_add.sudo") != 1 || node.count("setup.user_add") != 0 {
		t.Errorf("ran %v", node.ran())
	}
}

func TestSetupIsIdempotentForOurOwnAccount(t *testing.T) {
	node := newSetupNode(t)
	node.account = ownAccount
	node.members = "supermgmt systemd-journal"
	if _, err := Setup(context.Background(), node, setupParams()); err != nil {
		t.Fatal(err)
	}
	if node.count("setup.user_unlock") != 1 {
		t.Errorf("the password field must be ensured on every run, ran %d times", node.count("setup.user_unlock"))
	}
	for _, name := range []string{"setup.user_add", "setup.group_add", "setup.group_remove"} {
		if node.count(name) != 0 {
			t.Errorf("%s ran on an already provisioned node", name)
		}
	}
}

func TestSetupNeverHijacksAForeignAccount(t *testing.T) {
	for name, entry := range map[string]string{
		"login uid":   "supermgmt:x:1001:1001::/var/lib/supermgmt:/bin/sh\n",
		"other home":  "supermgmt:x:998:998::/home/supermgmt:/bin/sh\n",
		"other shell": "supermgmt:x:998:998::/var/lib/supermgmt:/bin/bash\n",
		"garbage":     "supermgmt\n",
	} {
		t.Run(name, func(t *testing.T) {
			node := newSetupNode(t)
			node.account = entry
			_, err := Setup(context.Background(), node, setupParams())
			if smerr.CodeOf(err) != smerr.CodeConflict {
				t.Fatalf("got %v, want CONFLICT", err)
			}
			if node.count("setup.dir") != 0 || node.count("setup.file_stage") != 0 {
				t.Error("setup continued after the conflict")
			}
		})
	}
}

func TestSetupGroupsFollowTheParameters(t *testing.T) {
	t.Run("docker_access adds docker", func(t *testing.T) {
		node := newSetupNode(t)
		p := setupParams()
		p.DockerAccess = true
		if _, err := Setup(context.Background(), node, p); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(node.lines(), "usermod -aG 'docker' 'supermgmt'") {
			t.Errorf("lines: %s", node.lines())
		}
	})
	t.Run("without docker_access docker is removed", func(t *testing.T) {
		node := newSetupNode(t)
		node.account, node.members = ownAccount, "supermgmt systemd-journal docker"
		if _, err := Setup(context.Background(), node, setupParams()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(node.lines(), "gpasswd -d 'supermgmt' 'docker'") || node.count("setup.group_add") != 0 {
			t.Errorf("lines: %s", node.lines())
		}
	})
	t.Run("broker mode removes the journal group", func(t *testing.T) {
		node := newSetupNode(t)
		node.account, node.members = ownAccount, "supermgmt systemd-journal"
		p := setupParams()
		p.LogsMode = runtimes.LogsBroker
		if _, err := Setup(context.Background(), node, p); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(node.lines(), "gpasswd -d 'supermgmt' 'systemd-journal'") {
			t.Errorf("lines: %s", node.lines())
		}
		if node.files[templates.BrokerPath] != BrokerScript || node.files[templates.BrokerUnitsPath] != "app.service\n" {
			t.Errorf("broker files = %v", node.files)
		}
		if !strings.Contains(node.files[templates.SudoersPath], "NOPASSWD: "+templates.BrokerPath+"\n") {
			t.Error("sudoers lacks the broker line")
		}
	})
	t.Run("adm when there is no systemd-journal group", func(t *testing.T) {
		node := newSetupNode(t)
		node.groups = []string{"adm"}
		if _, err := Setup(context.Background(), node, setupParams()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(node.lines(), "usermod -aG 'adm' 'supermgmt'") {
			t.Errorf("lines: %s", node.lines())
		}
	})
	t.Run("docker_access without a docker group fails", func(t *testing.T) {
		node := newSetupNode(t)
		node.groups = []string{"systemd-journal"}
		p := setupParams()
		p.DockerAccess = true
		if _, err := Setup(context.Background(), node, p); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSetupDiscardsAnInvalidSudoersFileAndNeverInstallsIt(t *testing.T) {
	node := newSetupNode(t)
	node.sudoersInvalid = true
	_, err := Setup(context.Background(), node, setupParams())
	if err == nil || !strings.Contains(err.Error(), "sudoers") {
		t.Fatalf("got %v", err)
	}
	if _, installed := node.files[templates.SudoersPath]; installed {
		t.Error("an invalid sudoers file was installed")
	}
	if _, left := node.staging[sudoersStage]; left {
		t.Error("the invalid staging file was left behind")
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Error("remote stderr reached the error unsanitized")
	}
}

func TestSetupRefusesIneligibleUnitsBeforeChangingAnything(t *testing.T) {
	node := newSetupNode(t)
	inner := node.handlers["systemd.path_chain"]
	node.on("systemd.path_chain", func(c templates.Command) transport.Result {
		if strings.Contains(c.Line, "/usr/local/bin/app") {
			return transport.Result{Stdout: []byte("1000 777 /usr/local/bin/app\n")}
		}
		return inner(c)
	})
	_, err := Setup(context.Background(), node, setupParams())
	assertNotEligible(t, err, "/usr/local/bin/app")
	for _, name := range node.ran() {
		if strings.HasPrefix(name, "setup.") && name != "setup.systemctl_path" {
			t.Errorf("%s ran before the trust check passed", name)
		}
	}
}

func TestSetupResolvesSystemctlOnTheNode(t *testing.T) {
	node := newSetupNode(t)
	node.reply("setup.systemctl_path", "/bin/systemctl\n")
	p := setupParams()
	p.SystemctlPath = ""
	out, err := Setup(context.Background(), node, p)
	if err != nil || out.SystemctlPath != "/bin/systemctl" {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	if !strings.Contains(node.files[templates.SudoersPath], "/bin/systemctl restart app.service") {
		t.Errorf("sudoers = %q", node.files[templates.SudoersPath])
	}
	odd := newSetupNode(t)
	odd.reply("setup.systemctl_path", "systemctl\n")
	if _, err := Setup(context.Background(), odd, p); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("relative path: %v", err)
	}
}

func TestSetupValidatesParametersBeforeContactingTheNode(t *testing.T) {
	for name, mutate := range map[string]func(*SetupParams){
		"user":      func(p *SetupParams) { p.User = "Bad User" },
		"key":       func(p *SetupParams) { p.AuthorizedKey = "ssh-ed25519" },
		"logs mode": func(p *SetupParams) { p.LogsMode = "" },
		"systemctl": func(p *SetupParams) { p.SystemctlPath = "/usr/bin/sudo" },
		"unit":      func(p *SetupParams) { p.Grants[0].Unit = "a b.service" },
	} {
		t.Run(name, func(t *testing.T) {
			node := newFakeNode(t)
			p := setupParams()
			p.Grants = append([]runtimes.UnitGrant{}, p.Grants...)
			mutate(&p)
			if _, err := Setup(context.Background(), node, p); err == nil {
				t.Fatal("no error")
			}
			if len(node.calls) != 0 {
				t.Errorf("node contacted: %v", node.ran())
			}
		})
	}
}

const sudoListing = `Matching Defaults entries for supermgmt on node:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/bin

User supermgmt may run the following commands on node:
    (root) NOPASSWD: /usr/bin/systemctl start a.service, /usr/bin/systemctl
        restart a.service, /usr/bin/systemctl restart b.service
`

func verifyNode(t *testing.T, user, markers, sudoOut string, sudoExit int) *fakeNode {
	return trustNode(t, goodShow(), nil, nil).reply("setup.verify_id", user+"\n").reply("setup.verify_markers", markers).
		on("setup.verify_sudo", func(templates.Command) transport.Result {
			return transport.Result{Stdout: []byte(sudoOut), ExitStatus: sudoExit}
		})
}

func verifyParams() VerifyParams {
	return VerifyParams{User: "supermgmt", SystemctlPath: testSystemctl, LogsMode: runtimes.LogsJournalGroup, Grants: []runtimes.UnitGrant{
		{Unit: "a.service", Verbs: []domain.ServiceVerb{domain.VerbStart, domain.VerbRestart}},
		{Unit: "b.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}},
	}}
}

func TestVerifyAcceptsExactlyTheRenderedSudoLines(t *testing.T) {
	if err := Verify(context.Background(), verifyNode(t, "supermgmt", "writable\n", sudoListing, 0), verifyParams()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFailures(t *testing.T) {
	listing := func(entries string) string {
		return "User supermgmt may run the following commands on node:\n" + entries
	}
	tests := map[string]*fakeNode{
		"wrong user":      verifyNode(t, "root", "writable\n", sudoListing, 0),
		"markers":         verifyNode(t, "supermgmt", "", sudoListing, 0),
		"missing line":    verifyNode(t, "supermgmt", "writable\n", listing("    (root) NOPASSWD: /usr/bin/systemctl start a.service, /usr/bin/systemctl restart a.service\n"), 0),
		"extra line":      verifyNode(t, "supermgmt", "writable\n", sudoListing+"    (root) NOPASSWD: /usr/bin/systemctl stop a.service\n", 0),
		"extra ALL":       verifyNode(t, "supermgmt", "writable\n", sudoListing+"    (ALL : ALL) ALL\n", 0),
		"password needed": verifyNode(t, "supermgmt", "writable\n", strings.ReplaceAll(sudoListing, "NOPASSWD: ", ""), 0),
		"no sudo at all":  verifyNode(t, "supermgmt", "writable\n", "Sorry, user supermgmt may not run sudo\n", 1),
	}
	for name, node := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Verify(context.Background(), node, verifyParams()); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestVerifyWithoutGrantsExpectsNoSudo(t *testing.T) {
	p := VerifyParams{User: "supermgmt", SystemctlPath: testSystemctl, LogsMode: runtimes.LogsJournalGroup}
	if err := Verify(context.Background(), verifyNode(t, "supermgmt", "writable\n", "Sorry\n", 1), p); err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), verifyNode(t, "supermgmt", "writable\n", sudoListing, 0), p); err == nil {
		t.Fatal("unexpected sudo rights accepted")
	}
}
