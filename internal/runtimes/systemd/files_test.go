package systemd

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const testSystemctl = "/usr/bin/systemctl"

// argvOf runs the command inside a rendered marker wrapper through a real shell with sudo replaced by a
// function that prints its arguments, one per line: the executed argv.
func argvOf(t *testing.T, line string) []string {
	t.Helper()
	_, rest, _ := strings.Cut(line, "timeout --kill-after=10s 120s ")
	inner, _, _ := strings.Cut(rest, "; rc=$?")
	script := "sudo() { printf '%s\\n' \"$@\"; }; " + inner
	out, err := exec.CommandContext(context.Background(), "/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatalf("sh -c %q: %v", line, err)
	}
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n")
}

func TestExecutedArgvEqualsTheSudoersLineByteForByte(t *testing.T) {
	units := []string{"nginx.service", "foo@bar.service", "my-app_2.v1.service", "A.service"}
	for _, verb := range domain.AllServiceVerbs() {
		for _, unit := range units {
			line, err := SudoersLine("supermgmt", testSystemctl, verb, unit)
			if err != nil {
				t.Fatal(err)
			}
			setup := runtimes.SetupMeta{SystemctlPath: testSystemctl, Units: []runtimes.UnitGrant{{Unit: unit, Verbs: []domain.ServiceVerb{verb}}}}
			cmd, err := New().Mutate(runtimes.ServiceRef{Kind: domain.ServiceSystemdUnit, NativeID: unit}, verb, "m1", setup)
			if err != nil {
				t.Fatal(err)
			}
			argv := argvOf(t, cmd.Line)
			if argv[0] != "-n" {
				t.Fatalf("argv = %q", argv)
			}
			granted := strings.TrimPrefix(line, "supermgmt ALL=(root) NOPASSWD: ")
			if executed := strings.Join(argv[1:], " "); executed != granted {
				t.Errorf("executed %q, granted %q", executed, granted)
			}
		}
	}
}

func TestSudoersGrammarRejectsMetacharacters(t *testing.T) {
	for _, bad := range []string{
		"a,b.service", "a:b.service", "a=b.service", `a\x2db.service`, "a#b.service", "a!b.service", "a b.service",
		"a\tb.service", "a\nb.service", "a*.service", "a(b).service", "a\"b.service", "-a.service", ".a.service",
		"a.service ", "a.timer", "a.service\n", "",
	} {
		if _, err := SudoersLine("supermgmt", testSystemctl, domain.VerbRestart, bad); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("unit %q: got %v, want CAPABILITY_UNAVAILABLE", bad, err)
		}
	}
	for _, user := range []string{"", "Super", "a b", "a,b", "a:b", "1abc", "-x", strings.Repeat("a", 33), "a\nb", "a=b"} {
		if _, err := SudoersLine(user, testSystemctl, domain.VerbRestart, "x.service"); err == nil {
			t.Errorf("user %q accepted", user)
		}
	}
	for _, path := range []string{"", "systemctl", "/usr/bin/systemctl ", "/usr/../bin/systemctl", "/usr/bin/./systemctl", "/usr/bin/sudo", "/usr/b in/systemctl", "/usr/bin/systemctl,x", "/usr/bin/systemctl\n"} {
		if _, err := SudoersLine("supermgmt", path, domain.VerbRestart, "x.service"); err == nil {
			t.Errorf("systemctl path %q accepted", path)
		}
	}
	if _, err := SudoersLine("supermgmt", testSystemctl, "reload", "x.service"); err == nil {
		t.Error("verb reload accepted")
	}
}

func TestSudoersIsCanonicalAndHasNoWildcards(t *testing.T) {
	grants := []runtimes.UnitGrant{
		{Unit: "b.service", Verbs: []domain.ServiceVerb{domain.VerbRestart, domain.VerbStart}},
		{Unit: "a.service", Verbs: []domain.ServiceVerb{domain.VerbStop}},
		{Unit: "b.service", Verbs: []domain.ServiceVerb{domain.VerbStart}},
	}
	got, err := Sudoers("supermgmt", testSystemctl, grants, runtimes.LogsBroker)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Managed by SuperMgmt (node.setup). Changes are overwritten.\n" +
		"supermgmt ALL=(root) NOPASSWD: /usr/bin/systemctl stop a.service\n" +
		"supermgmt ALL=(root) NOPASSWD: /usr/bin/systemctl start b.service\n" +
		"supermgmt ALL=(root) NOPASSWD: /usr/bin/systemctl restart b.service\n" +
		"supermgmt ALL=(root) NOPASSWD: /usr/local/libexec/supermgmt/unit-logs\n"
	if got != want {
		t.Errorf("sudoers:\n%s\nwant:\n%s", got, want)
	}
	if strings.ContainsAny(strings.ReplaceAll(got, "ALL=(root)", ""), "*?[]") {
		t.Error("sudoers contains a wildcard")
	}
	journal, _ := Sudoers("supermgmt", testSystemctl, grants, runtimes.LogsJournalGroup)
	if strings.Contains(journal, "unit-logs") || strings.Contains(journal, "journalctl") {
		t.Error("journal-group mode must grant no log command")
	}
}

func TestSudoersRejectsAnIneligibleGrant(t *testing.T) {
	_, err := Sudoers("supermgmt", testSystemctl, []runtimes.UnitGrant{{Unit: "x.service; ALL", Verbs: []domain.ServiceVerb{domain.VerbStart}}}, runtimes.LogsJournalGroup)
	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Fatalf("got %v", err)
	}
}

func TestAuthorizedKeysIsOneRestrictedLine(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbc"
	got, err := AuthorizedKeys("supermgmt", key+"\n", "0190a5e2-7c41")
	if err != nil {
		t.Fatal(err)
	}
	if want := "restrict " + key + " supermgmt@0190a5e2-7c41\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, bad := range []string{"", "ssh-ed25519", key + " extra", "command=\"x\" " + key, key + "\nssh-rsa AAAA", "ssh-ed25519 AA AA"} {
		if _, err := AuthorizedKeys("supermgmt", bad, "i1"); err == nil {
			t.Errorf("key %q accepted", bad)
		}
	}
	if _, err := AuthorizedKeys("supermgmt", key, "i 1"); err == nil {
		t.Error("instance id with a space accepted")
	}
}

func TestTmpfilesAndAllowedUnits(t *testing.T) {
	if got, _ := Tmpfiles("supermgmt"); got != "d /run/supermgmt/locks 0700 supermgmt supermgmt -\n" {
		t.Errorf("tmpfiles = %q", got)
	}
	got, err := AllowedUnits([]runtimes.UnitGrant{{Unit: "b.service"}, {Unit: "a.service"}})
	if err != nil || got != "a.service\nb.service\n" {
		t.Errorf("allowed-units = %q, %v", got, err)
	}
}

func TestBrokerScriptIsValidShellAndPinsItsInputs(t *testing.T) {
	if out, err := exec.CommandContext(context.Background(), "/bin/sh", "-n", "-c", BrokerScript).CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v\n%s", err, out)
	}
	for _, must := range []string{`"$#" -eq 2`, "-le 10000", "grep -qxF -- \"$unit\" " + templates.BrokerUnitsPath, "env -i", "--no-pager", "PAGER=cat"} {
		if !strings.Contains(BrokerScript, must) {
			t.Errorf("broker script lacks %q", must)
		}
	}
}
