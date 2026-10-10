//go:build fixtures

package integration

import (
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const systemctlPath = "/usr/bin/systemctl"

// visudoAccepts runs the node's own `visudo -cf` over content.
func visudoAccepts(t *testing.T, n *fixtureNode, content string) bool {
	t.Helper()
	script := "f=$(mktemp) && printf '%s' " + templates.Quote(content) + " > $f && chmod 0440 $f && visudo -cf $f"
	_, err := n.tryShell(t, script)
	return err == nil
}

func TestFixturesSudoers_EveryGrantedLineIsAcceptedByVisudo(t *testing.T) {
	n := startNode(t, fixture.Options{})
	unitsUnderTest := []string{demoUnit, "foo@bar.service", "docker.service", "a.b-c_d.service", "x@y.z-w.service"}

	for _, unit := range unitsUnderTest {
		for _, verb := range domain.AllServiceVerbs() {
			line, err := systemd.SudoersLine(dedicatedUser, systemctlPath, verb, unit)
			if err != nil {
				t.Errorf("render %s %s: %v", verb, unit, err)
				continue
			}
			if !visudoAccepts(t, n, line+"\n") {
				t.Errorf("visudo -cf rejects %q", line)
			}
		}
	}

	t.Run("the whole rendered drop-in, in both log modes", func(t *testing.T) {
		grants := make([]runtimes.UnitGrant, 0, len(unitsUnderTest))
		for _, unit := range unitsUnderTest {
			grants = append(grants, runtimes.UnitGrant{Unit: unit, Verbs: domain.AllServiceVerbs()})
		}
		for _, mode := range []runtimes.LogsMode{runtimes.LogsJournalGroup, runtimes.LogsBroker} {
			file, err := systemd.Sudoers(dedicatedUser, systemctlPath, grants, mode)
			if err != nil {
				t.Fatalf("render %s: %v", mode, err)
			}
			if !visudoAccepts(t, n, file) {
				t.Errorf("visudo -cf rejects the %s drop-in:\n%s", mode, file)
			}
			if lines := strings.Count(file, "NOPASSWD:"); lines < len(unitsUnderTest)*3 {
				t.Errorf("%s drop-in has %d grants; want one per unit and verb", mode, lines)
			}
		}
	})

	t.Run("visudo is a real gate on this node", func(t *testing.T) {
		if visudoAccepts(t, n, "supermgmt ALL=(root NOPASSWD: "+systemctlPath+" restart x.service\n") {
			t.Error("visudo accepted a malformed line; the check proves nothing")
		}
	})
}

func TestFixturesSudoers_MetacharactersCannotReachTheFile(t *testing.T) {
	n := startNode(t, fixture.Options{})

	t.Run("visudo alone would accept a comma-injected extra command", func(t *testing.T) {
		injected := "supermgmt ALL=(root) NOPASSWD: " + systemctlPath + " restart a.service, /bin/sh\n"
		if !visudoAccepts(t, n, injected) {
			t.Skip("visudo rejects the injection by itself on this sudo version; the renderer tests below still apply")
		}
		t.Log("visudo accepts the injected line: the renderer's allowlist is the only guard")
	})

	metacharacters := []string{",", ":", "=", "\\", "#", "!", " ", "\t", "\n", "\x00", "*", "?", "[", "]", "(", ")", ";", "|", "&", "$", "`", "\"", "'", "<", ">", "%", "~", "{", "}"}
	for _, m := range metacharacters {
		unit := "a" + m + "b.service"
		if line, err := systemd.SudoersLine(dedicatedUser, systemctlPath, domain.VerbRestart, unit); err == nil {
			t.Errorf("unit %q rendered %q", unit, line)
		}
		user := "sm" + m + "x"
		if line, err := systemd.SudoersLine(user, systemctlPath, domain.VerbRestart, demoUnit); err == nil {
			t.Errorf("user %q rendered %q", user, line)
		}
		path := "/usr/bin/system" + m + "ctl"
		if line, err := systemd.SudoersLine(dedicatedUser, path, domain.VerbRestart, demoUnit); err == nil {
			t.Errorf("systemctl path %q rendered %q", path, line)
		}
	}

	t.Run("units that need escapes or start with a dash are not eligible", func(t *testing.T) {
		for _, unit := range []string{"-x.service", "foo\\x2dbar.service", "a:b.service", "x.timer", "x.service ", "x", ".service", "../x.service", "a/b.service"} {
			if line, err := systemd.SudoersLine(dedicatedUser, systemctlPath, domain.VerbStart, unit); err == nil {
				t.Errorf("unit %q rendered %q", unit, line)
			}
		}
	})

	t.Run("verbs outside start, stop and restart are not rendered", func(t *testing.T) {
		for _, verb := range []domain.ServiceVerb{"reload", "enable", "mask", "restart ALL", "kill", "daemon-reload", ""} {
			if line, err := systemd.SudoersLine(dedicatedUser, systemctlPath, verb, demoUnit); err == nil {
				t.Errorf("verb %q rendered %q", verb, line)
			}
		}
	})

	t.Run("the executed argv carries exactly the granted words", func(t *testing.T) {
		meta := runtimes.SetupMeta{
			SystemctlPath: systemctlPath, LogsMode: runtimes.LogsJournalGroup,
			Units: []runtimes.UnitGrant{{Unit: "foo@bar.service", Verbs: domain.AllServiceVerbs()}},
		}
		for _, verb := range domain.AllServiceVerbs() {
			cmd, err := systemd.New().Mutate(unitRefOf("foo@bar.service"), verb, "t9a-argv", meta)
			if err != nil {
				t.Fatalf("mutate %s: %v", verb, err)
			}
			want := "sudo -n " + templates.Quote(systemctlPath) + " " + string(verb) + " " + templates.Quote("foo@bar.service")
			if !strings.Contains(cmd.Line, want) {
				t.Errorf("%s command line %q does not contain the sudoers words %q (quoted)", verb, cmd.Line, want)
			}
			if strings.Contains(cmd.Line, " -- ") {
				t.Errorf("%s command line %q uses `--`, which would not match the sudoers line", verb, cmd.Line)
			}
		}
	})
}

func unitRefOf(unit string) runtimes.ServiceRef {
	return runtimes.ServiceRef{Kind: domain.ServiceSystemdUnit, NativeID: unit, Name: unit}
}
