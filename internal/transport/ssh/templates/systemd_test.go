package templates

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestUnitGrammarRejectsEverythingSudoersOrTheShellCouldReadAsSyntax(t *testing.T) {
	for _, ok := range []string{"nginx.service", "foo@bar.service", "a-b_c.d.service", "A1.service", "getty@tty1.service"} {
		if err := ValidateUnit(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "nginx", "nginx.timer", "-x.service", ".x.service", "a b.service", "a\tb.service", "a\nb.service", "a,b.service",
		"a:b.service", "a=b.service", `a\x2db.service`, "a#b.service", "a!b.service", "a*.service", "a;b.service", "a$(id).service",
		"a'b.service", `a"b.service`, "a|b.service", "a&b.service", "a(b).service", "ünï.service", "x.service\n", "x.service ",
	} {
		if err := ValidateUnit(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSystemdActionsAreSudoTemplatesWithTheFixedShape(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		c, err := RenderMutating("systemd."+verb, "m1", map[string]string{"systemctl": "/usr/bin/systemctl", "unit": "foo@bar.service"})
		if err != nil {
			t.Fatal(err)
		}
		want := "timeout --kill-after=10s 120s sudo -n '/usr/bin/systemctl' " + verb + " 'foo@bar.service'; "
		if !strings.Contains(c.Line, want) || strings.Contains(c.Line, " -- ") {
			t.Errorf("%s line = %s", verb, c.Line)
		}
		if _, err := Render("systemd."+verb, map[string]string{"systemctl": "/usr/bin/systemctl", "unit": "x.service"}); err == nil {
			t.Errorf("%s rendered without the marker wrapper", verb)
		}
	}
	for _, bad := range map[string]string{"relative": "systemctl", "other binary": "/usr/bin/sudo", "dot segment": "/usr/../bin/systemctl", "space": "/usr/bin /systemctl"} {
		if _, err := RenderMutating("systemd.restart", "m1", map[string]string{"systemctl": bad, "unit": "x.service"}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("systemctl %q: %v", bad, err)
		}
	}
}

func TestSystemdReadsDisablePagersAndOrderTheUnitAfterDoubleDash(t *testing.T) {
	for _, name := range []string{"systemd.list_units", "systemd.list_jobs", "systemd.show", "systemd.trust_show", "systemd.logs_group"} {
		args := map[string]string{}
		if strings.HasSuffix(name, "show") || strings.HasSuffix(name, "logs_group") {
			args["unit"] = "x.service"
		}
		if strings.HasSuffix(name, "logs_group") {
			args["lines"] = "100"
		}
		c, err := Render(name, args)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(c.Line, "SYSTEMD_PAGER= PAGER=cat ") || !strings.Contains(c.Line, "--no-pager") {
			t.Errorf("%s does not disable pagers: %s", name, c.Line)
		}
		if strings.HasSuffix(name, "show") && !strings.Contains(c.Line, " -- 'x.service'") {
			t.Errorf("%s lacks '--' before the unit: %s", name, c.Line)
		}
	}
}

func TestTrustShowReadsExactlyTheSpecProperties(t *testing.T) {
	c, err := Render("systemd.trust_show", map[string]string{"unit": "x.service"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"FragmentPath", "DropInPaths", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "EnvironmentFiles", "WorkingDirectory", "User"} {
		if !strings.Contains(c.Line, p) {
			t.Errorf("property %s not read", p)
		}
	}
}

func TestLogLinesAreBounded(t *testing.T) {
	for _, lines := range []string{"1", "10000", "250"} {
		if _, err := Render("systemd.logs_group", map[string]string{"unit": "x.service", "lines": lines}); err != nil {
			t.Errorf("lines %s: %v", lines, err)
		}
	}
	for _, lines := range []string{"0", "10001", "-1", "1e3", "01", "a", "1; reboot", " 5"} {
		if _, err := Render("systemd.logs_group", map[string]string{"unit": "x.service", "lines": lines}); err == nil {
			t.Errorf("lines %q accepted", lines)
		}
	}
	c, err := Render("systemd.logs_broker", map[string]string{"unit": "x.service", "lines": "10"})
	if err != nil || c.Line != "sudo -n /usr/local/libexec/supermgmt/unit-logs 'x.service' '10'" {
		t.Errorf("broker = %q, %v", c.Line, err)
	}
}

func TestPathChainRunsAndReportsOwnerModeAndParents(t *testing.T) {
	c, err := Render("systemd.path_chain", map[string]string{"path": "/etc/hosts"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(context.Background(), "/bin/sh", "-c", c.Line).Output()
	if err != nil {
		t.Skipf("GNU stat or readlink -f unavailable on this host: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 3 || !strings.HasSuffix(lines[0], " /etc/hosts") || !strings.HasSuffix(lines[len(lines)-1], " /") {
		t.Errorf("chain = %q", lines)
	}
}

func TestPathParametersRefuseShellAndSpecifierSyntax(t *testing.T) {
	for _, bad := range []string{"relative/path", "/etc/a b", "/etc/%n", "/etc/$HOME", "/etc/a;b", "/etc/`id`", "/etc/a'b", "/", "//etc", "/etc/", "-/etc/x"} {
		if _, err := Render("systemd.file_magic", map[string]string{"path": bad}); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
}
