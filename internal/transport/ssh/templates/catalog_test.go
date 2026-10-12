package templates

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func anyText(string) error { return nil }

var unitParam = Param{Name: "unit", Validate: Matching(regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]*\.service$`))}

func testRegistry(t *testing.T) registry {
	t.Helper()
	r, err := newRegistry(
		[]Template{{Name: "echo", Body: "printf '%s' {{text}}", Params: []Param{{Name: "text", Validate: anyText}}, MaxBytes: 1 << 10}},
		[]Template{{
			Name: "restart", Body: "sudo -n {{systemctl}} restart {{unit}}", Sudo: true, Mutating: true,
			Params:   []Param{{Name: "systemctl", Validate: Matching(regexp.MustCompile(`^/[a-z/]+$`))}, unitParam},
			Deadline: 2 * time.Minute, MaxBytes: 4096,
		}},
		[]Template{{Name: "install", Body: "install -m 0440 /dev/stdin {{path}}", Setup: true, Params: []Param{{Name: "path", Validate: anyText}}, MaxBytes: 4096}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTheShippedCatalogIsValid(t *testing.T) {
	if _, err := Templates(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogRejectsMalformedTemplates(t *testing.T) {
	read := func(mut func(*Template)) Template {
		tpl := Template{Name: "t", Body: "cat {{path}}", Params: []Param{{Name: "path", Validate: anyText}}, MaxBytes: 1}
		mut(&tpl)
		return tpl
	}
	tests := map[string][]Template{
		"duplicate name":              {read(func(*Template) {}), read(func(*Template) {})},
		"empty name":                  {read(func(t *Template) { t.Name = "" })},
		"mutating and setup":          {read(func(t *Template) { t.Mutating, t.Setup, t.Deadline = true, true, time.Second })},
		"mutating without deadline":   {read(func(t *Template) { t.Mutating = true })},
		"sudo without sudo -n prefix": {read(func(t *Template) { t.Sudo = true })},
		"sudo with --":                {read(func(t *Template) { t.Sudo, t.Body = true, "sudo -n /bin/systemctl restart -- {{path}}" })},
		"unbounded output":            {read(func(t *Template) { t.MaxBytes = 0 })},
		"negative line limit":         {read(func(t *Template) { t.MaxLines = -1 })},
		"undeclared placeholder":      {read(func(t *Template) { t.Body = "cat {{path}} {{other}}" })},
		"unused parameter":            {read(func(t *Template) { t.Body = "cat /etc/os-release" })},
		"parameter without validator": {read(func(t *Template) { t.Params[0].Validate = nil })},
		"duplicate parameter":         {read(func(t *Template) { t.Params = append(t.Params, t.Params[0]) })},
		"malformed placeholder":       {read(func(t *Template) { t.Body = "cat {{path}} {{Bad}}" })},
	}
	for name, group := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := newRegistry(group)
			if smerr.CodeOf(err) != smerr.CodeInternal {
				t.Fatalf("got %v, want an INTERNAL catalog error", err)
			}
		})
	}
}

// TestRenderedArgumentsReachTheShellVerbatim runs the rendered line through
// /bin/sh: whatever the payload, the command receives it as one argument.
func TestRenderedArgumentsReachTheShellVerbatim(t *testing.T) {
	r := testRegistry(t)
	payloads := []string{
		"plain", "it's", `'; rm -rf / #`, "$(id)", "`id`", "${HOME}", "a b\tc", "line\nbreak",
		`\'\\''`, "x;y|z&w>v<u", "*?[a]", "ünïcødé", "''", "'",
	}
	for _, payload := range payloads {
		c, err := r.render("echo", map[string]string{"text": payload})
		if err != nil {
			t.Fatalf("render %q: %v", payload, err)
		}
		out, err := exec.CommandContext(context.Background(), "/bin/sh", "-c", c.Line).Output()
		if err != nil {
			t.Fatalf("sh -c %q: %v", c.Line, err)
		}
		if string(out) != payload {
			t.Errorf("payload %q reached the command as %q (line %q)", payload, out, c.Line)
		}
	}
}

func TestRenderRejectsInadmissibleArguments(t *testing.T) {
	r := testRegistry(t)
	tests := map[string]map[string]string{
		"leading dash":     {"text": "-rf"},
		"empty":            {"text": ""},
		"NUL":              {"text": "a\x00b"},
		"invalid UTF-8":    {"text": "\xff"},
		"missing argument": {},
		"extra argument":   {"text": "a", "other": "b"},
		"renamed argument": {"txt": "a"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := r.render("echo", args); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Fatalf("got %v, want INVALID_ARGUMENT", err)
			}
		})
	}
}

func TestRenderRunsTheParameterValidator(t *testing.T) {
	r := testRegistry(t)
	for _, unit := range []string{"nginx.service; reboot", "a:b.service", `x\x2d.service`, "nginx"} {
		_, err := r.renderMutating("restart", "m1", map[string]string{"systemctl": "/usr/bin/systemctl", "unit": unit})
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("unit %q: got %v, want INVALID_ARGUMENT", unit, err)
		}
	}
}

func TestEachRenderFunctionAcceptsOnlyItsKind(t *testing.T) {
	r := testRegistry(t)
	restartArgs := map[string]string{"systemctl": "/usr/bin/systemctl", "unit": "nginx.service"}
	attempts := map[string]func() error{
		"Render(mutating)":        func() error { _, err := r.render("restart", restartArgs); return err },
		"Render(setup)":           func() error { _, err := r.render("install", map[string]string{"path": "/x"}); return err },
		"RenderMutating(read)":    func() error { _, err := r.renderMutating("echo", "m1", map[string]string{"text": "x"}); return err },
		"RenderMutating(setup)":   func() error { _, err := r.renderMutating("install", "m1", map[string]string{"path": "/x"}); return err },
		"RenderSetup(read)":       func() error { _, err := r.renderSetup("echo", map[string]string{"text": "x"}, nil); return err },
		"RenderSetup(mutating)":   func() error { _, err := r.renderSetup("restart", restartArgs, nil); return err },
		"unknown template":        func() error { _, err := r.render("nope", nil); return err },
		"Render on empty catalog": func() error { _, err := Render("nope", nil); return err },
	}
	for name, attempt := range attempts {
		if err := attempt(); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: got %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestRenderMutatingWrapsTheCommandInTheMarkerProtocol(t *testing.T) {
	r := testRegistry(t)
	c, err := r.renderMutating("restart", "0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88",
		map[string]string{"systemctl": "/usr/bin/systemctl", "unit": "foo@bar.service"})
	if err != nil {
		t.Fatal(err)
	}
	m := "/var/lib/supermgmt/markers/0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88"
	want := ": > " + m + " && { timeout --kill-after=10s 120s sudo -n '/usr/bin/systemctl' restart 'foo@bar.service'; " +
		`rc=$?; printf '%d\n' "$rc" > ` + m + ".done.tmp && mv -f " + m + ".done.tmp " + m + `.done; exit "$rc"; }`
	if c.Line != want {
		t.Errorf("line\n got %s\nwant %s", c.Line, want)
	}
	if !c.Mutating || c.Deadline != 2*time.Minute || c.MaxBytes != 4096 || c.Template != "restart" {
		t.Errorf("command metadata = %+v", c)
	}
}

func TestRenderMutatingRejectsUnsafeMarkers(t *testing.T) {
	r := testRegistry(t)
	args := map[string]string{"systemctl": "/usr/bin/systemctl", "unit": "nginx.service"}
	for _, marker := range []string{"", "../etc/passwd", "a b", "-x", "A", strings.Repeat("a", 65), "a;b"} {
		if _, err := r.renderMutating("restart", marker, args); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("marker %q: got %v, want INVALID_ARGUMENT", marker, err)
		}
	}
}

func TestRenderSetupCarriesStdinOffTheCommandLine(t *testing.T) {
	r := testRegistry(t)
	secret := []byte("restrict ssh-ed25519 AAAA supermgmt@instance\n")
	c, err := r.renderSetup("install", map[string]string{"path": "/etc/sudoers.d/supermgmt"}, secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Stdin) != string(secret) || strings.Contains(c.Line, "AAAA") || c.Mutating {
		t.Errorf("command = %+v", c)
	}
	if c.Line != "install -m 0440 /dev/stdin '/etc/sudoers.d/supermgmt'" {
		t.Errorf("line = %q", c.Line)
	}
}

func TestDeadlinesRoundUpToWholeSeconds(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Second: "1s", 1500 * time.Millisecond: "2s", 2 * time.Minute: "120s"} {
		if got := seconds(d); got != want {
			t.Errorf("seconds(%s) = %s, want %s", d, got, want)
		}
	}
}

func isDeploymentTemplate(name string) bool {
	return strings.HasPrefix(name, "compose.") || strings.HasPrefix(name, "health.") || name == "postgres-dump"
}

// deploymentTemplates are the M4 groups: every parameter of theirs is fuzzed.
func deploymentTemplates(t *testing.T) []Template {
	t.Helper()
	all, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	var out []Template
	for _, tpl := range all {
		if isDeploymentTemplate(tpl.Name) {
			out = append(out, tpl)
		}
	}
	return out
}

var validDeploymentArgs = map[string]string{
	"root": "/srv/supermgmt", "project": "sm-shop-prod", "deployment": testDeployment,
	"image": "ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64), "path": "/srv/x", "database": "app",
	"container": "db", "addr": "127.0.0.1", "port": "8080", "timeout": "3",
}

var injectionPayloads = []string{
	"x;id", "$(id)", "`id`", "a b", "a\nb", "a\rb", "a\tb", "a'b", `a"b`, "a|b", "a&b", "a>b", "a<b", "a*b", "a?b",
	`a\b`, "a{b}", "a(b)", "a!b", "a$b", "a#b", "a%b", "a=b", "a,b", "a[b]", "../x", "-rf", "--help", "", "a\x00b", "a\xffb",
	"${IFS}", "&&id", "||id", ";", "'", `\`, "x y", "ünï",
}

func validArgsOf(tpl Template) map[string]string {
	args := map[string]string{}
	for _, p := range tpl.Params {
		args[p.Name] = validDeploymentArgs[p.Name]
	}
	return args
}

func TestEveryDeploymentParameterRejectsInjectionPayloads(t *testing.T) {
	templates := deploymentTemplates(t)
	if len(templates) != 17 {
		t.Fatalf("only %d deployment templates found", len(templates))
	}
	for _, tpl := range templates {
		if _, err := tpl.bind(validArgsOf(tpl)); err != nil {
			t.Errorf("%s: the valid arguments were rejected: %v", tpl.Name, err)
		}
		for _, p := range tpl.Params {
			if _, known := validDeploymentArgs[p.Name]; !known {
				t.Fatalf("%s: no valid value known for parameter %q", tpl.Name, p.Name)
			}
			for _, payload := range injectionPayloads {
				args := validArgsOf(tpl)
				args[p.Name] = payload
				if _, err := tpl.bind(args); err == nil {
					t.Errorf("%s: parameter %s accepted %q", tpl.Name, p.Name, payload)
				}
			}
		}
	}
}

// FuzzDeploymentValidatorsAdmitNoShellMetacharacters: whatever a validator of
// the M4 groups accepts is made of characters that mean nothing to a shell.
func FuzzDeploymentValidatorsAdmitNoShellMetacharacters(f *testing.F) {
	for _, s := range injectionPayloads {
		f.Add(s)
	}
	for _, s := range validDeploymentArgs {
		f.Add(s)
	}
	f.Add("/health")
	f.Add("::1")
	safe := regexp.MustCompile(`^[A-Za-z0-9._:/@~-]*$`)
	all, err := Templates()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, tpl := range all {
			if !isDeploymentTemplate(tpl.Name) {
				continue
			}
			for _, p := range tpl.Params {
				if admissible(s) == nil && p.Validate(s) == nil && !safe.MatchString(s) {
					t.Fatalf("%s/%s accepted %q", tpl.Name, p.Name, s)
				}
			}
		}
	})
}
