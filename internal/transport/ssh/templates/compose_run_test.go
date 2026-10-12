package templates

import (
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	testDir     = "'/srv/supermgmt'/'sm-shop-prod'/'" + testDeployment + "'"
	testProject = "sm-shop-prod"
)

func wantComposeLine(verb string) string {
	return "env -i PATH=/usr/local/bin:/usr/bin:/bin docker compose -f " + testDir + "/compose.yaml -p 'sm-shop-prod'" +
		" --project-directory " + testDir + " " + verb
}

func TestRunTemplatesRenderTheirGoldenLines(t *testing.T) {
	reads := map[string]string{
		"compose.ps":         wantComposeLine("ps --all --format json"),
		"compose.lock_probe": "flock --nonblock --conflict-exit-code 75 /run/supermgmt/locks/'sm-shop-prod'.lock true",
	}
	for name, want := range reads {
		args := deployArgs("/srv/supermgmt")
		if name == "compose.lock_probe" {
			args = map[string]string{"project": testProject}
		}
		c, err := Render(name, args)
		if err != nil || c.Line != want {
			t.Errorf("%s\n got %q (%v)\nwant %q", name, c.Line, err, want)
		}
	}
	locked := map[string]struct {
		verb     string
		deadline string
	}{
		"compose.up":   {"up --detach --pull never --no-build --remove-orphans", "600s"},
		"compose.down": {"down --remove-orphans", "300s"},
	}
	for name, tc := range locked {
		c, err := RenderMutatingInput(name, "m1", deployArgs("/srv/supermgmt"), nil, testProject)
		if err != nil {
			t.Fatal(err)
		}
		m := MarkerDir + "/m1"
		marked := ": > " + m + " && { timeout --kill-after=10s " + tc.deadline + " " + wantComposeLine(tc.verb) + "; rc=$?; " +
			`printf '%d\n' "$rc" > ` + m + ".done.tmp && mv -f " + m + ".done.tmp " + m + `.done; exit "$rc"; }`
		want := "flock --nonblock --conflict-exit-code 75 '/run/supermgmt/locks/sm-shop-prod.lock' sh -c " + Quote(marked)
		if c.Line != want {
			t.Errorf("%s\n got %s\nwant %s", name, c.Line, want)
		}
	}
}

func TestFlockWrapsTheWholeMarkerCommand(t *testing.T) {
	c, err := RenderMutatingInput("compose.up", "m1", deployArgs("/srv/supermgmt"), nil, testProject)
	if err != nil {
		t.Fatal(err)
	}
	before, inner, found := strings.Cut(c.Line, " sh -c ")
	if !found || !strings.HasPrefix(before, "flock ") {
		t.Fatalf("line is not flock ... sh -c ...: %s", c.Line)
	}
	if strings.Contains(before, "m1") {
		t.Error("the marker is created outside the lock")
	}
	for _, part := range []string{": > " + MarkerDir + "/m1 ", "timeout --kill-after=10s", "m1.done"} {
		if !strings.Contains(inner, part) {
			t.Errorf("the locked command lacks %q", part)
		}
	}
	if !c.Mutating || c.Sensitive || len(c.Stdin) != 0 {
		t.Errorf("command = %+v", c)
	}
}

func TestRunTemplatesNeverRemoveVolumesRebuildOrPull(t *testing.T) {
	for _, name := range []string{"compose.up", "compose.down"} {
		c, err := RenderMutatingInput(name, "m1", deployArgs("/srv/supermgmt"), nil, testProject)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"--volumes", " -v ", "--build", "--force-recreate", "--rmi"} {
			if strings.Contains(c.Line, banned) {
				t.Errorf("%s contains %q", name, banned)
			}
		}
	}
	up, _ := RenderMutatingInput("compose.up", "m1", deployArgs("/srv/supermgmt"), nil, testProject)
	if !strings.Contains(up.Line, "--pull never --no-build") {
		t.Error("compose.up must neither pull nor build: images were pulled and bound beforehand")
	}
}

func TestInputRulesBindStdinAndLockToTheirTemplates(t *testing.T) {
	stdin := []byte("compose")
	args := deployArgs("/srv/supermgmt")
	tests := map[string]func() error{
		"locked template without a project":      func() error { _, err := RenderMutatingInput("compose.up", "m1", args, nil, ""); return err },
		"locked template through RenderMutating": func() error { _, err := RenderMutating("compose.up", "m1", args); return err },
		"locked template with stdin":             func() error { _, err := RenderMutatingInput("compose.up", "m1", args, stdin, testProject); return err },
		"locked template, invalid project":       func() error { _, err := RenderMutatingInput("compose.up", "m1", args, nil, "x;id"); return err },
		"sensitive template without stdin":       func() error { _, err := RenderMutatingInput("compose.materialize", "m1", args, nil, ""); return err },
		"sensitive template through RenderMutating": func() error {
			_, err := RenderMutating("compose.materialize", "m1", args)
			return err
		},
		"sensitive template with a project": func() error {
			_, err := RenderMutatingInput("compose.materialize", "m1", args, stdin, testProject)
			return err
		},
		"plain template with stdin": func() error {
			_, err := RenderMutatingInput("compose.pull", "m1", map[string]string{"image": "r/a@sha256:" + strings.Repeat("a", 64)}, stdin, "")
			return err
		},
		"plain template with a project": func() error {
			_, err := RenderMutatingInput("compose.pull", "m1", map[string]string{"image": "r/a@sha256:" + strings.Repeat("a", 64)}, nil, testProject)
			return err
		},
		"read-only template": func() error { _, err := RenderMutatingInput("compose.ps", "m1", args, nil, ""); return err },
	}
	for name, attempt := range tests {
		if err := attempt(); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: got %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestSensitiveAndLockedNeedAMutatingTemplate(t *testing.T) {
	for _, mutate := range []func(*Template){func(t *Template) { t.Sensitive = true }, func(t *Template) { t.Locked = true }} {
		tpl := Template{Name: "t", Body: "true", MaxBytes: 1}
		mutate(&tpl)
		if _, err := newRegistry([]Template{tpl}); smerr.CodeOf(err) != smerr.CodeInternal {
			t.Errorf("got %v, want an INTERNAL catalog error", err)
		}
	}
}

func TestEveryComposeCommandRunsUnderEnvDashI(t *testing.T) {
	all, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	underEnv := map[string]bool{
		"compose.up": true, "compose.down": true, "compose.ps": true, "compose.verify": true,
		"health.http": true, "health.tcp": true,
	}
	seen := 0
	for _, tpl := range all {
		runsCompose := strings.HasPrefix(tpl.Name, "compose.") && strings.Contains(tpl.Body, "docker compose")
		if runsCompose != (underEnv[tpl.Name] && strings.HasPrefix(tpl.Name, "compose.")) {
			t.Errorf("%s: update the list of templates that run docker compose", tpl.Name)
		}
		if !underEnv[tpl.Name] {
			continue
		}
		seen++
		if !strings.HasPrefix(tpl.Body, "env -i PATH=/") {
			t.Errorf("%s does not start with env -i and a fixed PATH: %.60s", tpl.Name, tpl.Body)
		}
	}
	if seen != len(underEnv) {
		t.Errorf("checked %d templates, want %d", seen, len(underEnv))
	}
}

func TestLockPathIsPerProject(t *testing.T) {
	if got := LockPath("sm-shop-prod"); got != "/run/supermgmt/locks/sm-shop-prod.lock" {
		t.Errorf("LockPath = %s", got)
	}
}
