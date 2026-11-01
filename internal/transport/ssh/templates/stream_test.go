package templates

import (
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestStreamTemplatesRenderTheirGoldenLines(t *testing.T) {
	args := map[string]string{"container": "sm-shop-prod-web-1", "mount": "/var/lib/data", "deadline": "600s"}
	tests := map[string]struct {
		line    string
		kind    StreamKind
		mutates bool
	}{
		"docker.volume_export": {"timeout -k 10s '600s' docker cp 'sm-shop-prod-web-1':'/var/lib/data'/. -", StreamExport, false},
		"docker.volume_import": {"timeout -k 10s '600s' docker cp - 'sm-shop-prod-web-1':'/var/lib/data'", StreamImport, true},
	}
	for name, want := range tests {
		c, err := RenderStream(name, args)
		if err != nil {
			t.Fatal(err)
		}
		if c.Line != want.line || c.Stream != want.kind || c.Mutating != want.mutates || c.Deadline != 10*time.Minute {
			t.Errorf("%s = %+v", name, c)
		}
		if strings.Contains(c.Line, MarkerDir) {
			t.Errorf("%s is inside the marker wrapper", name)
		}
	}
}

func TestStreamTemplatesRenderOnlyThroughRenderStream(t *testing.T) {
	args := map[string]string{"container": "web", "mount": "/data", "deadline": "60s"}
	attempts := map[string]func() error{
		"Render":           func() error { _, err := Render("docker.volume_export", args); return err },
		"RenderMutating":   func() error { _, err := RenderMutating("docker.volume_import", "m1", args); return err },
		"RenderSetup":      func() error { _, err := RenderSetup("docker.volume_import", args, nil); return err },
		"stream of a read": func() error { _, err := RenderStream("compose.ps", deployArgs("/srv/supermgmt")); return err },
		"stream of a mutation": func() error {
			_, err := RenderStream("docker.stop", map[string]string{"container": "web"})
			return err
		},
	}
	for name, attempt := range attempts {
		if err := attempt(); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: got %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestStreamParametersRejectInjectionAndBadDeadlines(t *testing.T) {
	valid := map[string]string{"container": "web", "mount": "/data/app", "deadline": "60s"}
	for _, name := range []string{"docker.volume_export", "docker.volume_import"} {
		if _, err := RenderStream(name, valid); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for param := range valid {
			for _, payload := range injectionPayloads {
				args := map[string]string{"container": "web", "mount": "/data/app", "deadline": "60s"}
				args[param] = payload
				if _, err := RenderStream(name, args); err == nil {
					t.Errorf("%s: %s accepted %q", name, param, payload)
				}
			}
		}
		for _, mount := range []string{"data", "/data/../etc", "/data/./x", "//data", "/data/"} {
			args := map[string]string{"container": "web", "mount": mount, "deadline": "60s"}
			if _, err := RenderStream(name, args); err == nil {
				t.Errorf("%s: mount %q accepted", name, mount)
			}
		}
		for _, deadline := range []string{"0s", "60", "60m", "1.5s", "086400s", "86401s", "1000000s", "-5s"} {
			args := map[string]string{"container": "web", "mount": "/data", "deadline": deadline}
			if _, err := RenderStream(name, args); err == nil {
				t.Errorf("%s: deadline %q accepted", name, deadline)
			}
		}
	}
	if _, err := RenderStream("docker.volume_export", map[string]string{"container": "web", "mount": "/", "deadline": DeadlineArg(24 * time.Hour)}); err != nil {
		t.Errorf("root mount with the longest deadline: %v", err)
	}
}

func TestAStreamingTemplateMustRunUnderTimeout(t *testing.T) {
	bad := []Template{
		{Name: "s", Body: "docker cp - x:/y", Stream: StreamImport, MaxBytes: 1},
		{Name: "s", Body: "timeout 1s true", Stream: StreamImport, Mutating: true, Deadline: time.Second, MaxBytes: 1},
		{Name: "s", Body: "timeout 1s true", Stream: StreamImport, Deadline: time.Second, MaxBytes: 1},
	}
	for _, tpl := range bad {
		if _, err := newRegistry([]Template{tpl}); smerr.CodeOf(err) != smerr.CodeInternal {
			t.Errorf("%+v: got %v, want an INTERNAL catalog error", tpl, err)
		}
	}
}

func TestVolumeRmAndInspectTemplates(t *testing.T) {
	c, err := RenderMutating("docker.volume_rm", "m1", map[string]string{"volume": "sm-shop-prod_data"})
	if err != nil || !strings.Contains(c.Line, "docker volume rm -- 'sm-shop-prod_data'; rc=$?") {
		t.Fatalf("volume_rm = %q, %v", c.Line, err)
	}
	if strings.Contains(c.Line, "volume rm -f") || strings.Contains(c.Line, "--force") {
		t.Error("volume_rm forces")
	}
	for _, bad := range append([]string{"a/b", "a:b"}, injectionPayloads...) {
		if _, err := RenderMutating("docker.volume_rm", "m1", map[string]string{"volume": bad}); err == nil {
			t.Errorf("volume %q accepted", bad)
		}
	}

	many := map[string]string{"volumes": "p_a,p_b"}
	if _, err := Render("docker.volume_inspect_many", many); err != nil {
		t.Fatal(err)
	}
	names := make([]string, MaxInspectedVolumes+1)
	for i := range names {
		names[i] = "v"
	}
	for name, volumes := range map[string]string{
		"empty element": "a,,b", "trailing comma": "a,", "too many": strings.Join(names, ","), "option": "a,-b", "injection": "a,$(id)",
	} {
		if _, err := Render("docker.volume_inspect_many", map[string]string{"volumes": volumes}); err == nil {
			t.Errorf("%s: %q accepted", name, volumes)
		}
	}
}

func TestInfoResourcesAndSizesAreReads(t *testing.T) {
	for _, name := range []string{"docker.info_resources", "docker.volume_sizes"} {
		c, err := Render(name, nil)
		if err != nil || c.Mutating || c.Stream != StreamNone {
			t.Errorf("%s = %+v, %v", name, c, err)
		}
	}
	c, _ := Render("docker.info_resources", nil)
	if strings.Contains(c.Line, "{{") {
		t.Errorf("the Go template braces must be escaped: %s", c.Line)
	}
}
