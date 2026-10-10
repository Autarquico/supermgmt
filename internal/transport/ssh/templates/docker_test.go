package templates

import (
	"strings"
	"testing"
)

func TestDockerActionsAreMarkerWrappedAndPutDoubleDashFirst(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		c, err := RenderMutating("docker."+verb, "0190-m1", map[string]string{"container": "sm-demo-web"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(c.Line, "timeout --kill-after=10s 120s docker "+verb+" -- 'sm-demo-web'; rc=$?") {
			t.Errorf("%s line = %s", verb, c.Line)
		}
	}
}

func TestContainerGrammarRejectsInjectionAndOptions(t *testing.T) {
	for _, ok := range []string{"web", "sm-demo-web", "a_b.c-1", strings.Repeat("a", 64)} {
		if err := ValidateContainer(ok); err != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-rm", "a b", "a;b", "$(id)", "`id`", "a/b", "a:b", "a\nb", "a'b", "--all"} {
		if _, err := Render("docker.inspect", map[string]string{"container": bad}); err == nil {
			t.Errorf("container %q accepted", bad)
		}
		if _, err := RenderMutating("docker.stop", "m1", map[string]string{"container": bad}); err == nil {
			t.Errorf("container %q accepted for stop", bad)
		}
	}
}

func TestDockerTemplatesAvoidGoTemplateSyntax(t *testing.T) {
	all, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range all {
		if strings.HasPrefix(tpl.Name, "docker.") && strings.Contains(tpl.Body, "--format") {
			t.Errorf("%s uses --format, which needs the reserved double-brace sequence", tpl.Name)
		}
	}
}

func TestDockerLogsMergeStreamsAndBoundLines(t *testing.T) {
	c, err := Render("docker.logs", map[string]string{"container": "web", "lines": "100"})
	if err != nil || c.Line != "docker logs --timestamps --tail '100' -- 'web' 2>&1" {
		t.Errorf("line = %q, %v", c.Line, err)
	}
	if _, err := Render("docker.logs", map[string]string{"container": "web", "lines": "10001"}); err == nil {
		t.Error("10001 lines accepted")
	}
}
