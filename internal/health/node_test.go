package health

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func nodeCheck(typ string) Check {
	return Check{Origin: OriginManifest, Type: typ, Scope: ScopeNode, Path: "/healthz", Timeout: 5 * time.Second}
}

func nodeDestination(addr string) Destination {
	return Destination{Addr: netip.MustParseAddr(addr), Port: 8080}
}

func TestNodeInvocation_RendersThroughTheTemplateCatalog(t *testing.T) {
	tests := []struct {
		name      string
		check     Check
		dest      Destination
		template  string
		container string
		wantIn    string
	}{
		{"http ipv4", nodeCheck(TypeHTTP), nodeDestination("127.0.0.1"), "health.http", "", "/healthz"},
		{"http ipv6", nodeCheck(TypeHTTP), nodeDestination("::1"), "health.http", "", "::1"},
		{"tcp", nodeCheck(TypeTCP), nodeDestination("127.0.0.1"), "health.tcp", "", "/dev/tcp"},
		{"docker-health", nodeCheck(TypeDockerHealth), Destination{}, "health.docker", "web-1", "docker inspect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, args, err := NodeInvocation(tt.check, tt.dest)
			if err != nil || name != tt.template {
				t.Fatalf("NodeInvocation = %q, %v; want %q", name, err, tt.template)
			}
			if tt.container != "" {
				args["container"] = tt.container
			}
			cmd, err := templates.Render(name, args)
			if err != nil {
				t.Fatalf("catalog refused the invocation: %v", err)
			}
			if !strings.Contains(cmd.Line, tt.wantIn) {
				t.Fatalf("rendered %q lacks %q", cmd.Line, tt.wantIn)
			}
		})
	}
}

func TestNodeInvocation_Refusals(t *testing.T) {
	cp := nodeCheck(TypeHTTP)
	cp.Scope = ScopeControlPlane
	noTimeout := nodeCheck(TypeTCP)
	noTimeout.Timeout = 0

	tests := []struct {
		name  string
		check Check
		dest  Destination
	}{
		{"control_plane scope", cp, nodeDestination("127.0.0.1")},
		{"missing destination", nodeCheck(TypeTCP), Destination{}},
		{"timeout out of range", noTimeout, nodeDestination("127.0.0.1")},
		{"unknown type", nodeCheck("systemd-active"), nodeDestination("127.0.0.1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := NodeInvocation(tt.check, tt.dest); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNodeInvocation_CatalogRejectsUnvalidatedPath(t *testing.T) {
	c := nodeCheck(TypeHTTP)
	c.Path = "/a;rm -rf /"
	_, args, err := NodeInvocation(c, nodeDestination("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := templates.Render("health.http", args); err == nil {
		t.Fatal("template catalog accepted a hostile path")
	}
}
