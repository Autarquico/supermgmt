package health

import (
	"net/netip"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments/compose"
)

func validateAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func validatePort(addr string, port uint16) compose.HostPort {
	return compose.HostPort{Service: "web", Addr: validateAddr(addr), Port: port, Proto: "tcp"}
}

func validateCheck(origin Origin, typ string, port uint16) Check {
	return Check{Origin: origin, Type: typ, Scope: ScopeNode, Port: port, Path: "/healthz", Timeout: 5 * time.Second, Interval: time.Second, Attempts: 3}
}

func TestHealthValidate_ManifestVsControlPlaneOrigin(t *testing.T) {
	lan := validateAddr("10.0.0.5")
	onLAN := []compose.HostPort{validatePort("10.0.0.5", 8080)}

	if _, err := ValidateManifest(validateCheck(OriginManifest, TypeHTTP, 8080), onLAN); err == nil {
		t.Fatal("manifest check accepted a port published only on a non-loopback binding")
	}
	d, err := ValidateControlPlane(validateCheck(OriginControlPlane, TypeHTTP, 8080), onLAN, []netip.Addr{lan})
	if err != nil || d.Addr != lan || d.Port != 8080 {
		t.Fatalf("control-plane check on an allowed bind address = %v, %v", d, err)
	}
	if _, err := ValidateControlPlane(validateCheck(OriginControlPlane, TypeHTTP, 8080), onLAN, nil); err == nil {
		t.Fatal("control-plane check accepted an address outside allowed_bind_addresses")
	}
}

func TestHealthValidate_OriginMustMatchEntryPoint(t *testing.T) {
	ports := []compose.HostPort{validatePort("127.0.0.1", 8080)}
	if _, err := ValidateManifest(validateCheck(OriginControlPlane, TypeHTTP, 8080), ports); err == nil {
		t.Error("ValidateManifest accepted a control_plane origin")
	}
	if _, err := ValidateControlPlane(validateCheck(OriginManifest, TypeHTTP, 8080), ports, nil); err == nil {
		t.Error("ValidateControlPlane accepted a manifest origin")
	}
}

func TestHealthValidate_DestinationComesFromPublishedPort(t *testing.T) {
	tests := []struct {
		name    string
		port    uint16
		ports   []compose.HostPort
		want    string
		wantErr bool
	}{
		{"ipv4 loopback", 8080, []compose.HostPort{validatePort("127.0.0.1", 8080)}, "127.0.0.1", false},
		{"ipv6 loopback", 8080, []compose.HostPort{validatePort("::1", 8080)}, "::1", false},
		{"first matching in model order", 8080, []compose.HostPort{validatePort("::1", 8080), validatePort("127.0.0.1", 8080)}, "::1", false},
		{"unrelated loopback service port", 9999, []compose.HostPort{validatePort("127.0.0.1", 8080)}, "", true},
		{"wildcard binding is not loopback", 8080, []compose.HostPort{validatePort("0.0.0.0", 8080)}, "", true},
		{"udp publication does not count", 8080, []compose.HostPort{{Addr: validateAddr("127.0.0.1"), Port: 8080, Proto: "udp"}}, "", true},
		{"nothing published", 8080, nil, "", true},
		{"port zero", 0, []compose.HostPort{validatePort("127.0.0.1", 0)}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := ValidateManifest(validateCheck(OriginManifest, TypeTCP, tt.port), tt.ports)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && d.Addr.String() != tt.want {
				t.Fatalf("addr = %s, want %s", d.Addr, tt.want)
			}
		})
	}
}

func TestHealthValidate_RejectsUnsafeManifestFields(t *testing.T) {
	ports := []compose.HostPort{validatePort("127.0.0.1", 8080)}
	tests := []struct {
		name   string
		mutate func(*Check)
	}{
		{"url in manifest", func(c *Check) { c.URL = "http://169.254.169.254/" }},
		{"hostname as path", func(c *Check) { c.Path = "//evil.example?" }},
		{"query", func(c *Check) { c.Path = "/health?x=1" }},
		{"fragment", func(c *Check) { c.Path = "/health#top" }},
		{"userinfo", func(c *Check) { c.Path = "/u@host" }},
		{"space", func(c *Check) { c.Path = "/a b" }},
		{"newline", func(c *Check) { c.Path = "/a\nb" }},
		{"quote", func(c *Check) { c.Path = "/a'b" }},
		{"relative path", func(c *Check) { c.Path = "health" }},
		{"empty path", func(c *Check) { c.Path = "" }},
		{"control_plane scope", func(c *Check) { c.Scope = ScopeControlPlane }},
		{"https type", func(c *Check) { c.Type = TypeHTTPS }},
		{"command-template type", func(c *Check) { c.Type = "command-template" }},
		{"systemd-active type", func(c *Check) { c.Type = "systemd-active" }},
		{"zero timeout", func(c *Check) { c.Timeout = 0 }},
		{"sub-second timeout", func(c *Check) { c.Timeout = 1500 * time.Millisecond }},
		{"timeout over 60s", func(c *Check) { c.Timeout = 61 * time.Second }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validateCheck(OriginManifest, TypeHTTP, 8080)
			tt.mutate(&c)
			if _, err := ValidateManifest(c, ports); err == nil {
				t.Fatalf("accepted %+v", c)
			}
		})
	}
}

func TestHealthValidate_DockerHealthNeedsNoPort(t *testing.T) {
	c := validateCheck(OriginManifest, TypeDockerHealth, 0)
	d, err := ValidateManifest(c, nil)
	if err != nil || d.Addr.IsValid() {
		t.Fatalf("docker-health = %v, %v", d, err)
	}
}

func TestHealthValidate_ControlPlaneScopeURL(t *testing.T) {
	tests := []struct {
		name    string
		typ     string
		url     string
		wantErr bool
	}{
		{"http", TypeHTTP, "http://app.lan:8080/health", false},
		{"https", TypeHTTPS, "https://app.example.com/health", false},
		{"scheme/type mismatch", TypeHTTPS, "http://app.lan/", true},
		{"file scheme", TypeHTTP, "file:///etc/passwd", true},
		{"userinfo", TypeHTTP, "http://u:p@app.lan/", true},
		{"query", TypeHTTP, "http://app.lan/?a=1", true},
		{"empty query marker", TypeHTTP, "http://app.lan/?", true},
		{"fragment", TypeHTTP, "http://app.lan/#x", true},
		{"no host", TypeHTTP, "http:///health", true},
		{"bad port", TypeHTTP, "http://app.lan:99999/", true},
		{"tcp type", TypeTCP, "http://app.lan/", true},
		{"empty url", TypeHTTP, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Check{Origin: OriginControlPlane, Type: tt.typ, Scope: ScopeControlPlane, URL: tt.url, Timeout: 5 * time.Second}
			_, err := ValidateControlPlane(c, nil, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
