package client_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const proxyOption = "ProxyCommand="

func proxyOf(t *testing.T, argv []string) string {
	t.Helper()
	for i, a := range argv {
		if i > 0 && argv[i-1] == "-o" && strings.HasPrefix(a, proxyOption) {
			return strings.TrimPrefix(a, proxyOption)
		}
	}
	t.Fatalf("no ProxyCommand in %q", argv)
	return ""
}

func tunnelInfo(t *testing.T) wire.ConnectInfo {
	info := connectInfo(t)
	info.Transport, info.TunnelHostname = domain.TransportCloudflare, "ssh-web1.example.com"
	return info
}

func TestInteractiveCommandCloudflareOnlyChangesTheProxyCommand(t *testing.T) {
	direct := connectInfo(t)
	tunnel := direct
	tunnel.Transport, tunnel.TunnelHostname = domain.TransportCloudflare, "ssh-web1.example.com"
	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflared")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable stand-in
		t.Fatal(err)
	}
	defer client.WithCloudflaredDirs(dir)()

	want, err := client.InteractiveCommand(direct, wire.ToolShell, "/tmp/kh")
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.InteractiveCommand(tunnel, wire.ToolShell, "/tmp/kh")
	if err != nil {
		t.Fatal(err)
	}
	if proxy, wantProxy := proxyOf(t, got), "'"+path+"' access ssh --hostname ssh-web1.example.com"; proxy != wantProxy {
		t.Errorf("ProxyCommand = %q, want %q", proxy, wantProxy)
	}
	i := slices.Index(want, "ProxyCommand=none")
	want[i] = proxyOption + proxyOf(t, got)
	if !slices.Equal(got, want) {
		t.Errorf("argv:\n%q\nwant:\n%q", got, want)
	}
}

func TestInteractiveCommandCloudflareNeedsTheClientsOwnCloudflared(t *testing.T) {
	defer client.WithCloudflaredDirs(t.TempDir())()
	_, err := client.InteractiveCommand(tunnelInfo(t), wire.ToolShell, "/tmp/kh")
	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable || !strings.Contains(err.Error(), "cloudflared is not installed") {
		t.Errorf("got %v", err)
	}
}

func TestInteractiveCommandCloudflareQuotesThePathAndEscapesTokens(t *testing.T) {
	tests := map[string]struct {
		path string
		want string // empty: refused
	}{
		"plain":        {"/usr/local/bin/cloudflared", "'/usr/local/bin/cloudflared' access ssh --hostname ssh-web1.example.com"},
		"space":        {"/opt/my tools/cloudflared", "'/opt/my tools/cloudflared' access ssh --hostname ssh-web1.example.com"},
		"substitute":   {"/opt/$(x)/cloudflared", "'/opt/$(x)/cloudflared' access ssh --hostname ssh-web1.example.com"},
		"semicolon":    {"/opt/a;b/cloudflared", "'/opt/a;b/cloudflared' access ssh --hostname ssh-web1.example.com"},
		"token":        {"/opt/%h/cloudflared", "'/opt/%%h/cloudflared' access ssh --hostname ssh-web1.example.com"},
		"quote":        {path: "/opt/it's/cloudflared"},
		"newline":      {path: "/opt/a\nb/cloudflared"},
		"relative":     {path: "cloudflared"},
		"leading dash": {path: "-oProxyCommand=x"},
		"empty":        {path: ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			argv, err := client.InteractiveCommandWithCloudflared(tunnelInfo(t), wire.ToolShell, "/tmp/kh", tt.path)
			if tt.want == "" {
				if err == nil {
					t.Errorf("accepted %q as %q", tt.path, argv)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := proxyOf(t, argv); got != tt.want {
				t.Errorf("ProxyCommand = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInteractiveCommandCloudflareRefusesHostileHostnamesAndUnknownTransports(t *testing.T) {
	hostnames := []string{"", "a b.example.com", "$(x).example.com", "a;b.example.com", "%h.example.com", "it's.example.com", "-oProxyCommand=x.example.com", "web1", "WEB1.example.com", "web1.example.com.", "10.0.0.1"}
	for _, h := range hostnames {
		info := tunnelInfo(t)
		info.TunnelHostname = h
		if argv, err := client.InteractiveCommandWithCloudflared(info, wire.ToolShell, "/tmp/kh", "/usr/bin/cloudflared"); err == nil {
			t.Errorf("accepted hostname %q as %q", h, argv)
		}
	}
	info := tunnelInfo(t)
	info.Transport = "wireguard"
	if argv, err := client.InteractiveCommandWithCloudflared(info, wire.ToolShell, "/tmp/kh", "/usr/bin/cloudflared"); err == nil {
		t.Errorf("accepted unknown transport as %q", argv)
	}
}
