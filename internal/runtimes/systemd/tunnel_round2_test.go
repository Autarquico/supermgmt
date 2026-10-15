package systemd

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const theirKeyring = "/usr/share/keyrings/cloudflare-main.gpg"

// CODE-3: Cloudflare's own install guide writes the source file; a node set up
// that way is used, not refused, and its package is never managed.
func TestAnInstalledCloudflaredWithTheGuidesSourceIsUsedAndLeftAlone(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	node.installed = true
	guide := "deb [signed-by=" + theirKeyring + "] https://pkg.cloudflare.com/cloudflared any main\n"
	node.files[templates.CloudflaredSourcePath] = guide
	node.files[theirKeyring] = "their key"
	if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"setup.apt_update_cloudflared", "setup.apt_install_cloudflared"} {
		if node.count(name)+node.count(name+".sudo") != 0 {
			t.Errorf("%s ran against a node that already has cloudflared", name)
		}
	}
	if node.files[templates.CloudflaredSourcePath] != guide {
		t.Error("the guide's source file was replaced")
	}
	if _, written := node.files[templates.CloudflareKeyringPath]; written {
		t.Error("a keyring was written for a package setup does not manage")
	}
	if node.files[templates.CloudflaredTokenPath] == "" || node.files[templates.CloudflaredUnitPath] == "" {
		t.Error("the service must still be installed")
	}
	if err := RemoveTunnel(context.Background(), node, RemoveTunnelParams{AdminIsRoot: true}); err != nil {
		t.Fatal(err)
	}
	if !node.installed || node.files[templates.CloudflaredSourcePath] != guide || node.files[theirKeyring] != "their key" {
		t.Error("disable removed what setup does not manage")
	}
}

// SEC-3: a keyring at the conventional shared path belongs to somebody else.
func TestSetupNeverTouchesTheSharedCloudflareKeyring(t *testing.T) {
	ring := pinTestKey(t)
	node := newTunnelNode(t)
	const shared = "/etc/apt/keyrings/cloudflare-main.gpg"
	node.files[shared] = "used by another source"
	if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
		t.Fatal(err)
	}
	if node.files[shared] != "used by another source" {
		t.Error("the shared keyring was overwritten")
	}
	if node.files[templates.CloudflareKeyringPath] != string(ring) || templates.CloudflareKeyringPath == shared {
		t.Error("setup must use its own keyring path")
	}
	if err := RemoveTunnel(context.Background(), node, RemoveTunnelParams{AdminIsRoot: true}); err != nil {
		t.Fatal(err)
	}
	if node.files[shared] != "used by another source" {
		t.Error("disable removed the shared keyring")
	}
	if _, left := node.files[templates.CloudflareKeyringPath]; left {
		t.Error("disable left its own keyring")
	}
}

// SEC-4: the connector runs unprivileged and sandboxed, and gets the token
// from systemd, not from a root-only path it reads itself.
func TestTheTunnelUnitIsSandboxed(t *testing.T) {
	unit := cloudflaredUnit()
	for _, want := range []string{
		"\nDynamicUser=yes\n", "\nLoadCredential=token:" + templates.CloudflaredTokenPath + "\n",
		"\nCapabilityBoundingSet=\n", "\nAmbientCapabilities=\n", "\nNoNewPrivileges=true\n",
		"\nProtectSystem=strict\n", "\nProtectHome=yes\n", "\nPrivateTmp=true\n",
		"\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n", "\nRestrictNamespaces=yes\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q", strings.TrimSpace(want))
		}
	}
	if strings.Contains(unit, "--token-file "+templates.CloudflaredTokenPath) || strings.Contains(unit, "User=root") {
		t.Error("the connector reads the root-only file itself")
	}
}
