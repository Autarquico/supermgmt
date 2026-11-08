//go:build e2e && fixtures

package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/test/e2e/harness"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// hostAddress is the first routable IPv4 address of the test machine, or "" when there is none.
func hostAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ip, ok := a.(*net.IPNet)
		if !ok || ip.IP.To4() == nil || !ip.IP.IsGlobalUnicast() || ip.IP.IsLinkLocalUnicast() {
			continue
		}
		return ip.IP.String()
	}
	return ""
}

// fixtureNode is a fixture node (systemd, sshd) that can be administered with a key the test holds.
type fixtureNode struct {
	fx         *fixture.Node
	c          *harness.Container
	adminKey   string // host path of the private key for the bootstrap account
	hostKeyPin string // the sshd host key in authorized_keys form
}

// authorizeAdminKey creates a key for the bootstrap account `admin` (the fixture only exposes its
// own as a signer) and returns the host path of the private key, mode 0600.
func (n *fixtureNode) authorizeAdminKey(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "node admin")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	res := n.c.Exec(context.Background(), string(cryptossh.MarshalAuthorizedKey(sshPub)), "sh", "-c", "cat >> /home/admin/.ssh/authorized_keys")
	if res.Code != 0 {
		t.Fatalf("authorize the admin key: %s", res.Output())
	}
	return harness.WriteHostFile(t, t.TempDir(), "node-admin.key", pem.EncodeToMemory(block), 0o600)
}

// sshEndpoint is the static provider's endpoint block for a daemon that reaches the node at host:port.
func (n *fixtureNode) sshEndpoint(host string, port int) string {
	return fmt.Sprintf("    endpoint:\n      host: %s\n      port: %d\n      user: supermgmt\n      admin_user: %s\n      host_public_key: %q\n",
		host, port, fixture.AdminUser, n.hostKeyPin)
}
