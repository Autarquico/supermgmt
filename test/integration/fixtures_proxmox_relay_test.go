//go:build fixtures

package integration

import (
	"io"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// The Proxmox-through-a-node scenarios that need a real sshd: the dedicated
// account's `restrict` key (ADR-0009, unchanged) refuses every forwarding
// request, and the one catalog command is the way to a TCP service on the
// node's loopback. The PVE API itself is the in-process fake of
// internal/app/proxmox_relay_e2e_test.go; here the far end is a socat echo on
// 127.0.0.1:8006 inside the node.

func (p *provisioned) dedicatedClient(t *testing.T) *cryptossh.Client {
	t.Helper()
	c, err := cryptossh.Dial("tcp", p.Addr(), &cryptossh.ClientConfig{
		User: dedicatedUser, Auth: []cryptossh.AuthMethod{cryptossh.PublicKeys(p.identity.signer)},
		HostKeyCallback: cryptossh.FixedHostKey(p.HostKey), Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial as %s: %v", dedicatedUser, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestFixturesProxmoxRelay_TheDedicatedKeyRefusesEveryKindOfForwarding(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)
	c := p.dedicatedClient(t)

	t.Run("local TCP forwarding is refused", func(t *testing.T) {
		if conn, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
			_ = conn.Close()
			t.Error("direct-tcpip to the node's loopback was opened")
		}
	})
	t.Run("remote TCP forwarding is refused", func(t *testing.T) {
		if l, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
			_ = l.Close()
			t.Error("tcpip-forward was granted")
		}
	})
	t.Run("stream-local forwarding is refused in both directions", func(t *testing.T) {
		if conn, err := c.Dial("unix", "/run/dbus/system_bus_socket"); err == nil {
			_ = conn.Close()
			t.Error("direct-streamlocal was opened")
		}
		if l, err := c.ListenUnix("/tmp/sm-forward.sock"); err == nil {
			_ = l.Close()
			t.Error("streamlocal-forward was granted")
		}
	})
}

func TestFixturesProxmoxRelay_TheRelayCommandCarriesBytesToTheLoopbackServiceAsTheDedicatedAccount(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)
	p.shell(t, "apt-get update >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends socat >/dev/null 2>&1; test -x /usr/bin/socat")
	p.shell(t, "nohup socat TCP-LISTEN:8006,bind=127.0.0.1,fork,reuseaddr EXEC:/bin/cat >/dev/null 2>&1 &")

	var conn io.ReadWriteCloser
	deadline := time.Now().Add(10 * time.Second) //nolint:forbidigo // test polling against a real fixture
	for {
		c, err := p.h.pool.OpenRelay(t.Context(), p.superTarget(), templates.Relay{SocatPath: "/usr/bin/socat"})
		if err != nil {
			t.Fatalf("OpenRelay as the dedicated account: %v", err)
		}
		if _, err := c.Write([]byte("ping")); err == nil {
			buf := make([]byte, 4)
			if _, err := io.ReadFull(c, buf); err == nil && string(buf) == "ping" {
				conn = c
				break
			}
		}
		_ = c.Close()
		if time.Now().After(deadline) { //nolint:forbidigo // see above
			t.Fatal("the relay never echoed through socat to 127.0.0.1:8006")
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = conn.Close()
}
