package ssh

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func TestTargetsCarryTheEndpointTransport(t *testing.T) {
	n := testNode(t)
	n.Endpoint.Transport, n.Endpoint.TunnelHostname = domain.TransportCloudflare, "ssh.example.com"
	for name, target := range map[string]struct {
		transport domain.Transport
		hostname  string
	}{
		"admin":     {AdminTarget(n).Transport, AdminTarget(n).TunnelHostname},
		"dedicated": {DedicatedTarget(n, "secret://ssh/k").Transport, DedicatedTarget(n, "secret://ssh/k").TunnelHostname},
	} {
		if target.transport != domain.TransportCloudflare || target.hostname != "ssh.example.com" {
			t.Errorf("%s target = %+v", name, target)
		}
	}
}
