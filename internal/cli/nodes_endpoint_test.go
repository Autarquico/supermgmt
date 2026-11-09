package cli

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func TestEndpointOfATunnelNodeIsTheTunnelHostname(t *testing.T) {
	n := wire.Node{Kind: "host"}
	n.Endpoint.Host, n.Endpoint.Port, n.Endpoint.AdminUser = "10.0.0.5", 22, "alex"
	if got := endpointOf(n); got != "alex@10.0.0.5:22" {
		t.Errorf("direct: %q", got)
	}
	n.Endpoint.Transport, n.Endpoint.TunnelHostname = domain.TransportCloudflare, "ssh-web1.example.com"
	if got := endpointOf(n); got != "alex@ssh-web1.example.com (tunnel)" {
		t.Errorf("tunnel: %q", got)
	}
}
