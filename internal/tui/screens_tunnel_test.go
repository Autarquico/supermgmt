package tui

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func TestSetupViaPaletteSendsTunnelAndPreviewsTheTransport(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("setup web tunnel")
	h.press("enter")

	req := api.planRequests[0]
	if req.Action != "node.setup" || req.Parameters["tunnel"] != "true" {
		t.Errorf("setup request = %+v", req)
	}
	contains(t, h.view(), "transport: cloudflare (experimental)")

	h.press("esc", "/")
	h.typeText("setup web")
	h.press("enter")
	if _, sent := api.planRequests[1].Parameters["tunnel"]; sent {
		t.Errorf("tunnel sent without the word: %v", api.planRequests[1].Parameters)
	}
}

func TestTunnelDisableViaPalettePlansTheNodeAction(t *testing.T) {
	api := newFake()
	api.nodes[0].Endpoint.Transport = domain.TransportCloudflare
	api.nodes[0].Endpoint.TunnelHostname = "ssh-web.example.com"
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("tunnel-disable web")
	h.press("enter")

	req := api.planRequests[0]
	if req.Action != "node.tunnel.disable" || req.Targets[0].ID != api.nodes[0].ID {
		t.Errorf("request = %+v", req)
	}
	contains(t, h.view(), "transport: cloudflare -> direct (Cloudflare Tunnel support is experimental)")
}

func TestParseSetupWordsReadsTunnel(t *testing.T) {
	w, err := parseSetupWords([]string{"tunnel", "docker"})
	if err != nil || !w.tunnel || !w.docker {
		t.Errorf("got %+v, %v", w, err)
	}
	if _, err := parseSetupWords([]string{"tunnels"}); err == nil {
		t.Error("accepted an unknown word")
	}
}

func TestNodeFactsShowTransportOnlyForTunnelNodes(t *testing.T) {
	m := &Model{}
	direct := wire.Node{Name: "web"}
	tunnel := wire.Node{Name: "web", Endpoint: wire.Endpoint{Transport: domain.TransportCloudflare, TunnelHostname: "ssh-web.example.com"}}
	if got := len(m.nodeFacts(tunnel, 80)) - len(m.nodeFacts(direct, 80)); got != 1 {
		t.Errorf("a tunnel node adds %d lines, want 1", got)
	}
	if got := transportText(tunnel); got != "cloudflare · ssh-web.example.com" {
		t.Errorf("transportText = %q", got)
	}
}
