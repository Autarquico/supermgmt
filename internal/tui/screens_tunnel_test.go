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
	if err != nil || !w.tunnel.Value || !w.tunnel.Set || !w.docker.Value || !w.docker.Set {
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

func TestASetupRerunFromThePaletteKeepsDockerLogsAndTunnel(t *testing.T) {
	api := newFake()
	api.nodes[0].Setup.DockerAccess, api.nodes[0].Setup.LogsMode = true, "broker"
	api.nodes[0].Endpoint.Transport, api.nodes[0].Endpoint.TunnelHostname = domain.TransportCloudflare, "ssh-web-1.example.com"
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("setup web")
	h.press("enter")
	p := api.planRequests[0].Parameters
	if p["docker_access"] != "true" || p["logs_mode"] != "broker" || p["tunnel"] != "true" {
		t.Errorf("parameters = %v: a bare re-run must keep docker access, the logs mode and the tunnel", p)
	}

	h.press("esc", "/")
	h.typeText("setup web no-docker journal")
	h.press("enter")
	if p := api.planRequests[1].Parameters; p["docker_access"] != "false" || p["logs_mode"] != "journal-group" {
		t.Errorf("parameters = %v: no-docker and journal must change them", p)
	}
}

func TestAddNodeTunnelViaPaletteStartsTheEnrollmentAndPointsToTheCLI(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 140, 28)
	h.start()

	h.press("/")
	h.typeText("add node vps1 tunnel")
	h.press("enter")

	if len(api.enrollments) != 1 || api.enrollments[0].Name != "vps1" {
		t.Fatalf("requests = %+v", api.enrollments)
	}
	contains(t, h.view(), "sm nodes add --tunnel --name vps1")
}

func TestAddNodeTunnelNeedsTheWholeCommand(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 28)
	h.start()

	for _, line := range []string{"add", "add node vps1", "add host vps1 tunnel", "add node vps1 direct"} {
		h.press("/")
		h.typeText(line)
		h.press("enter")
		contains(t, h.view(), "usage: add node <name> tunnel")
		h.press("esc")
	}
	if len(api.enrollments) != 0 {
		t.Errorf("a malformed command started an enrollment: %+v", api.enrollments)
	}
}
