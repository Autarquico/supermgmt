package tunnel

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Scenario "Cloudflare stays optional": without a Cloudflare connection nothing
// changes (no Cloudflare call, no cloudflared requirement) and every tunnel
// action is refused saying the connection is not configured.

func TestWithoutACloudflareBlockEveryTunnelActionIsRefusedNamingTheMissingConnection(t *testing.T) {
	d := startDaemon(t, "")
	added, err := d.addNode("web1", "192.0.2.10")
	must(t, err)
	node := added.Applied.ID

	for name, req := range map[string]wire.CreatePlanRequest{
		"setup --tunnel": {
			Action: "node.setup", Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: node}},
			Parameters: map[string]any{"tunnel": "true", "docker_access": "false"},
		},
		"tunnel disable": {Action: "node.tunnel.disable", Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: node}}},
	} {
		_, err := d.api.CreatePlan(context.Background(), req)
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument || err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Errorf("%s without a cloudflare: block = %v, want INVALID_ARGUMENT saying the connection is not configured", name, err)
		}
	}
}

func TestWithoutACloudflareBlockSetupWithoutTunnelStillPlans(t *testing.T) {
	d := startDaemon(t, "")
	added, err := d.addNode("web1", "192.0.2.10")
	must(t, err)
	for _, tunnel := range []string{"", "false"} {
		params := map[string]any{"docker_access": "false"}
		if tunnel != "" {
			params["tunnel"] = tunnel
		}
		plan, err := d.api.CreatePlan(context.Background(), wire.CreatePlanRequest{
			Action: "node.setup", Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: added.Applied.ID}}, Parameters: params,
		})
		if err != nil {
			t.Errorf("node.setup with tunnel=%q without a cloudflare: block: %v, want a plan", tunnel, err)
			continue
		}
		if strings.Contains(string(plan.Plan), `"tunnel":"true"`) {
			t.Errorf("the plan for tunnel=%q turned the tunnel on: %s", tunnel, plan.Plan)
		}
	}
}

func TestWithoutACloudflareBlockACloudflareNodeFailsClosedWithoutACarrier(t *testing.T) {
	// An instance without the block never builds the cloudflare dialler: a
	// node whose stored transport is cloudflare (restored from a backup of
	// another instance) fails closed instead of reaching for cloudflared.
	s := newStack(t, stackOptions{withoutCloudflare: true})
	node := s.addNode("web1", unreachable(t), "secret://ssh/default")
	s.setTunnelEndpoint(node.ID, "ssh-web1.example.test")

	job, err := s.tryRun("node.probe", nodeRef(node), nil)
	if err == nil && job.State == domain.JobSucceeded {
		t.Fatalf("a cloudflare node was probed on an instance without the connection: %s", outcome(job, err))
	}
	t.Logf("probe: %s", outcome(job, err))
	if s.carrierStarts() != 0 {
		t.Error("a carrier process was started on an instance without a cloudflare: block")
	}

	_, err = s.plans.Create(context.Background(), s.admin, app.PlanRequest{
		Action: "node.setup", Target: nodeRef(node), Parameters: map[string]any{"tunnel": "true", "docker_access": "false"},
	})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("tunnel setup plan without the block = %v, want a refusal naming the missing connection", err)
	}
}
