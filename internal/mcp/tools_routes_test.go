package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const routeOtherNodeID domain.ID = "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e09"

func routesFake() *serverFakeAPI {
	api := newServerFakeAPI()
	api.nodes = append(api.nodes, wire.Node{ID: routeOtherNodeID, Name: "web-2"})
	api.routes = []wire.NodeRoute{
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e41", NodeID: readNodeID, Hostname: "shop.example.com", Port: 8080, Access: "public", Phase: "active", CreatedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)},
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e42", NodeID: routeOtherNodeID, Hostname: "stg.example.com", Port: 8080, Access: "owners", Phase: "failed", LastError: "token=hunter2 foreign DNS record"},
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e43", NodeID: readNodeID, Hostname: "docs.example.com", Port: 80, Access: "public", Phase: "provisioning"},
	}
	return api
}

func routeHostnames(out map[string]any) []string {
	var names []string
	for _, item := range out["items"].([]any) {
		names = append(names, item.(map[string]any)["hostname"].(string))
	}
	return names
}

func TestListRoutes_FiltersByNodeByNameOrId(t *testing.T) {
	session := readToolsSession(t, routesFake())
	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"everything":   {nil, "docs.example.com shop.example.com stg.example.com"},
		"node by name": {map[string]any{"node": "web-1"}, "docs.example.com shop.example.com"},
		"node by id":   {map[string]any{"node": string(routeOtherNodeID)}, "stg.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			got := routeHostnames(readToolStructured(t, callReadTool(t, session, "infra_list_routes", tc.args)))
			if strings.Join(sortedCopy(got), " ") != tc.want {
				t.Errorf("hostnames = %v, want %s", got, tc.want)
			}
		})
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestListRoutes_ARouteErrorIsUntrustedAndMasked(t *testing.T) {
	session := readToolsSession(t, routesFake())
	result := callReadTool(t, session, "infra_list_routes", map[string]any{"node": "web-2"})
	text := readToolText(t, result)
	if strings.Contains(text, "hunter2") {
		t.Errorf("credential-shaped value leaked: %s", text)
	}
	item := readToolStructured(t, result)["items"].([]any)[0].(map[string]any)
	remote := item["remote"].(map[string]any)
	if remote["untrusted_remote_output"] != true || !strings.Contains(remote["last_error"].(string), "foreign DNS record") {
		t.Errorf("remote = %v", remote)
	}
}

func TestListRoutes_AnUnknownNodeIsRefused(t *testing.T) {
	session := readToolsSession(t, routesFake())
	if result := callReadTool(t, session, "infra_list_routes", map[string]any{"node": "nope"}); !result.IsError {
		t.Errorf("want a tool error, got %s", readToolText(t, result))
	}
}

func TestExposePort_OmittedAccessIsPublicAndTheResultCarriesTheRisk(t *testing.T) {
	api := routesFake()
	out := writeSession(t, api)("infra_expose_port", map[string]any{
		"node": "web-1", "hostname": "shop.example.com", "port": 8080,
	})

	if len(api.exposes) != 1 {
		t.Fatalf("exposes = %v", api.exposes)
	}
	want := exposeCall{readNodeID, wire.ExposeNodeRouteRequest{Hostname: "shop.example.com", Port: 8080, Access: "public"}}
	if api.exposes[0] != want {
		t.Errorf("request = %+v, want %+v", api.exposes[0], want)
	}
	if out["status"] != "approval_required" || out["risk"] != "high" || out["job_id"] != string(serverJobID) {
		t.Errorf("result = %v", out)
	}
	if len(api.planRequests) != 0 || len(api.submits) != 0 {
		t.Errorf("the tool planned on its own: %v %v", api.planRequests, api.submits)
	}
}

func TestExposePort_OwnersIsPassedThroughAndAnUnknownAccessIsRefusedBeforeTheAPI(t *testing.T) {
	api := routesFake()
	call := writeSession(t, api)
	call("infra_expose_port", map[string]any{
		"node": string(routeOtherNodeID), "hostname": "stg.example.com", "port": 8080, "access": "owners",
	})
	if len(api.exposes) != 1 || api.exposes[0].node != routeOtherNodeID || api.exposes[0].request.Access != "owners" {
		t.Fatalf("exposes = %+v", api.exposes)
	}

	refused := routesFake()
	result := callReadTool(t, serverSession(t, refused, true), "infra_expose_port", map[string]any{
		"node": "web-1", "hostname": "a.example.com", "port": 80, "access": "everyone",
	})
	if !result.IsError || refused.wrote() {
		t.Errorf("an unknown access reached the API: error=%v exposes=%v", result.IsError, refused.exposes)
	}
}

func TestExposePort_AnUnresolvableNodeNeverReachesTheAPI(t *testing.T) {
	api := routesFake()
	result := callReadTool(t, serverSession(t, api, true), "infra_expose_port", map[string]any{"node": "nope", "hostname": "a.example.com", "port": 80})
	if !result.IsError || api.wrote() {
		t.Errorf("error=%v, a write reached the API: %v", result.IsError, api.exposes)
	}
}

func TestUnexposePort_SendsTheHostnameOfTheResolvedNode(t *testing.T) {
	api := routesFake()
	out := writeSession(t, api)("infra_unexpose_port", map[string]any{"node": "web-1", "hostname": "shop.example.com"})

	if len(api.unexposes) != 1 || api.unexposes[0] != (unexposeCall{readNodeID, "shop.example.com"}) {
		t.Errorf("unexposes = %+v", api.unexposes)
	}
	if out["status"] != "approval_required" {
		t.Errorf("result = %v", out)
	}
}
