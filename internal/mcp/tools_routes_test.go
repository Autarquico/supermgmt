package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	routeEnvID    domain.ID = "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e31"
	routeOtherID  domain.ID = "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e32"
	routeStagingT domain.ID = "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e33"
)

func routesFake() *serverFakeAPI {
	api := newServerFakeAPI()
	api.apps = []wire.App{
		{ID: readAppID, Name: "shop", Targets: []wire.AppTarget{
			{ID: readTargetID, EnvironmentID: routeEnvID, Environment: "production"},
			{ID: routeStagingT, EnvironmentID: routeOtherID, Environment: "staging"},
		}},
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e34", Name: "docs", Targets: []wire.AppTarget{{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e35", Environment: "production"}}},
	}
	api.routes = []wire.AppRoute{
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e41", AppTargetID: readTargetID, Hostname: "shop.example.com", Service: "web", Port: 8080, Access: "public", Phase: "active", CreatedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)},
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e42", AppTargetID: routeStagingT, Hostname: "stg.example.com", Service: "web", Port: 8080, Access: "owners", Phase: "failed", LastError: "token=hunter2 foreign DNS record"},
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e43", AppTargetID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e35", Hostname: "docs.example.com", Service: "site", Port: 80, Access: "public", Phase: "waiting"},
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

func TestListAppRoutes_FiltersByAppAndEnvironmentByNameOrId(t *testing.T) {
	session := readToolsSession(t, routesFake())
	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"everything":        {nil, "docs.example.com shop.example.com stg.example.com"},
		"app by name":       {map[string]any{"app": "shop"}, "shop.example.com stg.example.com"},
		"app by id":         {map[string]any{"app": string(readAppID)}, "shop.example.com stg.example.com"},
		"app and env":       {map[string]any{"app": "shop", "environment": "staging"}, "stg.example.com"},
		"environment by id": {map[string]any{"app": "shop", "environment": string(routeEnvID)}, "shop.example.com"},
		"environment alone": {map[string]any{"environment": "production"}, "docs.example.com shop.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			got := routeHostnames(readToolStructured(t, callReadTool(t, session, "infra_list_app_routes", tc.args)))
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

func TestListAppRoutes_ARouteErrorIsUntrustedAndMasked(t *testing.T) {
	session := readToolsSession(t, routesFake())
	result := callReadTool(t, session, "infra_list_app_routes", map[string]any{"app": "shop", "environment": "staging"})
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

func TestListAppRoutes_AnUnknownAppOrEnvironmentIsRefused(t *testing.T) {
	session := readToolsSession(t, routesFake())
	for name, args := range map[string]map[string]any{
		"unknown app": {"app": "nope"},
	} {
		if result := callReadTool(t, session, "infra_list_app_routes", args); !result.IsError {
			t.Errorf("%s: want a tool error, got %s", name, readToolText(t, result))
		}
	}
	if got := routeHostnames(readToolStructured(t, callReadTool(t, session, "infra_list_app_routes", map[string]any{"environment": "nowhere"}))); len(got) != 0 {
		t.Errorf("an environment nobody has lists %v", got)
	}
}

func TestExposeApp_OmittedAccessIsPublicAndTheResultCarriesTheRisk(t *testing.T) {
	api := routesFake()
	out := writeSession(t, api)("infra_expose_app", map[string]any{
		"app": "shop", "environment": "production", "hostname": "shop.example.com", "service": "web", "port": 8080,
	})

	if len(api.exposes) != 1 {
		t.Fatalf("exposes = %v", api.exposes)
	}
	want := exposeCall{readTargetID, wire.ExposeAppRouteRequest{Hostname: "shop.example.com", Service: "web", Port: 8080, Access: "public"}}
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

func TestExposeApp_OwnersIsPassedThroughAndAnUnknownAccessIsRefusedBeforeTheAPI(t *testing.T) {
	api := routesFake()
	call := writeSession(t, api)
	call("infra_expose_app", map[string]any{
		"app": string(readAppID), "environment": "staging", "hostname": "stg.example.com", "service": "web", "port": 8080, "access": "owners",
	})
	if len(api.exposes) != 1 || api.exposes[0].target != routeStagingT || api.exposes[0].request.Access != "owners" {
		t.Fatalf("exposes = %+v", api.exposes)
	}

	refused := routesFake()
	result := callReadTool(t, serverSession(t, refused, true), "infra_expose_app", map[string]any{
		"app": "shop", "environment": "production", "hostname": "a.example.com", "service": "web", "port": 80, "access": "everyone",
	})
	if !result.IsError || refused.wrote() {
		t.Errorf("an unknown access reached the API: error=%v exposes=%v", result.IsError, refused.exposes)
	}
}

func TestExposeApp_AnUnresolvableTargetNeverReachesTheAPI(t *testing.T) {
	api := routesFake()
	session := serverSession(t, api, true)
	for name, args := range map[string]map[string]any{
		"unknown app":         {"app": "nope", "environment": "production"},
		"unknown environment": {"app": "shop", "environment": "nowhere"},
	} {
		args["hostname"], args["service"], args["port"] = "a.example.com", "web", 80
		if result := callReadTool(t, session, "infra_expose_app", args); !result.IsError {
			t.Errorf("%s: want a tool error", name)
		}
	}
	if api.wrote() {
		t.Errorf("a write reached the API: %v", api.exposes)
	}
}

func TestUnexposeApp_SendsTheHostnameOfTheResolvedTarget(t *testing.T) {
	api := routesFake()
	out := writeSession(t, api)("infra_unexpose_app", map[string]any{"app": "shop", "environment": "production", "hostname": "shop.example.com"})

	if len(api.unexposes) != 1 || api.unexposes[0] != (unexposeCall{readTargetID, "shop.example.com"}) {
		t.Errorf("unexposes = %+v", api.unexposes)
	}
	if out["status"] != "approval_required" {
		t.Errorf("result = %v", out)
	}
}
