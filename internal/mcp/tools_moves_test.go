package mcp

import (
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func movesFake() *serverFakeAPI {
	api := routesFake()
	api.nodes = readTestAPI().nodes
	api.moves = []wire.AppMove{
		{
			ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e51", AppTargetID: readTargetID, DestNodeID: readNodeID, Phase: "failed",
			HaltedPhase: "compensating_source_started", Stateful: true, LastError: "token=hunter2 source not healthy",
			Volumes: []wire.AppMoveVolume{{Name: "shop_data", Service: "db", Mount: "/var/lib/db", State: "verified", Attempt: 2, CreatedByMove: true}},
			Routes:  []wire.AppMoveRoute{{RouteID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e60", Hostname: "shop.example.com", Access: "owners", FrozenPhase: "active", State: "dns_switched"}},
		},
		{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e52", AppTargetID: routeStagingT, Phase: "done"},
	}
	return api
}

func TestListAppMoves_ListsTheMovesOfTheResolvedTargetOnly(t *testing.T) {
	session := readToolsSession(t, movesFake())
	result := callReadTool(t, session, "infra_list_app_moves", map[string]any{"app": "shop", "environment": "production"})
	text := readToolText(t, result)
	if strings.Contains(text, "hunter2") {
		t.Errorf("credential-shaped value leaked: %s", text)
	}
	items := readToolStructured(t, result)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	move := items[0].(map[string]any)
	volume := move["volumes"].([]any)[0].(map[string]any)
	remote := move["remote"].(map[string]any)
	route := move["routes"].([]any)[0].(map[string]any)
	if route["hostname"] != "shop.example.com" || route["state"] != "dns_switched" || route["access"] != "owners" || route["frozen_phase"] != "active" {
		t.Errorf("route = %v", route)
	}
	if move["phase"] != "failed" || move["halted_phase"] != "compensating_source_started" || move["stateful"] != true || volume["name"] != "shop_data" {
		t.Errorf("move = %v", move)
	}
	if remote["untrusted_remote_output"] != true || !strings.Contains(remote["last_error"].(string), "source not healthy") {
		t.Errorf("remote = %v", remote)
	}
}

func TestListAppMoves_AnUnknownTargetIsRefused(t *testing.T) {
	session := readToolsSession(t, movesFake())
	for name, args := range map[string]map[string]any{
		"unknown app":         {"app": "nope", "environment": "production"},
		"unknown environment": {"app": "shop", "environment": "nowhere"},
	} {
		if result := callReadTool(t, session, "infra_list_app_moves", args); !result.IsError {
			t.Errorf("%s: want a tool error", name)
		}
	}
}

func TestMoveApp_ResolvesTargetAndNodeByNameAndWaitsForApproval(t *testing.T) {
	api := movesFake()
	out := writeSession(t, api)("infra_move_app", map[string]any{"app": "shop", "environment": "production", "to_node": "web-1"})

	if len(api.moveCalls) != 1 || api.moveCalls[0] != (moveCall{readTargetID, readNodeID}) {
		t.Fatalf("moves = %+v", api.moveCalls)
	}
	if out["status"] != "approval_required" || out["risk"] != "high" || out["job_id"] != string(serverJobID) {
		t.Errorf("result = %v", out)
	}
	if len(api.planRequests) != 0 || len(api.submits) != 0 {
		t.Errorf("the tool planned on its own: %v %v", api.planRequests, api.submits)
	}
}

func TestMoveApp_ASummaryStatesWhetherTheAppStops(t *testing.T) {
	api := movesFake()
	api.moveSubmission.Move.Stateful = true
	out := writeSession(t, api)("infra_move_app", map[string]any{"app": "shop", "environment": "production", "to_node": string(readNodeID)})

	if summary, _ := out["summary"].(string); !strings.Contains(summary, "stops while its volumes are copied") {
		t.Errorf("summary = %q", summary)
	}
}

func TestMoveApp_AnUnresolvableTargetOrNodeNeverReachesTheAPI(t *testing.T) {
	api := movesFake()
	session := serverSession(t, api, true)
	for name, args := range map[string]map[string]any{
		"unknown app":         {"app": "nope", "environment": "production", "to_node": "web-1"},
		"unknown environment": {"app": "shop", "environment": "nowhere", "to_node": "web-1"},
		"unknown node":        {"app": "shop", "environment": "production", "to_node": "ghost"},
	} {
		if result := callReadTool(t, session, "infra_move_app", args); !result.IsError {
			t.Errorf("%s: want a tool error", name)
		}
	}
	if api.wrote() {
		t.Errorf("a write reached the API: %v", api.moveCalls)
	}
}
