package mcp

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func planArguments(targets ...map[string]any) map[string]any {
	list := make([]any, len(targets))
	for i, target := range targets {
		list[i] = target
	}
	return map[string]any{"action": "service.restart", "targets": list}
}

func serviceTarget(ref string) map[string]any {
	return map[string]any{"type": "service", "ref": ref}
}

func TestPlanAction_BindsTheResolvedIdsAndDoesNotExecute(t *testing.T) {
	api := newServerFakeAPI()
	session := serverSession(t, api, false)
	out := readToolStructured(t, callReadTool(t, session, "infra_plan_action", planArguments(serviceTarget("nginx@web-1"))))
	if len(api.planRequests) != 1 {
		t.Fatalf("CreatePlan calls = %d, want 1", len(api.planRequests))
	}
	request := api.planRequests[0]
	wantTarget := wire.ResourceRef{Type: domain.ResourceService, ID: readServiceID}
	if request.Action != "service.restart" || len(request.Targets) != 1 || request.Targets[0] != wantTarget {
		t.Errorf("request = %+v", request)
	}
	if request.Parameters == nil {
		t.Error("parameters sent as null, want an empty object")
	}
	if len(api.submits) != 0 {
		t.Error("planning submitted")
	}
	if out["plan_id"] != string(serverPlanID) || out["plan_hash"] != serverHash {
		t.Errorf("output = %v", out)
	}
}

func TestPlanAction_SubmitViaFollowsTheWriteToolSwitch(t *testing.T) {
	for _, tc := range []struct {
		writeTools bool
		want       any
	}{
		{false, nil},
		{true, "infra_submit_plan"},
	} {
		session := serverSession(t, newServerFakeAPI(), tc.writeTools)
		out := readToolStructured(t, callReadTool(t, session, "infra_plan_action", planArguments(serviceTarget("nginx@web-1"))))
		got, present := out["submit_via"]
		if !present || got != tc.want {
			t.Errorf("write tools %v: submit_via = %v (present %v), want %v", tc.writeTools, got, present, tc.want)
		}
	}
}

func TestPlanAction_ForwardsParameters(t *testing.T) {
	api := newServerFakeAPI()
	arguments := planArguments(serviceTarget(string(readServiceID)))
	arguments["parameters"] = map[string]any{"mode": "graceful"}
	readToolStructured(t, callReadTool(t, serverSession(t, api, false), "infra_plan_action", arguments))
	if got := api.planRequests[0].Parameters["mode"]; got != "graceful" {
		t.Errorf("parameters = %v", api.planRequests[0].Parameters)
	}
}

func TestPlanAction_RefusedBeforeTheAPIIsAskedToPlan(t *testing.T) {
	twoNodes := newServerFakeAPI()
	twoNodes.nodes = append(twoNodes.nodes, wire.Node{ID: "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e99", Name: "web-1"})
	cases := []struct {
		name      string
		api       *serverFakeAPI
		arguments map[string]any
		reason    smerr.Reason
	}{
		{"no target", newServerFakeAPI(), planArguments(), ""},
		{"two targets", newServerFakeAPI(), planArguments(serviceTarget(string(readServiceID)), serviceTarget(string(readServiceID))), ""},
		{"empty action", newServerFakeAPI(), map[string]any{"action": "", "targets": []any{serviceTarget(string(readServiceID))}}, ""},
		{"target type outside the resource types", newServerFakeAPI(), planArguments(map[string]any{"type": "volume", "ref": "x"}), ""},
		{"deployment target by name", newServerFakeAPI(), planArguments(map[string]any{"type": "deployment", "ref": "latest"}), ""},
		{"service without a node", newServerFakeAPI(), planArguments(serviceTarget("nginx")), ""},
		{"ambiguous node name", twoNodes, planArguments(map[string]any{"type": "node", "ref": "web-1"}), smerr.ReasonAmbiguousTarget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failure := readToolFailure(t, callReadTool(t, serverSession(t, tc.api, false), "infra_plan_action", tc.arguments))
			if failure.Code != smerr.CodeInvalidArgument || failure.Reason != tc.reason {
				t.Errorf("failure = %+v, want INVALID_ARGUMENT %q", failure, tc.reason)
			}
			if len(tc.api.planRequests) != 0 {
				t.Error("CreatePlan was called")
			}
		})
	}
}

func TestPlanAction_UnknownActionAndParameterSurfaceTheAPIError(t *testing.T) {
	for _, reason := range []smerr.Reason{smerr.ReasonUnknownAction, ""} {
		api := newServerFakeAPI()
		api.planErr = smerr.New(smerr.CodeInvalidArgument, reason, "internal detail that must not leak")
		failure := readToolFailure(t, callReadTool(t, serverSession(t, api, false), "infra_plan_action", planArguments(serviceTarget(string(readServiceID)))))
		if failure.Code != smerr.CodeInvalidArgument || failure.Reason != reason || failure.Message != "" {
			t.Errorf("failure = %+v, want INVALID_ARGUMENT %q with no message", failure, reason)
		}
	}
}

func TestPlanAction_ADeniedVerdictIsStillReturned(t *testing.T) {
	api := newServerFakeAPI()
	api.plan.Policy = wire.Policy{Decision: "deny", Reason: smerr.ReasonDefaultDeny}
	out := readToolStructured(t, callReadTool(t, serverSession(t, api, true), "infra_plan_action", planArguments(serviceTarget(string(readServiceID)))))
	policy, _ := out["policy"].(map[string]any)
	if policy["decision"] != "deny" {
		t.Errorf("policy = %v", policy)
	}
}
