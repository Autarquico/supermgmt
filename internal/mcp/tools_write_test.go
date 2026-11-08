package mcp

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func writeSession(t *testing.T, api *serverFakeAPI) func(name string, arguments map[string]any) map[string]any {
	session := serverSession(t, api, true)
	return func(name string, arguments map[string]any) map[string]any {
		t.Helper()
		return readToolStructured(t, callReadTool(t, session, name, arguments))
	}
}

func TestSubmitPlan_SendsTheGivenIdAndHash(t *testing.T) {
	api := newServerFakeAPI()
	out := writeSession(t, api)("infra_submit_plan", map[string]any{"plan_id": string(serverPlanID), "plan_hash": serverHash})
	if len(api.submits) != 1 || api.submits[0] != (submitCall{serverPlanID, serverHash}) {
		t.Errorf("submits = %v", api.submits)
	}
	if out["status"] != "approval_required" || out["job_id"] != string(serverJobID) || out["plan_hash"] != serverHash {
		t.Errorf("result = %v", out)
	}
}

func TestSubmitPlan_StatusFollowsTheJobAndTheVerdict(t *testing.T) {
	cases := []struct {
		name     string
		state    domain.JobState
		decision string
		want     string
	}{
		{"awaiting approval", domain.JobAwaitingApproval, "allow", "approval_required"},
		{"queued", domain.JobQueued, "allow", "queued"},
		{"denied verdict", domain.JobQueued, "deny", "denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newServerFakeAPI()
			api.submission.Job.State = tc.state
			api.submission.Policy.Decision = tc.decision
			out := writeSession(t, api)("infra_submit_plan", map[string]any{"plan_id": string(serverPlanID), "plan_hash": serverHash})
			if out["status"] != tc.want {
				t.Errorf("status = %v, want %s", out["status"], tc.want)
			}
		})
	}
}

func TestSubmitPlan_RefusesMalformedArgumentsBeforeTheAPI(t *testing.T) {
	for name, arguments := range map[string]map[string]any{
		"plan id not an id": {"plan_id": "plan-1", "plan_hash": serverHash},
		"empty hash":        {"plan_id": string(serverPlanID), "plan_hash": ""},
	} {
		t.Run(name, func(t *testing.T) {
			api := newServerFakeAPI()
			failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_submit_plan", arguments))
			if failure.Code != smerr.CodeInvalidArgument || api.wrote() {
				t.Errorf("failure = %+v, wrote = %v", failure, api.wrote())
			}
		})
	}
}

func TestSubmitPlan_APIRefusalSurfacesCodeAndReason(t *testing.T) {
	api := newServerFakeAPI()
	api.submitErr = smerr.New(smerr.CodeConflict, smerr.ReasonPlanStale, "inputs changed")
	failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_submit_plan",
		map[string]any{"plan_id": string(serverPlanID), "plan_hash": serverHash}))
	if failure.Code != smerr.CodeConflict || failure.Reason != smerr.ReasonPlanStale || failure.Message != "" {
		t.Errorf("failure = %+v", failure)
	}
}

func TestRestartService_PlansThenSubmitsOnlyTheReturnedHash(t *testing.T) {
	api := newServerFakeAPI()
	out := writeSession(t, api)("infra_restart_service", map[string]any{"ref": "nginx@web-1"})
	if len(api.planRequests) != 1 || api.planRequests[0].Action != "service.restart" {
		t.Fatalf("plan requests = %+v", api.planRequests)
	}
	if want := (wire.ResourceRef{Type: domain.ResourceService, ID: readServiceID}); api.planRequests[0].Targets[0] != want {
		t.Errorf("target = %+v, want %+v", api.planRequests[0].Targets[0], want)
	}
	if len(api.submits) != 1 || api.submits[0] != (submitCall{serverPlanID, serverHash}) {
		t.Errorf("submits = %v, want exactly the plan just created", api.submits)
	}
	if out["status"] != "approval_required" {
		t.Errorf("result = %v", out)
	}
}

func TestRestartService_TakesNoHashFromTheModel(t *testing.T) {
	api := newServerFakeAPI()
	failureOrResult := callReadTool(t, serverSession(t, api, true), "infra_restart_service",
		map[string]any{"ref": "nginx@web-1", "plan_hash": "sha256:fabricated"})
	if !failureOrResult.IsError {
		t.Error("a plan_hash argument was accepted")
	}
	if api.wrote() {
		t.Error("the API was reached with a model-supplied hash")
	}
}

func TestRebootNode_PlansNodeRebootOnTheResolvedNode(t *testing.T) {
	api := newServerFakeAPI()
	writeSession(t, api)("infra_reboot_node", map[string]any{"ref": "web-1"})
	if len(api.planRequests) != 1 || api.planRequests[0].Action != "node.reboot" {
		t.Fatalf("plan requests = %+v", api.planRequests)
	}
	if want := (wire.ResourceRef{Type: domain.ResourceNode, ID: readNodeID}); api.planRequests[0].Targets[0] != want {
		t.Errorf("target = %+v, want %+v", api.planRequests[0].Targets[0], want)
	}
	if len(api.submits) != 1 {
		t.Errorf("submits = %v", api.submits)
	}
}

func TestWrappers_ADeniedPlanIsNotSubmitted(t *testing.T) {
	api := newServerFakeAPI()
	api.plan.Policy = wire.Policy{Decision: "deny", Reason: smerr.ReasonDefaultDeny}
	out := writeSession(t, api)("infra_restart_service", map[string]any{"ref": "nginx@web-1"})
	if out["status"] != "denied" || out["plan_hash"] != serverHash || out["risk"] != "operational" {
		t.Errorf("result = %v", out)
	}
	if len(api.submits) != 0 {
		t.Errorf("a denied plan was submitted: %v", api.submits)
	}
}

func TestWrappers_AmbiguousOrMissingTargetsNeverPlan(t *testing.T) {
	api := newServerFakeAPI()
	session := serverSession(t, api, true)
	for _, ref := range []string{"nginx@nowhere", "nginx", "ghost@web-1"} {
		failure := readToolFailure(t, callReadTool(t, session, "infra_restart_service", map[string]any{"ref": ref}))
		if failure.Code != smerr.CodeInvalidArgument && failure.Code != smerr.CodeNotFound {
			t.Errorf("%q: failure = %+v", ref, failure)
		}
	}
	if api.wrote() {
		t.Error("an unresolved target reached CreatePlan")
	}
}
