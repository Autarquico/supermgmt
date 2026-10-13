package mcp

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const writeDeploymentID domain.ID = "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e21"

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

func TestCreateDeployment_StatusFollowsTheDeploymentState(t *testing.T) {
	cases := map[string]string{
		"created":           "waiting_ci",
		"waiting_ci":        "waiting_ci",
		"awaiting_approval": "approval_required",
		"queued":            "queued",
	}
	for state, want := range cases {
		t.Run(state, func(t *testing.T) {
			api := newServerFakeAPI()
			api.deployment = wire.Deployment{ID: writeDeploymentID, Kind: "deploy", State: state, AppTargetID: readTargetID, CommitSHA: "abc123"}
			out := writeSession(t, api)("infra_create_deployment", map[string]any{
				"app_target_id": string(readTargetID), "commit_sha": "abc123",
				"images": []any{map[string]any{"service": "web", "digest": "sha256:00"}},
			})
			if out["status"] != want || out["deployment_id"] != string(writeDeploymentID) || out["risk"] != "operational" {
				t.Errorf("result = %v, want status %s", out, want)
			}
		})
	}
}

func TestCreateDeployment_SendsADeployRequest(t *testing.T) {
	api := newServerFakeAPI()
	api.deployment = wire.Deployment{ID: writeDeploymentID, State: "waiting_ci"}
	digest := "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	writeSession(t, api)("infra_create_deployment", map[string]any{
		"app_target_id": string(readTargetID), "commit_sha": "abc123",
		"images": []any{map[string]any{"service": "web", "digest": digest}},
	})
	if len(api.deploymentRequests) != 1 {
		t.Fatalf("requests = %d", len(api.deploymentRequests))
	}
	request := api.deploymentRequests[0]
	if request.AppTargetID != readTargetID || request.Kind != "deploy" || request.CommitSHA != "abc123" ||
		len(request.Images) != 1 || request.Images[0] != (wire.RequestedImage{Service: "web", Digest: digest}) {
		t.Errorf("request = %+v", request)
	}
}

func TestCreateDeployment_RefusesABadTargetBeforeTheAPI(t *testing.T) {
	api := newServerFakeAPI()
	failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_create_deployment",
		map[string]any{"app_target_id": "shop", "commit_sha": "abc123", "images": []any{}}))
	if failure.Code != smerr.CodeInvalidArgument || api.wrote() {
		t.Errorf("failure = %+v, wrote = %v", failure, api.wrote())
	}
}

func TestRollbackDeployment_DefaultsToTheNewestKnownGood(t *testing.T) {
	api := newServerFakeAPI()
	api.deployment = wire.Deployment{ID: writeDeploymentID, Kind: "rollback", State: "awaiting_approval"}
	out := writeSession(t, api)("infra_rollback_deployment", map[string]any{"deployment_id": string(readDeploymentID)})
	if len(api.rollbacks) != 1 || api.rollbacks[0].id != readDeploymentID || api.rollbacks[0].request.ToDeploymentID != nil {
		t.Errorf("rollbacks = %+v", api.rollbacks)
	}
	if out["status"] != "approval_required" || out["deployment_id"] != string(writeDeploymentID) {
		t.Errorf("result = %v", out)
	}
}

func TestRollbackDeployment_NamesTheTargetWhenGiven(t *testing.T) {
	api := newServerFakeAPI()
	api.deployment = wire.Deployment{ID: writeDeploymentID, State: "queued"}
	writeSession(t, api)("infra_rollback_deployment", map[string]any{
		"deployment_id": string(readDeploymentID), "to_deployment_id": string(writeDeploymentID),
	})
	to := api.rollbacks[0].request.ToDeploymentID
	if to == nil || *to != writeDeploymentID {
		t.Errorf("to_deployment_id = %v", to)
	}
}

func TestRollbackDeployment_RefusesBadIdsBeforeTheAPI(t *testing.T) {
	for name, arguments := range map[string]map[string]any{
		"deployment id": {"deployment_id": "latest"},
		"target id":     {"deployment_id": string(readDeploymentID), "to_deployment_id": "previous"},
	} {
		t.Run(name, func(t *testing.T) {
			api := newServerFakeAPI()
			failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_rollback_deployment", arguments))
			if failure.Code != smerr.CodeInvalidArgument || api.wrote() {
				t.Errorf("failure = %+v, wrote = %v", failure, api.wrote())
			}
		})
	}
}

func TestDeploymentTools_APIDenialSurfacesCodeAndReason(t *testing.T) {
	api := newServerFakeAPI()
	api.deploymentEr = smerr.New(smerr.CodePolicyDenied, smerr.ReasonMCPWritesDisabled, "writes are off")
	failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_rollback_deployment",
		map[string]any{"deployment_id": string(readDeploymentID)}))
	if failure.Code != smerr.CodePolicyDenied || failure.Reason != smerr.ReasonMCPWritesDisabled {
		t.Errorf("failure = %+v", failure)
	}
}
