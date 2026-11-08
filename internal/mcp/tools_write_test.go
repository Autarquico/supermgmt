package mcp

import (
	"fmt"
	"strings"
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

func TestPlanWrappers_PlanTheirActionOnTheResolvedTargetAndSubmitTheReturnedHash(t *testing.T) {
	node := wire.ResourceRef{Type: domain.ResourceNode, ID: readNodeID}
	cases := []struct {
		tool      string
		arguments map[string]any
		action    string
		target    wire.ResourceRef
		params    map[string]any
	}{
		{"infra_start_service", map[string]any{"ref": "nginx@web-1"}, "service.start", wire.ResourceRef{Type: domain.ResourceService, ID: readServiceID}, nil},
		{"infra_stop_service", map[string]any{"ref": "nginx@web-1"}, "service.stop", wire.ResourceRef{Type: domain.ResourceService, ID: readServiceID}, nil},
		{"infra_shutdown_node", map[string]any{"ref": "web-1"}, "node.shutdown", node, nil},
		{"infra_snapshot_guest", map[string]any{"ref": "web-1"}, "proxmox.snapshot.create", node, nil},
		{"infra_disable_tunnel", map[string]any{"ref": "web-1"}, "node.tunnel.disable", node, nil},
		{"infra_power_guest", map[string]any{"ref": "web-1", "verb": "stop"}, "proxmox.vm.power", node, map[string]any{"verb": "stop"}},
		{"infra_rotate_cloudflare_access_token", map[string]any{}, "cloudflare.access_token.rotate", wire.ResourceRef{Type: domain.ResourceInstance}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			api := newServerFakeAPI()
			out := writeSession(t, api)(tc.tool, tc.arguments)
			if len(api.planRequests) != 1 || api.planRequests[0].Action != tc.action {
				t.Fatalf("plan requests = %+v", api.planRequests)
			}
			request := api.planRequests[0]
			if request.Targets[0] != tc.target {
				t.Errorf("target = %+v, want %+v", request.Targets[0], tc.target)
			}
			if len(request.Parameters) != len(tc.params) || (tc.params != nil && request.Parameters["verb"] != tc.params["verb"]) {
				t.Errorf("parameters = %v, want %v", request.Parameters, tc.params)
			}
			if len(api.submits) != 1 || api.submits[0] != (submitCall{serverPlanID, serverHash}) {
				t.Errorf("submits = %v, want exactly the plan just created", api.submits)
			}
			if out["status"] != "approval_required" {
				t.Errorf("result = %v", out)
			}
		})
	}
}

func TestPlanWrappers_ADeniedPlanIsNotSubmittedAndNoToolTakesAHash(t *testing.T) {
	for tool, arguments := range map[string]map[string]any{
		"infra_start_service":                  {"ref": "nginx@web-1"},
		"infra_shutdown_node":                  {"ref": "web-1"},
		"infra_power_guest":                    {"ref": "web-1", "verb": "start"},
		"infra_rotate_cloudflare_access_token": {},
	} {
		t.Run(tool, func(t *testing.T) {
			api := newServerFakeAPI()
			api.plan.Policy = wire.Policy{Decision: "deny", Reason: smerr.ReasonDefaultDeny}
			out := writeSession(t, api)(tool, arguments)
			if out["status"] != "denied" || len(api.submits) != 0 {
				t.Errorf("result = %v, submits = %v", out, api.submits)
			}
			arguments["plan_hash"] = "sha256:fabricated"
			if res := callReadTool(t, serverSession(t, api, true), tool, arguments); !res.IsError {
				t.Error("a plan_hash argument was accepted")
			}
		})
	}
}

func TestPowerGuest_RequiresAVerbBeforeTheAPI(t *testing.T) {
	api := newServerFakeAPI()
	failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_power_guest", map[string]any{"ref": "web-1", "verb": ""}))
	if failure.Code != smerr.CodeInvalidArgument || api.wrote() {
		t.Errorf("failure = %+v, wrote = %v", failure, api.wrote())
	}
}

func TestNodeWrappers_AmbiguousOrMissingNodesNeverReachTheAPI(t *testing.T) {
	api := newServerFakeAPI()
	session := serverSession(t, api, true)
	for _, tool := range []string{"infra_shutdown_node", "infra_probe_node", "infra_snapshot_guest", "infra_disable_tunnel", "infra_power_guest"} {
		arguments := map[string]any{"ref": "ghost"}
		if tool == "infra_power_guest" {
			arguments["verb"] = "start"
		}
		failure := readToolFailure(t, callReadTool(t, session, tool, arguments))
		if failure.Code != smerr.CodeInvalidArgument && failure.Code != smerr.CodeNotFound {
			t.Errorf("%s: failure = %+v", tool, failure)
		}
	}
	if api.wrote() {
		t.Error("an unresolved node reached the API")
	}
}

func TestProbeNode_CallsTheProbeRouteWithoutPlanning(t *testing.T) {
	api := newServerFakeAPI()
	api.submission.Job.State = domain.JobQueued
	out := writeSession(t, api)("infra_probe_node", map[string]any{"ref": "web-1"})
	if len(api.probes) != 1 || api.probes[0] != readNodeID || len(api.planRequests) != 0 {
		t.Errorf("probes = %v, plans = %v", api.probes, api.planRequests)
	}
	if out["status"] != "queued" || out["job_id"] != string(serverJobID) {
		t.Errorf("result = %v", out)
	}
}

func TestCreateBackup_CallsTheBackupRouteWithoutPlanning(t *testing.T) {
	api := newServerFakeAPI()
	out := writeSession(t, api)("infra_create_backup", nil)
	if api.backupCreates != 1 || len(api.planRequests) != 0 {
		t.Errorf("backups = %d, plans = %v", api.backupCreates, api.planRequests)
	}
	if out["status"] != "approval_required" {
		t.Errorf("result = %v", out)
	}
}

func TestCancelJob_UsesTheHashStoredWithTheJob(t *testing.T) {
	api := newServerFakeAPI()
	stored := wire.Job{ID: serverJobID, Type: "service.restart", State: domain.JobAwaitingApproval, Risk: domain.RiskOperational, PlanHash: serverHash}
	api.jobDetails = map[domain.ID]wire.JobDetail{serverJobID: {Job: stored}}
	api.cancelJob = stored
	api.cancelJob.State = domain.JobCancelled
	out := writeSession(t, api)("infra_cancel_job", map[string]any{"id": string(serverJobID)})
	if len(api.cancels) != 1 || api.cancels[0] != (submitCall{serverJobID, serverHash}) {
		t.Errorf("cancels = %v, want the stored hash", api.cancels)
	}
	if out["status"] != "done" || out["plan_hash"] != serverHash {
		t.Errorf("result = %v", out)
	}
	if res := callReadTool(t, serverSession(t, api, true), "infra_cancel_job",
		map[string]any{"id": string(serverJobID), "plan_hash": "sha256:fabricated"}); !res.IsError {
		t.Error("a plan_hash argument was accepted")
	}
}

func TestCancelJob_UnknownOrMalformedJobIsNotCancelled(t *testing.T) {
	api := newServerFakeAPI()
	session := serverSession(t, api, true)
	for _, id := range []string{"job-1", string(serverJobID)} {
		failure := readToolFailure(t, callReadTool(t, session, "infra_cancel_job", map[string]any{"id": id}))
		if failure.Code != smerr.CodeInvalidArgument && failure.Code != smerr.CodeNotFound {
			t.Errorf("%q: failure = %+v", id, failure)
		}
	}
	if len(api.cancels) != 0 {
		t.Errorf("cancels = %v", api.cancels)
	}
}

func TestCancelJob_APIRefusalSurfacesCodeAndReason(t *testing.T) {
	api := newServerFakeAPI()
	api.jobDetails = map[domain.ID]wire.JobDetail{serverJobID: {Job: wire.Job{ID: serverJobID, PlanHash: serverHash}}}
	api.submitErr = smerr.New(smerr.CodePolicyDenied, smerr.ReasonNotPlanActor, "other actor")
	failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_cancel_job", map[string]any{"id": string(serverJobID)}))
	if failure.Code != smerr.CodePolicyDenied || failure.Reason != smerr.ReasonNotPlanActor {
		t.Errorf("failure = %+v", failure)
	}
}

func TestRefreshProvider_ResolvesByNameAndLeaksNoRemoteText(t *testing.T) {
	api := newServerFakeAPI()
	api.providers = []wire.Provider{{ID: opsProviderID, Type: "proxmox", Name: "pve-main"}}
	api.refreshed = &wire.Provider{ID: opsProviderID, Status: "ok"}
	res := callReadTool(t, serverSession(t, api, true), "infra_refresh_provider", map[string]any{"ref": "pve-main"})
	out := readToolStructured(t, res)
	if len(api.refreshes) != 1 || api.refreshes[0] != opsProviderID {
		t.Errorf("refreshes = %v", api.refreshes)
	}
	if out["status"] != "done" || strings.Contains(fmt.Sprint(out), viewHostile) {
		t.Errorf("result = %v", out)
	}
}

func TestRefreshProvider_AFailedSyncIsNotReportedAsDone(t *testing.T) {
	api := newServerFakeAPI()
	api.providers = []wire.Provider{{ID: opsProviderID, Type: "proxmox", Name: "pve-main"}}
	out := writeSession(t, api)("infra_refresh_provider", map[string]any{"ref": "pve-main"})
	if out["status"] != "failed" || strings.Contains(fmt.Sprint(out), viewHostile) ||
		!strings.Contains(fmt.Sprint(out["summary"]), "infra_get_provider") {
		t.Errorf("result = %v", out)
	}
}

func TestPlanWrappers_ADeniedResultSaysWhy(t *testing.T) {
	api := newServerFakeAPI()
	api.plan.Policy = wire.Policy{Decision: "deny", Reason: smerr.ReasonDefaultDeny}
	out := writeSession(t, api)("infra_shutdown_node", map[string]any{"ref": "web-1"})
	if out["status"] != "denied" || !strings.Contains(fmt.Sprint(out["summary"]), string(smerr.ReasonDefaultDeny)) {
		t.Errorf("result = %v", out)
	}
}

func TestRefreshProvider_UnknownProviderNeverRefreshes(t *testing.T) {
	api := newServerFakeAPI()
	failure := readToolFailure(t, callReadTool(t, serverSession(t, api, true), "infra_refresh_provider", map[string]any{"ref": "ghost"}))
	if failure.Code != smerr.CodeNotFound && failure.Code != smerr.CodeInvalidArgument {
		t.Errorf("failure = %+v", failure)
	}
	if len(api.refreshes) != 0 {
		t.Errorf("refreshes = %v", api.refreshes)
	}
}
