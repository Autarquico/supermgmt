package integration

import (
	"context"
	"slices"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// The scenarios of mcp-tool-coverage, end to end: the real database, app
// services and API server under the built-in policy, reached through the MCP
// server. Only the SSH boundary of a node is faked. Per-tool argument and view
// details are the unit tests of internal/mcp; the gate decisions per action
// are internal/app/mcp_operate_test.go.

// items is the "items" list of a list tool's result.
func items(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	raw, ok := out["items"].([]any)
	if !ok {
		t.Fatalf("result has no items list: %v", out)
	}
	rows := make([]map[string]any, len(raw))
	for i, row := range raw {
		rows[i] = row.(map[string]any)
	}
	return rows
}

// jobColumn reads one column of a job straight from the database.
func (rig *mcpRig) jobColumn(column string, id any) string {
	rig.t.Helper()
	var value string
	mcpRigMust(rig.t, rig.db.Reader().QueryRowContext(context.Background(), `SELECT `+column+` FROM jobs WHERE id = ?`, id).Scan(&value))
	return value
}

// restartProdService makes the MCP client submit a restart that waits for a
// person, and returns the job id and plan hash the tool reported.
func restartProdService(t *testing.T, rig *mcpRig) (jobID, planHash string) {
	t.Helper()
	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_restart_service", map[string]any{"ref": "api@web-1"})
	if failure != nil {
		t.Fatalf("restart failed: %+v", failure)
	}
	if out["status"] != "approval_required" {
		t.Fatalf("status = %v, want approval_required: %v", out["status"], out)
	}
	return out["job_id"].(string), out["plan_hash"].(string)
}

func TestTheModelFollowsAJobItSubmittedAndSeesItsPendingApprovalButCannotApprove(t *testing.T) {
	rig := newMCPRigGranting(t, true, "")
	session := mcpSecRigSession(t, rig, true)
	jobID, planHash := restartProdService(t, rig)

	job, failure := mcpSecCall(t, session, "infra_get_job", map[string]any{"id": jobID})
	if failure != nil {
		t.Fatalf("get_job failed: %+v", failure)
	}
	if job["state"] != "awaiting_approval" || job["plan_hash"] != planHash {
		t.Errorf("job = state %v hash %v, want awaiting_approval with %s", job["state"], job["plan_hash"], planHash)
	}
	for _, withheld := range []string{"intents", "pre_state", "evidence"} {
		if _, present := job[withheld]; present {
			t.Errorf("get_job serves %q, which carries observed node state", withheld)
		}
	}

	approvals, failure := mcpSecCall(t, session, "infra_list_approvals", nil)
	if failure != nil {
		t.Fatalf("list_approvals failed: %+v", failure)
	}
	var pending bool
	for _, approval := range items(t, approvals) {
		pending = pending || approval["job"].(map[string]any)["id"] == jobID
	}
	if !pending {
		t.Errorf("list_approvals does not show job %s: %v", jobID, approvals)
	}

	for _, name := range mcpSecToolNames(t, session) {
		if strings.Contains(name, "approve") || strings.Contains(name, "reject") || strings.Contains(name, "resolve") {
			t.Errorf("tool %q lets the model decide a job", name)
		}
	}
}

func TestTheModelListsOnlyTheActionsAnMCPIdentityMayPlan(t *testing.T) {
	rig := newMCPRigGranting(t, true, "")

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_list_actions", nil)
	if failure != nil {
		t.Fatalf("list_actions failed: %+v", failure)
	}
	var names []string
	for _, action := range items(t, out) {
		names = append(names, action["name"].(string))
		if action["needs_write_tools"] != true {
			t.Errorf("action %v does not say it needs write tools", action["name"])
		}
	}
	for _, want := range []string{"service.restart", "proxmox.vm.power", "node.reboot", "cloudflare.access_token.rotate"} {
		if !slices.Contains(names, want) {
			t.Errorf("list_actions lacks %s: %v", want, names)
		}
	}
	for _, refused := range []string{"proxmox.snapshot.delete", "node.setup", "node.remove", "node.add", "secret.write", "job.approve", "job.cancel", "node.connect"} {
		if slices.Contains(names, refused) {
			t.Errorf("list_actions offers %s, which an MCP identity may not plan", refused)
		}
	}
}

func TestADefaultInstallServesServiceLogsToAnMCPClientWithoutAnyExtraRule(t *testing.T) {
	rig := newMCPRigGranting(t, false, "")

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, false), "infra_get_service_logs", map[string]any{"ref": "web@dev-1"})
	if failure != nil {
		t.Fatalf("logs failed under the default policy: %+v", failure)
	}
	log, _ := out["log"].(map[string]any)
	if text, _ := log["text"].(string); !strings.Contains(text, "listening on :8080") {
		t.Errorf("logs lack the node's output: %v", out)
	}
}

func TestADenyRuleForServiceLogsMakesTheLogToolAnswerPolicyDenied(t *testing.T) {
	rig := newMCPRigGranting(t, false, `
  - name: mcp-no-logs
    subjects: ["type:mcp"]
    deny: ["service.logs"]
`)

	_, failure := mcpSecCall(t, mcpSecRigSession(t, rig, false), "infra_get_service_logs", map[string]any{"ref": "web@dev-1"})

	if failure == nil || failure.Code != "POLICY_DENIED" {
		t.Errorf("failure = %+v, want POLICY_DENIED", failure)
	}
}

func TestWithWritesOffTheWriteToolsAreUnknownAndWithWritesOnARestartWaitsForApproval(t *testing.T) {
	off := newMCPRigGranting(t, false, "")
	if slices.Contains(mcpSecToolNames(t, mcpSecRigSession(t, off, false)), "infra_restart_service") {
		t.Error("infra_restart_service is listed with write tools off")
	}

	on := newMCPRigGranting(t, true, "")
	if !slices.Contains(mcpSecToolNames(t, mcpSecRigSession(t, on, true)), "infra_restart_service") {
		t.Fatal("infra_restart_service is not listed with write tools on")
	}
	jobs := on.count("jobs")
	jobID, _ := restartProdService(t, on)

	if state := on.jobColumn("state", jobID); state != "awaiting_approval" || on.count("jobs") != jobs+1 {
		t.Errorf("job %s is %s after the restart, want awaiting_approval", jobID, state)
	}
	if commands := on.runtime.commands.Load(); commands != 0 {
		t.Errorf("%d commands reached a node before anyone approved", commands)
	}
}

func TestAProbeRunsWithoutApprovalWhenWritesAreOn(t *testing.T) {
	rig := newMCPRigGranting(t, true, "")

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_probe_node", map[string]any{"ref": "dev-1"})
	if failure != nil {
		t.Fatalf("probe failed: %+v", failure)
	}
	if out["status"] == "approval_required" {
		t.Errorf("a read-risk probe waited for approval: %v", out)
	}
	if state := rig.jobColumn("state", out["job_id"]); state == "awaiting_approval" {
		t.Errorf("the probe job %v is awaiting approval", out["job_id"])
	}
}

func TestAnInstanceLevelJobIsPlannedWithoutTheModelNamingAnIDAndWaitsForApproval(t *testing.T) {
	rig := newMCPRigGranting(t, true, `
  - name: rig-mcp-rotate
    subjects: ["type:mcp"]
    allow: ["cloudflare.access_token.rotate"]
`)

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_rotate_cloudflare_access_token", nil)
	if failure != nil {
		t.Fatalf("rotation failed: %+v", failure)
	}
	if out["status"] != "approval_required" {
		t.Fatalf("status = %v, want approval_required: %v", out["status"], out)
	}
	if resourceType := rig.jobColumn("resource_type", out["job_id"]); resourceType != "instance" {
		t.Errorf("the job targets %q, want the instance", resourceType)
	}
}

func TestAnInstanceLevelPlanNamesNoIDAndTheVerdictWaitsForApproval(t *testing.T) {
	rig := newMCPRigGranting(t, true, `
  - name: rig-mcp-rotate
    subjects: ["type:mcp"]
    allow: ["cloudflare.access_token.rotate"]
`)

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_plan_action", map[string]any{
		"action": "cloudflare.access_token.rotate", "targets": []map[string]any{{"type": "instance"}},
	})
	if failure != nil {
		t.Fatalf("planning failed: %+v", failure)
	}
	policy, _ := out["policy"].(map[string]any)
	if policy["decision"] != "allow" || policy["approval_required"] != true {
		t.Errorf("verdict = %v, want allow with approval_required", policy)
	}
}

func TestPlanningASnapshotDeleteIsRefusedEvenWhenPolicyGrantsItAndStoresNoPlan(t *testing.T) {
	rig := newMCPRigGranting(t, true, `
  - name: rig-mcp-delete-snapshot
    subjects: ["type:mcp"]
    allow: ["proxmox.snapshot.delete"]
`)
	plans, jobs := rig.count("plans"), rig.count("jobs")

	_, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_plan_action", map[string]any{
		"action": "proxmox.snapshot.delete", "targets": []map[string]any{{"type": "node", "ref": "vm-101"}},
	})

	mcpSecWantFailure(t, failure, smerr.ReasonMCPActionForbidden)
	if after := rig.count("plans"); after != plans {
		t.Errorf("plans went from %d to %d: a refused action was stored", plans, after)
	}
	if after := rig.count("jobs"); after != jobs {
		t.Errorf("jobs went from %d to %d", jobs, after)
	}
}

func TestAnAgentCancelsItsOwnJobWithoutSupplyingAHashAndCannotCancelSomeoneElses(t *testing.T) {
	rig := newMCPRigGranting(t, true, "")
	session := mcpSecRigSession(t, rig, true)
	own, _ := restartProdService(t, rig)

	out, failure := mcpSecCall(t, session, "infra_cancel_job", map[string]any{"id": own})
	if failure != nil {
		t.Fatalf("cancelling its own job failed: %+v", failure)
	}
	job, _ := mcpSecCall(t, session, "infra_get_job", map[string]any{"id": own})
	if job["state"] != "cancelled" {
		t.Errorf("own job is %v after cancel (tool said %v), want cancelled", job["state"], out["status"])
	}

	_, failure = mcpSecCall(t, session, "infra_cancel_job", map[string]any{"id": rig.fixtures["job"]})
	mcpSecWantFailure(t, failure, smerr.ReasonNotPlanActor)
	other, _ := mcpSecCall(t, session, "infra_get_job", map[string]any{"id": rig.fixtures["job"]})
	if other["state"] != "awaiting_approval" {
		t.Errorf("a job of another identity is %v after a refused cancel, want awaiting_approval", other["state"])
	}
}
