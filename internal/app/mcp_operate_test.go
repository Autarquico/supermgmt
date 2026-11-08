package app

import (
	"context"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

var mcpOperateWrites = []string{
	"service.start", "service.stop", "service.restart", "node.reboot", "proxmox.vm.power",
	"proxmox.snapshot.create", "proxmox.backup.create",
}

// mcpFixture is the standard fixture plus two mcp identities on the default
// policy with writes enabled.
func newMCPOperateFixture(t *testing.T, writes bool) (*fixture, domain.ID, domain.ID) {
	t.Helper()
	f := newFixture(t, func(c *Config) { c.MCPWritesEnabled = writes })
	var first, second domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		first = f.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		second = f.identity(ctx, tx, "assistant-2", domain.ActorMCP, "")
		return nil
	})
	return f, first, second
}

func requiredParams(spec policy.ActionSpec) map[string]any {
	params := map[string]any{}
	for _, p := range spec.Params {
		if p.Required && len(p.Values) > 0 {
			params[p.Name] = p.Values[0]
		}
	}
	return params
}

func (f *fixture) mcpDecision(t *testing.T, action string) policy.Result {
	t.Helper()
	spec, _ := policy.Lookup(action)
	c, err := newCore(f.cfg)
	mustf(t, err, "newCore")
	return c.authorize(policy.Request{
		Actor: domain.Actor{ID: "mcp-1", Type: domain.ActorMCP}, Action: action, Params: requiredParams(spec),
		Targets: []policy.Target{{
			Ref:          domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID},
			Capabilities: policy.NewCapabilitySet(spec.Capability),
		}},
	})
}

func TestDefaultPolicy_McpOperateWritesWaitForApproval(t *testing.T) {
	f, _, _ := newMCPOperateFixture(t, true)
	for _, action := range mcpOperateWrites {
		res := f.mcpDecision(t, action)
		if res.Decision != policy.DecisionAllow || !res.ApprovalRequired {
			t.Errorf("%s: %s approval=%v, want allow awaiting approval", action, res.Decision, res.ApprovalRequired)
		}
	}
}

func TestDefaultPolicy_McpProbeRunsWithoutApprovalOnceWritesAreOn(t *testing.T) {
	on, _, _ := newMCPOperateFixture(t, true)
	off, _, _ := newMCPOperateFixture(t, false)

	if res := on.mcpDecision(t, "node.probe"); res.Decision != policy.DecisionAllow || res.ApprovalRequired {
		t.Errorf("writes on: %s approval=%v, want allow without approval", res.Decision, res.ApprovalRequired)
	}
	wantDenied(t, off.mcpDecision(t, "node.probe"), smerr.ReasonMCPWritesDisabled, "probe, writes off")
}

func TestDefaultPolicy_McpWritesOffRefusesEveryGrantedWrite(t *testing.T) {
	f, _, _ := newMCPOperateFixture(t, false)
	for _, action := range mcpOperateWrites {
		wantDenied(t, f.mcpDecision(t, action), smerr.ReasonMCPWritesDisabled, action)
	}
}

func TestDefaultPolicy_McpDoesNotGetAdminReach(t *testing.T) {
	f, _, _ := newMCPOperateFixture(t, true)
	for _, action := range []string{"node.shutdown", "backup.create", "node.tunnel.disable", "cloudflare.access_token.rotate", "node_route.expose"} {
		if res := f.mcpDecision(t, action); res.Decision == policy.DecisionAllow {
			t.Errorf("%s is allowed to an mcp actor by default", action)
		}
	}
}

func TestPlansCreate_SnapshotDeleteByMCPIsRefusedAndNothingIsStored(t *testing.T) {
	f, assistant, _ := newMCPOperateFixture(t, true)
	before := f.count("SELECT COUNT(*) FROM plans")

	_, err := f.plans.Create(context.Background(), f.caller(assistant), PlanRequest{
		Action: "proxmox.snapshot.delete", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID},
	})

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonMCPActionForbidden)
	if after := f.count("SELECT COUNT(*) FROM plans"); after != before {
		t.Errorf("plans = %d, want %d: a refused plan was stored", after, before)
	}
}

func TestPlansCreate_WritesOffStillStoresTheDeniedPlan(t *testing.T) {
	f, assistant, _ := newMCPOperateFixture(t, false)

	created, err := f.plans.Create(context.Background(), f.caller(assistant), f.reboot())

	if err != nil || created.Policy.Reason != smerr.ReasonMCPWritesDisabled {
		t.Errorf("Create = %s, %v; want the plan stored with MCP_WRITES_DISABLED", created.Policy.Reason, err)
	}
}

func (f *fixture) submitRebootAs(t *testing.T, identity domain.ID) Submission {
	t.Helper()
	created, err := f.plans.Create(context.Background(), f.caller(identity), f.reboot())
	mustf(t, err, "Create")
	sub, err := f.plans.Submit(context.Background(), f.caller(identity), created.Record.ID, created.Record.PlanHash)
	mustf(t, err, "Submit")
	return sub
}

func TestCancel_AnMCPActorCancelsItsOwnJob(t *testing.T) {
	f, assistant, _ := newMCPOperateFixture(t, true)
	sub := f.submitRebootAs(t, assistant)

	job, err := f.governance(t).Cancel(context.Background(), f.caller(assistant), sub.Job.ID, sub.Job.PlanHash)

	if err != nil || job.State != domain.JobCancelled {
		t.Errorf("Cancel = %s, %v", job.State, err)
	}
}

func TestCancel_AnMCPActorCannotCancelAnotherIdentitysJob(t *testing.T) {
	f, assistant, other := newMCPOperateFixture(t, true)
	g := f.governance(t)
	human, _ := f.submitReboot()
	foreign := f.submitRebootAs(t, other)

	for name, sub := range map[string]Submission{"human's job": human, "other client's job": foreign} {
		_, err := g.Cancel(context.Background(), f.caller(assistant), sub.Job.ID, sub.Job.PlanHash)

		wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonNotPlanActor)
		if f.job(sub.Job.ID).State != domain.JobAwaitingApproval {
			t.Errorf("%s: a refused cancel changed the job", name)
		}
	}
	if len(f.events("policy.deny")) == 0 {
		t.Error("the refused cancel was not audited")
	}
}

func TestPlannableByMCP_ListsOnlyWhatTheGateWouldLetBePlanned(t *testing.T) {
	var names []string
	for _, spec := range PlannableByMCP() {
		names = append(names, spec.Name)
		if spec.Mode != policy.ModeJob || spec.Risk == domain.RiskDestructive || spec.CredentialIssuing || mcpForbids(spec.Name) {
			t.Errorf("%s must not be plannable by mcp", spec.Name)
		}
	}
	for _, want := range append([]string{"node.probe"}, mcpOperateWrites...) {
		if !slices.Contains(names, want) {
			t.Errorf("%s missing from PlannableByMCP", want)
		}
	}
	for _, banned := range []string{"proxmox.snapshot.delete", "job.cancel", "node.setup", "sudoers.write", "log_broker.install", "node.connect", "secret.write", "node.add"} {
		if slices.Contains(names, banned) {
			t.Errorf("%s must not be plannable by mcp", banned)
		}
	}
}
