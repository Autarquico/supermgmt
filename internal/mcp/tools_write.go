package mcp

import (
	"context"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The write tools (spec §24), registered only when mcp.write_tools_enabled
// is set. None of them executes anything directly: policy decides at the API
// and an mcp identity's writes of operational risk or more need approval.
func addWriteTools(s *sdk.Server, api API) {
	actionTool(s, submitPlanTool,
		"Submit a plan created by infra_plan_action, with the plan_id and plan_hash it returned.",
		func(ctx context.Context, in submitPlanInput) (WriteResult, error) {
			plan, err := domain.ParseID(in.PlanID)
			if err != nil {
				return WriteResult{}, invalidArgument("plan_id is not a valid id")
			}
			if in.PlanHash == "" {
				return WriteResult{}, invalidArgument("plan_hash is required")
			}
			submission, err := api.SubmitPlan(ctx, plan, in.PlanHash)
			return submissionResult(submission), err
		})
	actionTool(s, "infra_restart_service",
		"Plan and submit a restart of one service (id or name@node). The result says whether approval is required.",
		func(ctx context.Context, in refInput) (WriteResult, error) {
			return planAndSubmit(ctx, api, "service.restart", planTarget{Type: string(domain.ResourceService), Ref: in.Ref})
		})
	actionTool(s, "infra_reboot_node",
		"Plan and submit a reboot of one node (id or exact name). The result says whether approval is required.",
		func(ctx context.Context, in refInput) (WriteResult, error) {
			return planAndSubmit(ctx, api, "node.reboot", planTarget{Type: string(domain.ResourceNode), Ref: in.Ref})
		})
	actionTool(s, "infra_expose_port",
		"Publish a port of a node at a hostname through its Cloudflare Tunnel. Access defaults to public: reachable from the internet with no authentication, which is high risk; owners puts it behind Cloudflare Access. A request from an MCP client always waits for a person to approve it, and no route exists until then.",
		func(ctx context.Context, in exposePortInput) (WriteResult, error) { return exposePort(ctx, api, in) })
	actionTool(s, "infra_unexpose_port",
		"Remove the route of a hostname from a node. It removes the DNS record, then the ingress rule, then the Access app. A request from an MCP client always waits for a person to approve it.",
		func(ctx context.Context, in unexposePortInput) (WriteResult, error) {
			return unexposePort(ctx, api, in)
		})
}

// actionTool registers a tool that may change state. Its schema is versioned
// like every other tool's.
func actionTool[In, Out any](s *sdk.Server, name, description string, handler func(context.Context, In) (Out, error)) {
	tool := &sdk.Tool{
		Name:        name,
		Description: description,
		Meta:        sdk.Meta{SchemaVersionMetaKey: SchemaVersion},
	}
	sdk.AddTool(s, tool, func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, Out, error) {
		out, err := handler(ctx, in)
		if err != nil {
			var none Out
			return nil, none, toolFailure(err)
		}
		return nil, out, nil
	})
}

// ---- inputs -------------------------------------------------------------------

type submitPlanInput struct {
	PlanID   string `json:"plan_id" jsonschema:"plan_id returned by infra_plan_action"`
	PlanHash string `json:"plan_hash" jsonschema:"plan_hash returned by infra_plan_action"`
}

// ---- results ------------------------------------------------------------------

// planAndSubmit plans the action and submits exactly the hash that plan
// returned. A plan the policy denied is not submitted.
func planAndSubmit(ctx context.Context, api API, action string, target planTarget) (WriteResult, error) {
	created, err := requestPlan(ctx, api, action, target, nil)
	if err != nil {
		return WriteResult{}, err
	}
	if created.Policy.Decision == decisionDeny {
		return WriteResult{
			Status:   WriteDenied,
			PlanHash: &created.PlanHash,
			Summary:  fmt.Sprintf("policy denied %s on %s (plan %s)", action, target.Type, created.PlanID),
			Risk:     planRisk(created.Plan),
		}, nil
	}
	submission, err := api.SubmitPlan(ctx, created.PlanID, created.PlanHash)
	return submissionResult(submission), err
}

// submissionResult is built from control-plane fields only.
func submissionResult(s wire.Submission) WriteResult {
	status := WriteQueued
	switch {
	case s.Policy.Decision == decisionDeny:
		status = WriteDenied
	case s.Job.State == domain.JobAwaitingApproval:
		status = WriteApprovalRequired
	}
	return WriteResult{
		Status:   status,
		JobID:    &s.Job.ID,
		PlanHash: &s.Job.PlanHash,
		Summary:  fmt.Sprintf("%s on %s %s: job %s", s.Job.Type, s.Job.Resource.Type, s.Job.Resource.ID, s.Job.State),
		Risk:     string(s.Job.Risk),
	}
}
