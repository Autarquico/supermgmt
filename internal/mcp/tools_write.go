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
	actionTool(s, "infra_create_deployment",
		"Create a deployment of a commit and image digests on an app target. It waits for CI and, where policy requires, approval.",
		func(ctx context.Context, in createDeploymentInput) (WriteResult, error) {
			target, err := domain.ParseID(in.AppTargetID)
			if err != nil {
				return WriteResult{}, invalidArgument("app_target_id is not a valid id")
			}
			deployment, err := api.CreateDeployment(ctx, wire.CreateDeploymentRequest{
				AppTargetID: target,
				Kind:        deployKind,
				CommitSHA:   in.CommitSHA,
				Images:      in.requestedImages(),
			})
			return deploymentResult(deployment), err
		})
	actionTool(s, "infra_rollback_deployment",
		"Roll a deployment back to the newest known-good one, or to to_deployment_id. It waits for approval where policy requires.",
		func(ctx context.Context, in rollbackInput) (WriteResult, error) {
			from, err := domain.ParseID(in.DeploymentID)
			if err != nil {
				return WriteResult{}, invalidArgument("deployment_id is not a valid id")
			}
			to, err := optionalID("to_deployment_id", in.ToDeploymentID)
			if err != nil {
				return WriteResult{}, err
			}
			request := wire.RollbackRequest{}
			if to != "" {
				request.ToDeploymentID = &to
			}
			deployment, err := api.RollbackDeployment(ctx, from, request)
			return deploymentResult(deployment), err
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

type imageInput struct {
	Service string `json:"service" jsonschema:"compose service name"`
	Digest  string `json:"digest" jsonschema:"image digest, sha256:<64 hex>"`
}

type createDeploymentInput struct {
	AppTargetID string       `json:"app_target_id" jsonschema:"app target id"`
	CommitSHA   string       `json:"commit_sha" jsonschema:"commit to deploy"`
	Images      []imageInput `json:"images" jsonschema:"image digest per compose service"`
}

func (in createDeploymentInput) requestedImages() []wire.RequestedImage {
	images := make([]wire.RequestedImage, len(in.Images))
	for i, image := range in.Images {
		images[i] = wire.RequestedImage{Service: image.Service, Digest: image.Digest}
	}
	return images
}

type rollbackInput struct {
	DeploymentID   string `json:"deployment_id" jsonschema:"deployment to roll back"`
	ToDeploymentID string `json:"to_deployment_id,omitempty" jsonschema:"deployment to restore; default the newest known-good one"`
}

// Deployment values the results depend on (spec §20.1); the mcp package
// does not import the deployment state machine.
const (
	deployKind            = "deploy"
	stateCreated          = "created"
	stateWaitingCI        = "waiting_ci"
	stateAwaitingApproval = "awaiting_approval"
)

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

// deploymentResult maps the deployment state at admission to a status. The
// risk is the catalog's for deployments: a deployment has no plan until CI
// has passed.
func deploymentResult(d wire.Deployment) WriteResult {
	status := WriteQueued
	switch d.State {
	case stateCreated, stateWaitingCI:
		status = WriteWaitingCI
	case stateAwaitingApproval:
		status = WriteApprovalRequired
	}
	return WriteResult{
		Status:       status,
		JobID:        d.JobID,
		DeploymentID: &d.ID,
		PlanHash:     d.PlanHash,
		Summary:      fmt.Sprintf("%s %s on app target %s: %s", d.Kind, d.CommitSHA, d.AppTargetID, d.State),
		Risk:         string(domain.RiskOperational),
	}
}
