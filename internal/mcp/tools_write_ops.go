package mcp

import (
	"context"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/domain"
)

// The operate tools: service and node power, guests, backups, jobs, providers and the
// tunnel. Plans go through planAndSubmit; the routes that submit by themselves return their
// own Submission. No tool takes a plan hash from the model.

type powerGuestInput struct {
	Ref  string `json:"ref" jsonschema:"node id or exact name of the Proxmox guest"`
	Verb string `json:"verb" jsonschema:"start, shutdown (clean), reboot or stop (cuts the power; high risk)"`
}

type cancelJobInput struct {
	ID string `json:"id" jsonschema:"id of a queued or awaiting_approval job this client submitted"`
}

func addOperateTools(s *sdk.Server, api API) {
	node := func(action string) func(context.Context, refInput) (WriteResult, error) {
		return func(ctx context.Context, in refInput) (WriteResult, error) {
			return planAndSubmit(ctx, api, action, planTarget{Type: string(domain.ResourceNode), Ref: in.Ref}, nil)
		}
	}
	instance := func(action string) func(context.Context, struct{}) (WriteResult, error) {
		return func(ctx context.Context, _ struct{}) (WriteResult, error) {
			return planAndSubmit(ctx, api, action, planTarget{Type: string(domain.ResourceInstance)}, nil)
		}
	}
	service := func(action string) func(context.Context, refInput) (WriteResult, error) {
		return func(ctx context.Context, in refInput) (WriteResult, error) {
			return planAndSubmit(ctx, api, action, planTarget{Type: string(domain.ResourceService), Ref: in.Ref}, nil)
		}
	}
	actionTool(s, "infra_start_service",
		"Plan and submit a start of one service (id or name@node). The result says whether approval is required.",
		service("service.start"))
	actionTool(s, "infra_stop_service",
		"Plan and submit a stop of one service (id or name@node). The result says whether approval is required.",
		service("service.stop"))
	actionTool(s, "infra_shutdown_node",
		"Plan and submit a shutdown of one node (id or exact name). The node stays down until someone powers it on; high risk, so it needs approval. The default policy does not grant this; it needs a policy rule for type:mcp.",
		node("node.shutdown"))
	actionTool(s, "infra_probe_node",
		"Probe one node over SSH (id or exact name) to refresh what is known of it. Read risk: it does not wait for approval.",
		func(ctx context.Context, in refInput) (WriteResult, error) {
			id, err := resolveNode(ctx, api, in.Ref)
			if err != nil {
				return WriteResult{}, err
			}
			submission, err := api.ProbeNode(ctx, id)
			return submissionResult(submission), err
		})
	actionTool(s, "infra_power_guest",
		"Plan and submit a power action on a Proxmox VM or container, given as its node (id or exact name). stop cuts the power at once and is high risk.",
		func(ctx context.Context, in powerGuestInput) (WriteResult, error) {
			if in.Verb == "" {
				return WriteResult{}, invalidArgument("verb is required")
			}
			return planAndSubmit(ctx, api, "proxmox.vm.power",
				planTarget{Type: string(domain.ResourceNode), Ref: in.Ref}, map[string]any{"verb": in.Verb})
		})
	actionTool(s, "infra_snapshot_guest",
		"Plan and submit a snapshot of a Proxmox VM or container, given as its node (id or exact name). Deleting or rolling back snapshots is not available here.",
		node("proxmox.snapshot.create"))
	actionTool(s, "infra_create_backup",
		"Start a backup of the SuperMgmt instance itself. The result says whether approval is required. The default policy does not grant this; it needs a policy rule for type:mcp.",
		func(ctx context.Context, _ struct{}) (WriteResult, error) {
			submission, err := api.CreateBackup(ctx)
			return submissionResult(submission), err
		})
	actionTool(s, "infra_refresh_provider",
		"Contact one provider (id or exact name) and refresh what it reports. It reads from the provider and changes no remote state, but it dials out, so it is offered with the write tools.",
		func(ctx context.Context, in refInput) (WriteResult, error) { return refreshProvider(ctx, api, in) })
	actionTool(s, "infra_cancel_job",
		"Cancel a job that has not started (queued or awaiting approval). Only jobs this client submitted can be cancelled.",
		func(ctx context.Context, in cancelJobInput) (WriteResult, error) { return cancelJob(ctx, api, in) })
	actionTool(s, "infra_disable_tunnel",
		"Plan and submit disabling the Cloudflare Tunnel of one node (id or exact name), so the node is reached directly again. High risk, so it needs approval. The default policy does not grant this; it needs a policy rule for type:mcp.",
		node("node.tunnel.disable"))
	actionTool(s, "infra_rotate_cloudflare_access_token",
		"Plan and submit rotating the instance's Cloudflare Access token. High risk, so it needs approval. The default policy does not grant this; it needs a policy rule for type:mcp.",
		instance("cloudflare.access_token.rotate"))
}

// providerStatusError is the status the control plane gives a provider whose sync failed.
const providerStatusError = "error"

func refreshProvider(ctx context.Context, api API, in refInput) (WriteResult, error) {
	found, err := findProvider(ctx, api, in.Ref)
	if err != nil {
		return WriteResult{}, err
	}
	refreshed, err := api.RefreshProvider(ctx, found.ID)
	if err != nil {
		return WriteResult{}, err
	}
	if refreshed.Status == providerStatusError {
		return WriteResult{
			Status:  WriteFailed,
			Summary: fmt.Sprintf("provider %s: refresh failed, status %s; infra_get_provider has the provider's last_error", refreshed.ID, operatorLine(refreshed.Status)),
			Risk:    string(domain.RiskRead),
		}, nil
	}
	return WriteResult{
		Status:  WriteDone,
		Summary: fmt.Sprintf("provider %s: status %s", refreshed.ID, operatorLine(refreshed.Status)),
		Risk:    string(domain.RiskRead),
	}, nil
}

// cancelJob reads the job to cancel it with the hash the API stored, never one from the model.
func cancelJob(ctx context.Context, api API, in cancelJobInput) (WriteResult, error) {
	id, err := requiredID("id", in.ID)
	if err != nil {
		return WriteResult{}, err
	}
	detail, err := api.GetJob(ctx, id)
	if err != nil {
		return WriteResult{}, err
	}
	job, err := api.CancelJob(ctx, id, detail.Job.PlanHash)
	if err != nil {
		return WriteResult{}, err
	}
	return WriteResult{
		Status:   WriteDone,
		JobID:    &job.ID,
		PlanHash: &job.PlanHash,
		Summary:  fmt.Sprintf("%s on %s %s: job %s", job.Type, job.Resource.Type, job.Resource.ID, job.State),
		Risk:     string(job.Risk),
	}, nil
}
