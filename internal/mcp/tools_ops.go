package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The read tools for the operations plane: jobs, approvals, plans, providers,
// backups, enrollments, the instance key and the plannable actions.
func addOperationReadTools(s *sdk.Server, api API) {
	readTool(s, "infra_list_jobs",
		"List jobs, newest first, optionally only those in the given states (awaiting_approval, queued, running, interrupted, succeeded, failed, cancelled). Pass next_cursor back as cursor for the next page."+remoteDataNotice,
		func(ctx context.Context, in listJobsInput) (listResult[JobView], error) {
			page, err := api.ListJobs(ctx, wire.JobQuery{PageQuery: in.pageQuery(), States: in.jobStates()})
			return listOf(page, viewJob), err
		})
	readTool(s, "infra_get_job",
		"Get one job by id: its state, plan hash and, when it failed, why. Poll it after a write tool to follow what was submitted. While it is awaiting_approval, a person must approve it: tell the user rather than polling."+remoteDataNotice,
		func(ctx context.Context, in jobInput) (JobView, error) {
			id, err := requiredID("id", in.ID)
			if err != nil {
				return JobView{}, err
			}
			detail, err := api.GetJob(ctx, id)
			return viewJob(detail.Job), err
		})
	readTool(s, "infra_list_approvals",
		"List the jobs awaiting approval with the plan each one binds to. Approving is for a person; this only shows what waits. Pass next_cursor back as cursor for the next page."+remoteDataNotice,
		func(ctx context.Context, in pageInput) (listResult[ApprovalView], error) {
			page, err := api.ListApprovals(ctx, in.pageQuery())
			if err != nil {
				return listResult[ApprovalView]{}, err
			}
			return listOfChecked(page, ViewApproval)
		})
	readTool(s, "infra_get_plan",
		"Get a plan by id: the canonical document, its hash, expiry and the policy verdict."+remoteDataNotice,
		func(ctx context.Context, in planInput) (PlanView, error) {
			id, err := requiredID("plan_id", in.PlanID)
			if err != nil {
				return PlanView{}, err
			}
			plan, err := api.GetPlan(ctx, id)
			if err != nil {
				return PlanView{}, err
			}
			return ViewCreatedPlan(plan)
		})
	readTool(s, "infra_list_providers",
		"List the providers nodes are discovered from, with the state of their latest sync. Pass next_cursor back as cursor for the next page."+remoteDataNotice,
		func(ctx context.Context, in pageInput) (listResult[ProviderView], error) {
			page, err := api.ListProviders(ctx, in.pageQuery())
			return listOf(page, ViewProvider), err
		})
	readTool(s, "infra_get_provider",
		"Get one provider by id or exact name."+remoteDataNotice,
		func(ctx context.Context, in providerInput) (ProviderView, error) {
			provider, err := findProvider(ctx, api, in.Ref)
			return ViewProvider(provider), err
		})
	readTool(s, "infra_list_backups",
		"List the available backup archives of this SuperMgmt instance.",
		func(ctx context.Context, _ struct{}) (listResult[BackupView], error) {
			page, err := api.ListBackups(ctx)
			return listOf(page, ViewBackup), err
		})
	readTool(s, "infra_get_status",
		"Summarize this instance: who the caller is, how many nodes there are by reachability, and how many jobs are unfinished by state."+remoteDataNotice,
		func(ctx context.Context, _ struct{}) (StatusView, error) {
			return status(ctx, api)
		})
	readTool(s, "infra_list_tunnel_enrollments",
		"List the nodes being enrolled through a Cloudflare Tunnel and how far each one got."+remoteDataNotice,
		func(ctx context.Context, _ struct{}) (listResult[TunnelEnrollmentView], error) {
			page, err := api.ListTunnelEnrollments(ctx)
			return listOf(page, ViewTunnelEnrollment), err
		})
	readTool(s, "infra_get_ssh_key",
		"Get the public half of the SSH identity this instance uses to reach nodes, as an authorized_keys line.",
		func(ctx context.Context, _ struct{}) (SSHKeyView, error) {
			key, err := api.SSHKey(ctx)
			return ViewSSHKey(key), err
		})
	readTool(s, "infra_list_actions",
		"List the actions infra_plan_action may be asked to plan, with their parameters and risk. Policy still decides per target whether the caller may run one; every action here needs write tools.",
		func(ctx context.Context, _ struct{}) (listResult[ActionView], error) {
			page, err := api.ListActions(ctx)
			return listOf(page, ViewAction), err
		})
}

type listJobsInput struct {
	pageInput
	States []string `json:"states,omitempty" jsonschema:"only jobs in these states"`
}

func (in listJobsInput) jobStates() []domain.JobState {
	states := make([]domain.JobState, len(in.States))
	for i, state := range in.States {
		states[i] = domain.JobState(state)
	}
	return states
}

type jobInput struct {
	ID string `json:"id" jsonschema:"job id"`
}

type planInput struct {
	PlanID string `json:"plan_id" jsonschema:"plan id"`
}

type providerInput struct {
	Ref string `json:"ref" jsonschema:"provider id or exact name"`
}

func requiredID(field, raw string) (domain.ID, error) {
	id, err := optionalID(field, raw)
	if err == nil && id == "" {
		return "", invalidArgument(field + " is required")
	}
	return id, err
}

// listOfChecked is listOf for views that can fail to decode.
func listOfChecked[T, V any](page wire.Page[T], view func(T) (V, error)) (listResult[V], error) {
	items := make([]V, len(page.Items))
	for i, item := range page.Items {
		v, err := view(item)
		if err != nil {
			return listResult[V]{}, err
		}
		items[i] = v
	}
	return listResult[V]{Items: items, NextCursor: page.NextCursor}, nil
}

// activeJobStates are the states of a job that has not finished.
var activeJobStates = []domain.JobState{
	domain.JobAwaitingApproval, domain.JobQueued, domain.JobRunning, domain.JobInterrupted,
}

func status(ctx context.Context, api API) (StatusView, error) {
	me, err := api.Me(ctx)
	if err != nil {
		return StatusView{}, err
	}
	nodes, nodesCut, err := allPages(ctx, func(cursor string) (wire.Page[wire.Node], error) {
		return api.ListNodes(ctx, wire.NodeQuery{PageQuery: resolvePage(cursor)})
	})
	if err != nil {
		return StatusView{}, err
	}
	jobs, jobsCut, err := allPages(ctx, func(cursor string) (wire.Page[wire.Job], error) {
		return api.ListJobs(ctx, wire.JobQuery{PageQuery: resolvePage(cursor), States: activeJobStates})
	})
	if err != nil {
		return StatusView{}, err
	}
	view := StatusView{
		Identity: ViewIdentity(me),
		Nodes:    NodeCounts{Total: len(nodes), ByReachability: map[string]int{}, Truncated: nodesCut},
		Jobs:     JobCounts{Unfinished: len(jobs), ByState: map[string]int{}, Truncated: jobsCut},
	}
	for _, n := range nodes {
		view.Nodes.ByReachability[string(n.Reachability)]++
	}
	for _, j := range jobs {
		view.Jobs.ByState[string(j.State)]++
	}
	return view, nil
}

// allPages reads a listing to its end, or to maxResolvePages pages, in which
// case cut is true.
func allPages[T any](ctx context.Context, fetch func(cursor string) (wire.Page[T], error)) (items []T, cut bool, _ error) {
	cursor := ""
	for range maxResolvePages {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		page, err := fetch(cursor)
		if err != nil {
			return nil, false, err
		}
		items = append(items, page.Items...)
		if page.NextCursor == "" {
			return items, false, nil
		}
		cursor = page.NextCursor
	}
	return items, true, nil
}
