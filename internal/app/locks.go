package app

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// lockModeByJobType is the mode a job takes on its own resource (spec §20.5).
//
//   - node reboot, shutdown, power, setup, sudoers and log broker: exclusive on the node.
//   - service actions: exclusive on the service's Compose project or unit (ownLock).
//   - Proxmox snapshots and backups are not listed by the spec; they take the
//     node exclusively, the conservative reading.
//   - node.probe only reads the node, so it shares it.
var lockModeByJobType = map[string]domain.LockMode{
	"node.probe":                     domain.LockShared,
	"node.reboot":                    domain.LockExclusive,
	"node.shutdown":                  domain.LockExclusive,
	"proxmox.vm.power":               domain.LockExclusive,
	"proxmox.snapshot.create":        domain.LockExclusive,
	"proxmox.snapshot.rollback":      domain.LockExclusive,
	"proxmox.snapshot.delete":        domain.LockExclusive,
	"proxmox.backup.create":          domain.LockExclusive,
	"node.setup":                     domain.LockExclusive,
	"node.tunnel.disable":            domain.LockExclusive,
	"cloudflare.access_token.rotate": domain.LockExclusive,
	"control_plane.apply":            domain.LockExclusive,
	"sudoers.write":                  domain.LockExclusive,
	"log_broker.install":             domain.LockExclusive,
	"service.start":                  domain.LockExclusive,
	"service.stop":                   domain.LockExclusive,
	"service.restart":                domain.LockExclusive,
	"backup.create":                  domain.LockExclusive,
	deploymentCreateAction:           domain.LockExclusive, // the app target (ownLock); project and ports in deploymentLocks
	deploymentRollbackAction:         domain.LockExclusive,
	appMoveAction:                    domain.LockExclusive, // the app target (ownLock); projects and ports of both nodes in moveLocks
	appMoveCleanupAction:             domain.LockExclusive, // the app target; the source's project in moveLocks
	appMoveAbandonAction:             domain.LockExclusive,
}

// cloudflareInstanceLock serializes the jobs that touch the instance-wide
// Cloudflare objects (service token, reusable policies) across every node. It
// is also the ingress lock: every job that writes a node tunnel's ingress
// (setup, disable, expose, unexpose) holds it and recomputes the list after
// acquiring it (ADR-0040).
var cloudflareInstanceLock = domain.LockSpec{Key: "cloudflare:instance", Mode: domain.LockExclusive}

// ownLock is the lock on the job's own resource. A service is locked through
// what runs it (spec §20.5): its Compose project on the node when the service
// row records one (metadata "compose_project"), else its systemd unit or its
// Docker container. A service row with none of them cannot be locked, so its
// actions are not executable and the job fails with a typed error.
func ownLock(ctx context.Context, q database.Querier, job jobs.Job, mode domain.LockMode) (domain.LockSpec, error) {
	if job.Resource.Type != domain.ResourceService {
		return domain.ResourceLock(job.Resource, mode), nil
	}
	service, err := database.GetService(ctx, q, job.Resource.ID)
	if err != nil {
		return domain.LockSpec{}, err
	}
	return serviceLock(service, mode)
}

// serviceLock names what a service is locked by; UNIT_NOT_ELIGIBLE when the
// row records neither a Compose project nor a unit. Plan creation applies the
// same rule, so this is the claim-time defense.
func serviceLock(service domain.Service, mode domain.LockMode) (domain.LockSpec, error) {
	if project, _ := service.Metadata["compose_project"].(string); project != "" {
		return domain.ComposeProjectLock(service.NodeID, project, mode), nil
	}
	if service.NativeID != "" {
		switch domain.ServiceKind(service.Kind) {
		case domain.ServiceSystemdUnit:
			return domain.LockSpec{Key: fmt.Sprintf("unit:%s:%s", service.NodeID, service.NativeID), Mode: mode}, nil
		case domain.ServiceDockerContainer:
			return domain.LockSpec{Key: fmt.Sprintf("container:%s:%s", service.NodeID, service.NativeID), Mode: mode}, nil
		}
	}
	return domain.LockSpec{}, smerr.FromReason(smerr.ReasonUnitNotEligible,
		"service has neither a compose project, a unit nor a container to lock; its actions are not executable")
}

// LockPlanner implements jobs.LockPlanner for the M0 job-mode actions.
type LockPlanner struct{}

var _ jobs.LockPlanner = LockPlanner{}

// PlanLocks locks the job's resource in the mode its type needs and every
// other plan input shared. A deployment also takes its Compose project and
// every host port it or its rollback target publishes exclusively (spec §20.5). A job type without an
// entry is an error: a job that cannot name its locks must not run.
func (LockPlanner) PlanLocks(ctx context.Context, q database.Querier, job jobs.Job) ([]domain.LockSpec, error) {
	mode, known := lockModeByJobType[job.Type]
	if !known {
		return nil, smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "no lock plan for job type "+job.Type)
	}
	own, err := ownLock(ctx, q, job, mode)
	if err != nil {
		return nil, err
	}
	specs := []domain.LockSpec{own}
	if job.PlanID == nil {
		if isDeploymentJob(job.Type) || isMoveAction(job.Type) {
			return nil, smerr.New(smerr.CodeInternal, "", job.Type+" job has no plan to take its locks from")
		}
		return specs, nil
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	if err != nil {
		return nil, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return nil, err
	}
	if isDeploymentJob(job.Type) {
		if err := requireNoOpenMove(ctx, q, job.Resource.ID); err != nil { // claim-time refusal of ADR-0041
			return nil, err
		}
		held, err := deploymentLocks(ctx, q, job, *stored)
		if err != nil {
			return nil, err
		}
		specs = append(specs, held...)
	}
	tunnelSetup := job.Type == policy.ActionNodeSetup && stored.Parameters[policy.ParamTunnel] == "true"
	if err := requireNoRoutedMoveForJob(ctx, q, job, stored.Action, tunnelSetup); err != nil { // claim-time refusal of ADR-0042
		return nil, err
	}
	if isMoveAction(job.Type) {
		held, err := moveLocks(ctx, q, job, *stored)
		if err != nil {
			return nil, err
		}
		specs = append(specs, held...)
	}
	if tunnelSetup ||
		job.Type == policy.ActionCloudflareRotate || job.Type == policy.ActionNodeTunnelDisable ||
		job.Type == JobControlPlaneApply && isAppRouteAction(stored.Action) { // the route job moves its route under the app target's lock
		specs = append(specs, cloudflareInstanceLock)
	}
	instance, err := enrollmentInstanceLock(ctx, q, job, *stored)
	if err != nil {
		return nil, err
	}
	specs = append(specs, instance...)
	for _, in := range stored.Inputs {
		ref := domain.ResourceRef{Type: domain.ResourceType(in.Type), ID: domain.ID(in.ID)}
		specs = append(specs, domain.ResourceLock(ref, domain.LockShared))
	}
	return specs, nil
}

func isDeploymentJob(jobType string) bool {
	return jobType == deploymentCreateAction || jobType == deploymentRollbackAction
}

// moveLocks are the exclusive locks of a move beyond its app target, taken from the nodes the plan froze and never
// from the target's live node, which the commit changes (spec §13): the Compose project and each host port of the
// known-good model on both nodes, and the instance Cloudflare lock when the plan carries routes (ADR-0042).
// Cleanup holds the project of the source node only; an abandon touches no node. The nodes themselves are plan
// inputs, locked shared.
func moveLocks(ctx context.Context, q database.Querier, job jobs.Job, p plan.Plan) ([]domain.LockSpec, error) {
	if job.Type == appMoveAbandonAction {
		return nil, nil
	}
	target, err := database.GetAppTarget(ctx, q, job.Resource.ID)
	if err != nil {
		return nil, err
	}
	nodes := plannedNodes(p)
	var specs []domain.LockSpec
	switch job.Type {
	case appMoveAction:
		if len(nodes) != 2 {
			return nil, smerr.New(smerr.CodeInternal, "", "a move plan must freeze exactly two nodes")
		}
		for _, node := range nodes {
			held, err := projectAndPortLocks(node, target.ComposeProject, p.Content.HostPorts)
			if err != nil {
				return nil, err
			}
			specs = append(specs, held...)
		}
		if slices.ContainsFunc(p.Inputs, func(in plan.Input) bool { return in.Type == moveRouteInputType }) {
			specs = append(specs, cloudflareInstanceLock)
		}
	case appMoveCleanupAction:
		if len(nodes) != 1 {
			return nil, smerr.New(smerr.CodeInternal, "", "a cleanup plan must freeze exactly one node")
		}
		specs = append(specs, domain.ComposeProjectLock(nodes[0], target.ComposeProject, domain.LockExclusive))
	}
	return specs, nil
}

// plannedNodes are the nodes a plan pins, in input order.
func plannedNodes(p plan.Plan) []domain.ID {
	var nodes []domain.ID
	for _, in := range p.Inputs {
		if in.Type == string(domain.ResourceNode) {
			nodes = append(nodes, domain.ID(in.ID))
		}
	}
	return nodes
}

// deploymentLocks are the exclusive locks of a deployment beyond its app
// target: the Compose project and each host port on the target's node that
// the plan or its frozen rollback target publishes. Both are known at
// finalization, so the set is identical before and after a safety-recovery
// claim, which redeploys that rollback target (ADR-0029).
func deploymentLocks(ctx context.Context, q database.Querier, job jobs.Job, p plan.Plan) ([]domain.LockSpec, error) {
	target, err := database.GetAppTarget(ctx, q, job.Resource.ID)
	if err != nil {
		return nil, err
	}
	ports, err := lockedHostPorts(ctx, q, p)
	if err != nil {
		return nil, err
	}
	return projectAndPortLocks(target.NodeID, target.ComposeProject, ports)
}

// projectAndPortLocks are the exclusive locks on node of a Compose project and of each distinct host port that
// is published (addr:port, with /udp for UDP).
func projectAndPortLocks(node domain.ID, project string, published []string) ([]domain.LockSpec, error) {
	specs := []domain.LockSpec{domain.ComposeProjectLock(node, project, domain.LockExclusive)}
	seen := map[netip.AddrPort]bool{}
	for _, port := range published {
		endpoint, err := netip.ParseAddrPort(strings.TrimSuffix(port, "/udp"))
		if err != nil {
			return nil, smerr.Wrap(err, smerr.CodeInternal, "", "plan names an unreadable host port "+port)
		}
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		specs = append(specs, domain.PortLock(node, endpoint.Addr().String(), int(endpoint.Port()), domain.LockExclusive))
	}
	return specs, nil
}

// lockedHostPorts are the plan's host ports followed by those of its frozen
// rollback target, if any.
func lockedHostPorts(ctx context.Context, q database.Querier, p plan.Plan) ([]string, error) {
	ports := slices.Clone(p.Content.HostPorts)
	if p.Content.RollbackTarget == nil {
		return ports, nil
	}
	good, err := database.GetDeployment(ctx, q, domain.ID(p.Content.RollbackTarget.DeploymentID))
	if err != nil {
		return nil, err
	}
	if good.PlanID == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "rollback target "+good.ID.String()+" has no plan to take its ports from")
	}
	rec, err := database.GetPlan(ctx, q, *good.PlanID)
	if err != nil {
		return nil, err
	}
	frozen, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return nil, err
	}
	return append(ports, frozen.Content.HostPorts...), nil
}
