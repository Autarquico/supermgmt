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
)

// lockModeByJobType is the mode a job takes on its own resource (spec §20.5).
//
//   - node reboot, shutdown, power, setup, sudoers and log broker: exclusive on the node.
//   - service actions: exclusive on the service's Compose project or unit (ownLock).
//   - Proxmox snapshots and backups are not listed by the spec; they take the
//     node exclusively, the conservative reading.
//   - node.probe only reads the node, so it shares it.
var lockModeByJobType = map[string]domain.LockMode{
	"node.probe":                domain.LockShared,
	"node.reboot":               domain.LockExclusive,
	"node.shutdown":             domain.LockExclusive,
	"proxmox.vm.power":          domain.LockExclusive,
	"proxmox.snapshot.create":   domain.LockExclusive,
	"proxmox.snapshot.rollback": domain.LockExclusive,
	"proxmox.snapshot.delete":   domain.LockExclusive,
	"proxmox.backup.create":     domain.LockExclusive,
	"node.setup":                domain.LockExclusive,
	"control_plane.apply":       domain.LockExclusive,
	"sudoers.write":             domain.LockExclusive,
	"log_broker.install":        domain.LockExclusive,
	"service.start":             domain.LockExclusive,
	"service.stop":              domain.LockExclusive,
	"service.restart":           domain.LockExclusive,
	"backup.create":             domain.LockExclusive,
	deploymentCreateAction:      domain.LockExclusive, // the app target (ownLock); project and ports in deploymentLocks
	deploymentRollbackAction:    domain.LockExclusive,
}

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
		if isDeploymentJob(job.Type) {
			return nil, smerr.New(smerr.CodeInternal, "", "deployment job has no plan to take its locks from")
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
		held, err := deploymentLocks(ctx, q, job, *stored)
		if err != nil {
			return nil, err
		}
		specs = append(specs, held...)
	}
	for _, in := range stored.Inputs {
		ref := domain.ResourceRef{Type: domain.ResourceType(in.Type), ID: domain.ID(in.ID)}
		specs = append(specs, domain.ResourceLock(ref, domain.LockShared))
	}
	return specs, nil
}

func isDeploymentJob(jobType string) bool {
	return jobType == deploymentCreateAction || jobType == deploymentRollbackAction
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
	specs := []domain.LockSpec{domain.ComposeProjectLock(target.NodeID, target.ComposeProject, domain.LockExclusive)}
	seen := map[netip.AddrPort]bool{}
	for _, published := range ports {
		endpoint, err := netip.ParseAddrPort(strings.TrimSuffix(published, "/udp"))
		if err != nil {
			return nil, smerr.Wrap(err, smerr.CodeInternal, "", "plan names an unreadable host port "+published)
		}
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		specs = append(specs, domain.PortLock(target.NodeID, endpoint.Addr().String(), int(endpoint.Port()), domain.LockExclusive))
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
