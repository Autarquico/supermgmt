package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// lockModeByJobType is the mode a job takes on its own resource (spec §20.5).
//
//   - node reboot, shutdown, power, sudoers and log broker: exclusive on the node.
//   - service actions: exclusive on the service (its unit).
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
	"sudoers.write":             domain.LockExclusive,
	"log_broker.install":        domain.LockExclusive,
	"service.start":             domain.LockExclusive,
	"service.stop":              domain.LockExclusive,
	"service.restart":           domain.LockExclusive,
}

// LockPlanner implements jobs.LockPlanner for the M0 job-mode actions.
type LockPlanner struct{}

var _ jobs.LockPlanner = LockPlanner{}

// PlanLocks locks the job's resource in the mode its type needs and every
// other plan input shared. Compose project and host port locks arrive with
// deployments (M4). A job type without an entry is an error: a job that
// cannot name its locks must not run.
func (LockPlanner) PlanLocks(ctx context.Context, q database.Querier, job jobs.Job) ([]domain.LockSpec, error) {
	mode, known := lockModeByJobType[job.Type]
	if !known {
		return nil, smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "no lock plan for job type "+job.Type)
	}
	specs := []domain.LockSpec{domain.ResourceLock(job.Resource, mode)}
	if job.PlanID == nil {
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
	for _, in := range stored.Inputs {
		ref := domain.ResourceRef{Type: domain.ResourceType(in.Type), ID: domain.ID(in.ID)}
		specs = append(specs, domain.ResourceLock(ref, domain.LockShared))
	}
	return specs, nil
}
