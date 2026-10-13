package deployments

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain/plan"
)

// catalog holds the fixed attributes of every known step (ADR-0029).
var catalog = map[string]Step{
	StepPreflight:       {Name: StepPreflight, Deadline: 2 * time.Minute, Forward: true},
	StepSnapshot:        {Name: StepSnapshot, Deadline: 10 * time.Minute, Mutating: true, Forward: true},
	StepPreDeployBackup: {Name: StepPreDeployBackup, Mutating: true, Forward: true},
	StepPull:            {Name: StepPull, Deadline: 15 * time.Minute, Mutating: true, Forward: true},
	StepMaterialize:     {Name: StepMaterialize, Deadline: time.Minute, Mutating: true, Forward: true},
	StepVerifyOnNode:    {Name: StepVerifyOnNode, Deadline: 2 * time.Minute, Forward: true},
	StepDeploy:          {Name: StepDeploy, Deadline: 10 * time.Minute, Mutating: true, Forward: true},
	StepHealthCheck:     {Name: StepHealthCheck, Forward: true},

	StepRestorePull:        {Name: StepRestorePull, Deadline: 15 * time.Minute, Mutating: true},
	StepRestoreMaterialize: {Name: StepRestoreMaterialize, Deadline: time.Minute, Mutating: true},
	StepRestoreVerify:      {Name: StepRestoreVerify, Deadline: 2 * time.Minute},
	StepRestoreDeploy:      {Name: StepRestoreDeploy, Deadline: 10 * time.Minute, Mutating: true},
	StepRestoreHealthCheck: {Name: StepRestoreHealthCheck},
}

var restoreOrder = []string{
	StepRestorePull, StepRestoreMaterialize, StepRestoreVerify, StepRestoreDeploy, StepRestoreHealthCheck,
}

// Steps returns the steps to run for p under mode m. Forward mode follows the
// plan's own step list (plan steps this package does not know are skipped:
// the engine can only run what it can name). Safety recovery returns only
// restore steps, and none when the plan froze no rollback target.
func Steps(p plan.Plan, m RecoveryMode) []Step {
	if m == RecoverySafetyRecovery {
		return restoreSteps(p)
	}
	var out []Step
	for _, name := range p.Steps {
		if s, ok := catalog[name]; ok {
			out = append(out, s)
		}
	}
	return out
}

func restoreSteps(p plan.Plan) []Step {
	if p.Content.RollbackTarget == nil {
		return nil
	}
	out := make([]Step, len(restoreOrder))
	for i, name := range restoreOrder {
		out[i] = catalog[name]
	}
	return out
}
