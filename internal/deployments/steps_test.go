package deployments_test

import (
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain/plan"
)

var forwardPlanSteps = []string{
	"preflight", "snapshot", "pre-deploy-backup", "pull", "materialize",
	"verify-on-node", "deploy", "health-check",
}

func planWith(steps []string, target *plan.RollbackTarget) plan.Plan {
	return plan.Plan{Steps: steps, Content: plan.Content{RollbackTarget: target}}
}

func names(steps []deployments.Step) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Name
	}
	return out
}

func TestSteps_ForwardFollowsPlanOrder(t *testing.T) {
	got := deployments.Steps(planWith(forwardPlanSteps, nil), deployments.RecoveryForward)
	if !slices.Equal(names(got), forwardPlanSteps) {
		t.Fatalf("got %v, want %v", names(got), forwardPlanSteps)
	}
	for _, s := range got {
		if !s.Forward {
			t.Errorf("%s: forward step flagged as restore", s.Name)
		}
	}
}

func TestSteps_ForwardSkipsUnknownNames(t *testing.T) {
	got := deployments.Steps(planWith([]string{"preflight", "bogus", "pull"}, nil), deployments.RecoveryForward)
	if want := []string{"preflight", "pull"}; !slices.Equal(names(got), want) {
		t.Fatalf("got %v, want %v", names(got), want)
	}
}

func TestSteps_SafetyRecoveryContainsNoForwardStep(t *testing.T) {
	target := &plan.RollbackTarget{DeploymentID: "d1", ComposeHash: "sha256:x"}
	got := deployments.Steps(planWith(forwardPlanSteps, target), deployments.RecoverySafetyRecovery)
	want := []string{
		"restore-pull", "restore-materialize", "restore-verify-on-node", "restore-deploy", "restore-health-check",
	}
	if !slices.Equal(names(got), want) {
		t.Fatalf("got %v, want %v", names(got), want)
	}
	for _, s := range got {
		if s.Forward {
			t.Errorf("%s: forward step in safety recovery", s.Name)
		}
	}
}

func TestSteps_SafetyRecoveryWithoutTargetHasNothingToRestore(t *testing.T) {
	if got := deployments.Steps(planWith(forwardPlanSteps, nil), deployments.RecoverySafetyRecovery); len(got) != 0 {
		t.Fatalf("got %v, want none", names(got))
	}
}

func TestSteps_DeadlinesAndMutation(t *testing.T) {
	target := &plan.RollbackTarget{DeploymentID: "d1"}
	all := slices.Concat(
		deployments.Steps(planWith(forwardPlanSteps, nil), deployments.RecoveryForward),
		deployments.Steps(planWith(nil, target), deployments.RecoverySafetyRecovery),
	)
	want := map[string]struct {
		deadline time.Duration
		mutating bool
	}{
		"preflight":              {2 * time.Minute, false},
		"snapshot":               {10 * time.Minute, true},
		"pre-deploy-backup":      {0, true},
		"pull":                   {15 * time.Minute, true},
		"materialize":            {time.Minute, true},
		"verify-on-node":         {2 * time.Minute, false},
		"deploy":                 {10 * time.Minute, true},
		"health-check":           {0, false},
		"restore-pull":           {15 * time.Minute, true},
		"restore-materialize":    {time.Minute, true},
		"restore-verify-on-node": {2 * time.Minute, false},
		"restore-deploy":         {10 * time.Minute, true},
		"restore-health-check":   {0, false},
	}
	for _, s := range all {
		w := want[s.Name]
		if s.Deadline != w.deadline || s.Mutating != w.mutating {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", s.Name, s.Deadline, s.Mutating, w.deadline, w.mutating)
		}
	}
	if len(all) != len(want) {
		t.Errorf("covered %d steps, want %d", len(all), len(want))
	}
}
