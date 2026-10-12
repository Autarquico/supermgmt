package deployments_test

import (
	"errors"
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

type pair struct{ from, to deployments.State }

// allowedPairs restates the §20.1 table independently of the implementation.
func allowedPairs() map[pair]bool {
	const (
		created, waiting, approval, queued = deployments.StateCreated, deployments.StateWaitingCI, deployments.StateAwaitingApproval, deployments.StateQueued
		preparing, staging, deploying      = deployments.StatePreparing, deployments.StateStaging, deployments.StateDeploying
		verifying, rolling, interrupted    = deployments.StateVerifying, deployments.StateRollingBack, deployments.StateInterrupted
		succeeded, failed, rolledBack      = deployments.StateSucceeded, deployments.StateFailed, deployments.StateRolledBack
		rollbackFailed, cancelled          = deployments.StateRollbackFailed, deployments.StateCancelled
	)
	type states = []deployments.State
	m := map[pair]bool{}
	add := func(from states, to ...deployments.State) {
		for _, f := range from {
			for _, t := range to {
				m[pair{f, t}] = true
			}
		}
	}
	add(states{created}, waiting, approval, queued, failed)
	add(states{waiting}, approval, queued, failed)
	add(states{approval}, queued, failed)
	add(states{queued}, preparing, approval, failed)
	add(states{preparing}, staging, failed)
	add(states{staging}, deploying, failed)
	add(states{deploying}, verifying, rolling, failed)
	add(states{verifying}, succeeded, rolling, failed)
	add(states{rolling}, rolledBack, rollbackFailed)
	add(states{created, waiting, approval, queued, preparing}, cancelled)
	add(states{preparing, staging, deploying, verifying, rolling}, interrupted)
	add(states{interrupted}, preparing, staging, deploying, verifying, rolling,
		failed, succeeded, rolledBack, rollbackFailed)
	return m
}

func TestDeploymentState_TransitionTable(t *testing.T) {
	want := allowedPairs()
	invalid := smerr.FromReason(smerr.ReasonInvalidTransition, "")
	for _, from := range deployments.AllStates() {
		for _, to := range deployments.AllStates() {
			err := deployments.Transition(from, to)
			switch {
			case want[pair{from, to}] && err != nil:
				t.Errorf("%s -> %s: want allowed, got %v", from, to, err)
			case !want[pair{from, to}] && !errors.Is(err, invalid):
				t.Errorf("%s -> %s: want INVALID_TRANSITION, got %v", from, to, err)
			}
		}
	}
}

func TestDeploymentState_TerminalStatesHaveNoExit(t *testing.T) {
	for _, from := range deployments.AllStates() {
		if !from.Terminal() {
			continue
		}
		for _, to := range deployments.AllStates() {
			if deployments.Transition(from, to) == nil {
				t.Errorf("terminal %s -> %s allowed", from, to)
			}
		}
	}
}

func TestDeploymentState_CancelImpossibleFromStaging(t *testing.T) {
	for _, from := range []deployments.State{
		deployments.StateStaging, deployments.StateDeploying, deployments.StateVerifying,
		deployments.StateRollingBack, deployments.StateInterrupted,
	} {
		if deployments.Transition(from, deployments.StateCancelled) == nil {
			t.Errorf("%s -> cancelled allowed", from)
		}
	}
}

func TestDeploymentState_Predicates(t *testing.T) {
	set := func(states ...deployments.State) map[deployments.State]bool {
		m := map[deployments.State]bool{}
		for _, s := range states {
			m[s] = true
		}
		return m
	}
	terminal := set(deployments.StateSucceeded, deployments.StateFailed, deployments.StateRolledBack,
		deployments.StateRollbackFailed, deployments.StateCancelled)
	provisional := set(deployments.StateCreated, deployments.StateWaitingCI)
	mutated := set(deployments.StateDeploying, deployments.StateVerifying, deployments.StateRollingBack,
		deployments.StateSucceeded, deployments.StateRolledBack, deployments.StateRollbackFailed)
	for _, s := range deployments.AllStates() {
		if got := s.Terminal(); got != terminal[s] {
			t.Errorf("%s.Terminal() = %v", s, got)
		}
		if got := s.Provisional(); got != provisional[s] {
			t.Errorf("%s.Provisional() = %v", s, got)
		}
		if got := s.MutationStarted(); got != mutated[s] {
			t.Errorf("%s.MutationStarted() = %v", s, got)
		}
	}
}

func TestCoarseJobState(t *testing.T) {
	want := map[deployments.State]domain.JobState{
		deployments.StateCreated:          domain.JobAwaitingApproval,
		deployments.StateWaitingCI:        domain.JobAwaitingApproval,
		deployments.StateAwaitingApproval: domain.JobAwaitingApproval,
		deployments.StateQueued:           domain.JobQueued,
		deployments.StatePreparing:        domain.JobRunning,
		deployments.StateStaging:          domain.JobRunning,
		deployments.StateDeploying:        domain.JobRunning,
		deployments.StateVerifying:        domain.JobRunning,
		deployments.StateRollingBack:      domain.JobRunning,
		deployments.StateInterrupted:      domain.JobInterrupted,
		deployments.StateSucceeded:        domain.JobSucceeded,
		deployments.StateFailed:           domain.JobFailed,
		deployments.StateRolledBack:       domain.JobFailed,
		deployments.StateRollbackFailed:   domain.JobFailed,
		deployments.StateCancelled:        domain.JobCancelled,
	}
	for _, s := range deployments.AllStates() {
		got := deployments.CoarseJobState(s)
		if got != want[s] {
			t.Errorf("CoarseJobState(%s) = %s, want %s", s, got, want[s])
		}
		if got.Terminal() != s.Terminal() {
			t.Errorf("%s: coarse terminality disagrees with fine terminality", s)
		}
	}
}
