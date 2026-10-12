package deployments

import (
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// transitions is the exhaustive §20.1 table. Any pair not listed is rejected.
var transitions = map[State][]State{
	StateCreated:          {StateWaitingCI, StateAwaitingApproval, StateQueued, StateFailed, StateCancelled},
	StateWaitingCI:        {StateAwaitingApproval, StateQueued, StateFailed, StateCancelled},
	StateAwaitingApproval: {StateQueued, StateFailed, StateCancelled},
	StateQueued:           {StatePreparing, StateAwaitingApproval, StateFailed, StateCancelled},
	StatePreparing:        {StateStaging, StateFailed, StateCancelled, StateInterrupted},
	StateStaging:          {StateDeploying, StateFailed, StateInterrupted},
	StateDeploying:        {StateVerifying, StateRollingBack, StateFailed, StateInterrupted},
	StateVerifying:        {StateSucceeded, StateRollingBack, StateFailed, StateInterrupted},
	StateRollingBack:      {StateRolledBack, StateRollbackFailed, StateInterrupted},
	StateInterrupted: {
		StatePreparing, StateStaging, StateDeploying, StateVerifying, StateRollingBack,
		StateFailed, StateSucceeded, StateRolledBack, StateRollbackFailed,
	},
}

var terminalStates = []State{StateSucceeded, StateFailed, StateRolledBack, StateRollbackFailed, StateCancelled}

var mutatedStates = []State{
	StateDeploying, StateVerifying, StateRollingBack, StateSucceeded, StateRolledBack, StateRollbackFailed,
}

// coarse lists every state that does not map to a failed job.
var coarse = map[State]domain.JobState{
	StateCreated:          domain.JobAwaitingApproval,
	StateWaitingCI:        domain.JobAwaitingApproval,
	StateAwaitingApproval: domain.JobAwaitingApproval,
	StateQueued:           domain.JobQueued,
	StatePreparing:        domain.JobRunning,
	StateStaging:          domain.JobRunning,
	StateDeploying:        domain.JobRunning,
	StateVerifying:        domain.JobRunning,
	StateRollingBack:      domain.JobRunning,
	StateInterrupted:      domain.JobInterrupted,
	StateSucceeded:        domain.JobSucceeded,
	StateCancelled:        domain.JobCancelled,
}

// Transition returns nil when §20.1 allows from -> to and an INVALID_TRANSITION
// error otherwise.
func Transition(from, to State) error {
	if slices.Contains(transitions[from], to) {
		return nil
	}
	return smerr.FromReason(smerr.ReasonInvalidTransition,
		fmt.Sprintf("deployment cannot move from %q to %q", from, to))
}

// Terminal reports whether no further transition is possible.
func (s State) Terminal() bool {
	return slices.Contains(terminalStates, s)
}

// Provisional reports whether the deployment still holds only provisional
// inputs and no locks (§20.0).
func (s State) Provisional() bool {
	return s == StateCreated || s == StateWaitingCI
}

// MutationStarted reports whether the state implies running services were
// touched: deploying and the states reachable only through it. failed and
// interrupted are excluded because the state alone cannot tell; the
// deployments.mutation_started column decides for them.
func (s State) MutationStarted() bool {
	return slices.Contains(mutatedStates, s)
}

// CoarseJobState is the job state that mirrors s (ADR-0029). A provisional
// deployment maps to awaiting_approval so no worker can claim it. A rolled
// back deployment did not reach its goal, so its job is failed.
func CoarseJobState(s State) domain.JobState {
	if job, ok := coarse[s]; ok {
		return job
	}
	return domain.JobFailed
}
