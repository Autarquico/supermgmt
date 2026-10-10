package jobs

import (
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// transitions is the closed table of ADR-0013.
var transitions = map[domain.JobState][]domain.JobState{
	domain.JobAwaitingApproval: {domain.JobQueued, domain.JobFailed, domain.JobCancelled},
	domain.JobQueued:           {domain.JobRunning, domain.JobAwaitingApproval, domain.JobFailed, domain.JobCancelled},
	domain.JobRunning:          {domain.JobSucceeded, domain.JobFailed, domain.JobQueued, domain.JobInterrupted},
	domain.JobInterrupted:      {domain.JobQueued, domain.JobSucceeded, domain.JobFailed},
}

func canTransition(from, to domain.JobState) bool {
	return slices.Contains(transitions[from], to)
}

func invalidTransition(from, to domain.JobState) error {
	return smerr.FromReason(smerr.ReasonInvalidTransition, fmt.Sprintf("job cannot move from %s to %s", from, to))
}

// releasesLocks reports whether entering to ends the job's hold on resources:
// locks survive running and interrupted only (ADR-0013).
func releasesLocks(to domain.JobState) bool {
	return to != domain.JobRunning && to != domain.JobInterrupted
}
