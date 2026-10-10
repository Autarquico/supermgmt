package domain

import "slices"

// JobState is the coarse job lifecycle (ADR-0013).
type JobState string

const (
	JobAwaitingApproval JobState = "awaiting_approval"
	JobQueued           JobState = "queued"
	JobRunning          JobState = "running"
	JobInterrupted      JobState = "interrupted"
	JobSucceeded        JobState = "succeeded"
	JobFailed           JobState = "failed"
	JobCancelled        JobState = "cancelled"
)

func AllJobStates() []JobState {
	return []JobState{
		JobAwaitingApproval, JobQueued, JobRunning, JobInterrupted,
		JobSucceeded, JobFailed, JobCancelled,
	}
}
func ParseJobState(s string) (JobState, error) { return parseEnum("job state", AllJobStates(), s) }
func (v JobState) Valid() bool                 { return slices.Contains(AllJobStates(), v) }

// Terminal reports whether no further transition is possible.
func (v JobState) Terminal() bool {
	return v == JobSucceeded || v == JobFailed || v == JobCancelled
}
