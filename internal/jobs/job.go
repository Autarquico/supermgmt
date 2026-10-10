// Package jobs is the generic job engine (spec §20.4, §20.5, ADR-0013): the
// state machine, claim with locks and revalidation, lease fencing, operation
// intents, takeover, reconciliation and the worker loop.
//
// The Store owns every statement on jobs, operation_intents and resource_locks.
// Every state change is one UPDATE guarded by the expected from-state and is
// committed with its audit event in a single writer transaction.
package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// reasonLeaseLost refines CONFLICT when a worker's lease no longer holds. It is
// local until internal/errors declares it.
const reasonLeaseLost smerr.Reason = "LEASE_LOST"

// ErrLeaseLost is returned by every fenced write once the lease generation,
// owner or expiry no longer matches. The worker must stop.
var ErrLeaseLost = smerr.New(smerr.CodeConflict, reasonLeaseLost, "job lease lost")

// Job is a row of the jobs table.
type Job struct {
	ID              domain.ID
	Type            string
	Resource        domain.ResourceRef
	ActorID         domain.ID
	CredentialKind  domain.CredentialKind
	CredentialID    string
	Scopes          []string
	State           domain.JobState
	Risk            domain.RiskClass
	RetryClass      domain.RetryClass
	IdempotencyKey  string
	Payload         json.RawMessage
	PlanID          *domain.ID
	PlanHash        string
	LeaseOwner      string
	LeaseGeneration int64
	LeaseUntil      *time.Time
	HeartbeatAt     *time.Time
	Attempts        int
	MaxAttempts     int
	ScheduledAt     time.Time
	CreatedAt       time.Time
	StartedAt       *time.Time
	FinishedAt      *time.Time
	Error           *Failure
}

// Failure is the persisted reason a job ended in failed (jobs.error_json).
type Failure struct {
	Code    smerr.Code   `json:"code"`
	Reason  smerr.Reason `json:"reason,omitempty"`
	Message string       `json:"message,omitempty"`
}

// FailureOf describes err; a typed SuperMgmt error keeps its code and reason.
func FailureOf(err error) Failure {
	var typed *smerr.Error
	if errors.As(err, &typed) {
		return Failure{Code: typed.Code, Reason: typed.Reason, Message: typed.Message}
	}
	return Failure{Code: smerr.CodeInternal, Message: err.Error()}
}

// Revalidator re-checks, inside the claim transaction, everything that may have
// changed since enqueue: policy decision, credential status (revoked/expired),
// plan hash/spec_revision, approval quorum. Returning a *smerr.Error fails the
// claim for that job (APPROVAL_REQUIRED sends it back to awaiting_approval).
type Revalidator interface {
	Revalidate(ctx context.Context, q database.Querier, job Job) error
}

// LockPlanner computes the locks a job needs. It is called inside the claim
// transaction; locks are not stored at enqueue.
type LockPlanner interface {
	PlanLocks(ctx context.Context, q database.Querier, job Job) ([]domain.LockSpec, error)
}

// Handler executes one job type. It must open every write transaction with Lease.Fence.
type Handler interface {
	Run(ctx context.Context, lease Lease) error
}

// Lease proves a worker's right to write for one job. Generation is the value
// assigned at claim.
type Lease struct {
	JobID      domain.ID
	Owner      string
	Generation int64

	clock domain.Clock
}

// Fence is the first statement of every worker write transaction. It returns
// ErrLeaseLost unless the job is still running under exactly this lease and the
// lease has not expired.
func (l Lease) Fence(ctx context.Context, q database.Querier) error {
	if l.clock == nil {
		return errors.New("lease was not issued by a Store")
	}
	var one int
	err := q.QueryRowContext(ctx, `
		SELECT 1 FROM jobs
		WHERE id = ? AND state = 'running' AND lease_generation = ? AND lease_owner = ? AND lease_until > ?`,
		l.JobID, l.Generation, l.Owner, domain.UnixMillis(l.clock.Now())).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("job %s: %w", l.JobID, ErrLeaseLost)
	}
	if err != nil {
		return fmt.Errorf("fence job %s: %w", l.JobID, err)
	}
	return nil
}

// Claimed is a job handed to a worker together with its lease.
type Claimed struct {
	Job   Job
	Lease Lease
}
