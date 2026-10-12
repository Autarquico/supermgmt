package jobs

import (
	"context"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// TypePolicy lets one job type refine reconciliation and claims without
// weakening the fixed rules (ADR-0029). Job types without a policy keep
// today's behavior byte for byte. Wired through Config.TypePolicies (job type
// -> policy); T7b integrates it into Store.
//
// Fixed, whatever a policy says: every dispatched intent needs Proven()
// evidence (.done exit 0) before any automatic action; missing proof holds the
// job with its locks.
type TypePolicy interface {
	// Admit reports which proven classifications may form a confirmed pair of
	// samples. Proven() is checked before Admit and stays mandatory.
	Admit(ev Evidence) bool

	// Reconcile decides an interrupted job once every dispatched intent has a
	// confirmed, admitted sample. It never dispatches; when it requeues, it
	// persists the durable recovery record in tx.
	Reconcile(ctx context.Context, tx *database.Tx, job Job, intents []Intent, observed map[domain.ID]Evidence) (Verdict, error)

	// ClaimMode reads the durable recovery record of a queued job.
	ClaimMode(ctx context.Context, q database.Querier, job Job) (ClaimMode, error)

	// RevalidateRecovery replaces the requester Revalidator under
	// ClaimRecovery: it checks only that the frozen restoration target is
	// still restorable. It never returns APPROVAL_REQUIRED.
	RevalidateRecovery(ctx context.Context, q database.Querier, job Job) error

	// EscalateToRecovery is called inside the claim transaction when forward
	// revalidation failed with cause. It returns true after writing a safety
	// recovery record (mutation had started and rollback is available); the
	// claim then proceeds as ClaimRecovery. False lets the claim fail the job.
	EscalateToRecovery(ctx context.Context, tx *database.Tx, job Job, cause error) (bool, error)

	// Mirror runs inside Store.move for every coarse transition of a job of
	// this type, in the same transaction. An error aborts the transition.
	Mirror(ctx context.Context, q database.Querier, job Job, from, to domain.JobState, mode ClaimMode, f *Failure) error
}

// ClaimMode is how a claim revalidates and what the handler may dispatch.
type ClaimMode int

const (
	// ClaimForward runs the requester Revalidator (spec §20.4 claim step 3).
	ClaimForward ClaimMode = iota
	// ClaimRecovery runs TypePolicy.RevalidateRecovery as the system actor and
	// lets the handler dispatch restore steps only.
	ClaimRecovery
)

// VerdictAction is what a TypePolicy decided for an interrupted job.
type VerdictAction string

const (
	VerdictHeld             VerdictAction = "held"
	VerdictRequeued         VerdictAction = "requeued"          // forward resume
	VerdictRequeuedRecovery VerdictAction = "requeued_recovery" // safety recovery
	VerdictSucceeded        VerdictAction = "succeeded"
	VerdictFailed           VerdictAction = "failed"
)

// Verdict is TypePolicy.Reconcile's decision. Failure is set when Action is
// VerdictFailed; Reason is audited with the transition.
type Verdict struct {
	Action  VerdictAction
	Reason  string
	Failure *Failure
}
