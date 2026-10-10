package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Approval is one approver's decision on a job's plan hash (spec §11.4).
// CreatedAt is the time of the decision (or, on a renewal, of the original one).
type Approval struct {
	ID         domain.ID
	JobID      domain.ID
	PlanHash   string
	ApproverID domain.ID
	Decision   domain.ApprovalDecision
	Reason     string
	ExpiresAt  time.Time
	RenewedAt  *time.Time
	CreatedAt  time.Time
}

// Expired reports whether the approval no longer counts at now.
func (a Approval) Expired(now time.Time) bool { return !a.ExpiresAt.After(now) }

// RecordDecision stores a new decision, taken at now, or renews an expired one.
//
//   - no previous row: inserted.
//   - previous rejection: final, CONFLICT/ALREADY_DECIDED (even when expired).
//   - previous approval still unexpired: CONFLICT/ALREADY_DECIDED.
//   - previous approval expired: the row is renewed in place (decision, reason,
//     expires_at from a; renewed_at = now) and counts again.
//
// The returned Approval is the stored row. Callers run this inside the write
// transaction that also audits the decision.
func RecordDecision(ctx context.Context, q Querier, a Approval, now time.Time) (Approval, error) {
	existing, err := findDecision(ctx, q, a.JobID, a.PlanHash, a.ApproverID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return insertDecision(ctx, q, a, now)
	case err != nil:
		return Approval{}, err
	case existing.Decision == domain.DecisionReject || !existing.Expired(now):
		return Approval{}, smerr.FromReason(smerr.ReasonAlreadyDecided, "approver already decided on this plan")
	}
	return renewDecision(ctx, q, existing, a, now)
}

const approvalColumns = `id, job_id, plan_hash, approver_id, decision, reason, expires_at, renewed_at, created_at`

func scanApproval(row scanner) (Approval, error) {
	var (
		a                    Approval
		expiresMs, createdMs int64
		renewed              sql.NullInt64
	)
	if err := row.Scan(&a.ID, &a.JobID, &a.PlanHash, &a.ApproverID, &a.Decision, &a.Reason,
		&expiresMs, &renewed, &createdMs); err != nil {
		return Approval{}, err
	}
	a.ExpiresAt, a.CreatedAt = domain.FromUnixMillis(expiresMs), domain.FromUnixMillis(createdMs)
	a.RenewedAt = timeOf(renewed)
	return a, nil
}

// findDecision returns sql.ErrNoRows (unwrapped) when the approver has not decided.
func findDecision(ctx context.Context, q Querier, job domain.ID, planHash string, approver domain.ID) (Approval, error) {
	a, err := scanApproval(q.QueryRowContext(ctx, `SELECT `+approvalColumns+`
		FROM job_approvals WHERE job_id = ? AND plan_hash = ? AND approver_id = ?`, job, planHash, approver))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Approval{}, fmt.Errorf("find approval: %w", err)
	}
	return a, err
}

func insertDecision(ctx context.Context, q Querier, a Approval, now time.Time) (Approval, error) {
	a.CreatedAt, a.RenewedAt = now, nil
	_, err := q.ExecContext(ctx, `INSERT INTO job_approvals (`+approvalColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
		a.ID, a.JobID, a.PlanHash, a.ApproverID, a.Decision, a.Reason, millis(a.ExpiresAt), millis(a.CreatedAt))
	if err != nil {
		if isUniqueViolation(err) { // lost a race with the same approver
			return Approval{}, smerr.FromReason(smerr.ReasonAlreadyDecided, "approver already decided on this plan")
		}
		return Approval{}, fmt.Errorf("insert approval: %w", err)
	}
	return a, nil
}

func renewDecision(ctx context.Context, q Querier, existing, a Approval, now time.Time) (Approval, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE job_approvals SET decision = ?, reason = ?, expires_at = ?, renewed_at = ?
		WHERE id = ? AND decision = 'approve' AND expires_at <= ?`,
		a.Decision, a.Reason, millis(a.ExpiresAt), millis(now), existing.ID, millis(now))
	if err != nil {
		return Approval{}, fmt.Errorf("renew approval: %w", err)
	}
	if affected, err := res.RowsAffected(); err != nil || affected == 0 {
		return Approval{}, smerr.FromReason(smerr.ReasonAlreadyDecided, "approver already decided on this plan")
	}
	existing.Decision, existing.Reason, existing.ExpiresAt, existing.RenewedAt = a.Decision, a.Reason, a.ExpiresAt, &now
	return existing, nil
}

// ListDecisions returns every decision on (job, planHash), oldest first.
func ListDecisions(ctx context.Context, q Querier, jobID domain.ID, planHash string) ([]Approval, error) {
	return list(ctx, q, "approvals", `SELECT `+approvalColumns+`
		FROM job_approvals WHERE job_id = ? AND plan_hash = ? ORDER BY created_at, id`,
		scanApproval, jobID, planHash)
}
