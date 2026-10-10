package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// PlanRecord is a persisted canonical plan (Appendix C). PlanJSON and PlanHash
// are the hashed form; the credential context and ExpiresAt live beside it,
// outside the hash. Credential.ExpiresAt is not persisted: the plans table has
// no column for it (spec §9).
type PlanRecord struct {
	ID             domain.ID
	Action         string
	ActorID        domain.ID
	Credential     domain.CredentialContext
	PlanJSON       []byte
	PlanHash       string
	FinalizedAt    time.Time
	CreatedAt      time.Time
	ExpiresAt      time.Time
	SubmittedJobID *domain.ID
}

// InsertPlan stores p. SubmittedJobID is ignored: only MarkSubmitted sets it.
func InsertPlan(ctx context.Context, q Querier, p PlanRecord) error {
	scopes, err := json.Marshal(nonNil(p.Credential.Scopes))
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO plans (id, action, actor_id, credential_kind, credential_id, scopes_json, plan_json,
		                   plan_hash, finalized_at, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Action, p.ActorID, p.Credential.Kind, p.Credential.ID, string(scopes), string(p.PlanJSON),
		p.PlanHash, millis(p.FinalizedAt), millis(p.CreatedAt), millis(p.ExpiresAt))
	if err != nil {
		return conflictIfDuplicate(err, "plan")
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GetPlan returns the plan or NOT_FOUND.
func GetPlan(ctx context.Context, q Querier, id domain.ID) (PlanRecord, error) {
	var (
		p                                 PlanRecord
		scopes, planJSON                  string
		finalizedMs, createdMs, expiresMs int64
		submitted                         sql.NullString
	)
	err := q.QueryRowContext(ctx, `
		SELECT id, action, actor_id, credential_kind, credential_id, scopes_json, plan_json, plan_hash,
		       finalized_at, created_at, expires_at, submitted_job_id
		FROM plans WHERE id = ?`, id).
		Scan(&p.ID, &p.Action, &p.ActorID, &p.Credential.Kind, &p.Credential.ID, &scopes, &planJSON,
			&p.PlanHash, &finalizedMs, &createdMs, &expiresMs, &submitted)
	if err != nil {
		return PlanRecord{}, getErr(err, "plan")
	}
	if err := json.Unmarshal([]byte(scopes), &p.Credential.Scopes); err != nil {
		return PlanRecord{}, fmt.Errorf("decode scopes: %w", err)
	}
	p.PlanJSON = []byte(planJSON)
	p.FinalizedAt, p.CreatedAt, p.ExpiresAt =
		domain.FromUnixMillis(finalizedMs), domain.FromUnixMillis(createdMs), domain.FromUnixMillis(expiresMs)
	p.SubmittedJobID = idOf(submitted)
	return p, nil
}

// MarkSubmitted binds the plan to jobID. Exactly one job may ever be submitted
// per plan: a second attempt returns CONFLICT/ALREADY_SUBMITTED.
func MarkSubmitted(ctx context.Context, q Querier, planID, jobID domain.ID) error {
	res, err := q.ExecContext(ctx,
		`UPDATE plans SET submitted_job_id = ? WHERE id = ? AND submitted_job_id IS NULL`, jobID, planID)
	if err != nil {
		if isUniqueViolation(err) { // the job is already bound to another plan
			return alreadySubmitted(err)
		}
		return fmt.Errorf("mark plan submitted: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark plan submitted: %w", err)
	}
	if affected > 0 {
		return nil
	}
	var exists int
	switch err := q.QueryRowContext(ctx, `SELECT 1 FROM plans WHERE id = ?`, planID).Scan(&exists); {
	case errors.Is(err, sql.ErrNoRows):
		return notFound("plan")
	case err != nil:
		return fmt.Errorf("mark plan submitted: %w", err)
	}
	return alreadySubmitted(nil)
}

func alreadySubmitted(cause error) error {
	e := smerr.FromReason(smerr.ReasonAlreadySubmitted, "plan already has a submitted job")
	e.Err = cause
	return e
}
