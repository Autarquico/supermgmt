package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Deployment is one row of deployments (spec §20.0, ADR-0011, ADR-0029): the fine
// state, the provisional inputs and credential context, and the durable recovery
// record.
type Deployment struct {
	ID            domain.ID
	Kind          string
	AppID         domain.ID
	AppTargetID   domain.ID
	EnvironmentID domain.ID
	NodeID        domain.ID
	ArtifactID    *domain.ID
	JobID         *domain.ID
	PlanID        *domain.ID
	Strategy      string
	State         deployments.State
	Failure       StateFailure
	RequestedBy   domain.ID

	PreviousDeploymentID   *domain.ID
	RollbackOfDeploymentID *domain.ID
	KnownGood              bool
	ComposeHash            string
	PlanHash               string

	CommitSha    string
	RequestedRaw json.RawMessage
	Credential   domain.CredentialContext
	CIDeadlineAt *time.Time
	NextCICheck  *time.Time

	MutationStarted bool
	Recovery        *deployments.Recovery

	CreatedAt  time.Time
	UpdatedAt  time.Time
	FinishedAt *time.Time
}

// StateFailure is the code, reason and cause (§20.1) a failed or interrupted
// deployment carries; the zero value means none.
type StateFailure struct {
	Code   string
	Reason string
	Cause  string
}

// DeploymentFilter narrows ListDeployments; zero fields do not filter.
type DeploymentFilter struct {
	AppID         domain.ID
	AppTargetID   domain.ID
	EnvironmentID domain.ID
	State         deployments.State
}

const deploymentColumns = `id, kind, app_id, app_target_id, environment_id, node_id, artifact_id, job_id, plan_id,
	strategy, state, state_code, state_reason, state_cause, requested_by, previous_deployment_id,
	rollback_of_deployment_id, known_good, compose_hash, plan_hash, commit_sha, requested_json, credential_kind,
	credential_id, scopes_json, credential_expires_at, ci_deadline_at, next_ci_check_at, mutation_started,
	recovery_mode, resume_step, recovery_reason, recovery_target_deployment_id, created_at, updated_at, finished_at`

// InsertDeployment stores a new deployment. Only the provisional inputs are
// written: the state, the plan binding, the known-good flag and the recovery
// record change through their own functions.
func InsertDeployment(ctx context.Context, q Querier, d Deployment) error {
	scopes, err := json.Marshal(nonNil(d.Credential.Scopes))
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, artifact_id, strategy,
		    state, requested_by, previous_deployment_id, rollback_of_deployment_id, commit_sha, requested_json,
		    credential_kind, credential_id, scopes_json, credential_expires_at, ci_deadline_at, next_ci_check_at,
		    created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), 'docker-compose'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.Kind, d.AppID, d.AppTargetID, d.EnvironmentID, d.NodeID, nullID(d.ArtifactID), d.Strategy,
		string(d.State), d.RequestedBy, nullID(d.PreviousDeploymentID), nullID(d.RollbackOfDeploymentID),
		d.CommitSha, string(d.RequestedRaw), d.Credential.Kind, d.Credential.ID, string(scopes),
		nullMillis(d.Credential.ExpiresAt), nullMillis(d.CIDeadlineAt), nullMillis(d.NextCICheck),
		millis(d.CreatedAt), millis(d.UpdatedAt))
	if err != nil {
		return conflictIfDuplicate(err, "deployment")
	}
	return nil
}

// GetDeployment returns the deployment or NOT_FOUND.
func GetDeployment(ctx context.Context, q Querier, id domain.ID) (Deployment, error) {
	d, err := scanDeployment(q.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM deployments WHERE id = ?`, id))
	return d, getErr(err, "deployment")
}

// GetDeploymentByJob returns the deployment a job executes or NOT_FOUND.
func GetDeploymentByJob(ctx context.Context, q Querier, jobID domain.ID) (Deployment, error) {
	d, err := scanDeployment(q.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM deployments WHERE job_id = ?`, jobID))
	return d, getErr(err, "deployment")
}

// ListDeployments returns the matching deployments, newest first, at most limit.
func ListDeployments(ctx context.Context, q Querier, f DeploymentFilter, limit int) ([]Deployment, error) {
	var (
		where []string
		args  []any
	)
	for _, c := range []struct{ column, value string }{
		{"app_id", f.AppID.String()},
		{"app_target_id", f.AppTargetID.String()},
		{"environment_id", f.EnvironmentID.String()},
		{"state", string(f.State)},
	} {
		if c.value != "" {
			where = append(where, c.column+" = ?")
			args = append(args, c.value)
		}
	}
	query := `SELECT ` + deploymentColumns + ` FROM deployments`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	return queryDeployments(ctx, q, query, append(args, limit)...)
}

// ListDueCIChecks returns the waiting_ci deployments whose next CI check is at or
// before now, oldest check first.
func ListDueCIChecks(ctx context.Context, q Querier, now time.Time, limit int) ([]Deployment, error) {
	return queryDeployments(ctx, q, `SELECT `+deploymentColumns+` FROM deployments
		WHERE state = 'waiting_ci' AND next_ci_check_at <= ? ORDER BY next_ci_check_at, id LIMIT ?`,
		millis(now), limit)
}

// ScheduleCICheck sets when a waiting_ci deployment is next evaluated.
func ScheduleCICheck(ctx context.Context, q Querier, id domain.ID, next time.Time, now time.Time) error {
	return updateDeployment(ctx, q, id, `UPDATE deployments SET next_ci_check_at = ?, updated_at = ? WHERE id = ?`,
		millis(next), millis(now), id)
}

// TransitionDeployment moves a deployment to state to if §20.1 allows it. Entering
// deploying (or any later state) records that services may have been touched;
// entering a terminal state stamps finished_at. failure replaces the previous
// one (the zero value clears it). A cause requires a reason.
func TransitionDeployment(ctx context.Context, q Querier, id domain.ID, to deployments.State, failure StateFailure, now time.Time) error {
	current, err := GetDeployment(ctx, q, id)
	if err != nil {
		return err
	}
	if err := deployments.Transition(current.State, to); err != nil {
		return err
	}
	var finished sql.NullInt64
	if to.Terminal() {
		finished = sql.NullInt64{Int64: millis(now), Valid: true}
	}
	return updateDeployment(ctx, q, id, `
		UPDATE deployments SET state = ?, state_code = NULLIF(?, ''), state_reason = NULLIF(?, ''),
		       state_cause = NULLIF(?, ''), mutation_started = max(mutation_started, ?),
		       finished_at = COALESCE(?, finished_at), updated_at = ?
		WHERE id = ?`,
		string(to), failure.Code, failure.Reason, failure.Cause, boolInt(to.MutationStarted()),
		finished, millis(now), id)
}

// BindDeploymentPlan records the finalization result (ADR-0011): the plan, its
// hash, the job and the target-bound compose hash. A deployment is bound once.
func BindDeploymentPlan(ctx context.Context, q Querier, id, planID, jobID domain.ID, planHash, composeHash string, now time.Time) error {
	res, err := q.ExecContext(ctx, `
		UPDATE deployments SET plan_id = ?, job_id = ?, plan_hash = ?, compose_hash = ?, updated_at = ?
		WHERE id = ? AND plan_id IS NULL`,
		planID, jobID, planHash, composeHash, millis(now), id)
	if err != nil {
		if isUniqueViolation(err) {
			return smerr.Wrap(err, smerr.CodeConflict, "", "job already executes another deployment")
		}
		return fmt.Errorf("bind deployment plan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := GetDeployment(ctx, q, id); err != nil {
		return err
	}
	return smerr.New(smerr.CodeConflict, "", "deployment is already bound to a plan")
}

// SetDeploymentRecovery writes the durable recovery record in one statement
// (ADR-0029). Safety recovery requires the frozen rollback target; forward
// resume must not name one.
func SetDeploymentRecovery(ctx context.Context, q Querier, id domain.ID, r deployments.Recovery, now time.Time) error {
	switch {
	case r.Mode == deployments.RecoverySafetyRecovery && r.Target == nil:
		return smerr.New(smerr.CodeInvalidArgument, "", "safety recovery needs a restoration target")
	case r.Mode == deployments.RecoveryForward && r.Target != nil:
		return smerr.New(smerr.CodeInvalidArgument, "", "forward resume has no restoration target")
	case r.Mode != deployments.RecoveryForward && r.Mode != deployments.RecoverySafetyRecovery:
		return smerr.New(smerr.CodeInvalidArgument, "", "unknown recovery mode")
	}
	return updateDeployment(ctx, q, id, `
		UPDATE deployments SET recovery_mode = ?, resume_step = NULLIF(?, ''), recovery_reason = NULLIF(?, ''),
		       recovery_target_deployment_id = ?, updated_at = ?
		WHERE id = ?`,
		string(r.Mode), r.ResumeStep, r.Reason, nullID(r.Target), millis(now), id)
}

// GetDeploymentRecovery returns the recovery record, or nil when no reconcile
// verdict has written one. NOT_FOUND when the deployment does not exist.
func GetDeploymentRecovery(ctx context.Context, q Querier, id domain.ID) (*deployments.Recovery, error) {
	d, err := GetDeployment(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return d.Recovery, nil
}

// MarkDeploymentKnownGood flags a succeeded deployment as a rollback source.
func MarkDeploymentKnownGood(ctx context.Context, q Querier, id domain.ID, now time.Time) error {
	res, err := q.ExecContext(ctx,
		`UPDATE deployments SET known_good = 1, updated_at = ? WHERE id = ? AND state = 'succeeded'`, millis(now), id)
	if err != nil {
		return fmt.Errorf("mark deployment known good: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := GetDeployment(ctx, q, id); err != nil {
		return err
	}
	return smerr.FromReason(smerr.ReasonInvalidTransition, "only a succeeded deployment can be known good")
}

// NewestKnownGood returns the target's newest known-good deployment, or NOT_FOUND.
// With before set, only deployments created strictly before that deployment count.
func NewestKnownGood(ctx context.Context, q Querier, appTargetID domain.ID, before *domain.ID) (Deployment, error) {
	query := `SELECT ` + deploymentColumns + ` FROM deployments WHERE app_target_id = ? AND known_good = 1`
	args := []any{appTargetID}
	if before != nil {
		query += ` AND (created_at, id) < (SELECT created_at, id FROM deployments WHERE id = ?)`
		args = append(args, *before)
	}
	query += ` ORDER BY finished_at DESC, id DESC LIMIT 1`
	d, err := scanDeployment(q.QueryRowContext(ctx, query, args...))
	return d, getErr(err, "known-good deployment")
}

func updateDeployment(ctx context.Context, q Querier, id domain.ID, query string, args ...any) error {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update deployment: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return notFound("deployment")
	}
	return nil
}

func queryDeployments(ctx context.Context, q Querier, query string, args ...any) ([]Deployment, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	defer rows.Close()
	var out []Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("list deployments: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanDeployment(row scanner) (Deployment, error) {
	var (
		d                                                     Deployment
		state, scopes, requested                              string
		artifact, job, plan, previous, rollbackOf, recoveryTo sql.NullString
		code, reason, cause, composeHash, planHash            sql.NullString
		recoveryMode, resumeStep, recoveryReason              sql.NullString
		credExpires, ciDeadline, nextCI, finished             sql.NullInt64
		knownGood, mutated                                    int
		createdMs, updatedMs                                  int64
	)
	err := row.Scan(&d.ID, &d.Kind, &d.AppID, &d.AppTargetID, &d.EnvironmentID, &d.NodeID, &artifact, &job, &plan,
		&d.Strategy, &state, &code, &reason, &cause, &d.RequestedBy, &previous, &rollbackOf, &knownGood,
		&composeHash, &planHash, &d.CommitSha, &requested, &d.Credential.Kind, &d.Credential.ID, &scopes,
		&credExpires, &ciDeadline, &nextCI, &mutated, &recoveryMode, &resumeStep, &recoveryReason, &recoveryTo,
		&createdMs, &updatedMs, &finished)
	if err != nil {
		return Deployment{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &d.Credential.Scopes); err != nil {
		return Deployment{}, fmt.Errorf("decode scopes: %w", err)
	}
	d.State = deployments.State(state)
	d.Failure = StateFailure{Code: code.String, Reason: reason.String, Cause: cause.String}
	d.ArtifactID, d.JobID, d.PlanID = idOf(artifact), idOf(job), idOf(plan)
	d.PreviousDeploymentID, d.RollbackOfDeploymentID = idOf(previous), idOf(rollbackOf)
	d.KnownGood, d.MutationStarted = knownGood == 1, mutated == 1
	d.ComposeHash, d.PlanHash = composeHash.String, planHash.String
	d.RequestedRaw = json.RawMessage(requested)
	d.Credential.ExpiresAt = timeOf(credExpires)
	d.CIDeadlineAt, d.NextCICheck, d.FinishedAt = timeOf(ciDeadline), timeOf(nextCI), timeOf(finished)
	d.CreatedAt, d.UpdatedAt = domain.FromUnixMillis(createdMs), domain.FromUnixMillis(updatedMs)
	if recoveryMode.Valid {
		d.Recovery = &deployments.Recovery{
			Mode: deployments.RecoveryMode(recoveryMode.String), ResumeStep: resumeStep.String,
			Reason: recoveryReason.String, Target: idOf(recoveryTo),
		}
	}
	return d, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// StepState is the state of a deployment_steps row.
type StepState string

const (
	StepPending   StepState = "pending"
	StepRunning   StepState = "running"
	StepSucceeded StepState = "succeeded"
	StepFailed    StepState = "failed"
	StepSkipped   StepState = "skipped"
)

// DeploymentStep is one attempt of a named step (App. C order via Ordinal).
type DeploymentStep struct {
	ID           domain.ID
	DeploymentID domain.ID
	Ordinal      int
	Name         string
	State        StepState
	Attempt      int
	StartedAt    *time.Time
	FinishedAt   *time.Time
	OutputRef    string
	ErrorJSON    json.RawMessage
}

// InsertDeploymentStep stores a step attempt; the same (deployment, name, attempt)
// twice is a CONFLICT. Attempt defaults to 1.
func InsertDeploymentStep(ctx context.Context, q Querier, s DeploymentStep) error {
	if s.Attempt == 0 {
		s.Attempt = 1
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO deployment_steps (id, deployment_id, ordinal, name, state, attempt, started_at, finished_at,
		                              output_ref, error_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?)`,
		s.ID, s.DeploymentID, s.Ordinal, s.Name, string(s.State), s.Attempt, nullMillis(s.StartedAt),
		nullMillis(s.FinishedAt), s.OutputRef, nullJSON(s.ErrorJSON))
	if err != nil {
		return conflictIfDuplicate(err, "deployment step")
	}
	return nil
}

// UpdateDeploymentStep records a step's progress: its state, timestamps, output
// reference and error. NOT_FOUND when the step does not exist.
func UpdateDeploymentStep(ctx context.Context, q Querier, s DeploymentStep) error {
	res, err := q.ExecContext(ctx, `
		UPDATE deployment_steps SET state = ?, started_at = ?, finished_at = ?, output_ref = NULLIF(?, ''), error_json = ?
		WHERE id = ?`,
		string(s.State), nullMillis(s.StartedAt), nullMillis(s.FinishedAt), s.OutputRef, nullJSON(s.ErrorJSON), s.ID)
	if err != nil {
		return fmt.Errorf("update deployment step: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return notFound("deployment step")
	}
	return nil
}

// ListDeploymentSteps returns every attempt of a deployment's steps, in step
// order and then attempt order.
func ListDeploymentSteps(ctx context.Context, q Querier, deploymentID domain.ID) ([]DeploymentStep, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, deployment_id, ordinal, name, state, attempt, started_at, finished_at, output_ref, error_json
		FROM deployment_steps WHERE deployment_id = ? ORDER BY ordinal, attempt`, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("list deployment steps: %w", err)
	}
	defer rows.Close()
	var out []DeploymentStep
	for rows.Next() {
		var (
			s                    DeploymentStep
			state                string
			started, finished    sql.NullInt64
			outputRef, errorBlob sql.NullString
		)
		if err := rows.Scan(&s.ID, &s.DeploymentID, &s.Ordinal, &s.Name, &state, &s.Attempt, &started, &finished,
			&outputRef, &errorBlob); err != nil {
			return nil, fmt.Errorf("list deployment steps: %w", err)
		}
		s.State, s.StartedAt, s.FinishedAt, s.OutputRef = StepState(state), timeOf(started), timeOf(finished), outputRef.String
		if errorBlob.Valid {
			s.ErrorJSON = json.RawMessage(errorBlob.String)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func nullJSON(b json.RawMessage) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// HealthCheck is a control-plane health check of an app target (spec §21); the
// manifest's own checks are frozen in snapshots, not stored here.
type HealthCheck struct {
	ID           domain.ID
	ResourceType string
	ResourceID   domain.ID
	Type         string
	Scope        string
	Config       json.RawMessage
	Enabled      bool
	SpecRevision int64
	CreatedAt    time.Time
}

// ResourceAppTarget is the only resource type a health check can attach to in M4.
const ResourceAppTarget = "app_target"

// ReplaceHealthChecks swaps the whole set of checks of an app target. Callers
// run it inside the transaction that bumps the target's revision.
func ReplaceHealthChecks(ctx context.Context, q Querier, appTargetID domain.ID, checks []HealthCheck) error {
	if _, err := q.ExecContext(ctx,
		`DELETE FROM health_checks WHERE resource_type = ? AND resource_id = ?`, ResourceAppTarget, appTargetID); err != nil {
		return fmt.Errorf("delete health checks: %w", err)
	}
	for _, c := range checks {
		if _, err := q.ExecContext(ctx, `
			INSERT INTO health_checks (id, resource_type, resource_id, type, scope, config_json, enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, ResourceAppTarget, appTargetID, c.Type, c.Scope, string(c.Config), boolInt(c.Enabled), millis(c.CreatedAt)); err != nil {
			return conflictIfDuplicate(err, "health check")
		}
	}
	return nil
}

// ListHealthChecks returns an app target's checks in creation order.
func ListHealthChecks(ctx context.Context, q Querier, appTargetID domain.ID, enabledOnly bool) ([]HealthCheck, error) {
	query := `SELECT id, resource_type, resource_id, type, scope, config_json, enabled, spec_revision, created_at
		FROM health_checks WHERE resource_type = ? AND resource_id = ?`
	if enabledOnly {
		query += ` AND enabled = 1`
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY created_at, id`, ResourceAppTarget, appTargetID)
	if err != nil {
		return nil, fmt.Errorf("list health checks: %w", err)
	}
	defer rows.Close()
	var out []HealthCheck
	for rows.Next() {
		var (
			c         HealthCheck
			config    string
			enabled   int
			createdMs int64
		)
		if err := rows.Scan(&c.ID, &c.ResourceType, &c.ResourceID, &c.Type, &c.Scope, &config, &enabled,
			&c.SpecRevision, &createdMs); err != nil {
			return nil, fmt.Errorf("list health checks: %w", err)
		}
		c.Config, c.Enabled, c.CreatedAt = json.RawMessage(config), enabled == 1, domain.FromUnixMillis(createdMs)
		out = append(out, c)
	}
	return out, rows.Err()
}
