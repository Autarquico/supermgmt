package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	defaultLeaseTTL    = 30 * time.Second
	defaultBackoffBase = 5 * time.Second
	defaultBackoffMax  = 5 * time.Minute
	defaultListLimit   = 100

	defaultReconcileGrace = 45 * time.Second
	defaultSampleGap      = 30 * time.Second
	eventSource           = "jobs"
)

var systemActor = domain.Actor{Type: domain.ActorSystem}

// Config wires a Store. DB, Clock, IDs, Revalidator and LockPlanner are required.
type Config struct {
	DB          *database.DB
	Clock       domain.Clock
	IDs         domain.IDGenerator
	Revalidator Revalidator
	LockPlanner LockPlanner

	LeaseTTL    time.Duration // default 30s
	BackoffBase time.Duration // first retry delay, doubled per attempt; default 5s
	BackoffMax  time.Duration // default 5m

	// ReconcileGrace is added to an intent's deadline_at before its remote
	// process is presumed gone (config key jobs.reconcile_grace, spec §8); default 45s.
	ReconcileGrace time.Duration
	// SampleGap is the minimum spacing of the two identical outcome samples
	// required before an automatic recovery (spec §20.4 step 3); default 30s.
	SampleGap time.Duration

	// TaskTracked reports whether an operation is tracked by a provider task
	// whose stop must be proven before its intent may be reconciled or resolved
	// (ADR-0025). Default: operations prefixed "proxmox.".
	TaskTracked func(operation string) bool
}

// DefaultTaskTracked marks Proxmox operations as task-tracked.
func DefaultTaskTracked(operation string) bool { return strings.HasPrefix(operation, "proxmox.") }

// Store owns all SQL on jobs, operation_intents and resource_locks.
type Store struct {
	db          *database.DB
	clock       domain.Clock
	ids         domain.IDGenerator
	emitter     audit.Emitter
	revalidator Revalidator
	planner     LockPlanner

	leaseTTL    time.Duration
	backoffBase time.Duration
	backoffMax  time.Duration

	reconcileGrace time.Duration
	sampleGap      time.Duration
	taskTracked    func(operation string) bool

	restoreHold atomic.Bool

	reconcileMu sync.Mutex
	samples     map[sampleKey]sample // first outcome sample per intent and interruption, in memory
	held        map[domain.ID]string // reason of the last job.reconcile_held event per job
}

// NewStore validates cfg and applies defaults.
func NewStore(cfg Config) (*Store, error) {
	switch {
	case cfg.DB == nil:
		return nil, errors.New("jobs: database is required")
	case cfg.Clock == nil:
		return nil, errors.New("jobs: clock is required")
	case cfg.IDs == nil:
		return nil, errors.New("jobs: id generator is required")
	case cfg.Revalidator == nil:
		return nil, errors.New("jobs: revalidator is required")
	case cfg.LockPlanner == nil:
		return nil, errors.New("jobs: lock planner is required")
	}
	s := &Store{
		db:          cfg.DB,
		clock:       cfg.Clock,
		ids:         cfg.IDs,
		emitter:     audit.Emitter{Clock: cfg.Clock, IDs: cfg.IDs, Source: eventSource},
		revalidator: cfg.Revalidator,
		planner:     cfg.LockPlanner,
		leaseTTL:    orDefault(cfg.LeaseTTL, defaultLeaseTTL),
		backoffBase: orDefault(cfg.BackoffBase, defaultBackoffBase),
		backoffMax:  orDefault(cfg.BackoffMax, defaultBackoffMax),

		reconcileGrace: orDefault(cfg.ReconcileGrace, defaultReconcileGrace),
		sampleGap:      orDefault(cfg.SampleGap, defaultSampleGap),
		samples:        map[sampleKey]sample{},
		held:           map[domain.ID]string{},
	}
	s.taskTracked = DefaultTaskTracked
	if cfg.TaskTracked != nil {
		s.taskTracked = cfg.TaskTracked
	}
	return s, nil
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

// SetRestoreHold turns the restore hold (spec §29.2 phase C) on or off. While
// held, Claim returns nothing.
func (s *Store) SetRestoreHold(held bool) { s.restoreHold.Store(held) }

// NewJob describes a job to enqueue. AwaitingApproval decides the initial state.
type NewJob struct {
	Type             string
	Resource         domain.ResourceRef
	ActorID          domain.ID
	Credential       domain.CredentialContext
	Risk             domain.RiskClass
	RetryClass       domain.RetryClass
	IdempotencyKey   string
	Payload          json.RawMessage
	PlanID           *domain.ID
	PlanHash         string
	MaxAttempts      int       // default 1
	ScheduledAt      time.Time // default now
	AwaitingApproval bool
}

// Enqueue stores a new job as awaiting_approval or queued. Like every Store
// method taking a Querier, it must run inside the caller's write transaction.
func (s *Store) Enqueue(ctx context.Context, q database.Querier, nj NewJob) (Job, error) {
	if err := validateNewJob(nj); err != nil {
		return Job{}, err
	}
	now := s.clock.Now()
	state := domain.JobQueued
	if nj.AwaitingApproval {
		state = domain.JobAwaitingApproval
	}
	scheduled := nj.ScheduledAt
	if scheduled.IsZero() {
		scheduled = now
	}
	maxAttempts := max(nj.MaxAttempts, 1)
	payload := string(nj.Payload)
	if payload == "" {
		payload = "{}"
	}
	scopes, err := json.Marshal(nonNil(nj.Credential.Scopes))
	if err != nil {
		return Job{}, fmt.Errorf("encode scopes: %w", err)
	}
	id := s.ids.NewID()
	_, err = q.ExecContext(ctx, `
		INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, credential_id,
		                  scopes_json, state, risk, retry_class, idempotency_key, payload_json, plan_id,
		                  plan_hash, max_attempts, scheduled_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, nj.Type, nj.Resource.Type, nj.Resource.ID, nj.ActorID, nj.Credential.Kind, nj.Credential.ID,
		string(scopes), state, nj.Risk, nj.RetryClass, nullText(nj.IdempotencyKey), payload, nullID(nj.PlanID),
		nullText(nj.PlanHash), maxAttempts, domain.UnixMillis(scheduled), domain.UnixMillis(now))
	if err != nil {
		return Job{}, fmt.Errorf("insert job: %w", err)
	}
	job, err := s.Get(ctx, q, id)
	if err != nil {
		return Job{}, err
	}
	if err := s.emitTransition(ctx, q, systemActor, job, "", nil); err != nil {
		return Job{}, err
	}
	return job, nil
}

func validateNewJob(nj NewJob) error {
	switch {
	case nj.Type == "":
		return smerr.New(smerr.CodeInvalidArgument, "", "job type is required")
	case !nj.Resource.Type.Valid() || nj.Resource.ID == "":
		return smerr.New(smerr.CodeInvalidArgument, "", "job resource is invalid")
	case !nj.Credential.Kind.Valid():
		return smerr.New(smerr.CodeInvalidArgument, "", "job credential kind is invalid")
	case !nj.Risk.Valid():
		return smerr.New(smerr.CodeInvalidArgument, "", "job risk is invalid")
	case !nj.RetryClass.Valid():
		return smerr.New(smerr.CodeInvalidArgument, "", "job retry class is invalid")
	}
	return nil
}

// Approve moves an awaiting_approval job to queued once the caller has
// established quorum (spec §11.4).
func (s *Store) Approve(ctx context.Context, q database.Querier, id domain.ID, by domain.Actor) (Job, error) {
	return s.move(ctx, q, move{id: id, from: domain.JobAwaitingApproval, to: domain.JobQueued, actor: by})
}

// Cancel cancels a job that has not started (awaiting_approval or queued).
func (s *Store) Cancel(ctx context.Context, q database.Querier, id domain.ID, by domain.Actor) (Job, error) {
	return s.moveFromCurrent(ctx, q, id, domain.JobCancelled, by, nil)
}

// FailPending fails a job that has not started (rejection, plan expiry).
func (s *Store) FailPending(ctx context.Context, q database.Querier, id domain.ID, failure Failure, by domain.Actor) (Job, error) {
	return s.moveFromCurrent(ctx, q, id, domain.JobFailed, by, &failure)
}

// moveFromCurrent restricts a user-triggered move to pre-running states.
func (s *Store) moveFromCurrent(ctx context.Context, q database.Querier, id domain.ID, to domain.JobState, by domain.Actor, failure *Failure) (Job, error) {
	job, err := s.Get(ctx, q, id)
	if err != nil {
		return Job{}, err
	}
	if job.State != domain.JobAwaitingApproval && job.State != domain.JobQueued {
		return Job{}, invalidTransition(job.State, to)
	}
	return s.move(ctx, q, move{id: id, from: job.State, to: to, actor: by, failure: failure})
}

// Get returns the job or NOT_FOUND.
func (s *Store) Get(ctx context.Context, q database.Querier, id domain.ID) (Job, error) {
	job, err := scanJob(q.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, smerr.New(smerr.CodeNotFound, "", "job not found")
	}
	if err != nil {
		return Job{}, fmt.Errorf("get job %s: %w", id, err)
	}
	return job, nil
}

// ListFilter narrows List. Empty States means every state; Limit defaults to 100.
type ListFilter struct {
	States []domain.JobState
	Limit  int
}

// List returns jobs, newest first.
func (s *Store) List(ctx context.Context, q database.Querier, f ListFilter) ([]Job, error) {
	query := `SELECT ` + jobColumns + ` FROM jobs`
	var args []any
	if len(f.States) > 0 {
		query += ` WHERE state IN (?` + strings.Repeat(`, ?`, len(f.States)-1) + `)`
		for _, st := range f.States {
			args = append(args, st)
		}
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, orLimit(f.Limit))
	return queryJobs(ctx, q, query, args...)
}

func orLimit(n int) int {
	if n <= 0 {
		return defaultListLimit
	}
	return n
}

func queryJobs(ctx context.Context, q database.Querier, query string, args ...any) ([]Job, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query jobs: %w", err)
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan job: %w", err)
		}
		out = append(out, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query jobs: %w", err)
	}
	return out, nil
}

const jobColumns = `id, type, resource_type, resource_id, actor_id, credential_kind, credential_id, scopes_json,
	state, risk, retry_class, idempotency_key, payload_json, plan_id, plan_hash, lease_owner, lease_generation,
	lease_until, heartbeat_at, attempts, max_attempts, scheduled_at, created_at, started_at, finished_at, error_json`

type rowScanner interface{ Scan(dest ...any) error }

func scanJob(row rowScanner) (Job, error) {
	var (
		j                                         Job
		scopes, payload                           string
		idemKey, planID, planHash, owner, errJSON sql.NullString
		leaseUntil, heartbeat, started, finished  sql.NullInt64
		scheduled, created                        int64
	)
	err := row.Scan(&j.ID, &j.Type, &j.Resource.Type, &j.Resource.ID, &j.ActorID, &j.CredentialKind,
		&j.CredentialID, &scopes, &j.State, &j.Risk, &j.RetryClass, &idemKey, &payload, &planID, &planHash,
		&owner, &j.LeaseGeneration, &leaseUntil, &heartbeat, &j.Attempts, &j.MaxAttempts, &scheduled,
		&created, &started, &finished, &errJSON)
	if err != nil {
		return Job{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &j.Scopes); err != nil {
		return Job{}, fmt.Errorf("decode scopes: %w", err)
	}
	j.Payload = json.RawMessage(payload)
	j.IdempotencyKey, j.PlanHash, j.LeaseOwner = idemKey.String, planHash.String, owner.String
	if planID.Valid {
		id := domain.ID(planID.String)
		j.PlanID = &id
	}
	j.LeaseUntil, j.HeartbeatAt = timeOf(leaseUntil), timeOf(heartbeat)
	j.StartedAt, j.FinishedAt = timeOf(started), timeOf(finished)
	j.ScheduledAt, j.CreatedAt = domain.FromUnixMillis(scheduled), domain.FromUnixMillis(created)
	if errJSON.Valid {
		var f Failure
		if err := json.Unmarshal([]byte(errJSON.String), &f); err != nil {
			return Job{}, fmt.Errorf("decode error_json: %w", err)
		}
		j.Error = &f
	}
	return j, nil
}

func timeOf(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := domain.FromUnixMillis(n.Int64)
	return &t
}

func nullText(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func nullID(id *domain.ID) sql.NullString {
	if id == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// assignment is an extra SET clause of a move, e.g. {"lease_until = ?", [ms]}.
type assignment struct {
	expr string
	args []any
}

// move is one guarded state transition with its event (ADR-0013).
type move struct {
	id      domain.ID
	from    domain.JobState
	to      domain.JobState
	actor   domain.Actor
	assign  []assignment
	failure *Failure
	data    map[string]any
}

// move applies m as a single UPDATE guarded by the expected from-state, releases
// locks when the target state ends the job's hold, and emits the event. It
// returns the updated job.
func (s *Store) move(ctx context.Context, q database.Querier, m move) (Job, error) {
	if !canTransition(m.from, m.to) {
		return Job{}, invalidTransition(m.from, m.to)
	}
	set := []string{"state = ?"}
	args := []any{m.to}
	for _, a := range m.assign {
		set = append(set, a.expr)
		args = append(args, a.args...)
	}
	if m.to.Terminal() {
		set = append(set, "finished_at = ?")
		args = append(args, domain.UnixMillis(s.clock.Now()))
	}
	if m.failure != nil {
		scrubbed := *m.failure
		scrubbed.Message = audit.ScrubString(scrubbed.Message)
		encoded, err := json.Marshal(scrubbed)
		if err != nil {
			return Job{}, fmt.Errorf("encode failure: %w", err)
		}
		set = append(set, "error_json = ?")
		args = append(args, string(encoded))
	}
	args = append(args, m.id, m.from)
	res, err := q.ExecContext(ctx, `UPDATE jobs SET `+strings.Join(set, ", ")+` WHERE id = ? AND state = ?`, args...)
	if err != nil {
		return Job{}, fmt.Errorf("move job %s to %s: %w", m.id, m.to, err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return Job{}, s.explainMissedMove(ctx, q, m, err)
	}
	if releasesLocks(m.to) {
		if _, err := q.ExecContext(ctx, `DELETE FROM resource_locks WHERE job_id = ?`, m.id); err != nil {
			return Job{}, fmt.Errorf("release locks of job %s: %w", m.id, err)
		}
	}
	job, err := s.Get(ctx, q, m.id)
	if err != nil {
		return Job{}, err
	}
	if err := s.emitTransition(ctx, q, m.actor, job, m.from, m.data); err != nil {
		return Job{}, err
	}
	return job, nil
}

// explainMissedMove turns a zero-row UPDATE into NOT_FOUND or INVALID_TRANSITION.
func (s *Store) explainMissedMove(ctx context.Context, q database.Querier, m move, rowsErr error) error {
	if rowsErr != nil {
		return fmt.Errorf("rows affected: %w", rowsErr)
	}
	current, err := s.Get(ctx, q, m.id)
	if err != nil {
		return err
	}
	return invalidTransition(current.State, m.to)
}

func (s *Store) emitTransition(ctx context.Context, q database.Querier, actor domain.Actor, job Job, from domain.JobState, extra map[string]any) error {
	data := map[string]any{
		"to":               string(job.State),
		"attempts":         job.Attempts,
		"lease_generation": job.LeaseGeneration,
	}
	if from != "" {
		data["from"] = string(from)
	}
	if job.Error != nil && job.State == domain.JobFailed {
		data["error_code"], data["error_reason"] = string(job.Error.Code), string(job.Error.Reason)
	}
	for k, v := range extra {
		data[k] = v
	}
	return s.emit(ctx, q, actor, "job."+string(job.State), job.ID, outcomeOf(job.State), data)
}

type eventOutcome struct {
	severity domain.Severity
	result   domain.Result
}

func outcomeOf(to domain.JobState) eventOutcome {
	switch to {
	case domain.JobFailed:
		return eventOutcome{domain.SeverityError, domain.ResultFailed}
	case domain.JobInterrupted:
		return eventOutcome{domain.SeverityWarning, domain.ResultPending}
	case domain.JobAwaitingApproval:
		return eventOutcome{domain.SeverityInfo, domain.ResultPending}
	case domain.JobQueued, domain.JobRunning, domain.JobSucceeded, domain.JobCancelled:
		return eventOutcome{domain.SeverityInfo, domain.ResultSucceeded}
	}
	return eventOutcome{domain.SeverityInfo, domain.ResultSucceeded}
}

func (s *Store) emit(ctx context.Context, q database.Querier, actor domain.Actor, action string, jobID domain.ID, o eventOutcome, data map[string]any) error {
	_, err := s.emitter.Emit(ctx, database.EventsIn(q), domain.Event{
		ActorType:    actor.Type,
		ActorID:      actor.ID,
		Action:       action,
		ResourceType: domain.ResourceJob,
		ResourceID:   jobID,
		Severity:     o.severity,
		Result:       o.result,
		Data:         data,
	})
	return err
}

// backoffAfter is the delay before retrying a job that has made attempts attempts.
func (s *Store) backoffAfter(attempts int) time.Duration {
	delay := s.backoffBase
	for i := 1; i < attempts && delay < s.backoffMax; i++ {
		delay *= 2
	}
	return min(delay, s.backoffMax)
}
