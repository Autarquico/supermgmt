package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Takeover interrupts every running job whose lease has expired (spec §20.4).
// The lease generation is bumped in the same transaction, so every later write
// by the old worker fails its fence. Locks are kept. It returns the interrupted
// jobs.
//
// The expiry test is lease_until <= now, the exact complement of the fence's
// lease_until > now, so there is no instant at which both sides may write.
func (s *Store) Takeover(ctx context.Context, reconcilerID string) ([]domain.ID, error) {
	var taken []domain.ID
	err := s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		expired, err := queryJobs(ctx, tx, `SELECT `+jobColumns+` FROM jobs
			WHERE state = 'running' AND lease_until <= ? ORDER BY id`, domain.UnixMillis(s.clock.Now()))
		if err != nil {
			return err
		}
		for _, job := range expired {
			_, err := s.move(ctx, tx, move{
				id: job.ID, from: domain.JobRunning, to: domain.JobInterrupted, actor: systemActor,
				assign: []assignment{
					{"lease_generation = lease_generation + 1", nil},
					{"lease_owner = ?", []any{"reconciler:" + reconcilerID}},
				},
				data: map[string]any{"previous_owner": job.LeaseOwner},
			})
			if err != nil {
				return err
			}
			taken = append(taken, job.ID)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("takeover: %w", err)
	}
	return taken, nil
}

// evidenceWindow bounds how long after an intent's deadline the reconciler keeps
// asking adapters for evidence (spec §20.4); after it the job waits for a human.
const evidenceWindow = 5 * time.Minute

// Classification is the outcome of an operation, judged only after its
// completion is proven (spec §20.4 step 3).
type Classification string

const (
	ClassComplete      Classification = "complete"
	ClassNotStarted    Classification = "not_started"
	ClassPartialStable Classification = "partial_stable"
	ClassUnknown       Classification = "unknown"
)

// Evidence is what an adapter observed about one dispatched operation.
//
// Done and ExitStatus are the completion proof: only a completion signal with
// exit status 0 proves the platform finished. Classification is a separate
// judgement of the resulting state, valid only with proof. Nothing is ever
// concluded from Done alone.
type Evidence struct {
	Done           bool           `json:"done"`
	ExitStatus     int            `json:"exit_status"`
	Classification Classification `json:"classification,omitempty"`
}

// Proven reports whether the operation provably completed with exit status 0.
func (e Evidence) Proven() bool { return e.Done && e.ExitStatus == 0 }

// definite reports whether the evidence is proven and names a classification
// automatic recovery may act on (partial_stable and unknown never are).
func (e Evidence) definite() bool {
	return e.Proven() && (e.Classification == ClassComplete || e.Classification == ClassNotStarted)
}

// EvidenceSource collects completion evidence for a dispatched intent. Concrete
// adapters (SSH, Docker, systemd, Proxmox) arrive with their milestones.
// Collect runs outside any transaction; an error counts as no evidence. The
// reconciler asks again on later passes and acts only when two samples at least
// SampleGap apart agree.
type EvidenceSource interface {
	Collect(ctx context.Context, intent Intent) (Evidence, error)
}

// ReconcileAction is what the reconciler did with an interrupted job.
type ReconcileAction string

const (
	ReconcileRequeued  ReconcileAction = "requeued"
	ReconcileSucceeded ReconcileAction = "succeeded"
	ReconcileFailed    ReconcileAction = "failed"
	// ReconcileHeld means evidence is missing or inconclusive: the job stays
	// interrupted with its locks, for human resolution. Nothing is ever redispatched.
	ReconcileHeld ReconcileAction = "held"
)

// Resolution reports one reconciled job.
type Resolution struct {
	JobID  domain.ID
	Action ReconcileAction
}

// Reconcile examines every quiescent interrupted job (spec §20.4). src may be
// nil, which means no evidence is ever available. Per-job failures do not stop
// the pass; they are returned joined, next to the resolutions that did happen.
func (s *Store) Reconcile(ctx context.Context, src EvidenceSource) ([]Resolution, error) {
	interrupted, err := s.List(ctx, s.db.Reader(), ListFilter{States: []domain.JobState{domain.JobInterrupted}, Limit: 1 << 20})
	if err != nil {
		return nil, fmt.Errorf("reconcile: %w", err)
	}
	var (
		resolutions []Resolution
		errs        []error
	)
	for _, job := range interrupted {
		res, err := s.reconcileJob(ctx, job, src)
		if err != nil {
			errs = append(errs, fmt.Errorf("job %s: %w", job.ID, err))
			continue
		}
		if res != nil {
			resolutions = append(resolutions, *res)
		}
	}
	return resolutions, errors.Join(errs...)
}

func (s *Store) reconcileJob(ctx context.Context, job Job, src EvidenceSource) (*Resolution, error) {
	intents, err := s.Intents(ctx, s.db.Reader(), job.ID)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	if !s.quiescent(job, intents, now) {
		return nil, nil
	}
	observed := s.observe(ctx, src, intents, now)

	var (
		res    *Resolution
		reason string
	)
	err = s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		fresh, err := s.Get(ctx, tx, job.ID)
		if err != nil {
			return err
		}
		if fresh.State != domain.JobInterrupted || fresh.LeaseGeneration != job.LeaseGeneration {
			return nil // resolved or taken over meanwhile
		}
		current, err := s.Intents(ctx, tx, job.ID)
		if err != nil {
			return err
		}
		res, reason, err = s.applyVerdict(ctx, tx, fresh, current, observed)
		return err
	})
	if err == nil && res != nil {
		s.rememberHeld(job.ID, res.Action, reason)
	}
	return res, err
}

// quiescent holds when no worker can still write for the job and no remote
// process of ours can still be running: the lease has expired, the generation
// was bumped past every intent's, and every dispatched intent either carries
// completion proof or is past deadline_at + reconcile_grace (spec §20.4).
func (s *Store) quiescent(job Job, intents []Intent, now time.Time) bool {
	if job.LeaseUntil == nil || job.LeaseUntil.After(now) {
		return false
	}
	for _, in := range intents {
		if in.LeaseGeneration >= job.LeaseGeneration {
			return false
		}
		if in.Dispatched() && !storedEvidence(in).Proven() && !now.After(in.DeadlineAt.Add(s.reconcileGrace)) {
			return false
		}
	}
	return true
}

func storedEvidence(in Intent) Evidence {
	var ev Evidence
	if len(in.Evidence) > 0 {
		_ = json.Unmarshal(in.Evidence, &ev) // unreadable evidence is no evidence
	}
	return ev
}

// sample is the first observation of an intent's outcome, awaiting its twin.
type sample struct {
	class Classification
	at    time.Time
}

// observe returns the evidence the reconciler may act on, per dispatched
// intent: proven, classified, and confirmed by two identical samples at least
// sampleGap apart. Collection stops at deadline_at + evidenceWindow.
func (s *Store) observe(ctx context.Context, src EvidenceSource, intents []Intent, now time.Time) map[domain.ID]Evidence {
	confirmed := map[domain.ID]Evidence{}
	if src == nil {
		return confirmed
	}
	for _, in := range intents {
		if !in.Dispatched() || now.After(in.DeadlineAt.Add(evidenceWindow)) {
			continue
		}
		ev, err := src.Collect(ctx, in)
		if err != nil || !s.confirm(in.ID, ev, now) {
			continue
		}
		confirmed[in.ID] = ev
	}
	return confirmed
}

// confirm records ev as a sample and reports whether it completes a pair.
// Anything that is not definite resets the pair.
func (s *Store) confirm(id domain.ID, ev Evidence, now time.Time) bool {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if !ev.definite() {
		delete(s.samples, id)
		return false
	}
	first, seen := s.samples[id]
	if !seen || first.class != ev.Classification {
		s.samples[id] = sample{class: ev.Classification, at: now}
		return false
	}
	return !now.Before(first.at.Add(s.sampleGap))
}

// rememberHeld tracks the reason of the last job.reconcile_held event, so a
// held job is reported when it enters held or its reason changes, not each pass.
func (s *Store) rememberHeld(job domain.ID, action ReconcileAction, reason string) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if action == ReconcileHeld {
		s.held[job] = reason
		return
	}
	delete(s.held, job)
}

func (s *Store) alreadyReported(job domain.ID, reason string) bool {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	last, ok := s.held[job]
	return ok && last == reason
}

type verdict struct {
	action  ReconcileAction
	reason  string
	failure *Failure
}

func held(reason string) verdict { return verdict{action: ReconcileHeld, reason: reason} }

func failed(msg string) verdict {
	return verdict{action: ReconcileFailed, reason: msg, failure: &Failure{Code: smerr.CodeInternal, Message: msg}}
}

// decide is the reconciliation table of spec §20.4 as a pure function. It never
// returns an action that would dispatch an operation again. Every dispatched
// intent, completed by its worker or not, needs confirmed exit-0 proof first;
// the outcome the worker recorded is kept apart from that proof.
func decide(job Job, intents []Intent, observed map[domain.ID]Evidence) verdict {
	for _, in := range intents {
		if in.Dispatched() && !observed[in.ID].definite() {
			return held("no confirmed completion proof for intent " + in.ID.String())
		}
	}
	switch job.RetryClass {
	case domain.RetryIdempotent:
		if job.Attempts >= job.MaxAttempts {
			return failed("job interrupted and its attempts are exhausted")
		}
		return verdict{action: ReconcileRequeued, reason: "idempotent job requeued"}
	case domain.RetryResumable:
		if job.Attempts >= job.MaxAttempts {
			return held("resumable job has no attempts left")
		}
		return verdict{action: ReconcileRequeued, reason: "resumable job resumes from its completed intents"}
	case domain.RetryNonRetryable:
		return decideNonRetryable(intents, observed)
	}
	return held("unknown retry class")
}

func decideNonRetryable(intents []Intent, observed map[domain.ID]Evidence) verdict {
	var complete, notStarted int
	for _, in := range intents {
		if !in.Dispatched() {
			return failed("job interrupted before dispatching intent " + in.ID.String())
		}
		if observed[in.ID].Classification != ClassComplete { // decide guarantees definite: not_started
			notStarted++
			continue
		}
		if in.State == IntentCompleted && in.Outcome != OutcomeSucceeded {
			return held("intent " + in.ID.String() + " contradicts its recorded outcome")
		}
		complete++
	}
	switch {
	case complete == 0:
		return failed("job interrupted before any operation took effect")
	case notStarted > 0:
		return held("some operations took effect and others did not")
	}
	return verdict{action: ReconcileSucceeded, reason: "every dispatched operation completed"}
}

func (s *Store) applyVerdict(ctx context.Context, tx *database.Tx, job Job, intents []Intent, observed map[domain.ID]Evidence) (*Resolution, string, error) {
	v := decide(job, intents, observed)
	res := &Resolution{JobID: job.ID, Action: v.action}
	if v.action == ReconcileHeld {
		if s.alreadyReported(job.ID, v.reason) {
			return res, v.reason, nil
		}
		err := s.emit(ctx, tx, systemActor, "job.reconcile_held", job.ID,
			eventOutcome{domain.SeverityWarning, domain.ResultPending}, map[string]any{"reason": v.reason})
		return res, v.reason, err
	}
	if err := s.completeProven(ctx, tx, job, intents, observed); err != nil {
		return nil, "", err
	}
	if v.action == ReconcileRequeued {
		return res, v.reason, s.requeueNow(ctx, tx, job, domain.JobInterrupted, v.reason)
	}
	to := domain.JobSucceeded
	if v.action == ReconcileFailed {
		to = domain.JobFailed
	}
	_, err := s.move(ctx, tx, move{
		id: job.ID, from: domain.JobInterrupted, to: to, actor: systemActor, failure: v.failure,
		data: map[string]any{"reason": v.reason},
	})
	return res, v.reason, err
}

// completeProven closes dispatched intents the evidence settled: complete
// operations as succeeded, operations that never started as not_started.
func (s *Store) completeProven(ctx context.Context, q database.Querier, job Job, intents []Intent, observed map[domain.ID]Evidence) error {
	for _, in := range intents {
		if in.State != IntentRecorded || !in.Dispatched() {
			continue
		}
		ev := observed[in.ID]
		raw, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("encode evidence: %w", err)
		}
		outcome := OutcomeSucceeded
		if ev.Classification == ClassNotStarted {
			outcome = OutcomeNotStarted
		}
		if err := s.completeIntent(ctx, q, job.ID, in.ID, outcome, raw); err != nil {
			return err
		}
	}
	return nil
}
