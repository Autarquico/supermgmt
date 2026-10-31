package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Backoff of the jobs the scheduler re-arms, per kind of work: the first retry waits base, each next one
// twice as long, up to limit. An enrollment waits for a person typing a line on a host, so the scan starts
// quick and settles at a minute.
type enrollmentPace struct{ base, limit time.Duration }

var enrollmentPaces = map[enrollmentWork]enrollmentPace{
	workProvision: {5 * time.Second, time.Minute},
	workScan:      {5 * time.Second, time.Minute},
	workCommit:    {10 * time.Second, 2 * time.Minute},
	workCleanup:   {15 * time.Second, 5 * time.Minute},
}

type enrollmentWork int

const (
	workNone enrollmentWork = iota
	workProvision
	workScan
	workCommit
	workCleanup
)

// TunnelEnrollmentScheduler submits the jobs that move the open enrollments along, as the system actor: a
// person starts an enrollment and confirms its key, but the scan that waits for the node, the commit, the
// expiry and the retry of a failed cleanup belong to nobody's credential, which could have expired by then.
// It keeps in memory only when it last submitted for an enrollment: a restart submits at once, which is
// the resume.
type TunnelEnrollmentScheduler struct {
	service  *TunnelEnrollments
	systemID domain.ID

	mu    sync.Mutex
	paced map[domain.ID]pacing
}

type pacing struct {
	work     enrollmentWork
	phase    database.TunnelPhase
	attempts int
	next     time.Time
}

// Scheduler returns the scheduler of the service; systemID is the daemon's identity row of actor type system.
func (s *TunnelEnrollments) Scheduler(systemID domain.ID) *TunnelEnrollmentScheduler {
	return &TunnelEnrollmentScheduler{service: s, systemID: systemID, paced: map[domain.ID]pacing{}}
}

// workOf is what an enrollment needs from a job now.
func (s *TunnelEnrollments) workOf(row database.TunnelEnrollment, now time.Time) enrollmentWork {
	switch {
	case database.EnrollmentFinished(row.Phase):
		return workNone
	case s.endDue(row, now):
		return workCleanup
	case row.Phase.Halted():
		return workNone
	case provisioningPhase(row.Phase):
		return workProvision
	case row.Phase == database.PhaseDNSCreated:
		return workScan
	case row.Phase == database.PhaseConfirmed:
		return workCommit
	}
	return workNone // scanned: the operator confirms or refuses
}

// Tick submits a job for each open enrollment that needs one, has none queued or running and is not waiting
// out its backoff. A failure for one enrollment does not stop the others.
func (t *TunnelEnrollmentScheduler) Tick(ctx context.Context) error {
	s := t.service
	if s.engine == nil {
		return nil
	}
	rows, err := database.ListOpenTunnelEnrollments(ctx, s.cfg.DB.Reader())
	if err != nil {
		return fmt.Errorf("list tunnel enrollments: %w", err)
	}
	now := s.cfg.Clock.Now()
	t.forgetFinished(rows)
	var failures []error
	for _, row := range rows {
		work := s.workOf(row, now)
		if work == workNone || !t.due(row, work, now) {
			continue
		}
		active, err := s.hasActiveJob(ctx, row.ID)
		if err == nil && !active {
			err = t.submit(ctx, row)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("enrollment %s: %w", row.Name, err))
			continue
		}
		t.arm(row, work, now)
	}
	return joinErrors(failures)
}

func joinErrors(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	return fmt.Errorf("%w (and %d more)", errs[0], len(errs)-1)
}

// due reports whether the backoff of the enrollment's current work has run out. Work that changed since the
// last submission starts over.
func (t *TunnelEnrollmentScheduler) due(row database.TunnelEnrollment, work enrollmentWork, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, known := t.paced[row.ID]
	return !known || p.work != work || p.phase != row.Phase || !now.Before(p.next)
}

// arm records that a job was submitted (or is still running) and when the next one may be.
func (t *TunnelEnrollmentScheduler) arm(row database.TunnelEnrollment, work enrollmentWork, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.paced[row.ID]
	if p.work != work || p.phase != row.Phase {
		p = pacing{work: work, phase: row.Phase}
	}
	pace := enrollmentPaces[work]
	delay := pace.base << min(p.attempts, 20)
	if delay <= 0 || delay > pace.limit {
		delay = pace.limit
	}
	p.attempts++
	p.next = now.Add(delay)
	t.paced[row.ID] = p
}

// forgetFinished drops the pacing of enrollments that are no longer open.
func (t *TunnelEnrollmentScheduler) forgetFinished(open []database.TunnelEnrollment) {
	t.mu.Lock()
	defer t.mu.Unlock()
	live := make(map[domain.ID]bool, len(open))
	for _, row := range open {
		live[row.ID] = true
	}
	for id := range t.paced {
		if !live[id] {
			delete(t.paced, id)
		}
	}
}

// hasActiveJob reports whether a job of the enrollment is waiting, running or interrupted.
func (s *TunnelEnrollments) hasActiveJob(ctx context.Context, id domain.ID) (bool, error) {
	var n int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM jobs
		WHERE type = ? AND resource_type = ? AND resource_id = ? AND state IN (?, ?, ?, ?)`,
		JobControlPlaneApply, domain.ResourceNode, id,
		domain.JobAwaitingApproval, domain.JobQueued, domain.JobRunning, domain.JobInterrupted).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count the jobs of enrollment %s: %w", id, err)
	}
	return n > 0, nil
}

// submit plans and enqueues a node.add job for the enrollment as the system actor. The plan names only the
// node: the job reads the enrollment's own row.
func (t *TunnelEnrollmentScheduler) submit(ctx context.Context, row database.TunnelEnrollment) error {
	s := t.service
	by := Caller{ID: t.systemID, Credential: systemCredential, Source: scheduledSource}
	_, err := commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (struct{}, error) {
		actor, err := loadActor(ctx, tx, t.systemID, systemCredential)
		if err != nil {
			return struct{}{}, err
		}
		if actor.Type != domain.ActorSystem {
			return struct{}{}, smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "only the system identity submits the steps of an enrollment")
		}
		params, err := toParams(nodeAddParams{NodeID: row.ID, Name: row.Name, Tunnel: true})
		if err != nil {
			return struct{}{}, err
		}
		b, err := build(ctx, tx, actionNodeAdd, t.systemID, nodeRef(row.ID), params)
		if err != nil {
			return struct{}{}, err
		}
		res, err := s.evaluate(ctx, tx, actor, b)
		if err != nil {
			return struct{}{}, err
		}
		_, err = s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		return struct{}{}, err
	})
	return err
}
