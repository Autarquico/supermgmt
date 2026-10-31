package app

import (
	"context"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// txStep is work that must commit with a record change, in the same fenced transaction.
type txStep func(ctx context.Context, tx *database.Tx) error

// recordHooks wrap the state change of Advance: Before runs after the lease fence and ahead of the
// change (the endpoint switch, the capability), After runs once it is written (the audit event).
type recordHooks struct{ Before, After txStep }

// tunnelRecord is what provisionCloudflare and its helpers read and advance: the per-node
// tunnel_operations row of `sm nodes setup --tunnel`, or the tunnel_enrollments row of a node that does not
// exist yet. Both fence every write on the job's lease and refuse to change a recorded object ID.
type tunnelRecord interface {
	ID() domain.ID
	Objects() database.TunnelObjects // the IDs written so far
	Phase() database.TunnelPhase
	PhaseStartedAt() time.Time // the adoption window starts here
	// Advance moves to next and records any non-empty IDs of set, atomically with the hooks.
	Advance(ctx context.Context, next database.TunnelPhase, set database.TunnelObjects, hooks recordHooks) error
	// Halt moves to halt (failed or conflict), keeping the phase it left as the halted phase. message is
	// already sanitized; after runs in the same transaction.
	Halt(ctx context.Context, halt database.TunnelPhase, message string, after txStep) error
}

// record is the run's tunnel record: the node's operation unless the run was given another.
func (r *tunnelRun) record() tunnelRecord {
	if r.rec == nil {
		r.rec = operationRecord{run: r}
	}
	return r.rec
}

// operationRecord is the tunnel_operations row held in run.op, which the disable path also reads.
type operationRecord struct{ run *tunnelRun }

func (o operationRecord) ID() domain.ID                   { return o.run.op.ID }
func (o operationRecord) Objects() database.TunnelObjects { return o.run.op.Objects }
func (o operationRecord) Phase() database.TunnelPhase     { return o.run.op.Phase }
func (o operationRecord) PhaseStartedAt() time.Time       { return o.run.op.PhaseStartedAt }

func (o operationRecord) Advance(ctx context.Context, next database.TunnelPhase, set database.TunnelObjects, hooks recordHooks) error {
	r := o.run
	var advanced database.TunnelOperation
	err := r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if err := runStep(ctx, tx, hooks.Before); err != nil {
			return err
		}
		var err error
		advanced, err = database.AdvanceTunnelPhase(ctx, tx, r.op.ID, r.op.Generation, r.op.Phase, next, set, r.cfg.Clock.Now())
		if err != nil {
			return err
		}
		return runStep(ctx, tx, hooks.After)
	})
	if err == nil {
		r.op = advanced
	}
	return err
}

func (o operationRecord) Halt(ctx context.Context, halt database.TunnelPhase, message string, after txStep) error {
	r := o.run
	return r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if _, err := database.HaltTunnelOperation(ctx, tx, r.op.ID, r.op.Generation, r.op.Phase, halt, message, r.cfg.Clock.Now()); err != nil {
			return err
		}
		return runStep(ctx, tx, after)
	})
}

// enrollmentRecord is a tunnel_enrollments row, advanced under the same fence. Its state is the copy it
// last wrote; the compare-and-swap on the stored phase catches any other writer.
type enrollmentRecord struct {
	e     database.TunnelEnrollment
	write func(context.Context, func(context.Context, *database.Tx) error) error
	lease jobs.Lease
	now   func() time.Time
}

// newEnrollmentRecord wraps e. write is the daemon's write transaction runner.
func newEnrollmentRecord(e database.TunnelEnrollment, lease jobs.Lease,
	write func(context.Context, func(context.Context, *database.Tx) error) error, now func() time.Time,
) *enrollmentRecord {
	return &enrollmentRecord{e: e, write: write, lease: lease, now: now}
}

// Enrollment is the row as last read or written.
func (e *enrollmentRecord) Enrollment() database.TunnelEnrollment { return e.e }

func (e *enrollmentRecord) ID() domain.ID                   { return e.e.ID }
func (e *enrollmentRecord) Objects() database.TunnelObjects { return e.e.Objects }
func (e *enrollmentRecord) Phase() database.TunnelPhase     { return e.e.Phase }
func (e *enrollmentRecord) PhaseStartedAt() time.Time       { return e.e.PhaseStartedAt }

func (e *enrollmentRecord) Advance(ctx context.Context, next database.TunnelPhase, set database.TunnelObjects, hooks recordHooks) error {
	var advanced database.TunnelEnrollment
	err := e.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := e.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if err := runStep(ctx, tx, hooks.Before); err != nil {
			return err
		}
		var err error
		advanced, err = database.AdvanceTunnelEnrollment(ctx, tx, e.e.ID, e.e.Phase, next, set, e.now())
		if err != nil {
			return err
		}
		return runStep(ctx, tx, hooks.After)
	})
	if err == nil {
		e.e = advanced
	}
	return err
}

func (e *enrollmentRecord) Halt(ctx context.Context, halt database.TunnelPhase, message string, after txStep) error {
	return e.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := e.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if _, err := database.HaltTunnelEnrollment(ctx, tx, e.e.ID, e.e.Phase, halt, message, e.now()); err != nil {
			return err
		}
		return runStep(ctx, tx, after)
	})
}

func runStep(ctx context.Context, tx *database.Tx, step txStep) error {
	if step == nil {
		return nil
	}
	return step(ctx, tx)
}
