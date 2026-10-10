package jobs

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// adrAllowed is ADR-0013's transition table, written out independently of the
// implementation (the "(submit)" rows are covered by the Enqueue tests).
var adrAllowed = map[[2]domain.JobState]bool{
	{domain.JobAwaitingApproval, domain.JobQueued}:    true,
	{domain.JobAwaitingApproval, domain.JobFailed}:    true,
	{domain.JobAwaitingApproval, domain.JobCancelled}: true,
	{domain.JobQueued, domain.JobRunning}:             true,
	{domain.JobQueued, domain.JobAwaitingApproval}:    true,
	{domain.JobQueued, domain.JobFailed}:              true,
	{domain.JobQueued, domain.JobCancelled}:           true,
	{domain.JobRunning, domain.JobSucceeded}:          true,
	{domain.JobRunning, domain.JobFailed}:             true,
	{domain.JobRunning, domain.JobQueued}:             true,
	{domain.JobRunning, domain.JobInterrupted}:        true,
	{domain.JobInterrupted, domain.JobQueued}:         true,
	{domain.JobInterrupted, domain.JobSucceeded}:      true,
	{domain.JobInterrupted, domain.JobFailed}:         true,
}

func TestMoveFollowsTheADRTable(t *testing.T) {
	e := newEnv(t)
	for _, from := range domain.AllJobStates() {
		for _, to := range domain.AllJobStates() {
			t.Run(string(from)+"->"+string(to), func(t *testing.T) {
				job := e.enqueue()
				e.inTx(func(tx *database.Tx) {
					if _, err := tx.ExecContext(context.Background(), `UPDATE jobs SET state = ? WHERE id = ?`, from, job.ID); err != nil {
						t.Fatal(err)
					}
				})
				var got error
				e.inTx(func(tx *database.Tx) {
					_, got = e.store.move(context.Background(), tx, move{id: job.ID, from: from, to: to, actor: systemActor})
				})
				if adrAllowed[[2]domain.JobState{from, to}] {
					if got != nil {
						t.Fatalf("move = %v, want allowed", got)
					}
					if state := e.state(job.ID); state != to {
						t.Fatalf("state = %s, want %s", state, to)
					}
					return
				}
				if !errors.Is(got, smerr.FromReason(smerr.ReasonInvalidTransition, "")) {
					t.Fatalf("move = %v, want CONFLICT/INVALID_TRANSITION", got)
				}
				if state := e.state(job.ID); state != from {
					t.Fatalf("state = %s after rejected move, want %s", state, from)
				}
			})
		}
	}
}

func TestMoveGuardedByExpectedFromState(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue() // queued
	var err error
	e.inTx(func(tx *database.Tx) {
		_, err = e.store.move(context.Background(), tx, move{
			id: job.ID, from: domain.JobAwaitingApproval, to: domain.JobQueued, actor: systemActor,
		})
	})
	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("move from the wrong state = %v, want CONFLICT", err)
	}
}

func TestEnqueueStates(t *testing.T) {
	e := newEnv(t)
	queued := e.enqueue()
	awaiting := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })
	if queued.State != domain.JobQueued || awaiting.State != domain.JobAwaitingApproval {
		t.Fatalf("states = %s, %s", queued.State, awaiting.State)
	}
	if !slices.Equal(e.actions(queued.ID), []string{"job.queued"}) ||
		!slices.Equal(e.actions(awaiting.ID), []string{"job.awaiting_approval"}) {
		t.Fatalf("enqueue events = %v, %v", e.actions(queued.ID), e.actions(awaiting.ID))
	}
	if queued.MaxAttempts != 1 || queued.Attempts != 0 || queued.LeaseGeneration != 0 {
		t.Fatalf("defaults = %+v", queued)
	}
}

func TestEnqueueRejectsInvalidJobs(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func(*NewJob){
		"missing type":       func(nj *NewJob) { nj.Type = "" },
		"unknown resource":   func(nj *NewJob) { nj.Resource.Type = "bogus" },
		"unknown credential": func(nj *NewJob) { nj.Credential.Kind = "bogus" },
		"unknown risk":       func(nj *NewJob) { nj.Risk = "bogus" },
		"unknown retry":      func(nj *NewJob) { nj.RetryClass = "bogus" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			nj := NewJob{
				Type: "x", Resource: domain.ResourceRef{Type: domain.ResourceNode, ID: e.ids.NewID()}, ActorID: e.actor,
				Credential: domain.CredentialContext{Kind: domain.CredentialSession}, Risk: domain.RiskRead,
				RetryClass: domain.RetryIdempotent,
			}
			mutate(&nj)
			err := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
				_, err := e.store.Enqueue(ctx, tx, nj)
				return err
			})
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Fatalf("Enqueue = %v, want INVALID_ARGUMENT", err)
			}
		})
	}
}

func TestApproveMovesAwaitingApprovalToQueued(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })
	e.claimNothing("w1") // not runnable before approval

	e.inTx(func(tx *database.Tx) {
		if _, err := e.store.Approve(context.Background(), tx, job.ID, domain.Actor{ID: e.actor, Type: domain.ActorHuman}); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	})
	if got := e.claim("w1").Job.ID; got != job.ID {
		t.Fatalf("claimed %s, want %s", got, job.ID)
	}
}

func TestApproveRequiresAwaitingApproval(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue() // already queued
	err := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := e.store.Approve(ctx, tx, job.ID, systemActor)
		return err
	})
	if !errors.Is(err, smerr.FromReason(smerr.ReasonInvalidTransition, "")) {
		t.Fatalf("Approve on queued job = %v, want INVALID_TRANSITION", err)
	}
}

func TestCancelOnlyBeforeRunning(t *testing.T) {
	e := newEnv(t)
	for _, awaiting := range []bool{true, false} {
		job := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = awaiting })
		e.inTx(func(tx *database.Tx) {
			got, err := e.store.Cancel(context.Background(), tx, job.ID, systemActor)
			if err != nil || got.State != domain.JobCancelled || got.FinishedAt == nil {
				t.Fatalf("Cancel = %+v, %v", got, err)
			}
		})
	}

	e.enqueue()
	running := e.claim("w1")
	err := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := e.store.Cancel(ctx, tx, running.Job.ID, systemActor)
		return err
	})
	if !errors.Is(err, smerr.FromReason(smerr.ReasonInvalidTransition, "")) {
		t.Fatalf("Cancel of running job = %v, want INVALID_TRANSITION", err)
	}
}

func TestFailPendingRecordsFailure(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })
	failure := Failure{Code: smerr.CodeConflict, Reason: smerr.ReasonPlanExpired, Message: "plan expired"}
	e.inTx(func(tx *database.Tx) {
		if _, err := e.store.FailPending(context.Background(), tx, job.ID, failure, systemActor); err != nil {
			t.Fatalf("FailPending: %v", err)
		}
	})
	got := e.get(job.ID)
	if got.State != domain.JobFailed || got.Error == nil || got.Error.Reason != smerr.ReasonPlanExpired {
		t.Fatalf("job = %+v", got)
	}
}

func TestUnknownJobIsNotFound(t *testing.T) {
	e := newEnv(t)
	_, err := e.store.Get(context.Background(), e.db.Reader(), e.ids.NewID())
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Fatalf("Get = %v, want NOT_FOUND", err)
	}
}

func TestEventWriteFailureRollsBackTheTransition(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })
	err := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := e.store.Approve(ctx, tx, job.ID, domain.Actor{Type: "bogus"}) // event validation fails
		return err
	})
	if err == nil {
		t.Fatal("Approve succeeded with an unwritable event")
	}
	if state := e.state(job.ID); state != domain.JobAwaitingApproval {
		t.Fatalf("state = %s, want awaiting_approval", state)
	}
}

func TestEveryTransitionEmitsAnEvent(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })
	e.inTx(func(tx *database.Tx) {
		if _, err := e.store.Approve(context.Background(), tx, job.ID, systemActor); err != nil {
			t.Fatal(err)
		}
	})
	c := e.claim("w1")
	if err := e.store.Succeed(context.Background(), c.Lease); err != nil {
		t.Fatal(err)
	}
	want := []string{"job.awaiting_approval", "job.queued", "job.running", "job.succeeded"}
	if got := e.actions(job.ID); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestListFiltersByState(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	waiting := e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })
	got, err := e.store.List(context.Background(), e.db.Reader(), ListFilter{States: []domain.JobState{domain.JobAwaitingApproval}})
	if err != nil || len(got) != 1 || got[0].ID != waiting.ID {
		t.Fatalf("List = %v, %v", got, err)
	}
	all, err := e.store.List(context.Background(), e.db.Reader(), ListFilter{})
	if err != nil || len(all) != 2 {
		t.Fatalf("List all = %d jobs, %v", len(all), err)
	}
}
