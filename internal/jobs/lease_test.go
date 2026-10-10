package jobs

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

var errBoom = errors.New("boom")

func TestFenceAcceptsTheCurrentLease(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	c := e.claim("w1")
	e.inTx(func(tx *database.Tx) {
		if err := c.Lease.Fence(context.Background(), tx); err != nil {
			t.Fatalf("Fence = %v", err)
		}
	})
}

func TestFenceRejectsAnExpiredLease(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	c := e.claim("w1")
	e.clock.Advance(leaseTTL) // lease_until > now no longer holds
	err := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return c.Lease.Fence(ctx, tx)
	})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Fence = %v, want ErrLeaseLost", err)
	}
}

func TestFenceRejectsAForeignOwnerOrGeneration(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	c := e.claim("w1")
	for name, lease := range map[string]Lease{
		"other owner":      {JobID: c.Lease.JobID, Owner: "w2", Generation: c.Lease.Generation, clock: e.clock},
		"other generation": {JobID: c.Lease.JobID, Owner: "w1", Generation: c.Lease.Generation + 1, clock: e.clock},
	} {
		err := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
			return lease.Fence(ctx, tx)
		})
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("%s: Fence = %v, want ErrLeaseLost", name, err)
		}
	}
}

func TestHeartbeatExtendsTheLease(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	for range 3 {
		e.clock.Advance(20 * time.Second)
		if err := e.store.Heartbeat(context.Background(), c.Lease); err != nil {
			t.Fatalf("Heartbeat: %v", err)
		}
	}
	got := e.get(job.ID)
	if want := e.clock.Now().Add(leaseTTL); !got.LeaseUntil.Equal(want) || !got.HeartbeatAt.Equal(e.clock.Now()) {
		t.Fatalf("lease_until %v heartbeat_at %v, want %v / %v", got.LeaseUntil, got.HeartbeatAt, want, e.clock.Now())
	}
}

func TestHeartbeatNeverRenewsAnExpiredLease(t *testing.T) {
	e := newEnv(t)
	e.enqueue()
	c := e.claim("w1")
	e.clock.Advance(leaseTTL + time.Second)
	if err := e.store.Heartbeat(context.Background(), c.Lease); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Heartbeat = %v, want ErrLeaseLost", err)
	}
}

func TestTakeoverFencesOldWorker(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	old := e.claim("w1")
	e.clock.Advance(leaseTTL + time.Second)

	taken, err := e.store.Takeover(context.Background(), "r1")
	if err != nil || !slices.Equal(taken, []domain.ID{job.ID}) {
		t.Fatalf("Takeover = %v, %v", taken, err)
	}
	got := e.get(job.ID)
	if got.State != domain.JobInterrupted || got.LeaseGeneration != 2 || got.LeaseOwner != "reconciler:r1" {
		t.Fatalf("job after takeover = %+v", got)
	}
	if e.lockCount(job.ID) != 1 {
		t.Fatalf("locks = %d, takeover must keep them", e.lockCount(job.ID))
	}
	if want := []string{"job.queued", "job.running", "job.interrupted"}; !slices.Equal(e.actions(job.ID), want) {
		t.Fatalf("events = %v, want %v", e.actions(job.ID), want)
	}

	ctx := context.Background()
	writes := map[string]func() error{
		"fence": func() error {
			return e.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error { return old.Lease.Fence(ctx, tx) })
		},
		"heartbeat": func() error { return e.store.Heartbeat(ctx, old.Lease) },
		"succeed":   func() error { return e.store.Succeed(ctx, old.Lease) },
		"fail":      func() error { return e.store.Fail(ctx, old.Lease, errBoom) },
		"record intent": func() error {
			_, err := e.store.RecordIntent(ctx, old.Lease, sampleIntent(e))
			return err
		},
	}
	for name, write := range writes {
		if err := write(); !errors.Is(err, ErrLeaseLost) {
			t.Errorf("old worker %s = %v, want ErrLeaseLost", name, err)
		}
	}
	if after := e.get(job.ID); after.State != domain.JobInterrupted || after.FinishedAt != nil {
		t.Fatalf("old worker changed the job: %+v", after)
	}
}

func TestTakeoverLeavesLiveLeasesAlone(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	e.claim("w1")
	e.clock.Advance(leaseTTL - time.Second)
	taken, err := e.store.Takeover(context.Background(), "r1")
	if err != nil || len(taken) != 0 || e.state(job.ID) != domain.JobRunning {
		t.Fatalf("Takeover = %v, %v; state %s", taken, err, e.state(job.ID))
	}
}

func TestInterruptedJobKeepsLocksAndBlocksConflictingClaims(t *testing.T) {
	e := newEnv(t)
	e.planner.setLocks("holder", domain.LockSpec{Key: "node:n1", Mode: domain.LockExclusive})
	e.planner.setLocks("wanter", domain.LockSpec{Key: "node:n1", Mode: domain.LockShared})
	holder := e.enqueue(func(nj *NewJob) { nj.Type = "holder" })
	wanter := e.enqueue(func(nj *NewJob) { nj.Type = "wanter" })

	e.claim("w1") // holder (older)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	e.claimNothing("w2")
	if e.state(wanter.ID) != domain.JobQueued || e.lockCount(holder.ID) != 1 {
		t.Fatalf("wanter %s, holder locks %d", e.state(wanter.ID), e.lockCount(holder.ID))
	}
}

func TestSucceedReleasesLocks(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	if err := e.store.Succeed(context.Background(), c.Lease); err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	got := e.get(job.ID)
	if got.State != domain.JobSucceeded || got.FinishedAt == nil || e.lockCount(job.ID) != 0 {
		t.Fatalf("job = %+v, locks %d", got, e.lockCount(job.ID))
	}
}

func TestFailByRetryClass(t *testing.T) {
	cases := []struct {
		name       string
		class      domain.RetryClass
		maxAttempt int
		want       domain.JobState
	}{
		{"idempotent with attempts left requeues", domain.RetryIdempotent, 3, domain.JobQueued},
		{"idempotent on its last attempt fails", domain.RetryIdempotent, 1, domain.JobFailed},
		{"resumable is never retried blindly", domain.RetryResumable, 3, domain.JobFailed},
		{"non_retryable never requeues", domain.RetryNonRetryable, 3, domain.JobFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = tc.class, tc.maxAttempt })
			c := e.claim("w1")
			if err := e.store.Fail(context.Background(), c.Lease, errBoom); err != nil {
				t.Fatalf("Fail: %v", err)
			}
			got := e.get(job.ID)
			wantLocks := 0
			if tc.want == domain.JobQueued {
				wantLocks = 1 // locks are held until the job is terminal (spec §20.5)
			}
			if got.State != tc.want || e.lockCount(job.ID) != wantLocks || got.Error == nil || got.Error.Message != "boom" {
				t.Fatalf("job = %+v, locks %d, want %d", got, e.lockCount(job.ID), wantLocks)
			}
		})
	}
}

func TestIdempotentRetryBacksOffExponentially(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 3 })

	for attempt, wait := range []time.Duration{backoffBase, 2 * backoffBase} {
		c := e.claim("w1")
		if err := e.store.Fail(context.Background(), c.Lease, errBoom); err != nil {
			t.Fatal(err)
		}
		got := e.get(job.ID)
		if got.State != domain.JobQueued || got.Attempts != attempt+1 || !got.ScheduledAt.Equal(e.clock.Now().Add(wait)) {
			t.Fatalf("attempt %d: %+v, want queued at +%v", attempt+1, got, wait)
		}
		e.claimNothing("w1") // still backing off
		e.clock.Advance(wait)
	}

	c := e.claim("w1")
	if err := e.store.Fail(context.Background(), c.Lease, errBoom); err != nil {
		t.Fatal(err)
	}
	if got := e.get(job.ID); got.State != domain.JobFailed || got.Attempts != 3 {
		t.Fatalf("after last attempt: %+v", got)
	}
}

func TestRetryClearsThePreviousError(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 2 })
	c := e.claim("w1")
	if err := e.store.Fail(context.Background(), c.Lease, errBoom); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(backoffBase)
	e.claim("w1")
	if got := e.get(job.ID); got.Error != nil {
		t.Fatalf("running job still carries error %+v", got.Error)
	}
}

func TestFailTerminalIgnoresRetryClass(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue(func(nj *NewJob) { nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 5 })
	c := e.claim("w1")
	if err := e.store.FailTerminal(context.Background(), c.Lease, errBoom); err != nil {
		t.Fatal(err)
	}
	if e.state(job.ID) != domain.JobFailed {
		t.Fatalf("state = %s, want failed", e.state(job.ID))
	}
}

func TestLeaseNotIssuedByAStoreIsRejected(t *testing.T) {
	e := newEnv(t)
	err := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return Lease{JobID: e.ids.NewID(), Owner: "x"}.Fence(ctx, tx)
	})
	if err == nil || errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Fence = %v, want a programming error", err)
	}
}
