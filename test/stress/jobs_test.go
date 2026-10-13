//go:build stress

package stress

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
)

var jobsEpoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const jobsLeaseTTL = 30 * time.Second

// jobsRevalidator admits every job.
type jobsRevalidator struct{}

func (jobsRevalidator) Revalidate(context.Context, database.Querier, jobs.Job) error { return nil }

// jobsPlanner takes an exclusive lock on the job's own resource, so jobs on one
// resource exclude each other and jobs on distinct resources never do.
type jobsPlanner struct{}

func (jobsPlanner) PlanLocks(_ context.Context, _ database.Querier, job jobs.Job) ([]domain.LockSpec, error) {
	return []domain.LockSpec{{Key: "node:" + job.Resource.ID.String(), Mode: domain.LockExclusive}}, nil
}

type jobsRig struct {
	t     *testing.T
	db    *database.DB
	ids   *domaintest.SequentialIDs
	store *jobs.Store
	actor domain.ID
}

func newJobsRig(t *testing.T, clock domain.Clock, backoff time.Duration) *jobsRig {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	rig := &jobsRig{t: t, db: db, ids: domaintest.NewSequentialIDs()}
	rig.store, err = jobs.NewStore(jobs.Config{
		DB: db, Clock: clock, IDs: rig.ids, Revalidator: jobsRevalidator{}, LockPlanner: jobsPlanner{},
		LeaseTTL: jobsLeaseTTL, BackoffBase: backoff, BackoffMax: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	rig.actor = rig.ids.NewID()
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.CreateIdentity(ctx, tx, database.Identity{
			ID: rig.actor, ActorType: domain.ActorHuman, Subject: "stress", CreatedAt: clock.Now(),
		})
	})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	return rig
}

// enqueue stores one queued job on the given resource.
func (r *jobsRig) enqueue(resource domain.ID) jobs.Job {
	r.t.Helper()
	var job jobs.Job
	err := r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		var err error
		job, err = r.store.Enqueue(ctx, tx, jobs.NewJob{
			Type:       "stress.job",
			Resource:   domain.ResourceRef{Type: domain.ResourceNode, ID: resource},
			ActorID:    r.actor,
			Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: "cred", Scopes: []string{"node.read"}},
			Risk:       domain.RiskOperational,
			RetryClass: domain.RetryNonRetryable,
		})
		return err
	})
	if err != nil {
		r.t.Fatalf("Enqueue: %v", err)
	}
	return job
}

// claimOne claims the next job for owner and fails the test when there is none.
func (r *jobsRig) claimOne(owner string) jobs.Claimed {
	r.t.Helper()
	claimed, ok, err := r.store.Claim(context.Background(), owner)
	if err != nil || !ok {
		r.t.Fatalf("Claim(%s) = ok %v, err %v; want a job", owner, ok, err)
	}
	return claimed
}

func (r *jobsRig) state(id domain.ID) domain.JobState {
	r.t.Helper()
	job, err := r.store.Get(context.Background(), r.db.Reader(), id)
	if err != nil {
		r.t.Fatalf("Get %s: %v", id, err)
	}
	return job.State
}

// jobsRunConcurrently starts n goroutines at once and waits for all of them.
func jobsRunConcurrently(n int, body func(worker int)) {
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(n)
	done.Add(n)
	for i := range n {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			body(i)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}

func jobsOwner(worker int) string { return "worker-" + strconv.Itoa(worker) }

func TestConcurrentWorkersClaimEveryQueuedJobExactlyOnce(t *testing.T) {
	const jobCount, workers = 40, 8
	rig := newJobsRig(t, domaintest.NewFakeClock(jobsEpoch), 5*time.Second)
	for range jobCount {
		rig.enqueue(rig.ids.NewID())
	}

	var mu sync.Mutex
	claimedBy := map[domain.ID][]string{}
	jobsRunConcurrently(workers, func(worker int) {
		owner := jobsOwner(worker)
		for {
			claimed, ok, err := rig.store.Claim(context.Background(), owner)
			if err != nil {
				t.Errorf("Claim(%s): %v", owner, err)
				return
			}
			if !ok {
				return
			}
			mu.Lock()
			claimedBy[claimed.Job.ID] = append(claimedBy[claimed.Job.ID], owner)
			mu.Unlock()
		}
	})

	if len(claimedBy) != jobCount {
		t.Fatalf("%d jobs claimed, want %d", len(claimedBy), jobCount)
	}
	for id, owners := range claimedBy {
		if len(owners) != 1 {
			t.Errorf("job %s claimed by %v, want exactly one worker", id, owners)
		}
	}
}

func TestJobsOnOneResourceNeverRunAtTheSameTime(t *testing.T) {
	const jobCount, workers = 12, 6
	rig := newJobsRig(t, domain.SystemClock{}, time.Millisecond)
	resource := rig.ids.NewID()
	for range jobCount {
		rig.enqueue(resource)
	}

	var running, peak, succeeded atomic.Int32
	giveUp := time.After(30 * time.Second)
	jobsRunConcurrently(workers, func(worker int) {
		owner := jobsOwner(worker)
		for succeeded.Load() < jobCount {
			select {
			case <-giveUp:
				return
			default:
			}
			claimed, ok, err := rig.store.Claim(context.Background(), owner)
			if err != nil {
				t.Errorf("Claim(%s): %v", owner, err)
				return
			}
			if !ok {
				time.Sleep(time.Millisecond)
				continue
			}
			now := running.Add(1)
			for old := peak.Load(); now > old && !peak.CompareAndSwap(old, now); old = peak.Load() {
			}
			time.Sleep(time.Millisecond)
			running.Add(-1)
			if err := rig.store.Succeed(context.Background(), claimed.Lease); err != nil {
				t.Errorf("Succeed: %v", err)
				return
			}
			succeeded.Add(1)
		}
	})

	if got := succeeded.Load(); got != jobCount {
		t.Fatalf("%d jobs succeeded, want %d", got, jobCount)
	}
	if got := peak.Load(); got != 1 {
		t.Errorf("peak concurrency on one resource = %d, want 1", got)
	}
}

func TestExactlyOneTerminalWriteWinsTheLease(t *testing.T) {
	rig := newJobsRig(t, domaintest.NewFakeClock(jobsEpoch), 5*time.Second)
	rig.enqueue(rig.ids.NewID())
	lease, ctx, cause := rig.claimOne("worker").Lease, context.Background(), errors.New("stress")
	terminalWrites := []func() error{
		func() error { return rig.store.Succeed(ctx, lease) },
		func() error { return rig.store.Succeed(ctx, lease) },
		func() error { return rig.store.Fail(ctx, lease, cause) },
		func() error { return rig.store.FailTerminal(ctx, lease, cause) },
		func() error { return rig.store.Interrupt(ctx, lease, cause) },
	}

	errs := make([]error, len(terminalWrites))
	jobsRunConcurrently(len(terminalWrites), func(i int) { errs[i] = terminalWrites[i]() })

	winners := 0
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case !errors.Is(err, jobs.ErrLeaseLost):
			t.Errorf("write %d failed with %v, want nil or ErrLeaseLost", i, err)
		}
	}
	if winners != 1 {
		t.Errorf("%d terminal writes succeeded, want exactly 1", winners)
	}
	if state := rig.state(lease.JobID); state == domain.JobRunning || state == domain.JobQueued {
		t.Errorf("job state = %s after a terminal write, want a settled state", state)
	}
}

func TestAStaleWorkerCannotWriteWhileReconcilersTakeTheJobOver(t *testing.T) {
	const staleWriters, reconcilers = 8, 4
	clock := domaintest.NewFakeClock(jobsEpoch)
	rig := newJobsRig(t, clock, 5*time.Second)
	rig.enqueue(rig.ids.NewID())
	claimed := rig.claimOne("worker")
	clock.Advance(jobsLeaseTTL + time.Second)

	var mu sync.Mutex
	var taken []domain.ID
	jobsRunConcurrently(staleWriters+reconcilers, func(i int) {
		ctx := context.Background()
		if i < staleWriters {
			for _, err := range []error{
				rig.store.Heartbeat(ctx, claimed.Lease),
				rig.store.Succeed(ctx, claimed.Lease),
			} {
				if !errors.Is(err, jobs.ErrLeaseLost) {
					t.Errorf("stale write = %v, want ErrLeaseLost", err)
				}
			}
			return
		}
		ids, err := rig.store.Takeover(ctx, "reconciler-"+strconv.Itoa(i))
		if err != nil {
			t.Errorf("Takeover: %v", err)
			return
		}
		mu.Lock()
		taken = append(taken, ids...)
		mu.Unlock()
	})

	if len(taken) != 1 || taken[0] != claimed.Job.ID {
		t.Errorf("takeovers = %v, want the job taken exactly once", taken)
	}
	if state := rig.state(claimed.Job.ID); state != domain.JobInterrupted {
		t.Errorf("job state = %s, want interrupted", state)
	}
}

func TestConcurrentHeartbeatsAndTakeoversLeaveALiveLeaseRunning(t *testing.T) {
	const beaters = 8
	rig := newJobsRig(t, domaintest.NewFakeClock(jobsEpoch), 5*time.Second)
	rig.enqueue(rig.ids.NewID())
	claimed := rig.claimOne("worker")

	jobsRunConcurrently(beaters, func(int) {
		ctx := context.Background()
		for range 10 {
			if err := rig.store.Heartbeat(ctx, claimed.Lease); err != nil {
				t.Errorf("Heartbeat on a live lease: %v", err)
				return
			}
			if taken, err := rig.store.Takeover(ctx, "reconciler"); err != nil || len(taken) != 0 {
				t.Errorf("Takeover = %v, %v; a live lease must not be taken", taken, err)
				return
			}
		}
	})

	if state := rig.state(claimed.Job.ID); state != domain.JobRunning {
		t.Errorf("job state = %s, want running", state)
	}
}
