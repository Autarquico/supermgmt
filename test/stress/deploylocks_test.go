//go:build stress

package stress

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const (
	lockStressJobs     = 60
	lockStressWorkers  = 8
	lockStressProjects = 4
	lockStressPorts    = 6
	lockStressBackoff  = time.Second
)

// lockStressPlanner names, per job, the lock set a deployment takes at claim
// (ADR-0029): its Compose project and published ports exclusively, the shared
// inputs shared. The sets overlap on purpose.
type lockStressPlanner struct {
	byJob map[domain.ID][]domain.LockSpec
}

func (p lockStressPlanner) PlanLocks(_ context.Context, _ database.Querier, job jobs.Job) ([]domain.LockSpec, error) {
	return p.byJob[job.Resource.ID], nil
}

type lockStressRevalidator struct{}

func (lockStressRevalidator) Revalidate(context.Context, database.Querier, jobs.Job) error {
	return nil
}

// lockStressHolders is what the workers believe they hold; a second holder of
// an exclusive key, or a shared one beside an exclusive one, is a violation.
type lockStressHolders struct {
	mu         sync.Mutex
	writers    map[string]int
	readers    map[string]int
	violations []string
}

func (h *lockStressHolders) enter(job domain.ID, specs []domain.LockSpec) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range specs {
		if s.Mode == domain.LockExclusive {
			if h.writers[s.Key] > 0 || h.readers[s.Key] > 0 {
				h.violations = append(h.violations, fmt.Sprintf("job %s took exclusive %s while it was held", job, s.Key))
			}
			h.writers[s.Key]++
			continue
		}
		if h.writers[s.Key] > 0 {
			h.violations = append(h.violations, fmt.Sprintf("job %s took shared %s while it was held exclusively", job, s.Key))
		}
		h.readers[s.Key]++
	}
}

func (h *lockStressHolders) leave(specs []domain.LockSpec) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range specs {
		if s.Mode == domain.LockExclusive {
			h.writers[s.Key]--
		} else {
			h.readers[s.Key]--
		}
	}
}

func TestDeployLocksStress_NoTwoJobsEverHoldConflictingLocksAndEveryJobRuns(t *testing.T) {
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	ids := domaintest.NewSequentialIDs()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	node := ids.NewID()
	planner := lockStressPlanner{byJob: map[domain.ID][]domain.LockSpec{}}
	store, err := jobs.NewStore(jobs.Config{
		DB: db, Clock: clock, IDs: ids, Revalidator: lockStressRevalidator{}, LockPlanner: planner,
		LeaseTTL: time.Hour, BackoffBase: lockStressBackoff,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	actor := ids.NewID()
	enqueueErr := db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateIdentity(ctx, tx, database.Identity{ID: actor, ActorType: domain.ActorHuman, Subject: "tester", CreatedAt: clock.Now()})
		if err != nil {
			return err
		}
		for i := range lockStressJobs {
			target := ids.NewID()
			planner.byJob[target] = []domain.LockSpec{
				domain.ComposeProjectLock(node, fmt.Sprintf("project-%d", i%lockStressProjects), domain.LockExclusive),
				domain.PortLock(node, "127.0.0.1", 8000+i%lockStressPorts, domain.LockExclusive),
				domain.PortLock(node, "127.0.0.1", 8000+(i+1)%lockStressPorts, domain.LockExclusive),
				{Key: fmt.Sprintf("input:%s:shared-%d", node, i%2), Mode: domain.LockShared},
			}
			_, err := store.Enqueue(ctx, tx, jobs.NewJob{
				Type: "deployment.create", Resource: domain.ResourceRef{Type: domain.ResourceAppTarget, ID: target},
				ActorID: actor, Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: "cred", Scopes: []string{"deploy"}},
				Risk: domain.RiskOperational, RetryClass: domain.RetryNonRetryable,
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if enqueueErr != nil {
		t.Fatalf("enqueue: %v", enqueueErr)
	}

	holders := &lockStressHolders{writers: map[string]int{}, readers: map[string]int{}}
	var finished atomic.Int32
	var wg sync.WaitGroup
	for w := range lockStressWorkers {
		owner := fmt.Sprintf("worker-%d", w)
		wg.Go(func() {
			for finished.Load() < lockStressJobs {
				claimed, ok, err := store.Claim(ctx, owner)
				if err != nil {
					t.Errorf("%s: Claim: %v", owner, err)
					return
				}
				if !ok {
					clock.Advance(lockStressBackoff) // lock-blocked jobs are deferred by one backoff step
					runtime.Gosched()
					continue
				}
				specs := planner.byJob[claimed.Job.Resource.ID]
				holders.enter(claimed.Job.ID, specs)
				time.Sleep(200 * time.Microsecond)
				holders.leave(specs)
				if err := store.Succeed(ctx, claimed.Lease); err != nil {
					t.Errorf("%s: Succeed %s: %v", owner, claimed.Job.ID, err)
					return
				}
				finished.Add(1)
			}
		})
	}
	waitDone := make(chan struct{})
	go func() { wg.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(60 * time.Second):
		t.Fatalf("only %d of %d jobs finished: a lock was never released or a job starved", finished.Load(), lockStressJobs)
	}

	for _, v := range holders.violations {
		t.Error(v)
	}
	if got := finished.Load(); got != lockStressJobs {
		t.Errorf("finished %d jobs, want %d", got, lockStressJobs)
	}
	var left int
	if err := db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM resource_locks`).Scan(&left); err != nil {
		t.Fatalf("count locks: %v", err)
	}
	if left != 0 {
		t.Errorf("%d resource locks remain after every job ended, want 0", left)
	}
}
