package jobs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestClaimLeasesTheOldestDueJob(t *testing.T) {
	e := newEnv(t)
	oldest := e.enqueue()
	e.clock.Advance(time.Millisecond)
	e.enqueue()

	c := e.claim("w1")
	if c.Job.ID != oldest.ID {
		t.Fatalf("claimed %s, want oldest %s", c.Job.ID, oldest.ID)
	}
	j := e.get(oldest.ID)
	if j.State != domain.JobRunning || j.LeaseOwner != "w1" || j.LeaseGeneration != 1 || j.Attempts != 1 ||
		j.StartedAt == nil || j.LeaseUntil == nil || !j.LeaseUntil.Equal(e.clock.Now().Add(leaseTTL)) {
		t.Fatalf("running job = %+v", j)
	}
	if c.Lease.Generation != 1 || c.Lease.Owner != "w1" || c.Lease.JobID != oldest.ID {
		t.Fatalf("lease = %+v", c.Lease)
	}
	if e.lockCount(oldest.ID) != 1 {
		t.Fatalf("locks = %d, want 1", e.lockCount(oldest.ID))
	}
}

func TestClaimSkipsJobsNotYetDue(t *testing.T) {
	e := newEnv(t)
	e.enqueue(func(nj *NewJob) { nj.ScheduledAt = epoch.Add(time.Minute) })
	e.claimNothing("w1")
	e.clock.Advance(time.Minute)
	e.claim("w1")
}

func TestClaimIgnoresJobsThatAreNotQueued(t *testing.T) {
	e := newEnv(t)
	e.enqueue(func(nj *NewJob) { nj.AwaitingApproval = true })
	e.claimNothing("w1")
}

func TestConcurrentClaimsNeverDoubleClaim(t *testing.T) {
	const workers = 8
	cases := map[string]int{"one job": 1, "three jobs": 3, "more jobs than workers": 12}
	for name, jobs := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			for range jobs {
				e.enqueue()
			}
			var (
				mu      sync.Mutex
				claimed = map[domain.ID]int{}
				wg      sync.WaitGroup
			)
			for i := range workers {
				wg.Go(func() {
					owner := "w" + string(rune('a'+i))
					for {
						c, ok, err := e.store.Claim(context.Background(), owner)
						if err != nil {
							t.Errorf("Claim: %v", err)
							return
						}
						if !ok {
							return
						}
						mu.Lock()
						claimed[c.Job.ID]++
						mu.Unlock()
					}
				})
			}
			wg.Wait()
			if len(claimed) != jobs {
				t.Fatalf("claimed %d distinct jobs, want %d", len(claimed), jobs)
			}
			for id, n := range claimed {
				if n != 1 || e.get(id).Attempts != 1 || e.get(id).LeaseGeneration != 1 {
					t.Fatalf("job %s claimed %d times (%+v)", id, n, e.get(id))
				}
			}
		})
	}
}

func TestLockCompatibilityMatrix(t *testing.T) {
	const key = "compose_project:node-1:shop"
	cases := []struct {
		held, wanted domain.LockMode
		wantClaim    bool
	}{
		{domain.LockExclusive, domain.LockExclusive, false},
		{domain.LockExclusive, domain.LockShared, false},
		{domain.LockShared, domain.LockExclusive, false},
		{domain.LockShared, domain.LockShared, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.held)+" held, "+string(tc.wanted)+" wanted", func(t *testing.T) {
			e := newEnv(t)
			e.planner.setLocks("holder", domain.LockSpec{Key: key, Mode: tc.held})
			e.planner.setLocks("wanter", domain.LockSpec{Key: key, Mode: tc.wanted})
			holder := e.enqueue(func(nj *NewJob) { nj.Type = "holder" })
			e.clock.Advance(time.Millisecond)
			wanter := e.enqueue(func(nj *NewJob) { nj.Type = "wanter" })

			if got := e.claim("w1").Job.ID; got != holder.ID {
				t.Fatalf("first claim = %s, want holder", got)
			}
			c, ok, err := e.store.Claim(context.Background(), "w2")
			if err != nil || ok != tc.wantClaim {
				t.Fatalf("second claim ok=%v err=%v, want ok=%v", ok, err, tc.wantClaim)
			}
			if !tc.wantClaim && e.state(wanter.ID) != domain.JobQueued {
				t.Fatalf("blocked job state = %s, want queued", e.state(wanter.ID))
			}
			if tc.wantClaim && c.Job.ID != wanter.ID {
				t.Fatalf("second claim = %s, want wanter", c.Job.ID)
			}
		})
	}
}

func TestLockKeySplitsAtTheFirstColon(t *testing.T) {
	e := newEnv(t)
	e.planner.setLocks("test.job", domain.LockSpec{Key: "compose_project:node-1:shop", Mode: domain.LockExclusive})
	job := e.enqueue()
	e.claim("w1")
	var kind, id string
	err := e.db.Reader().QueryRowContext(context.Background(),
		`SELECT resource_type, resource_id FROM resource_locks WHERE job_id = ?`, job.ID).Scan(&kind, &id)
	if err != nil || kind != "compose_project" || id != "node-1:shop" {
		t.Fatalf("lock = %q %q, %v", kind, id, err)
	}
}

func TestDuplicateLockSpecsMergeToTheStrongestMode(t *testing.T) {
	e := newEnv(t)
	e.planner.setLocks("test.job",
		domain.LockSpec{Key: "node:n1", Mode: domain.LockShared},
		domain.LockSpec{Key: "node:n1", Mode: domain.LockExclusive})
	job := e.enqueue()
	e.claim("w1")
	var mode string
	if err := e.db.Reader().QueryRowContext(context.Background(),
		`SELECT mode FROM resource_locks WHERE job_id = ?`, job.ID).Scan(&mode); err != nil || mode != "exclusive" {
		t.Fatalf("mode = %q, %v", mode, err)
	}
}

func TestLockConflictLeavesJobQueuedAndTriesTheNextCandidate(t *testing.T) {
	e := newEnv(t)
	e.planner.setLocks("holder", domain.LockSpec{Key: "node:n1", Mode: domain.LockExclusive})
	e.planner.setLocks("blocked", domain.LockSpec{Key: "node:n1", Mode: domain.LockExclusive})
	e.enqueue(func(nj *NewJob) { nj.Type = "holder" })
	e.clock.Advance(time.Millisecond)
	blocked := e.enqueue(func(nj *NewJob) { nj.Type = "blocked" })
	e.clock.Advance(time.Millisecond)
	free := e.enqueue()

	e.claim("w1") // holder
	c := e.claim("w2")
	if c.Job.ID != free.ID {
		t.Fatalf("claimed %s, want the unblocked job %s", c.Job.ID, free.ID)
	}
	if e.state(blocked.ID) != domain.JobQueued || e.get(blocked.ID).Attempts != 0 {
		t.Fatalf("blocked job = %+v", e.get(blocked.ID))
	}
}

func TestRevalidationFailureFailsTheJobInASecondTransaction(t *testing.T) {
	e := newEnv(t)
	bad := e.enqueue()
	e.clock.Advance(time.Millisecond)
	good := e.enqueue()
	e.reval.failJob(bad.ID, smerr.FromReason(smerr.ReasonCredentialRevoked, "token revoked"))

	c := e.claim("w1")
	if c.Job.ID != good.ID {
		t.Fatalf("claimed %s, want %s after the failed one", c.Job.ID, good.ID)
	}
	failed := e.get(bad.ID)
	if failed.State != domain.JobFailed || failed.Error == nil ||
		failed.Error.Code != smerr.CodeUnauthenticated || failed.Error.Reason != smerr.ReasonCredentialRevoked {
		t.Fatalf("rejected job = %+v", failed)
	}
	if failed.Attempts != 0 || failed.LeaseGeneration != 0 || e.lockCount(bad.ID) != 0 {
		t.Fatalf("failed claim left traces: attempts %d, generation %d, locks %d",
			failed.Attempts, failed.LeaseGeneration, e.lockCount(bad.ID))
	}
	if got, want := e.actions(bad.ID), []string{"job.queued", "job.failed"}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestLapsedQuorumReturnsTheJobToAwaitingApproval(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	e.reval.failJob(job.ID, smerr.New(smerr.CodeApprovalRequired, "", "quorum lapsed"))
	e.claimNothing("w1")
	got := e.get(job.ID)
	if got.State != domain.JobAwaitingApproval || got.Error != nil || e.lockCount(job.ID) != 0 {
		t.Fatalf("job = %+v", got)
	}
}

func TestInfrastructureErrorFromRevalidatorKeepsTheJobQueued(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	e.reval.failJob(job.ID, context.DeadlineExceeded)
	if _, ok, err := e.store.Claim(context.Background(), "w1"); err == nil || ok {
		t.Fatalf("Claim = ok %v, err %v; want an error", ok, err)
	}
	if e.state(job.ID) != domain.JobQueued {
		t.Fatalf("state = %s, want queued", e.state(job.ID))
	}
}

func TestRestoreHoldStopsClaims(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	e.store.SetRestoreHold(true)
	e.claimNothing("w1")
	if e.state(job.ID) != domain.JobQueued {
		t.Fatalf("state = %s, want queued", e.state(job.ID))
	}
	e.store.SetRestoreHold(false)
	e.claim("w1")
}

func TestPoisonJobFailsWithoutBlockingTheQueue(t *testing.T) {
	cases := map[string]func(e *env, poison domain.ID){
		"invalid lock spec": func(e *env, _ domain.ID) {
			e.planner.setLocks("poison", domain.LockSpec{Key: "no-colon", Mode: domain.LockExclusive})
		},
		"untyped revalidator data error": func(e *env, poison domain.ID) {
			e.reval.failJob(poison, errors.New("decode payload: invalid character"))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			poison := e.enqueue(func(nj *NewJob) { nj.Type = "poison" })
			e.clock.Advance(time.Millisecond)
			healthy := e.enqueue()
			setup(e, poison.ID)

			if got := e.claim("w1").Job.ID; got != healthy.ID {
				t.Fatalf("claimed %s, want the healthy job", got)
			}
			failed := e.get(poison.ID)
			if failed.State != domain.JobFailed || failed.Error == nil || failed.Error.Code != smerr.CodeInternal || e.lockCount(poison.ID) != 0 {
				t.Fatalf("poison job = %+v", failed)
			}
		})
	}
}

func TestMarkedInfrastructureErrorKeepsTheJobQueued(t *testing.T) {
	e := newEnv(t)
	job := e.enqueue()
	e.reval.failJob(job.ID, fmt.Errorf("load grants: %w", ErrInfrastructure))
	if _, ok, err := e.store.Claim(context.Background(), "w1"); err == nil || ok {
		t.Fatalf("Claim = ok %v, err %v; want an error", ok, err)
	}
	if e.state(job.ID) != domain.JobQueued {
		t.Fatalf("state = %s, want queued", e.state(job.ID))
	}
}

func TestLockBlockedJobIsDeferredByABackoffStep(t *testing.T) {
	e := newEnv(t)
	e.planner.setLocks("holder", domain.LockSpec{Key: "node:n1", Mode: domain.LockExclusive})
	e.planner.setLocks("blocked", domain.LockSpec{Key: "node:n1", Mode: domain.LockExclusive})
	e.enqueue(func(nj *NewJob) { nj.Type = "holder" })
	e.clock.Advance(time.Millisecond)
	blocked := e.enqueue(func(nj *NewJob) { nj.Type = "blocked" })
	e.claim("w1")
	e.claimNothing("w2")
	if got := e.get(blocked.ID).ScheduledAt; !got.Equal(e.clock.Now().Add(backoffBase)) {
		t.Fatalf("scheduled_at = %v, want now+%v", got, backoffBase)
	}
}

func TestFailedAttemptKeepsItsLocksUntilTerminal(t *testing.T) {
	e := newEnv(t)
	e.planner.setLocks("retrying", domain.LockSpec{Key: "node:n1", Mode: domain.LockExclusive})
	e.planner.setLocks("rival", domain.LockSpec{Key: "node:n1", Mode: domain.LockShared})
	retrying := e.enqueue(func(nj *NewJob) { nj.Type = "retrying"; nj.RetryClass, nj.MaxAttempts = domain.RetryIdempotent, 2 })
	c := e.claim("w1")
	if err := e.store.Fail(context.Background(), c.Lease, errBoom); err != nil {
		t.Fatal(err)
	}
	e.enqueue(func(nj *NewJob) { nj.Type = "rival" })
	e.claimNothing("w2") // the requeued job still holds node:n1

	e.clock.Advance(backoffBase)
	again := e.claim("w1") // re-claim replaces its own rows without conflict
	if again.Job.ID != retrying.ID || e.lockCount(retrying.ID) != 1 {
		t.Fatalf("claimed %s with %d locks", again.Job.ID, e.lockCount(retrying.ID))
	}
	if err := e.store.Fail(context.Background(), again.Lease, errBoom); err != nil {
		t.Fatal(err)
	}
	if e.lockCount(retrying.ID) != 0 {
		t.Fatal("terminal failure kept its locks")
	}
}
