package jobs

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const (
	leaseTTL    = 30 * time.Second
	backoffBase = 5 * time.Second
)

// stubRevalidator fails the jobs it is told to fail and counts every call.
type stubRevalidator struct {
	mu    sync.Mutex
	fail  map[domain.ID]error
	calls int
}

func (r *stubRevalidator) Revalidate(_ context.Context, _ database.Querier, job Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.fail[job.ID]
}

func (r *stubRevalidator) failJob(id domain.ID, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail[id] = err
}

func (r *stubRevalidator) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// stubPlanner returns locks chosen per job type; the default is an exclusive
// lock on the node named by the job's resource.
type stubPlanner struct {
	mu     sync.Mutex
	byType map[string][]domain.LockSpec
}

func (p *stubPlanner) PlanLocks(_ context.Context, _ database.Querier, job Job) ([]domain.LockSpec, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if specs, ok := p.byType[job.Type]; ok {
		return specs, nil
	}
	return []domain.LockSpec{{Key: "node:" + job.Resource.ID.String(), Mode: domain.LockExclusive}}, nil
}

func (p *stubPlanner) setLocks(jobType string, specs ...domain.LockSpec) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byType[jobType] = specs
}

type env struct {
	t       *testing.T
	db      *database.DB
	clock   *domaintest.FakeClock
	ids     *domaintest.SequentialIDs
	reval   *stubRevalidator
	planner *stubPlanner
	store   *Store
	actor   domain.ID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clock := domaintest.NewFakeClock(epoch)
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	e := &env{
		t: t, db: db, clock: clock, ids: domaintest.NewSequentialIDs(),
		reval:   &stubRevalidator{fail: map[domain.ID]error{}},
		planner: &stubPlanner{byType: map[string][]domain.LockSpec{}},
	}
	e.store, err = NewStore(Config{
		DB: db, Clock: clock, IDs: e.ids, Revalidator: e.reval, LockPlanner: e.planner,
		LeaseTTL: leaseTTL, BackoffBase: backoffBase, BackoffMax: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	e.actor = e.ids.NewID()
	e.inTx(func(tx *database.Tx) {
		err := database.CreateIdentity(context.Background(), tx, database.Identity{
			ID: e.actor, ActorType: domain.ActorHuman, Subject: "tester", CreatedAt: clock.Now(),
		})
		if err != nil {
			t.Fatalf("CreateIdentity: %v", err)
		}
	})
	return e
}

func (e *env) inTx(fn func(tx *database.Tx)) {
	e.t.Helper()
	err := e.db.WithWriteTx(context.Background(), func(_ context.Context, tx *database.Tx) error {
		fn(tx)
		return nil
	})
	if err != nil {
		e.t.Fatalf("write tx: %v", err)
	}
}

// enqueue stores a queued job on a fresh node; opts adjust it before storing.
func (e *env) enqueue(opts ...func(*NewJob)) Job {
	e.t.Helper()
	nj := NewJob{
		Type:       "test.job",
		Resource:   domain.ResourceRef{Type: domain.ResourceNode, ID: e.ids.NewID()},
		ActorID:    e.actor,
		Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: "cred", Scopes: []string{"node.read"}},
		Risk:       domain.RiskOperational,
		RetryClass: domain.RetryNonRetryable,
	}
	for _, opt := range opts {
		opt(&nj)
	}
	var job Job
	e.inTx(func(tx *database.Tx) {
		var err error
		if job, err = e.store.Enqueue(context.Background(), tx, nj); err != nil {
			e.t.Fatalf("Enqueue: %v", err)
		}
	})
	return job
}

func (e *env) get(id domain.ID) Job {
	e.t.Helper()
	job, err := e.store.Get(context.Background(), e.db.Reader(), id)
	if err != nil {
		e.t.Fatalf("Get %s: %v", id, err)
	}
	return job
}

func (e *env) state(id domain.ID) domain.JobState { return e.get(id).State }

func (e *env) claim(owner string) Claimed {
	e.t.Helper()
	c, ok, err := e.store.Claim(context.Background(), owner)
	if err != nil || !ok {
		e.t.Fatalf("Claim(%s) = ok %v, err %v; want a job", owner, ok, err)
	}
	return c
}

func (e *env) claimNothing(owner string) {
	e.t.Helper()
	c, ok, err := e.store.Claim(context.Background(), owner)
	if err != nil || ok {
		e.t.Fatalf("Claim(%s) = %s ok %v, err %v; want nothing", owner, c.Job.ID, ok, err)
	}
}

// interrupt claims a job, lets its lease expire and takes it over.
func (e *env) interrupt(owner string) Claimed {
	e.t.Helper()
	c := e.claim(owner)
	e.clock.Advance(leaseTTL + time.Second)
	taken, err := e.store.Takeover(context.Background(), "r1")
	if err != nil || len(taken) != 1 || taken[0] != c.Job.ID {
		e.t.Fatalf("Takeover = %v, %v; want [%s]", taken, err, c.Job.ID)
	}
	return c
}

func (e *env) lockCount(id domain.ID) int {
	e.t.Helper()
	var n int
	err := e.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM resource_locks WHERE job_id = ?`, id).Scan(&n)
	if err != nil {
		e.t.Fatalf("count locks: %v", err)
	}
	return n
}

// actions lists the audit actions recorded for a job, oldest first.
func (e *env) actions(id domain.ID) []string {
	e.t.Helper()
	events, err := database.ListEvents(context.Background(), e.db.Reader(), 0, 10_000)
	if err != nil {
		e.t.Fatalf("ListEvents: %v", err)
	}
	var out []string
	for _, ev := range events {
		if ev.ResourceType == domain.ResourceJob && ev.ResourceID == id {
			out = append(out, ev.Action)
		}
	}
	return out
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 2000 {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
