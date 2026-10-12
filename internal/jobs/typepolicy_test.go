package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

type mirrorCall struct {
	from, to domain.JobState
	mode     ClaimMode
	failure  *Failure
}

// fakePolicy is a TypePolicy whose behavior each test scripts. Its recovery
// record lives in the policy, so two Stores sharing it share the "durable"
// record, as two processes sharing a database would.
type fakePolicy struct {
	mu sync.Mutex

	admit        func(Evidence) bool
	verdict      Verdict
	reconcileErr error
	observed     []map[domain.ID]Evidence

	recovery      map[domain.ID]bool
	recoveryErr   error
	recoveryCalls int

	escalate      bool
	escalateErr   error
	escalateCalls int

	mirrors   []mirrorCall
	mirrorErr error
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{
		admit: func(ev Evidence) bool {
			return ev.Classification == ClassComplete || ev.Classification == ClassNotStarted || ev.Classification == ClassPartialStable
		},
		recovery: map[domain.ID]bool{},
	}
}

func (p *fakePolicy) Admit(ev Evidence) bool { return p.admit(ev) }

func (p *fakePolicy) Reconcile(_ context.Context, _ *database.Tx, job Job, _ []Intent, observed map[domain.ID]Evidence) (Verdict, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observed = append(p.observed, observed)
	if p.verdict.Action == VerdictRequeuedRecovery {
		p.recovery[job.ID] = true
	}
	return p.verdict, p.reconcileErr
}

func (p *fakePolicy) ClaimMode(_ context.Context, _ database.Querier, job Job) (ClaimMode, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recovery[job.ID] {
		return ClaimRecovery, nil
	}
	return ClaimForward, nil
}

func (p *fakePolicy) RevalidateRecovery(context.Context, database.Querier, Job) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recoveryCalls++
	return p.recoveryErr
}

// EscalateToRecovery marks the job's payload through tx so a test can see
// whether the write committed or rolled back with the claim.
func (p *fakePolicy) EscalateToRecovery(ctx context.Context, tx *database.Tx, job Job, _ error) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.escalateCalls++
	if p.escalateErr != nil || !p.escalate {
		return false, p.escalateErr
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET payload_json = ? WHERE id = ?`, escalatedPayload, job.ID); err != nil {
		return false, err
	}
	p.recovery[job.ID] = true
	return true, nil
}

const escalatedPayload = `{"escalated":true}`

func (p *fakePolicy) Mirror(_ context.Context, _ database.Querier, _ Job, from, to domain.JobState, mode ClaimMode, f *Failure) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mirrorErr != nil {
		return p.mirrorErr
	}
	p.mirrors = append(p.mirrors, mirrorCall{from, to, mode, f})
	return nil
}

func (p *fakePolicy) mirrored() []mirrorCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]mirrorCall(nil), p.mirrors...)
}

// withPolicy replaces the env's Store by one that routes "test.job" through p.
func (e *env) withPolicy(p TypePolicy) {
	e.t.Helper()
	e.store = e.newStoreWith(p)
}

func (e *env) newStoreWith(p TypePolicy) *Store {
	e.t.Helper()
	store, err := NewStore(Config{
		DB: e.db, Clock: e.clock, IDs: e.ids, Revalidator: e.reval, LockPlanner: e.planner,
		LeaseTTL: leaseTTL, BackoffBase: backoffBase,
		TypePolicies: map[string]TypePolicy{"test.job": p},
	})
	if err != nil {
		e.t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestNewStoreRejectsANilTypePolicy(t *testing.T) {
	e := newEnv(t)
	_, err := NewStore(Config{
		DB: e.db, Clock: e.clock, IDs: e.ids, Revalidator: e.reval, LockPlanner: e.planner,
		TypePolicies: map[string]TypePolicy{"test.job": nil},
	})
	if err == nil {
		t.Fatal("NewStore accepted a nil policy")
	}
}

func TestMirrorFollowsEveryCoarseTransitionOfAPolicyType(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	e.withPolicy(p)
	e.enqueue()
	e.interrupt("w1")

	want := []mirrorCall{
		{domain.JobQueued, domain.JobRunning, ClaimForward, nil},
		{domain.JobRunning, domain.JobInterrupted, ClaimForward, nil},
	}
	got := p.mirrored()
	if len(got) != len(want) {
		t.Fatalf("mirrors = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mirror %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMirrorFailureAbortsTheTransition(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	p.mirrorErr = errors.New("deployment row missing")
	e.withPolicy(p)
	job := e.enqueue()

	if _, ok, err := e.store.Claim(context.Background(), "w1"); err == nil || ok {
		t.Fatalf("Claim = ok %v, err %v; want the mirror error", ok, err)
	}
	got := e.get(job.ID)
	if got.State != domain.JobQueued || got.Attempts != 0 || e.lockCount(job.ID) != 0 {
		t.Fatalf("job after aborted claim = %+v, locks %d; want untouched queued", got, e.lockCount(job.ID))
	}
	if actions := e.actions(job.ID); len(actions) != 1 {
		t.Fatalf("events = %v; the aborted transition must leave none", actions)
	}
}

func TestMirrorReceivesTheFailureOfAFailedTransition(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	e.withPolicy(p)
	job := e.enqueue()
	e.reval.failJob(job.ID, errors.New("plan is stale"))

	e.claimNothing("w1")

	got := p.mirrored()
	if len(got) != 1 || got[0].to != domain.JobFailed || got[0].failure == nil || got[0].mode != ClaimForward {
		t.Fatalf("mirrors = %+v; want one forward queued -> failed with its failure", got)
	}
}

func TestPolicyOfAnotherTypeLeavesTheJobTypeUntouched(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	e.withPolicy(p)
	e.enqueue(func(nj *NewJob) { nj.Type = "other.job" })

	e.claim("w1")

	if got := p.mirrored(); len(got) != 0 {
		t.Fatalf("mirrors = %+v; a type without policy must not be mirrored", got)
	}
}
