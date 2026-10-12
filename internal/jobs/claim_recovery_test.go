package jobs

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// requeuedForRecovery drives a job through the real Reconcile until the policy
// has requeued it into safety recovery.
func requeuedForRecovery(e *env, p *fakePolicy) Job {
	e.t.Helper()
	p.verdict = Verdict{Action: VerdictRequeuedRecovery, Reason: "partial_stable"}
	job, intent := interruptedPolicyJob(e, p)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: proof(ClassPartialStable)}}
	if got := reconcile(e, src); len(got) != 1 || got[0].Action != ReconcileRequeued {
		e.t.Fatalf("Reconcile = %v; want requeued", got)
	}
	return job
}

func (e *env) lockRows(id domain.ID) []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(context.Background(),
		`SELECT resource_type || ':' || resource_id || ':' || mode FROM resource_locks WHERE job_id = ? ORDER BY 1`, id)
	if err != nil {
		e.t.Fatalf("lock rows: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func TestClaimRecovery_StalePlanRevokedRequesterLostQuorum(t *testing.T) {
	causes := map[string]error{
		"stale plan":     smerr.New(smerr.CodeConflict, "", "plan is stale"),
		"revoked":        smerr.FromReason(smerr.ReasonCredentialRevoked, "requester revoked"),
		"lost quorum":    smerr.New(smerr.CodeApprovalRequired, "", "quorum lapsed"),
		"forward broken": errors.New("anything the forward validator dislikes"),
	}
	for name, cause := range causes {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			p := newFakePolicy()
			job := requeuedForRecovery(e, p)
			e.reval.failJob(job.ID, cause)
			locksBefore := e.lockRows(job.ID)
			forwardCalls := e.reval.callCount()

			c := e.claim("w2")

			if c.Job.ID != job.ID || e.state(job.ID) != domain.JobRunning {
				t.Fatalf("claimed %s, state %s; want the recovery job running", c.Job.ID, e.state(job.ID))
			}
			if e.reval.callCount() != forwardCalls || p.recoveryCalls != 1 {
				t.Fatalf("forward revalidations %d -> %d, recovery %d; want recovery only",
					forwardCalls, e.reval.callCount(), p.recoveryCalls)
			}
			if !slices.Equal(locksBefore, e.lockRows(job.ID)) || len(locksBefore) == 0 {
				t.Fatalf("locks %v -> %v; want identical and held", locksBefore, e.lockRows(job.ID))
			}
			if slices.Contains(e.actions(job.ID), "job.awaiting_approval") {
				t.Fatalf("events = %v; recovery must never wait for approval", e.actions(job.ID))
			}
			mirrors := p.mirrored()
			if last := mirrors[len(mirrors)-1]; last.to != domain.JobRunning || last.mode != ClaimRecovery {
				t.Fatalf("claim mirror = %+v; want running under recovery", last)
			}
		})
	}
}

func TestClaimRecovery_RestartBetweenRequeueAndClaim(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	job := requeuedForRecovery(e, p)
	e.reval.failJob(job.ID, smerr.New(smerr.CodeApprovalRequired, "", "quorum lapsed"))

	e.store = e.newStoreWith(p) // a new process reads the same durable record

	c := e.claim("w2")
	if c.Job.ID != job.ID || p.recoveryCalls != 1 || e.state(job.ID) != domain.JobRunning {
		t.Fatalf("claimed %s, recovery calls %d, state %s; want recovery after restart",
			c.Job.ID, p.recoveryCalls, e.state(job.ID))
	}
}

func TestClaimRecovery_KeepsLocksNeverAwaitingApproval(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	job := requeuedForRecovery(e, p)
	p.recoveryErr = smerr.New(smerr.CodeApprovalRequired, "", "a misbehaving policy asks for approval")

	e.claimNothing("w2")

	got := e.get(job.ID)
	if got.State != domain.JobFailed || got.Error == nil || got.Error.Code != smerr.CodeInternal {
		t.Fatalf("job = %+v; want failed INTERNAL, never awaiting_approval", got)
	}
	if slices.Contains(e.actions(job.ID), "job.awaiting_approval") {
		t.Fatalf("events = %v", e.actions(job.ID))
	}
	last := p.mirrored()[len(p.mirrored())-1]
	if last.to != domain.JobFailed || last.mode != ClaimRecovery {
		t.Fatalf("failure mirror = %+v; want failed under recovery", last)
	}
}

func TestClaimRecovery_RevalidationFailureFailsTheJobWithItsReason(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	job := requeuedForRecovery(e, p)
	p.recoveryErr = smerr.New(smerr.CodeConflict, "", "rollback target is gone")

	e.claimNothing("w2")

	got := e.get(job.ID)
	if got.State != domain.JobFailed || got.Error == nil || got.Error.Code != smerr.CodeConflict {
		t.Fatalf("job = %+v; want failed with the recovery revalidation error", got)
	}
}

func TestClaimForward_EscalatesAfterMutation(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	p.escalate = true
	e.withPolicy(p)
	job := e.enqueue()
	e.reval.failJob(job.ID, smerr.New(smerr.CodeApprovalRequired, "", "quorum lapsed"))

	c := e.claim("w1")

	if c.Job.ID != job.ID || p.escalateCalls != 1 || p.recoveryCalls != 1 {
		t.Fatalf("claimed %s, escalations %d, recovery calls %d; want escalated recovery claim",
			c.Job.ID, p.escalateCalls, p.recoveryCalls)
	}
	if got := e.get(job.ID); string(got.Payload) != escalatedPayload || got.State != domain.JobRunning {
		t.Fatalf("job = %+v; want the in-transaction write committed with the claim", got)
	}
	if last := p.mirrored()[len(p.mirrored())-1]; last.mode != ClaimRecovery || last.to != domain.JobRunning {
		t.Fatalf("claim mirror = %+v", last)
	}
}

func TestClaimForward_EscalationIsRolledBackWithAFailedRecoveryClaim(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	p.escalate = true
	p.recoveryErr = smerr.New(smerr.CodeConflict, "", "rollback target is gone")
	e.withPolicy(p)
	job := e.enqueue()
	e.reval.failJob(job.ID, errors.New("stale plan"))

	e.claimNothing("w1")

	got := e.get(job.ID)
	if got.State != domain.JobFailed || string(got.Payload) != "{}" {
		t.Fatalf("job = state %s payload %s; want failed with the escalation write rolled back", got.State, got.Payload)
	}
}

func TestClaimForward_WithoutEscalationKeepsTheForwardOutcome(t *testing.T) {
	cases := []struct {
		name      string
		cause     error
		wantState domain.JobState
	}{
		{"quorum lapsed waits for approval", smerr.New(smerr.CodeApprovalRequired, "", "quorum lapsed"), domain.JobAwaitingApproval},
		{"other failures fail the job", errors.New("stale plan"), domain.JobFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			p := newFakePolicy() // escalate = false: before deploying
			e.withPolicy(p)
			job := e.enqueue()
			e.reval.failJob(job.ID, tc.cause)

			e.claimNothing("w1")

			if e.state(job.ID) != tc.wantState || p.escalateCalls != 1 || p.recoveryCalls != 0 {
				t.Fatalf("state %s, escalations %d, recovery %d; want %s with one declined escalation",
					e.state(job.ID), p.escalateCalls, p.recoveryCalls, tc.wantState)
			}
		})
	}
}

func TestClaimForward_InfrastructureErrorIsNeverEscalated(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	p.escalate = true
	e.withPolicy(p)
	job := e.enqueue()
	e.reval.failJob(job.ID, context.DeadlineExceeded)

	if _, ok, err := e.store.Claim(context.Background(), "w1"); err == nil || ok {
		t.Fatalf("Claim = ok %v, err %v; want an error", ok, err)
	}
	if p.escalateCalls != 0 || e.state(job.ID) != domain.JobQueued {
		t.Fatalf("escalations %d, state %s; want none and queued", p.escalateCalls, e.state(job.ID))
	}
}

func TestClaimForward_HealthyJobUsesTheRequesterRevalidator(t *testing.T) {
	e := newEnv(t)
	p := newFakePolicy()
	e.withPolicy(p)
	e.enqueue()

	e.claim("w1")

	if e.reval.callCount() != 1 || p.recoveryCalls != 0 || p.escalateCalls != 0 {
		t.Fatalf("forward %d, recovery %d, escalations %d; want forward only", e.reval.callCount(), p.recoveryCalls, p.escalateCalls)
	}
}
