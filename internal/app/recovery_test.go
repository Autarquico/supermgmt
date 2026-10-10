package app

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// recovery is a service restart whose daemon died right after the command was
// sent: the job is interrupted, its intent dispatched, and time has passed
// beyond the remote deadline plus the reconcile grace.
type recovery struct {
	*action
	router *EvidenceRouter
	job    jobs.Job
	node   *fakeNode // the dedicated-user session the router reads markers over
}

func newRecovery(t *testing.T) *recovery {
	t.Helper()
	a := newAction(t)
	router, err := NewEvidenceRouter(a.cfg, a.conn, fakeAdapters(a.adapter, newFakeAdapter(domain.RuntimeDocker)))
	mustf(t, err, "NewEvidenceRouter")
	r := &recovery{action: a, router: router, node: a.dialer.as("supermgmt")}
	r.job = a.restartApproved()

	ctx, kill := context.WithCancel(context.Background())
	r.node.on("fake.restart", func(templates.Command) (transport.Result, error) {
		kill() // the daemon dies while the command is in flight
		return transport.Result{}, context.Canceled
	})
	claimed, ok := a.claim()
	if !ok {
		t.Fatal("job not claimable")
	}
	a.lease = claimed.Lease
	if err := a.handler.Run(ctx, claimed.Lease); err == nil {
		t.Fatal("the handler must not report success for a killed run")
	}

	a.clock.Advance(31 * time.Second) // the lease expires
	taken, err := a.store.Takeover(context.Background(), "test")
	if err != nil || len(taken) != 1 {
		t.Fatalf("Takeover = %v, %v", taken, err)
	}
	a.clock.Advance(3 * time.Minute) // past deadline_at + reconcile grace
	return r
}

// settle runs the reconciler twice, spaced like two samples.
func (r *recovery) settle() {
	r.t.Helper()
	r.pass()
	r.clock.Advance(31 * time.Second)
	r.pass()
}

func (r *recovery) pass() {
	r.t.Helper()
	if _, err := r.store.Reconcile(context.Background(), r.router); err != nil {
		r.t.Fatalf("Reconcile: %v", err)
	}
}

func (r *recovery) state() domain.JobState { return r.job_(r.job.ID).State }

func (r *recovery) job_(id domain.ID) jobs.Job { return r.fixture.job(id) }

func TestAKillBeforeTheCommandStartedFailsTheJobWithMarkerAbsentProof(t *testing.T) {
	r := newRecovery(t)
	r.node.reply("marker.state", "absent\n")

	r.settle()

	if r.state() != domain.JobFailed {
		t.Fatalf("job = %s, want failed: the marker never appeared so nothing ran", r.state())
	}
	in := r.intents(r.job.ID)[0]
	var ev jobs.Evidence
	_ = json.Unmarshal(in.Evidence, &ev)
	if in.Outcome != jobs.OutcomeNotStarted || ev.Proof != jobs.ProofMarkerAbsent || len(ev.Fingerprint) == 0 || len(ev.Pre) == 0 {
		t.Errorf("intent %s evidence %+v; want not_started with proof, a fingerprint and the pre-state", in.Outcome, ev)
	}
}

func TestAKillAfterTheCommandCompletedSucceedsTheJobFromTheAdaptersEvidence(t *testing.T) {
	r := newRecovery(t)
	r.node.reply("marker.state", "started\n")
	r.adapter.observe = func(int) (jobs.Evidence, error) { return complete(jobs.ClassComplete), nil }

	r.settle()

	if r.state() != domain.JobSucceeded {
		t.Fatalf("job = %s, want succeeded on two identical complete samples", r.state())
	}
	var ev jobs.Evidence
	_ = json.Unmarshal(r.intents(r.job.ID)[0].Evidence, &ev)
	if ev.Classification != jobs.ClassComplete || string(ev.Pre) != `{"invocation_id":"before"}` {
		t.Errorf("evidence = %+v; the audit record must show pre and post state", ev)
	}
}

func TestAnUnreachableNodeHoldsTheJobForAHuman(t *testing.T) {
	r := newRecovery(t)
	r.node.down("marker.state", smerr.New(smerr.CodeNodeUnreachable, "", "connection refused"))

	r.settle()

	if r.state() != domain.JobInterrupted || len(r.events("job.reconcile_held")) != 1 {
		t.Errorf("job = %s, held events %d; want it held, reported once", r.state(), len(r.events("job.reconcile_held")))
	}
}

func TestAnUnreadableMarkersDirectoryIsNotEvidenceOfAbsence(t *testing.T) {
	r := newRecovery(t)
	r.node.reply("marker.state", "unavailable\n")

	r.settle()

	if r.state() != domain.JobInterrupted {
		t.Errorf("job = %s; a directory we cannot read proves nothing", r.state())
	}
}

func TestAnInconclusiveStateHoldsTheJob(t *testing.T) {
	for name, observe := range map[string]func(int) (jobs.Evidence, error){
		"changed but not active": func(int) (jobs.Evidence, error) { return complete(jobs.ClassUnknown), nil },
		"no completion proof": func(int) (jobs.Evidence, error) {
			return jobs.Evidence{}, errors.New("no .done file with exit status 0")
		},
	} {
		r := newRecovery(t)
		r.node.reply("marker.state", "started\n")
		r.adapter.observe = observe

		r.settle()

		if r.state() != domain.JobInterrupted {
			t.Errorf("%s: job = %s, want it held", name, r.state())
		}
	}
}

func TestAnInvocationIDThatChangesBetweenSamplesDoesNotPair(t *testing.T) {
	r := newRecovery(t)
	r.node.reply("marker.state", "started\n")
	first := r.adapter.observeCalls + 1 // the first sample the reconciler takes
	r.adapter.observe = func(call int) (jobs.Evidence, error) {
		ev := complete(jobs.ClassComplete)
		if call == first {
			ev.Fingerprint = json.RawMessage(`{"invocation_id":"first","active_state":"active"}`)
		}
		return ev, nil
	}

	r.settle()
	if r.state() != domain.JobInterrupted {
		t.Fatalf("job = %s after samples with different fingerprints, want it still interrupted", r.state())
	}
	r.clock.Advance(31 * time.Second)
	r.pass()

	if r.state() != domain.JobSucceeded {
		t.Errorf("job = %s; two identical samples after the reset should settle it", r.state())
	}
}

func TestTheRouterRefusesIntentsItDoesNotUnderstand(t *testing.T) {
	r := newRecovery(t)
	dispatched := time.Now() //nolint:forbidigo // an arbitrary instant for a value object
	tests := map[string]jobs.Intent{
		"not a service":        {TargetType: "node", Operation: "service.restart", DispatchedAt: &dispatched},
		"never dispatched":     {TargetType: "service", Operation: "service.restart", TargetID: r.service.ID.String()},
		"not a service action": {TargetType: "service", Operation: "node.reboot", TargetID: r.service.ID.String(), DispatchedAt: &dispatched},
		"unknown service":      {TargetType: "service", Operation: "service.restart", TargetID: "nope", DispatchedAt: &dispatched},
	}
	for name, intent := range tests {
		if _, err := r.router.Collect(context.Background(), intent); err == nil {
			t.Errorf("%s: Collect succeeded", name)
		}
	}
}

func TestEvidenceWithoutAFingerprintIsNeverPassedOn(t *testing.T) {
	r := newRecovery(t)
	r.node.reply("marker.state", "done 0\n")
	r.adapter.observe = func(int) (jobs.Evidence, error) {
		ev := complete(jobs.ClassComplete)
		ev.Fingerprint = nil // such evidence would pair with any other empty sample
		return ev, nil
	}
	in := r.intents(r.job.ID)[0]

	_, err := r.router.Collect(context.Background(), in)

	if err == nil {
		t.Error("evidence without a fingerprint was accepted")
	}
}
