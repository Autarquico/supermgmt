package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const testUPID = "UPID:pve1:0001A2B3:0C4D5E6F:6700A1B2:qmstart:100:sm-ab12cd34@pve!sm:"

// trackedIntent records and dispatches a Proxmox power intent and persists its UPID.
func trackedIntent(e *env, lease Lease) Intent {
	e.t.Helper()
	ni := sampleIntent(e)
	ni.Step, ni.Operation, ni.TargetType = "power", "proxmox.vm.power.start", "node"
	intent, err := e.store.RecordIntent(context.Background(), lease, ni)
	if err != nil {
		e.t.Fatalf("RecordIntent: %v", err)
	}
	if err := e.store.MarkDispatched(context.Background(), lease, intent.ID); err != nil {
		e.t.Fatalf("MarkDispatched: %v", err)
	}
	if err := e.store.RecordExternalRef(context.Background(), lease, intent.ID, testUPID); err != nil {
		e.t.Fatalf("RecordExternalRef: %v", err)
	}
	return intent
}

// interruptedTracked is a job taken over while its Proxmox task may still run.
func interruptedTracked(e *env) (Job, Intent) {
	e.t.Helper()
	job := e.enqueue(func(nj *NewJob) { nj.PlanHash = planHash })
	c := e.claim("w1")
	intent := trackedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		e.t.Fatal(err)
	}
	return job, intent
}

func pveStop(class Classification, status, exitstatus string) Evidence {
	fp, _ := json.Marshal(map[string]string{"upid": testUPID, "status": status, "exitstatus": exitstatus})
	return Evidence{Done: true, Proof: ProofPVETask, Classification: class, Fingerprint: fp}
}

func (e *env) intent(job, id domain.ID) Intent {
	e.t.Helper()
	intents, err := e.store.Intents(context.Background(), e.db.Reader(), job)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, in := range intents {
		if in.ID == id {
			return in
		}
	}
	e.t.Fatalf("intent %s not found", id)
	return Intent{}
}

func wantCode(t *testing.T, err error, code smerr.Code) {
	t.Helper()
	var se *smerr.Error
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

func TestRecordExternalRef(t *testing.T) {
	t.Run("persists the ref and repeating it is a no-op", func(t *testing.T) {
		e := newEnv(t)
		job := e.enqueue()
		c := e.claim("w1")
		intent := trackedIntent(e, c.Lease)
		if got := e.intent(job.ID, intent.ID).ExternalRef; got != testUPID {
			t.Fatalf("ExternalRef = %q, want %q", got, testUPID)
		}
		if err := e.store.RecordExternalRef(context.Background(), c.Lease, intent.ID, testUPID); err != nil {
			t.Fatalf("repeat: %v", err)
		}
	})

	t.Run("is write-once", func(t *testing.T) {
		e := newEnv(t)
		e.enqueue()
		c := e.claim("w1")
		intent := trackedIntent(e, c.Lease)
		wantCode(t, e.store.RecordExternalRef(context.Background(), c.Lease, intent.ID, "UPID:other"), smerr.CodeConflict)
	})

	t.Run("needs a dispatched intent and a ref", func(t *testing.T) {
		e := newEnv(t)
		e.enqueue()
		c := e.claim("w1")
		intent, err := e.store.RecordIntent(context.Background(), c.Lease, sampleIntent(e))
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, e.store.RecordExternalRef(context.Background(), c.Lease, intent.ID, testUPID), smerr.CodeConflict)
		wantCode(t, e.store.RecordExternalRef(context.Background(), c.Lease, intent.ID, ""), smerr.CodeInvalidArgument)
	})

	t.Run("is fenced by the lease", func(t *testing.T) {
		e := newEnv(t)
		job := e.enqueue()
		c := e.claim("w1")
		ni := sampleIntent(e)
		ni.Operation = "proxmox.vm.power.start"
		intent, err := e.store.RecordIntent(context.Background(), c.Lease, ni)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.store.MarkDispatched(context.Background(), c.Lease, intent.ID); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(leaseTTL + time.Second)
		if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
			t.Fatal(err)
		}
		if err := e.store.RecordExternalRef(context.Background(), c.Lease, intent.ID, testUPID); err == nil {
			t.Fatal("a worker that lost its lease recorded an external ref")
		}
		if got := e.intent(job.ID, intent.ID).ExternalRef; got != "" {
			t.Fatalf("ExternalRef = %q after a fenced write, want empty", got)
		}
	})

	t.Run("intents without a ref read back empty", func(t *testing.T) {
		e := newEnv(t)
		job := e.enqueue()
		c := e.claim("w1")
		intent := dispatchedIntent(e, c.Lease)
		if got := e.intent(job.ID, intent.ID).ExternalRef; got != "" {
			t.Fatalf("ExternalRef = %q, want empty", got)
		}
	})
}

func TestRecordTaskStop(t *testing.T) {
	record := func(e *env, id domain.ID, ev Evidence) error {
		var err error
		txErr := e.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
			err = e.store.RecordTaskStop(ctx, tx, id, ev)
			return nil
		})
		if txErr != nil {
			t.Fatal(txErr)
		}
		return err
	}

	t.Run("stores evidence and leaves the intent recorded", func(t *testing.T) {
		e := newEnv(t)
		job, intent := interruptedTracked(e)
		if err := record(e, intent.ID, pveStop(ClassComplete, "stopped", "OK")); err != nil {
			t.Fatal(err)
		}
		got := e.intent(job.ID, intent.ID)
		if got.State != IntentRecorded || !storedEvidence(got).taskStop() {
			t.Fatalf("intent = state %s, evidence %s; want recorded with task stop evidence", got.State, got.Evidence)
		}
		if err := record(e, intent.ID, pveStop(ClassComplete, "stopped", "OK")); err != nil {
			t.Fatalf("identical repeat: %v", err)
		}
		wantCode(t, record(e, intent.ID, pveStop(ClassNotStarted, "stopped", "boom")), smerr.CodeConflict)
	})

	t.Run("refuses evidence that is not a definite task stop", func(t *testing.T) {
		e := newEnv(t)
		_, intent := interruptedTracked(e)
		noFingerprint := pveStop(ClassComplete, "stopped", "OK")
		noFingerprint.Fingerprint = nil
		wrongProof := pveStop(ClassComplete, "stopped", "OK")
		wrongProof.Proof = ProofDoneFile
		for _, ev := range map[string]Evidence{
			"not done":       {Proof: ProofPVETask, Classification: ClassComplete, Fingerprint: json.RawMessage(`{}`)},
			"failed exit":    {Done: true, ExitStatus: 1, Proof: ProofPVETask, Classification: ClassComplete, Fingerprint: json.RawMessage(`{}`)},
			"unclassified":   {Done: true, Proof: ProofPVETask, Fingerprint: json.RawMessage(`{}`)},
			"partial":        pveStop(ClassPartialStable, "stopped", "OK"),
			"other proof":    wrongProof,
			"no fingerprint": noFingerprint,
		} {
			wantCode(t, record(e, intent.ID, ev), smerr.CodeInvalidArgument)
		}
	})

	t.Run("refuses an undispatched intent and a finished job", func(t *testing.T) {
		e := newEnv(t)
		e.enqueue()
		c := e.claim("w1")
		undispatched, err := e.store.RecordIntent(context.Background(), c.Lease, sampleIntent(e))
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, record(e, undispatched.ID, pveStop(ClassComplete, "stopped", "OK")), smerr.CodeConflict)

		job, intent := interruptedTracked(e)
		e.inTx(func(tx *database.Tx) {
			if _, err := e.store.move(context.Background(), tx, move{id: job.ID, from: domain.JobInterrupted, to: domain.JobFailed, actor: systemActor}); err != nil {
				t.Fatal(err)
			}
		})
		wantCode(t, record(e, intent.ID, pveStop(ClassComplete, "stopped", "OK")), smerr.CodeConflict)
	})
}

func TestTaskTrackedIntentIsNeverReconciledByDeadlineAlone(t *testing.T) {
	cases := map[string]func(Intent) EvidenceSource{
		"no evidence source": func(Intent) EvidenceSource { return nil },
		"task still running": func(Intent) EvidenceSource { return &evidenceStub{err: errors.New("task is running")} },
		"generic proof is not a task stop": func(in Intent) EvidenceSource {
			return &evidenceStub{byIntent: map[domain.ID]Evidence{in.ID: proof(ClassComplete)}}
		},
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			job, intent := interruptedTracked(e)
			src := source(intent)
			e.clock.Advance(time.Hour) // far past deadline + grace
			for range 3 {
				got, err := e.store.Reconcile(context.Background(), src)
				if err != nil || len(got) != 0 {
					t.Fatalf("Reconcile = %v, %v; want nothing", got, err)
				}
				e.clock.Advance(sampleGap)
			}
			if e.state(job.ID) != domain.JobInterrupted || e.lockCount(job.ID) == 0 {
				t.Fatalf("job state %s, locks %d; want interrupted and still locked", e.state(job.ID), e.lockCount(job.ID))
			}
			if len(e.intent(job.ID, intent.ID).Evidence) != 0 {
				t.Fatal("evidence was stored without a task stop")
			}
		})
	}
}

func TestReconcileProxmoxTaskStop(t *testing.T) {
	cases := []struct {
		name      string
		evidence  Evidence
		want      ReconcileAction
		wantState domain.JobState
		outcome   string
	}{
		{"stopped OK succeeds", pveStop(ClassComplete, "stopped", "OK"), ReconcileSucceeded, domain.JobSucceeded, OutcomeSucceeded},
		{"stopped with an error fails", pveStop(ClassNotStarted, "stopped", "command failed"), ReconcileFailed, domain.JobFailed, OutcomeNotStarted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			job, intent := interruptedTracked(e)
			src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: tc.evidence}}

			got := reconcile(e, src)

			if len(got) != 1 || got[0].Action != tc.want || e.state(job.ID) != tc.wantState {
				t.Fatalf("Reconcile = %v, state %s; want %s, %s", got, e.state(job.ID), tc.want, tc.wantState)
			}
			closed := e.intent(job.ID, intent.ID)
			if closed.State != IntentCompleted || closed.Outcome != tc.outcome || closed.ExternalRef != testUPID {
				t.Fatalf("intent = %s/%s ref %q; want completed/%s with its ref", closed.State, closed.Outcome, closed.ExternalRef, tc.outcome)
			}
			if e.lockCount(job.ID) != 0 {
				t.Fatal("locks were not released")
			}
		})
	}
}

func TestReconcileProxmoxNeedsTwoSamplesAcrossTheGap(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedTracked(e)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: pveStop(ClassComplete, "stopped", "OK")}}
	e.clock.Advance(time.Minute)
	if got, err := e.store.Reconcile(context.Background(), src); err != nil || len(got) != 0 {
		t.Fatalf("first sample: Reconcile = %v, %v", got, err)
	}
	e.clock.Advance(sampleGap - time.Second)
	if got, err := e.store.Reconcile(context.Background(), src); err != nil || len(got) != 0 || e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("second sample too early: Reconcile = %v, %v, state %s", got, err, e.state(job.ID))
	}
	e.clock.Advance(sampleGap)
	if got, err := e.store.Reconcile(context.Background(), src); err != nil || len(got) != 1 || got[0].Action != ReconcileSucceeded {
		t.Fatalf("second sample in time: Reconcile = %v, %v", got, err)
	}
}

func TestResolveTaskTrackedRequiresStoppedTask(t *testing.T) {
	t.Run("past deadline without stop evidence is a conflict", func(t *testing.T) {
		e := newEnv(t)
		job, _ := interruptedTracked(e)
		e.clock.Advance(time.Hour)
		_, err := e.resolve(resolveRequest(job, ResolveFailed))
		wantCode(t, err, smerr.CodeConflict)
		if e.state(job.ID) != domain.JobInterrupted {
			t.Fatalf("state = %s, want interrupted", e.state(job.ID))
		}
	})

	t.Run("assume_quiescent is honoured and audited", func(t *testing.T) {
		e := newEnv(t)
		job, intent := interruptedTracked(e)
		e.clock.Advance(time.Hour)
		req := resolveRequest(job, ResolveFailed)
		req.AssumeQuiescent = true
		if _, err := e.resolve(req); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got := e.intent(job.ID, intent.ID); got.State != IntentCompleted || got.Outcome != OutcomeFailed {
			t.Fatalf("intent = %s/%s, want completed/failed", got.State, got.Outcome)
		}
		events, err := database.ListEvents(context.Background(), e.db.Reader(), 0, 10_000)
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range events {
			if ev.ResourceID == job.ID && ev.Action == "job.failed" && ev.Data["assume_quiescent"] == true {
				return
			}
		}
		t.Fatal("no job.failed event records assume_quiescent=true")
	})

	t.Run("recorded stop evidence resolves without the override", func(t *testing.T) {
		e := newEnv(t)
		job, intent := interruptedTracked(e)
		e.inTx(func(tx *database.Tx) {
			if err := e.store.RecordTaskStop(context.Background(), tx, intent.ID, pveStop(ClassComplete, "stopped", "OK")); err != nil {
				t.Fatal(err)
			}
		})
		if _, err := e.resolve(resolveRequest(job, ResolveSucceeded)); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	})

	t.Run("a non-proxmox intent past deadline plus grace still resolves", func(t *testing.T) {
		e := newEnv(t)
		job, _ := interruptedWithDispatchedIntent(e)
		e.clock.Advance(time.Hour)
		if _, err := e.resolve(resolveRequest(job, ResolveFailed)); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	})
}

func TestTaskTrackedRuleIsConfigurable(t *testing.T) {
	e := newEnv(t)
	store, err := NewStore(Config{
		DB: e.db, Clock: e.clock, IDs: e.ids, Revalidator: e.reval, LockPlanner: e.planner,
		TaskTracked: func(op string) bool { return op == "compose.up" },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.store = store
	job := e.enqueue(func(nj *NewJob) { nj.PlanHash = planHash })
	c := e.claim("w1")
	dispatchedIntent(e, c.Lease) // operation compose.up
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Hour)
	_, err = e.resolve(resolveRequest(job, ResolveFailed))
	wantCode(t, err, smerr.CodeConflict)
}

func TestATaskThatStopsLongAfterTheDeadlineIsStillReconciled(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedTracked(e)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: pveStop(ClassComplete, "stopped", "OK")}}
	e.clock.Advance(time.Hour)
	if _, err := e.store.Reconcile(context.Background(), src); err != nil {
		t.Fatalf("first sample: %v", err)
	}
	e.clock.Advance(sampleGap)

	got, err := e.store.Reconcile(context.Background(), src)

	if err != nil || len(got) != 1 || got[0].Action != ReconcileSucceeded || e.state(job.ID) != domain.JobSucceeded {
		t.Fatalf("an hour past the deadline: Reconcile = %v, %v, state %s; want succeeded", got, err, e.state(job.ID))
	}
}
