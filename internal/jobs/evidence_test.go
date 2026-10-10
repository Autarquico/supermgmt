package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

func systemdProof(c Classification, fingerprint string) Evidence {
	return Evidence{
		Done: true, Proof: ProofSystemdNoJobs, Classification: c,
		Fingerprint: json.RawMessage(fingerprint),
	}
}

// interruptedAwaitingEvidence is a non_retryable job whose dispatched intent
// has no proof yet and whose deadline plus grace have passed.
func interruptedAwaitingEvidence(e *env) (Job, Intent) {
	e.t.Helper()
	job := e.enqueue()
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		e.t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	return job, intent
}

func reconcileOnce(e *env, src EvidenceSource) ReconcileAction {
	e.t.Helper()
	got, err := e.store.Reconcile(context.Background(), src)
	if err != nil || len(got) != 1 {
		e.t.Fatalf("Reconcile = %v, %v; want one resolution", got, err)
	}
	return got[0].Action
}

func TestChangedFingerprintRestartsThePairEvenWithTheSameClassification(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedAwaitingEvidence(e)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{
		intent.ID: systemdProof(ClassComplete, `{"invocation_id":"A","active_state":"active"}`),
	}}

	if got := reconcileOnce(e, src); got != ReconcileHeld {
		t.Fatalf("first sample = %s, want held", got)
	}
	e.clock.Advance(sampleGap)
	src.byIntent[intent.ID] = systemdProof(ClassComplete, `{"invocation_id":"B","active_state":"active"}`)
	if got := reconcileOnce(e, src); got != ReconcileHeld {
		t.Fatalf("sample with a new InvocationID = %s, want held: the pair must restart", got)
	}
	e.clock.Advance(sampleGap - time.Second)
	if got := reconcileOnce(e, src); got != ReconcileHeld {
		t.Fatalf("restarted pair completed after %s, want it to need the full gap", sampleGap-time.Second)
	}
	e.clock.Advance(time.Second)
	if got := reconcileOnce(e, src); got != ReconcileSucceeded || e.state(job.ID) != domain.JobSucceeded {
		t.Fatalf("stable pair = %s, state %s, want succeeded", got, e.state(job.ID))
	}
}

func TestFingerprintComparisonIgnoresKeyOrderAndWhitespace(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedAwaitingEvidence(e)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{
		intent.ID: systemdProof(ClassComplete, `{"invocation_id":"A","sub_state":"running","n":1}`),
	}}
	reconcileOnce(e, src)
	e.clock.Advance(sampleGap)
	src.byIntent[intent.ID] = systemdProof(ClassComplete, ` { "n": 1, "sub_state": "running",
		"invocation_id": "A" } `)

	if got := reconcileOnce(e, src); got != ReconcileSucceeded || e.state(job.ID) != domain.JobSucceeded {
		t.Fatalf("reordered but equal fingerprint = %s, want succeeded", got)
	}
}

func TestMalformedFingerprintNeverPairs(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedAwaitingEvidence(e)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{
		intent.ID: systemdProof(ClassComplete, `{"invocation_id":`),
	}}
	for range 3 {
		if got := reconcileOnce(e, src); got != ReconcileHeld {
			t.Fatalf("malformed fingerprint = %s, want held", got)
		}
		e.clock.Advance(sampleGap)
	}
	if e.state(job.ID) != domain.JobInterrupted {
		t.Fatalf("state = %s, want interrupted", e.state(job.ID))
	}
}

func TestPersistedEvidenceCarriesProofFingerprintAndPreState(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedAwaitingEvidence(e)
	post := `{"invocation_id":"B","active_state":"active","sub_state":"running"}`
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: systemdProof(ClassComplete, post)}}
	reconcileOnce(e, src)
	e.clock.Advance(sampleGap)
	reconcileOnce(e, src)

	detail, err := e.store.Detail(context.Background(), e.db.Reader(), job.ID)
	if err != nil || len(detail.Intents) != 1 {
		t.Fatalf("Detail = %+v, %v", detail, err)
	}
	var stored Evidence
	if err := json.Unmarshal(detail.Intents[0].Evidence, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Proof != ProofSystemdNoJobs || stored.Classification != ClassComplete || !stored.Proven() {
		t.Fatalf("stored evidence = %+v", stored)
	}
	if string(stored.Fingerprint) != post {
		t.Fatalf("stored fingerprint = %s, want the post state %s", stored.Fingerprint, post)
	}
	if string(stored.Pre) != string(intent.PreState) {
		t.Fatalf("stored pre = %s, want the intent's pre_state %s", stored.Pre, intent.PreState)
	}
}

func TestAdapterSuppliedPreStateIsKept(t *testing.T) {
	e := newEnv(t)
	job, intent := interruptedAwaitingEvidence(e)
	ev := systemdProof(ClassNotStarted, `{"invocation_id":"A"}`)
	ev.Pre = json.RawMessage(`{"invocation_id":"A"}`)
	src := &evidenceStub{byIntent: map[domain.ID]Evidence{intent.ID: ev}}
	reconcileOnce(e, src)
	e.clock.Advance(sampleGap)
	reconcileOnce(e, src)

	detail, err := e.store.Detail(context.Background(), e.db.Reader(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	var stored Evidence
	if err := json.Unmarshal(detail.Intents[0].Evidence, &stored); err != nil {
		t.Fatal(err)
	}
	if string(stored.Pre) != `{"invocation_id":"A"}` || detail.Intents[0].Outcome != OutcomeNotStarted {
		t.Fatalf("stored = %+v, outcome %q", stored, detail.Intents[0].Outcome)
	}
}

func TestEvidenceRowsWrittenBeforeTheFingerprintFieldsStillDecode(t *testing.T) {
	var ev Evidence
	if err := json.Unmarshal([]byte(settledEvidence), &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Proven() || !ev.definite() || ev.Classification != ClassComplete ||
		ev.Proof != "" || ev.Fingerprint != nil || ev.Pre != nil {
		t.Fatalf("decoded = %+v, want proven and complete with no v2 fields", ev)
	}

	e := newEnv(t)
	job := e.enqueue()
	c := e.claim("w1")
	intent := dispatchedIntent(e, c.Lease)
	if err := e.store.CompleteIntent(context.Background(), c.Lease, intent.ID, OutcomeSucceeded, json.RawMessage(settledEvidence)); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(leaseTTL + time.Second)
	if _, err := e.store.Takeover(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	if got := reconcile(e, nil); len(got) != 1 || got[0].Action != ReconcileSucceeded || e.state(job.ID) != domain.JobSucceeded {
		t.Fatalf("job with an old-format settled intent: %v, state %s", got, e.state(job.ID))
	}
}

func TestCanonicalJSON(t *testing.T) {
	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"absent", ``, ``, false},
		{"key order", `{"b":1,"a":{"d":2,"c":3}}`, `{"a":{"c":3,"d":2},"b":1}`, false},
		{"whitespace", "{ \"a\" :\n [1, 2] }", `{"a":[1,2]}`, false},
		{"large integers keep their digits", `{"n":12345678901234567890}`, `{"n":12345678901234567890}`, false},
		{"malformed", `{"a":`, ``, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalJSON(json.RawMessage(tc.in))
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("canonicalJSON(%q) = %q, %v; want %q (error %v)", tc.in, got, err, tc.want, tc.wantErr)
			}
		})
	}
}
