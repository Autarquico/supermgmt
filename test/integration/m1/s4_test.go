//go:build fixtures

package m1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// Scenario: daemon matado a mitad de restart.
// Given a restart in progress, when the daemon is killed, then the job stays
// interrupted and the reconciler resolves it from evidence (InvocationID).
//
// This runs on the real clock: after the restart the reconciler needs two
// identical samples at least 30s apart, behind a lease that has to expire.
func TestM1_DaemonKilledMidRestartReconciles(t *testing.T) {
	n := startNodes(t, fixture.Options{})[0]
	in := newInstance(t, instanceOptions{})
	in.startDaemon()
	api := in.client()

	nd := addNode(t, api, in, n, "slow-node", "staging")
	waitDiscovered(t, api, nd.ID)
	setup(t, api, nd, false, allVerbs(slowUnit)...)
	probe(t, api, nd.ID)
	svc := serviceNamed(t, api, nd.ID, slowUnit)
	before := n.invocationID(t, slowUnit)

	sub, err := api.ServiceAction(t.Context(), svc.ID, domain.VerbRestart)
	if err != nil {
		t.Fatalf("request restart: %v", err)
	}
	if sub.Job.State == domain.JobAwaitingApproval {
		t.Fatalf("restart in staging unexpectedly needs approval")
	}

	// Independent evidence, from the node itself, that the restart is under
	// way (ExecStop sleeps 8s): only then is the daemon killed.
	eventually(t, 30*time.Second, "sm-slow.service to be deactivating on the node", func() bool {
		state, _ := n.trySh(t, "systemctl show -p ActiveState --value "+slowUnit)
		return state == "deactivating"
	})
	in.killDaemon()
	if state := n.sh(t, "systemctl show -p ActiveState --value "+slowUnit); state != "deactivating" && state != "activating" && state != "active" {
		t.Fatalf("unit state after the kill = %q", state)
	}

	in.startDaemon()
	api = in.client()

	sawInterrupted := false
	var final wire.JobDetail
	deadline := monotonicNow().Add(6 * time.Minute)
	for monotonicNow().Before(deadline) {
		detail, err := api.GetJob(t.Context(), sub.Job.ID)
		if err == nil {
			final = detail
			if detail.Job.State == domain.JobInterrupted {
				sawInterrupted = true
			}
			if isFinal(detail.Job.State) {
				break
			}
		}
		time.Sleep(pollEvery)
	}
	if final.Job.State != domain.JobSucceeded {
		t.Fatalf("job ended %s after the daemon restart: %s\n%s", final.Job.State, describeFailure(final.Job), in.logText())
	}
	if !sawInterrupted {
		t.Errorf("the job was never observed in state interrupted between the kill and its resolution")
	}

	after := n.invocationID(t, slowUnit)
	if after == before {
		t.Fatalf("InvocationID did not change across the restart (%s)", before)
	}
	pre, post := evidenceInvocationIDs(t, final)
	if pre != before {
		t.Errorf("audit record pre-state InvocationID = %q, want %q", pre, before)
	}
	if post != after {
		t.Errorf("audit record post-state InvocationID = %q, want %q", post, after)
	}
}

// evidenceInvocationIDs reads the InvocationIDs the job's intent recorded
// before (pre_state) and observed after (evidence) the operation.
func evidenceInvocationIDs(t *testing.T, d wire.JobDetail) (pre, post string) {
	t.Helper()
	for _, in := range d.Intents {
		if !strings.Contains(in.Operation, "restart") && !strings.Contains(in.Operation, "service") {
			continue
		}
		pre = findString(in.PreState, "invocation_id")
		post = findString(in.Evidence, "invocation_id")
		if pre != "" || post != "" {
			return pre, post
		}
	}
	t.Fatalf("no intent carries an InvocationID: %+v", d.Intents)
	return "", ""
}

// findString returns the first string value stored under key anywhere in raw.
func findString(raw json.RawMessage, key string) string {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	var walk func(any) string
	walk = func(v any) string {
		switch x := v.(type) {
		case map[string]any:
			if s, ok := x[key].(string); ok {
				return s
			}
			for _, child := range x {
				if s := walk(child); s != "" {
					return s
				}
			}
		case []any:
			for _, child := range x {
				if s := walk(child); s != "" {
					return s
				}
			}
		}
		return ""
	}
	return walk(doc)
}
