//go:build fixtures

package m1

import (
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// Scenario: restart en producción espera aprobación.
// Given a service on a node of a production environment, when a restart is
// requested, then it waits in Approvals until it is approved in the TUI.
func TestM1_ProductionRestartWaitsForApprovalInTUI(t *testing.T) {
	n := startNodes(t, fixture.Options{})[0]
	in := newInstance(t, instanceOptions{FastRefresh: true})
	in.startDaemon()
	api := in.client()

	prod := addNode(t, api, in, n, "prod-1", "production")
	waitDiscovered(t, api, prod.ID)
	setup(t, api, prod, false, allVerbs(demoUnit)...)
	probe(t, api, prod.ID)
	svc := serviceNamed(t, api, prod.ID, demoUnit)
	if !hasVerb(svc.Actions, domain.VerbRestart) {
		t.Fatalf("%s offers %v after setup, want restart", demoUnit, svc.Actions)
	}
	before := n.invocationID(t, demoUnit)

	sub, err := api.ServiceAction(t.Context(), svc.ID, domain.VerbRestart)
	if err != nil {
		t.Fatalf("request restart: %v", err)
	}
	if sub.Job.State != domain.JobAwaitingApproval || !sub.Policy.ApprovalRequired {
		t.Fatalf("restart in production is %s (policy %+v), want awaiting_approval", sub.Job.State, sub.Policy)
	}

	time.Sleep(10 * time.Second)
	if got := n.invocationID(t, demoUnit); got != before {
		t.Fatalf("the unit restarted before approval: InvocationID %s -> %s", before, got)
	}
	if job, err := api.GetJob(t.Context(), sub.Job.ID); err != nil || job.Job.State != domain.JobAwaitingApproval {
		t.Fatalf("job after 10s = %v (%v), want awaiting_approval", job.Job.State, err)
	}

	tui := newTUI(t, api, 120, 40)
	tui.press("4")
	tui.waitScreen("AWAITING APPROVAL", 10*time.Second)
	if !tui.screenHas("service.restart") {
		t.Fatalf("Approvals does not list the restart:\n%s", tui.screen())
	}
	tui.press("A")

	waitJob(t, api, sub.Job.ID, domain.JobSucceeded, 2*time.Minute)
	if got := n.invocationID(t, demoUnit); got == before {
		t.Errorf("approved restart left InvocationID unchanged (%s)", got)
	}
}

func hasVerb(verbs []domain.ServiceVerb, want domain.ServiceVerb) bool {
	for _, v := range verbs {
		if v == want {
			return true
		}
	}
	return false
}
