package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func proxmoxNode(name, pveNode string, g wire.ProxmoxGuest) wire.Node {
	g.PVENode = pveNode
	return wire.Node{
		ID: newTestID(), Name: name, Kind: "proxmox." + g.Type, Provider: "pve", Origin: domain.ProviderStatic,
		ManagementState: domain.ManagementDiscovered, Proxmox: &g,
	}
}

func treeInventory() []wire.Node {
	managed := wire.Node{
		ID: newTestID(), Name: "web-1", Kind: "ssh", Provider: "lab", ManagementState: domain.ManagementManaged,
		Reachability: domain.ReachabilityReachable,
	}
	offline := wire.Node{
		ID: newTestID(), Name: "old-box", Kind: "ssh", Provider: "lab", ManagementState: domain.ManagementManaged,
		Reachability: domain.ReachabilityUnreachable, Stale: true,
	}
	return []wire.Node{
		proxmoxNode("web", "pve1", wire.ProxmoxGuest{VMID: 100, Type: "qemu", Status: "running"}),
		proxmoxNode("pve2", "pve2", wire.ProxmoxGuest{Type: "node", Status: "online"}),
		proxmoxNode("db", "pve2", wire.ProxmoxGuest{VMID: 200, Type: "lxc", Status: "unknown", Absent: true}),
		proxmoxNode("pve1", "pve1", wire.ProxmoxGuest{Type: "node", Status: "online"}),
		proxmoxNode("base", "pve1", wire.ProxmoxGuest{VMID: 300, Type: "qemu", Status: "stopped", Template: true}),
		proxmoxNode("cache", "pve2", wire.ProxmoxGuest{VMID: 210, Type: "lxc", Status: "unknown", Inaccessible: true}),
		managed, offline,
	}
}

func TestNodesListTreeGroupsGuestsUnderTheirClusterNodeAndMarksWhatIsNotThere(t *testing.T) {
	inventory := treeInventory()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("cursor") == "" {
				reply(w, 200, wire.Page[wire.Node]{Items: inventory[:4], NextCursor: "c2"})
				return
			}
			reply(w, 200, wire.Page[wire.Node]{Items: inventory[4:]})
		},
	}))

	r := f.run("nodes", "list", "--tree")

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	assertGolden(t, "nodes.tree.golden", r.stdout)
	if n := len(f.Requests()); n != 2 {
		t.Errorf("requests = %d, want both pages read", n)
	}
}

func TestNodesListTreeJSONIsEveryNode(t *testing.T) {
	inventory := treeInventory()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: inventory})
		},
	}))

	r := f.run("nodes", "list", "--tree", "--json")

	var env struct {
		Items []wire.Node `json:"items"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &env); err != nil || len(env.Items) != len(inventory) {
		t.Errorf("items = %d, err = %v:\n%s", len(env.Items), err, r.stdout)
	}
}

func TestNodesListTreeStillWorksWhenEveryNodeIsOffline(t *testing.T) {
	down := []wire.Node{
		{ID: newTestID(), Name: "a", Kind: "ssh", Provider: "lab", ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnreachable, Stale: true},
		{ID: newTestID(), Name: "b", Kind: "ssh", Provider: "lab", ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnreachable, Stale: true},
	}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Page[wire.Node]{Items: down}) },
	}))

	r := f.run("nodes", "list", "--tree")

	if r.code != 0 || strings.Count(r.stdout, "unreachable (stale)") != 2 {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
}

// ---- power -----------------------------------------------------------------

type powerAPI struct {
	guest    wire.Node
	plan     wire.CreatedPlan
	policy   wire.Policy
	job      wire.Job
	jobStats []domain.JobState // GET /jobs/{id} answers these in turn, the last one forever
	polls    atomic.Int32
}

func newPowerAPI(t *testing.T, guest wire.Node, risk string, policy wire.Policy) (*fakeAPI, *powerAPI) {
	t.Helper()
	p := &powerAPI{guest: guest, policy: policy}
	p.plan = wire.CreatedPlan{
		PlanID: newTestID(), PlanHash: "0123456789abcdef0123", Plan: json.RawMessage(`{"action":"proxmox.vm.power","risk":"` + risk + `"}`),
		Policy: policy,
	}
	p.job = wire.Job{ID: newTestID(), Type: "proxmox.vm.power", State: domain.JobQueued}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{guest}})
		},
		"GET " + wire.Path(wire.PathNode, string(guest.ID)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, guest) },
		"POST " + wire.PathPlans:                            func(w http.ResponseWriter, _ *http.Request) { reply(w, 201, p.plan) },
		"POST " + wire.Path(wire.PathPlanSubmit, string(p.plan.PlanID)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, wire.Submission{Job: p.job, Policy: policy})
		},
		"GET " + wire.Path(wire.PathJob, string(p.job.ID)): func(w http.ResponseWriter, _ *http.Request) {
			i := min(int(p.polls.Add(1))-1, len(p.jobStats)-1)
			job := p.job
			job.State = p.jobStats[i]
			if job.State == domain.JobFailed {
				job.Error = &wire.Failure{Code: smerr.CodeInternal, Message: "task failed: guest is locked"}
			}
			reply(w, 200, wire.JobDetail{Job: job})
		},
	}))
	return f, p
}

func runningGuest() wire.Node {
	return proxmoxNode("web", "pve1", wire.ProxmoxGuest{VMID: 100, Type: "qemu", Status: "running"})
}

func TestNodesPowerStopShowsItsHighRiskAndTheApprovalPathBeforeAnythingIsSubmitted(t *testing.T) {
	guest := runningGuest()
	f, p := newPowerAPI(t, guest, "high", wire.Policy{Decision: "allow", ApprovalRequired: true, Quorum: 2})

	r := f.runCtx(t.Context(), "yes\n", "nodes", "power", "web", "stop")

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{
		"risk: high", "it needs 2 approval(s) before it runs", "cuts the guest's power", "Type 'yes' to continue",
		"to approve: sm jobs approve " + string(p.job.ID) + " --plan-hash " + p.plan.PlanHash,
	} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
	if !strings.Contains(r.stdout, "is queued; approval required (quorum 2)") {
		t.Errorf("stdout = %q", r.stdout)
	}
	var create wire.CreatePlanRequest
	body := mutationBody(t, f, wire.PathPlans)
	if err := json.Unmarshal([]byte(body), &create); err != nil {
		t.Fatal(err)
	}
	if create.Action != "proxmox.vm.power" || create.Parameters["verb"] != "stop" || len(create.Targets) != 1 || create.Targets[0].ID != guest.ID {
		t.Errorf("plan request = %+v", create)
	}
}

func mutationBody(t *testing.T, f *fakeAPI, path string) string {
	t.Helper()
	for _, m := range f.Mutations() {
		if m.Path == path {
			return m.Body
		}
	}
	t.Fatalf("no request to %s in %+v", path, f.Mutations())
	return ""
}

func TestNodesPowerNeedsTheUserToConfirmAndSubmitsNothingOtherwise(t *testing.T) {
	f, p := newPowerAPI(t, runningGuest(), "operational", wire.Policy{Decision: "allow"})

	r := f.runCtx(t.Context(), "no\n", "nodes", "power", "web", "reboot")

	if r.code != exitUsage || !strings.Contains(r.stderr, "not confirmed") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, m := range f.Mutations() {
		if strings.HasSuffix(m.Path, "/submit") {
			t.Errorf("submitted %s without confirmation", p.plan.PlanID)
		}
	}
}

func TestNodesPowerStartRunsAtOnceWithYes(t *testing.T) {
	f, _ := newPowerAPI(t, runningGuest(), "operational", wire.Policy{Decision: "allow"})

	r := f.run("nodes", "power", "web", "start", "--yes")

	if r.code != 0 || !strings.Contains(r.stderr, "it runs as soon as it is submitted") || strings.Contains(r.stderr, "to approve") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "risk: operational") {
		t.Errorf("stderr lacks the risk: %q", r.stderr)
	}
}

func TestNodesPowerRefusesWhatPolicyDeniesWithoutSubmitting(t *testing.T) {
	f, _ := newPowerAPI(t, runningGuest(), "high", wire.Policy{Decision: "deny", Reason: smerr.ReasonDefaultDeny})

	r := f.run("nodes", "power", "web", "stop", "--yes")

	if r.code == 0 || !strings.Contains(r.stderr, "policy: deny") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, m := range f.Mutations() {
		if strings.HasSuffix(m.Path, "/submit") {
			t.Error("a denied plan was submitted")
		}
	}
}

func TestNodesPowerRefusesBeforeAnyPlanWhatCannotBePowered(t *testing.T) {
	tests := []struct {
		name  string
		guest wire.Node
		verb  string
		want  string
	}{
		{"unknown verb", runningGuest(), "kill", `unknown power action "kill"`},
		{"cluster node", proxmoxNode("pve1", "pve1", wire.ProxmoxGuest{Type: "node", Status: "online"}), "stop", "is not a Proxmox VM or container"},
		{"ssh node", wire.Node{ID: newTestID(), Name: "web", Kind: "ssh"}, "stop", "is not a Proxmox VM or container"},
		{"template", proxmoxNode("web", "pve1", wire.ProxmoxGuest{VMID: 300, Type: "qemu", Template: true}), "start", "is a template"},
		{"absent", proxmoxNode("web", "pve1", wire.ProxmoxGuest{VMID: 100, Type: "qemu", Absent: true}), "start", "(absent)"},
		{"inaccessible", proxmoxNode("web", "pve1", wire.ProxmoxGuest{VMID: 100, Type: "qemu", Inaccessible: true}), "start", "is inaccessible"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := newPowerAPI(t, tt.guest, "operational", wire.Policy{Decision: "allow"})

			r := f.run("nodes", "power", tt.guest.Name, tt.verb, "--yes")

			if r.code != exitUsage || !strings.Contains(r.stderr, tt.want) {
				t.Errorf("code=%d stderr=%q, want %q", r.code, r.stderr, tt.want)
			}
			if len(f.Mutations()) != 0 {
				t.Errorf("mutations = %+v, want none", f.Mutations())
			}
		})
	}
}

func TestNodesPowerWaitFollowsTheJobToItsEnd(t *testing.T) {
	f, p := newPowerAPI(t, runningGuest(), "operational", wire.Policy{Decision: "allow"})
	p.jobStats = []domain.JobState{domain.JobQueued, domain.JobRunning, domain.JobSucceeded}

	r := f.run("nodes", "power", "web", "start", "--yes", "--wait")

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{"is queued", "is running", "is succeeded"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("progress lacks %q:\n%s", want, r.stderr)
		}
	}
	if !strings.Contains(r.stdout, "(proxmox.vm.power) succeeded") {
		t.Errorf("stdout = %q", r.stdout)
	}
}

func TestNodesPowerWaitFailsWithTheJobsFailureAndSaysWhenOutcomeIsUnknown(t *testing.T) {
	tests := []struct {
		state domain.JobState
		want  string
	}{
		{domain.JobFailed, "task failed: guest is locked"},
		{domain.JobInterrupted, "outcome is unknown"},
		{domain.JobCancelled, "cancelled"},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			f, p := newPowerAPI(t, runningGuest(), "operational", wire.Policy{Decision: "allow"})
			p.jobStats = []domain.JobState{tt.state}

			r := f.run("nodes", "power", "web", "start", "--yes", "--wait")

			if r.code != exitInternal || !strings.Contains(r.stderr, tt.want) {
				t.Errorf("code=%d stderr=%q, want %q", r.code, r.stderr, tt.want)
			}
		})
	}
}
