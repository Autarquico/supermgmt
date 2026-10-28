package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// actionPlan submits and approves a parameterless job-mode action as admin.
func (s *setting) actionPlan(action string, target domain.ResourceRef) jobs.Job {
	s.t.Helper()
	ctx, by := context.Background(), s.caller(s.admin)
	created, err := s.plans.Create(ctx, by, PlanRequest{Action: action, Target: target})
	mustf(s.t, err, "Create %s", action)
	sub, err := s.plans.Submit(ctx, by, created.Record.ID, created.Record.PlanHash)
	mustf(s.t, err, "Submit %s", action)
	job := sub.Job
	for _, approver := range []domain.ID{s.bob, s.carol} { // as many as the policy asks for
		if job.State != domain.JobAwaitingApproval {
			break
		}
		job, err = s.approve(approver, job)
		mustf(s.t, err, "approve %s", action)
	}
	return job
}

// newEnabledTunnel is a node that completed `setup --tunnel`.
func newEnabledTunnel(t *testing.T, cfOptions ...cffake.Option) *tunnelSetting {
	t.Helper()
	ts := newTunnelSetting(t, cfOptions...)
	ts.plan()
	mustf(t, ts.attempt(), "tunnel setup")
	return ts
}

func (ts *tunnelSetting) nodeRef() domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceNode, ID: ts.node.ID}
}

// planDisable submits and approves node.tunnel.disable and makes attempt run it.
func (ts *tunnelSetting) planDisable() jobs.Job {
	ts.queued = ts.actionPlan(policy.ActionNodeTunnelDisable, ts.nodeRef())
	ts.current = ts.disable
	return ts.queued
}

// arm makes the k-th Cloudflare mutation from now on suffer fault mode.
func (ts *tunnelSetting) arm(mode string, k int) {
	switch mode {
	case "lost response", "refused before":
		fault, base := cffake.LostResponse, len(ts.cf.Mutations())
		if mode == "refused before" {
			fault = cffake.FailBefore
		}
		ts.cf.Plan(func(m cffake.Mutation) cffake.Fault {
			if m.Seq == base+k {
				return fault
			}
			return cffake.NoFault
		})
	default:
		ts.chaos.mu.Lock()
		defer ts.chaos.mu.Unlock()
		ts.chaos.k, ts.chaos.mode, ts.chaos.fired = ts.chaos.count+k, mode, false
	}
}

// committedOps lists the Cloudflare operations that changed state after the
// first skip mutations, in order.
func (ts *tunnelSetting) committedOps(skip int) []cffake.Op {
	var ops []cffake.Op
	for _, m := range ts.cf.Mutations()[skip:] {
		if m.Committed {
			ops = append(ops, m.Op)
		}
	}
	return ops
}

// instanceObjects is what survives a disable: the reusable policies and the
// service token, with their IDs.
type instanceObjects struct {
	policies []cffake.Policy
	tokens   []cffake.ServiceToken
	secrets  int
}

func (ts *tunnelSetting) instanceObjects() instanceObjects {
	snap := ts.cf.Snapshot()
	return instanceObjects{policies: snap.Policies, tokens: snap.ServiceTokens, secrets: ts.secrets.versions("cloudflare/access-service-token")}
}

// wantDisabled fails unless the node is direct again, only the node's own
// Cloudflare objects are gone, the instance's stay and the hostname was never
// routable without Access.
func (ts *tunnelSetting) wantDisabled(before instanceObjects) {
	ts.t.Helper()
	snap := ts.cf.Snapshot()
	if len(snap.Tunnels) != 0 || len(snap.Apps) != 0 || len(snap.DNSRecords) != 0 {
		ts.t.Errorf("left in Cloudflare: %d tunnels, %d apps, %d dns records", len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords))
	}
	if after := ts.instanceObjects(); !slices.EqualFunc(after.policies, before.policies, func(a, b cffake.Policy) bool {
		return a.ID == b.ID && slices.Equal(a.ServiceTokenIDs, b.ServiceTokenIDs) && slices.Equal(a.Emails, b.Emails)
	}) || !slices.EqualFunc(after.tokens, before.tokens, func(a, b cffake.ServiceToken) bool { return a.ID == b.ID }) || after.secrets != before.secrets {
		ts.t.Errorf("the instance's policies, service token or secret changed: %+v -> %+v", before, after)
	}
	if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		ts.t.Errorf("routable without Access at some point: %v", routable)
	}
	node := ts.currentNode()
	if node.Endpoint.Transport.Effective() != domain.TransportDirect || node.Endpoint.TunnelHostname != "" {
		ts.t.Errorf("endpoint = %q %q, want direct without a hostname", node.Endpoint.Transport, node.Endpoint.TunnelHostname)
	}
	meta, ok := ts.setupCapability()
	if !ok || meta.Tunnel != nil {
		ts.t.Errorf("capability = %+v, %v: want setup metadata without the tunnel", meta, ok)
	}
	if ops := ts.operations(); len(ops) < 2 || ops[0].Kind != database.TunnelDisable || ops[0].Phase != database.PhaseDone {
		ts.t.Errorf("operations = %+v, want the newest to be a finished disable", ops)
	}
	for _, path := range []string{templates.CloudflaredTokenPath, templates.CloudflaredUnitPath, templates.CloudflaredSourcePath, templates.CloudflareKeyringPath} {
		if _, left := ts.files[path]; left {
			ts.t.Errorf("%s is still on the node", path)
		}
	}
}

func TestDisableReturnsTheNodeToTheDirectPathInTheOrderOfTheADR(t *testing.T) {
	ts := newEnabledTunnel(t)
	before, base, files := ts.instanceObjects(), len(ts.cf.Mutations()), len(ts.files)
	known := ts.operations()[0].Objects
	revision := ts.currentNode().SpecRevision
	dialed := len(ts.dialer.targets())
	ts.planDisable()

	mustf(t, ts.attempt(), "disable")

	ts.wantDisabled(before)
	want := []cffake.Op{cffake.OpDNSDelete, cffake.OpTunnelConfigPut, cffake.OpAppDelete, cffake.OpTunnelCleanup, cffake.OpTunnelDelete}
	if got := ts.committedOps(base); !slices.Equal(got, want) {
		t.Errorf("Cloudflare mutations = %v, want %v: the route closes, then Access goes, the tunnel last", got, want)
	}
	if got := ts.currentNode().SpecRevision; got != revision+1 {
		t.Errorf("spec revision %d -> %d, want one conditional update", revision, got)
	}
	ops := ts.operations()
	if ops[0].Objects != known || ops[0].Generation != 2 {
		t.Errorf("disable record = %+v, want generation 2 holding the objects %+v", ops[0], known)
	}
	if got := ts.dialer.invalidated[len(ts.dialer.invalidated)-1]; got != ts.node.ID.String()+"/*" {
		t.Errorf("last invalidation = %q: the pooled connections must be retired after the switch", got)
	}
	for _, action := range []string{
		"node.tunnel.direct_verified", "node.tunnel.switched_to_direct", "node.tunnel.service_removed", "cloudflare.dns_record.deleted",
		"cloudflare.tunnel.ingress_closed", "cloudflare.access_app.deleted", "cloudflare.tunnel.deleted", "node.tunnel.disabled",
	} {
		if len(ts.events(action)) == 0 {
			t.Errorf("no %s event", action)
		}
	}
	if len(ts.files) >= files {
		t.Errorf("the node kept %d of its %d files: setup's tunnel files were not removed", len(ts.files), files)
	}
	var admin, dedicated bool
	for _, target := range ts.dialer.targets()[dialed:] {
		if target.Transport.Effective() != domain.TransportDirect || target.HostKey != ts.node.Endpoint.HostPublicKey {
			t.Errorf("target %+v: the disable must use the direct path with the pinned host key", target)
		}
		admin, dedicated = admin || target.User == "admin", dedicated || target.User == "supermgmt"
	}
	if !admin || !dedicated {
		t.Errorf("direct verification covered admin=%v dedicated=%v, want both", admin, dedicated)
	}
}

func TestDisableOnlyRemovesWhatSetupInstalledOnTheNode(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.files["/etc/somebody/else.conf"] = "kept"
	ts.planDisable()

	mustf(t, ts.attempt(), "disable")

	if ts.files["/etc/somebody/else.conf"] != "kept" {
		t.Error("a file setup did not install was removed")
	}
	for _, call := range ts.dialer.as("admin").ran() {
		if strings.Contains(call, "purge") || strings.Contains(call, "userdel") {
			t.Errorf("unexpected node command %q", call)
		}
	}
}

func TestADirectPathThatCannotBeVerifiedChangesNothing(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(ts *tunnelSetting)
		step   string
	}{
		{"admin account unreachable", func(ts *tunnelSetting) {
			ts.dialer.as("admin").down("probe", errors.New("connection refused"))
		}, "admin account"},
		{"dedicated account fails verification", func(ts *tunnelSetting) {
			ts.dialer.as("supermgmt").reply("setup.verify_id", "someone-else\n")
		}, "dedicated account"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := newEnabledTunnel(t)
			base, files, node := len(ts.cf.Mutations()), len(ts.files), ts.currentNode()
			tc.break_(ts)
			ts.planDisable()

			err := ts.attempt()

			if err == nil || !strings.Contains(err.Error(), "verification of the direct path ("+tc.step+")") {
				t.Fatalf("error = %v, want one naming the verification of the %s", err, tc.step)
			}
			if got := len(ts.cf.Mutations()); got != base {
				t.Errorf("%d Cloudflare mutations, want none", got-base)
			}
			after := ts.currentNode()
			if after.Endpoint != node.Endpoint || after.SpecRevision != node.SpecRevision {
				t.Errorf("node = %+v, want it untouched", after)
			}
			if ops := ts.operations(); len(ops) != 1 || ops[0].Kind != database.TunnelEnable {
				t.Errorf("operations = %+v, want only the committed enable: no disable record was written", ops)
			}
			if len(ts.files) != files {
				t.Error("files on the node changed")
			}
			if meta, _ := ts.setupCapability(); meta.Tunnel == nil {
				t.Error("the tunnel was dropped from the setup metadata")
			}
		})
	}
}

func TestEveryFaultAfterEveryMutationOfADisableConverges(t *testing.T) {
	clean := newEnabledTunnel(t)
	base := len(clean.cf.Mutations())
	clean.planDisable()
	mustf(t, clean.attempt(), "clean disable")
	total := len(clean.cf.Mutations()) - base
	if total != 5 {
		t.Fatalf("a clean disable made %d mutations, want 5 (DNS, ingress, app, connections, tunnel)", total)
	}

	for _, mode := range []string{"lost response", "refused before", "crash", "lease loss"} {
		for k := 1; k <= total; k++ {
			t.Run(fmt.Sprintf("%s at mutation %d", mode, k), func(t *testing.T) {
				ts := newEnabledTunnel(t)
				before, base := ts.instanceObjects(), len(ts.cf.Mutations())
				ts.planDisable()
				ts.arm(mode, k)

				failures := ts.converge(5)

				if len(failures) == 0 && (mode == "crash" || mode == "lease loss") {
					t.Fatal("the fault changed nothing")
				}
				ts.wantDisabled(before)
				ops := ts.committedOps(base)
				dns, ingress, app, tunnel := slices.Index(ops, cffake.OpDNSDelete), slices.Index(ops, cffake.OpTunnelConfigPut),
					slices.Index(ops, cffake.OpAppDelete), slices.Index(ops, cffake.OpTunnelDelete)
				if dns < 0 || ingress < 0 || app < 0 || tunnel < 0 || dns > app || ingress > app || tunnel != len(ops)-1 {
					t.Errorf("committed mutations %v: the route must close before Access goes and the tunnel must go last", ops)
				}
				if mode == "lease loss" && !errors.Is(failures[0], jobs.ErrLeaseLost) {
					t.Errorf("first failure = %v, want the lease loss", failures[0])
				}
			})
		}
	}
}

func TestADisableRefusedByLeaseLossMakesNoFurtherMutation(t *testing.T) {
	ts := newEnabledTunnel(t)
	base := len(ts.cf.Mutations())
	ts.planDisable()
	ts.arm("lease loss", 2)

	err := ts.attempt()

	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("error = %v, want ErrLeaseLost", err)
	}
	if got := len(ts.cf.Mutations()) - base; got != 2 {
		t.Errorf("%d Cloudflare mutations, want 2: nothing after the lease was lost", got)
	}
}

func TestDisableTreatsAnObjectThatIsAlreadyGoneAsRemoved(t *testing.T) {
	tests := []struct {
		name   string
		vanish func(ts *tunnelSetting, objects database.TunnelObjects)
		kind   string
	}{
		{"DNS record", func(ts *tunnelSetting, o database.TunnelObjects) {
			mustf(t, ts.chaos.CloudflareAPI.DeleteDNSRecord(context.Background(), ts.zoneID(), o.DNSRecordID), "delete")
		}, "DNS record"},
		{"Access application", func(ts *tunnelSetting, o database.TunnelObjects) {
			mustf(t, ts.chaos.CloudflareAPI.DeleteDNSRecord(context.Background(), ts.zoneID(), o.DNSRecordID), "delete DNS")
			mustf(t, ts.chaos.CloudflareAPI.DeleteAccessApp(context.Background(), o.AccessAppID), "delete")
		}, "Access application"},
		{"tunnel", func(ts *tunnelSetting, o database.TunnelObjects) {
			mustf(t, ts.chaos.CloudflareAPI.DeleteDNSRecord(context.Background(), ts.zoneID(), o.DNSRecordID), "delete DNS")
			mustf(t, ts.chaos.CloudflareAPI.DeleteAccessApp(context.Background(), o.AccessAppID), "delete app")
			mustf(t, ts.chaos.CloudflareAPI.DeleteTunnel(context.Background(), o.TunnelID), "delete")
		}, "tunnel"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := newEnabledTunnel(t)
			before := ts.instanceObjects()
			tc.vanish(ts, ts.operations()[0].Objects)
			ts.planDisable()

			mustf(t, ts.attempt(), "disable")

			ts.wantDisabled(before)
			vanished := ts.events("cloudflare.object.vanished")
			if len(vanished) == 0 {
				t.Fatalf("no vanished-object event for the %s", tc.kind)
			}
			if !strings.Contains(string(mustJSON(t, vanished[len(vanished)-1].Data)), tc.kind) {
				t.Errorf("the vanished event does not name the %s: %+v", tc.kind, vanished[len(vanished)-1].Data)
			}
		})
	}
}

func (ts *tunnelSetting) zoneID() string {
	_, id := ts.cf.Zone()
	return id
}

func TestDisableLeavesAForeignRecordOnTheHostnameAlone(t *testing.T) {
	ts := newEnabledTunnel(t)
	known := ts.operations()[0].Objects
	mustf(t, ts.chaos.CloudflareAPI.DeleteDNSRecord(context.Background(), ts.zoneID(), known.DNSRecordID), "delete ours")
	ts.cf.SeedDNSRecord(ts.hostname(), "elsewhere.example.test", "someone else's")
	ts.planDisable()

	mustf(t, ts.attempt(), "disable")

	if records := ts.cf.DNSRecords(); len(records) != 1 || records[0].Comment != "someone else's" {
		t.Errorf("DNS records = %+v, want the foreign one untouched", records)
	}
}

func TestDisableOfANodeWithoutATunnelIsRefusedBeforeAnythingChanges(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.planDisable()

	err := ts.attempt()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	ts.grantSetup()
	interruptAndRequeue(t, ts.fixture, ts.queued.ID)
	wantError(t, ts.attempt(), smerr.CodeInvalidArgument, "")
	if got := len(ts.cf.Mutations()); got != 0 {
		t.Errorf("%d Cloudflare mutations, want none", got)
	}
	if ops := ts.operations(); len(ops) != 0 {
		t.Errorf("operations = %+v, want none", ops)
	}
}

func TestADisablePlanIsHighRiskNeedsApprovalAndIsRefusedWithoutAConnection(t *testing.T) {
	ts := newTunnelSetting(t)
	created, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{Action: policy.ActionNodeTunnelDisable, Target: ts.nodeRef()})
	mustf(t, err, "Create")
	if created.Plan.Risk != domain.RiskHigh || !created.Policy.ApprovalRequired {
		t.Errorf("risk %s policy %+v, want high risk gated by approval", created.Plan.Risk, created.Policy)
	}
	if _, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{
		Action: policy.ActionNodeTunnelDisable, Target: ts.nodeRef(), Parameters: map[string]any{"force": "true"},
	}); err == nil {
		t.Error("the closed schema accepted a parameter")
	}

	plain := newSetting(t) // no cloudflare: block
	_, err = plain.plans.Create(context.Background(), plain.caller(plain.admin), PlanRequest{
		Action: policy.ActionNodeTunnelDisable, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: plain.node.ID},
	})
	wantError(t, err, smerr.CodeInvalidArgument, "")
	if err != nil && !strings.Contains(err.Error(), "cloudflare") {
		t.Errorf("error %q does not say the connection is not configured", err)
	}
}

func TestADisableHoldsTheNodeExclusively(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.planDisable()
	if _, ok := ts.claim(); !ok {
		t.Fatal("no job to claim")
	}

	if got := ts.locks()["node:"+ts.node.ID.String()]; got != domain.LockExclusive {
		t.Errorf("node lock = %q, want exclusive", got)
	}
}
