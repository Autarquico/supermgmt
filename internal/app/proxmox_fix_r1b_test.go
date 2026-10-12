package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
)

func incarnationOf(n domain.Node) string { return incarnationOfNode(n) }

// SEC-9: a guest that left and came back may be another guest under a reused
// VMID, so it is a new incarnation and every plan made for the old one is stale.
func TestProxmoxSyncAGuestThatLeftAndCameBackIsANewIncarnation(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()
	before := c.object("lxc/200")
	if incarnationOf(before) == "" {
		t.Fatal("discovery assigned no incarnation")
	}

	c.fake.RemoveGuest(200)
	c.clock.Advance(time.Minute)
	c.doSync()
	gone := c.object("lxc/200")
	c.fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "db", Status: "stopped"}) // same name, other guest
	c.clock.Advance(time.Minute)
	c.doSync()

	after := c.object("lxc/200")
	if after.ID != before.ID || gone.SpecRevision != before.SpecRevision {
		t.Fatalf("the row must be kept and an absent guest must not change revision: %+v -> %+v -> %+v", before, gone, after)
	}
	if after.SpecRevision != before.SpecRevision+1 || incarnationOf(after) == incarnationOf(before) {
		t.Errorf("after coming back: revision %d incarnation %q; before: revision %d incarnation %q; want a new revision and incarnation",
			after.SpecRevision, incarnationOf(after), before.SpecRevision, incarnationOf(before))
	}
	c.clock.Advance(time.Minute)
	c.doSync()
	if again := c.object("lxc/200"); again.SpecRevision != after.SpecRevision || incarnationOf(again) != incarnationOf(after) {
		t.Errorf("a guest that stays does not change incarnation: %+v -> %+v", after, again)
	}
}

// SEC-9: at dispatch the guest is read again and must be the one planned for.
func TestPowerRefusesAGuestThatIsNotTheOnePlannedFor(t *testing.T) {
	tests := map[string]func(*powerRig){
		"vmid reused under another name": func(r *powerRig) {
			r.fake.RemoveGuest(200)
			r.fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "payroll", Status: "stopped"})
		},
		"guest deleted": func(r *powerRig) { r.fake.RemoveGuest(200) },
		"vmid reused by another type": func(r *powerRig) {
			r.fake.RemoveGuest(200)
			r.fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "qemu", VMID: 200, Name: "db", Status: "stopped"})
		},
		"guest became a template": func(r *powerRig) {
			r.fake.RemoveGuest(200)
			r.fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "db", Template: true})
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			r := newPowerRig(t)
			change(r) // after discovery, before the job runs

			job, err := r.run("lxc/200", "start")

			if job.State != domain.JobFailed || smerr.CodeOf(err) != smerr.CodeConflict {
				t.Fatalf("job = %s, err %v; want failed with CONFLICT", job.State, err)
			}
			if n := r.posts("start"); n != 0 {
				t.Errorf("POSTs = %d, want none", n)
			}
			if intents, _ := r.store.Intents(context.Background(), r.db.Reader(), job.ID); len(intents) != 0 {
				t.Errorf("%d intents recorded for a dispatch that never happened", len(intents))
			}
		})
	}
}

// SEC-13: the privilege is read for the guest's own path, so a pool the guest
// has left cannot keep granting it.
func TestPowerDoesNotTrustThePoolDiscoveryRemembers(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Revoke(pveTokenUser, "/", pveRole)
	r.fake.Grant(pveTokenUser, "/pool/prod", pveRole, true) // the only source of power over guest 100
	mustf(t, r.handler.sync.Sync(context.Background(), r.pve.ID), "discovery under the pool grant")
	if !r.canPower(t, "qemu/100") {
		t.Fatal("precondition: the pool grant advertises power")
	}
	r.fake.SetPool(100, "") // after discovery: the guest left the pool

	job, err := r.run("qemu/100", "stop")

	if job.State != domain.JobFailed || smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Fatalf("job = %s, err %v; want failed with CAPABILITY_UNAVAILABLE", job.State, err)
	}
	if n := r.posts("stop"); n != 0 {
		t.Errorf("POSTs = %d, want none", n)
	}
}

func (r *powerRig) canPower(t *testing.T, native string) bool {
	t.Helper()
	caps, err := database.ListNodeCapabilities(context.Background(), r.db.Reader(), r.guest(native).ID)
	mustf(t, err, "capabilities")
	for _, k := range caps {
		if k.Capability == CapabilityVMPower {
			return k.Available
		}
	}
	return false
}

// SEC-14: a grant that does not propagate is still effective on its own path.
func TestProxmoxSyncAdvertisesPowerFromANonPropagatingGrantOnTheGuest(t *testing.T) {
	c := newPVECluster(t)
	c.fake.Revoke(pveTokenUser, "/", pveRole)
	c.fake.SetRole("SMAudit", "VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit")
	c.fake.SetRole("SMPowerAudit", "VM.Audit", "VM.PowerMgmt")
	c.fake.Grant(pveTokenUser, "/", "SMAudit", true)
	c.fake.Grant(pveTokenUser, "/vms/100", "SMPowerAudit", false)

	c.doSync()

	if !c.canPower("qemu/100") {
		t.Error("VM.PowerMgmt granted on /vms/100 without propagation is effective there")
	}
	if c.canPower("lxc/200") {
		t.Error("the grant on /vms/100 must not reach /vms/200")
	}
}

// SEC-15: a provider that left the configuration can no longer power anything.
func TestRemovingAProxmoxProviderRevokesPowerAndStalesItsPlans(t *testing.T) {
	r := newPowerRig(t)
	before := r.providerRow()

	mustf(t, r.reconciler(t).Reconcile(context.Background(), nil, nil), "remove the provider")

	after := r.providerRow()
	if after.Status != ProviderStatusRemoved || after.SpecRevision != before.SpecRevision+1 {
		t.Errorf("provider = %+v, want removed with revision %d: plans that used it are stale", after, before.SpecRevision+1)
	}
	for _, native := range []string{"qemu/100", "lxc/200"} {
		if r.canPower(t, native) {
			t.Errorf("%s still advertises proxmox.vm.power", native)
		}
	}
	job, err := r.run("lxc/200", "start")
	if job.State != domain.JobFailed || smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Fatalf("job = %s, err %v; want failed with CAPABILITY_UNAVAILABLE", job.State, err)
	}
	if n := r.posts("start"); n != 0 {
		t.Errorf("POSTs = %d: a removed provider must not dispatch", n)
	}
}

func TestRemovedProviderStillResolvesTheIntentsItAlreadyDispatched(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: pvefake.DropAfter()})
	job, _ := r.run("lxc/200", "start")

	mustf(t, r.reconciler(t).Reconcile(context.Background(), nil, nil), "remove the provider")
	r.reconcileTwice()

	if r.state(job) != domain.JobSucceeded {
		t.Errorf("job = %s, want succeeded: recovery of an existing intent must keep working", r.state(job))
	}
}

// SEC-16: a sync that was already reading when the provider changed must not
// write over the change.
func TestProxmoxSyncInFlightDoesNotResurrectARemovedProvider(t *testing.T) {
	var removeNow func()
	c := newPVECluster(t, func(o *ProxmoxSyncOptions) {
		token := o.Token
		o.Token = func(ctx context.Context, ref string) (audit.Secret, error) {
			if removeNow != nil {
				hook := removeNow
				removeNow = nil
				hook()
			}
			return token(ctx, ref)
		}
	})
	removeNow = func() { mustf(t, c.reconciler(t).Reconcile(context.Background(), nil, nil), "remove the provider") }

	err := c.sync.Sync(context.Background(), c.provider.ID)

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("Sync = %v, want CONFLICT: the provider changed while it was being synced", err)
	}
	if p := c.providerRow(); p.Status != ProviderStatusRemoved {
		t.Errorf("status = %q: the sync resurrected the provider", p.Status)
	}
	if n := len(c.objects()); n != 0 {
		t.Errorf("%d objects written for a removed provider", n)
	}
}

func TestProxmoxSyncInFlightDoesNotApplyAReadMadeWithAnOldConfiguration(t *testing.T) {
	var reconfigure func()
	c := newPVECluster(t, func(o *ProxmoxSyncOptions) {
		token := o.Token
		o.Token = func(ctx context.Context, ref string) (audit.Secret, error) {
			if reconfigure != nil {
				hook := reconfigure
				reconfigure = nil
				hook()
			}
			return token(ctx, ref)
		}
	})
	reconfigure = func() {
		p := c.providerRow()
		p.Config = map[string]any{providerConfigCAFile: p.Config[providerConfigCAFile], providerConfigSyncInterval: "5m0s"}
		c.inTx(func(ctx context.Context, tx *database.Tx) error {
			_, err := database.UpdateProviderSpec(ctx, tx, p, p.SpecRevision)
			return err
		})
	}

	err := c.sync.Sync(context.Background(), c.provider.ID)

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("Sync = %v, want CONFLICT", err)
	}
	if n := len(c.objects()); n != 0 {
		t.Errorf("%d objects written from a read made before the reconfiguration", n)
	}
	c.doSync() // the next sync reads under the new revision
	if n := len(c.objects()); n != 5 {
		t.Errorf("objects after the next sync = %d, want 5", n)
	}
}

// SEC-10: a UPID outside the dispatch window is not recorded as the intent's task.
func TestPowerDoesNotRecordATaskThatStartedOutsideTheDispatchWindow(t *testing.T) {
	r := newPowerRig(t)
	stale := "UPID:pve2:000003E9:000003E9:00000001:vzstart:200:" + pveTokenID + ":"
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: pvefake.Respond(200, `{"data":"`+stale+`"}`)})

	job, err := r.run("lxc/200", "start")

	if !errors.Is(err, jobs.ErrOutcomeUnknown) || job.State != domain.JobInterrupted {
		t.Fatalf("job = %s, err %v; want interrupted: the answer contradicts the dispatch", job.State, err)
	}
	if in := r.intent(job); in.ExternalRef != "" {
		t.Errorf("intent recorded %s", in.ExternalRef)
	}
}

// SEC-18: what PVE says about a failed task is shown, never the token.
func TestPowerEvidenceNeverCarriesTheTokenOrControlSequences(t *testing.T) {
	r := newPowerRig(t, pvefake.WithManualTasks())
	token := r.tokenValue(t)
	r.onSleep = func() {
		r.fake.FinishTask(r.fake.Tasks()[0].UPID, "\x1b[31mfailed\x1b[0m for "+token+strings.Repeat(" z", 200))
	}

	job, _ := r.run("lxc/200", "start")

	in := r.intent(job)
	_, fp := evidenceOf(t, in)
	secret := token[strings.Index(token, "=")+1:]
	if strings.Contains(string(in.Evidence), secret) || strings.ContainsAny(fp.ExitStatus, "\x1b") || !strings.HasPrefix(fp.ExitStatus, "failed for") {
		t.Errorf("fingerprint exit status = %q", fp.ExitStatus)
	}
}
