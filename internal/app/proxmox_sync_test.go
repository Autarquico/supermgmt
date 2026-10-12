package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
)

const (
	pveTokenRef  = "secret://providers/pve/token"
	pveRole      = "SMDiscovery"
	pveTokenUser = "sm@pve"
)

// pveCluster is a two-node fake PVE cluster, a provider configured for it and
// a ProxmoxSync that reaches it.
type pveCluster struct {
	*fixture
	fake     *pvefake.Fake
	token    string
	provider domain.Provider
	sync     *ProxmoxSync
}

func newPVECluster(t *testing.T, tweak ...func(*ProxmoxSyncOptions)) *pveCluster {
	t.Helper()
	f := newFixture(t)
	fake := pvefake.New(t)
	fake.AddNode("pve1")
	fake.AddNode("pve2")
	fake.AddGuest(pvefake.Guest{
		Node: "pve1", Type: "qemu", VMID: 100, Name: "web", Status: "running",
		MaxCPU: 2, MaxMem: 2 << 30, MaxDisk: 16 << 30, CPU: 0.25, Mem: 1 << 30, Disk: 4 << 30, Uptime: 3600, Pool: "prod",
	})
	fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "db", Status: "stopped", MaxCPU: 1, MaxMem: 1 << 30, MaxDisk: 8 << 30})
	fake.AddGuest(pvefake.Guest{Node: "pve1", Type: "qemu", VMID: 300, Name: "base", Template: true, MaxDisk: 8 << 30})
	fake.AddStorage(pvefake.Storage{ID: "local", Node: "pve1", Plugin: "dir", Content: []string{"iso", "vztmpl"}, Total: 100 << 30, Used: 10 << 30})
	fake.AddStorage(pvefake.Storage{ID: "ceph", Node: "pve2", Plugin: "rbd", Content: []string{"images"}, Total: 500 << 30, Used: 50 << 30, Shared: true})
	fake.SetRole(pveRole, "VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit", "VM.PowerMgmt")
	token := fake.AddToken(pveTokenUser, "sm", false)
	fake.Grant(pveTokenUser, "/", pveRole, true)

	caFile := filepath.Join(t.TempDir(), "pve-root-ca.pem")
	if err := os.WriteFile(caFile, fake.CAPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	pve := config.Provider{Proxmox: &config.ProxmoxProvider{
		Type: "proxmox", Name: "pve", Endpoint: fake.Endpoint(), CredentialRef: pveTokenRef,
		VerifyTLS: true, CAFile: caFile, SyncInterval: 30 * time.Second,
	}}
	mustf(t, f.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{pve}), "configure the provider")

	c := &pveCluster{fixture: f, fake: fake, token: token}
	opts := ProxmoxSyncOptions{
		Token: func(_ context.Context, ref string) (audit.Secret, error) {
			if ref != pveTokenRef {
				return "", errors.New("unexpected credential reference " + ref)
			}
			return audit.Secret(c.token), nil
		},
		Client: []proxmox.Option{proxmox.WithHTTPTimeout(2 * time.Second), proxmox.WithNetguardOptions(netguard.WithTestDialer(fake.Dial))},
	}
	for _, fn := range tweak {
		fn(&opts)
	}
	var err error
	c.sync, err = NewProxmoxSync(f.cfg, opts)
	mustf(t, err, "NewProxmoxSync")
	c.provider = c.providerRow()
	return c
}

func (c *pveCluster) providerRow() domain.Provider {
	c.t.Helper()
	providers, err := database.ListProviders(context.Background(), c.db.Reader())
	mustf(c.t, err, "ListProviders")
	for _, p := range providers {
		if p.Name == "pve" {
			return p
		}
	}
	c.t.Fatal("no provider named pve")
	return domain.Provider{}
}

func (c *pveCluster) doSync() {
	c.t.Helper()
	mustf(c.t, c.sync.Sync(context.Background(), c.provider.ID), "Sync")
}

// objects are the discovered nodes of the provider by native id.
func (c *pveCluster) objects() map[string]domain.Node {
	c.t.Helper()
	out := map[string]domain.Node{}
	for _, n := range mustNodes(c.t, c.fixture) {
		if n.ProviderID == c.provider.ID {
			out[n.NativeID] = n
		}
	}
	return out
}

func (c *pveCluster) object(native string) domain.Node {
	c.t.Helper()
	n, ok := c.objects()[native]
	if !ok {
		c.t.Fatalf("no discovered object %s", native)
	}
	return n
}

func (c *pveCluster) status(native string) ProxmoxStatus {
	c.t.Helper()
	o, err := database.LatestObservation(context.Background(), c.db.Reader(), nodeRef(c.object(native).ID), proxmox.ObservationStatus)
	mustf(c.t, err, "status observation of %s", native)
	var status ProxmoxStatus
	mustf(c.t, decodeObservation(o, &status), "decode status")
	return status
}

func (c *pveCluster) canPower(native string) bool {
	c.t.Helper()
	caps, err := database.ListNodeCapabilities(context.Background(), c.db.Reader(), c.object(native).ID)
	mustf(c.t, err, "capabilities of %s", native)
	for _, k := range caps {
		if k.Capability == CapabilityVMPower {
			return k.Available
		}
	}
	return false
}

func TestProxmoxSyncDiscoversTheClusterAsATreeWithMetricsAndStorages(t *testing.T) {
	c := newPVECluster(t)

	c.doSync()

	objects := c.objects()
	for native, kind := range map[string]string{
		"node/pve1": proxmox.KindNode, "node/pve2": proxmox.KindNode,
		"qemu/100": proxmox.KindQEMU, "lxc/200": proxmox.KindLXC, "qemu/300": proxmox.KindQEMU,
	} {
		n, ok := objects[native]
		if !ok || n.Kind != kind || n.ManagementState != domain.ManagementDiscovered || n.Reachability != domain.ReachabilityUnknown {
			t.Errorf("%s = %+v, want a discovered %s with unknown reachability", native, n, kind)
		}
	}
	if len(objects) != 5 {
		t.Errorf("discovered %d objects, want 5", len(objects))
	}
	web := c.object("qemu/100")
	if web.Name != "web" || web.Metadata["pve_node"] != "pve1" || web.Metadata["vmid"] != float64(100) || web.Metadata["type"] != "qemu" ||
		web.Metadata["maxcpu"] != float64(2) || web.Metadata["maxmem"] != float64(2<<30) || web.Metadata["maxdisk"] != float64(16<<30) ||
		web.Metadata["template"] != false || web.Metadata["pool"] != "prod" || web.LastSeenAt == nil {
		t.Errorf("web = %+v", web)
	}
	if got := c.object("qemu/300").Metadata["template"]; got != true {
		t.Errorf("template metadata = %v, want true", got)
	}

	o, err := database.LatestObservation(context.Background(), c.db.Reader(), nodeRef(web.ID), observationMetrics)
	mustf(t, err, "metrics observation")
	var m wire.Metrics
	mustf(t, decodeObservation(o, &m), "decode metrics")
	if m.CPUPercent != 25 || m.MemoryUsedBytes != 1<<30 || m.MemoryTotalBytes != 2<<30 || m.DiskUsedBytes != 4<<30 ||
		m.DiskTotalBytes != 16<<30 || m.UptimeSeconds != 3600 || !m.ObservedAt.Equal(c.clock.Now()) {
		t.Errorf("metrics = %+v", m)
	}
	if got := c.status("qemu/100"); got != (ProxmoxStatus{Status: "running", Presence: PresencePresent}) {
		t.Errorf("web status = %+v", got)
	}
	if got := c.status("lxc/200"); got.Status != "stopped" {
		t.Errorf("db status = %+v, want stopped", got)
	}

	storages, err := database.LatestObservation(context.Background(), c.db.Reader(), providerRef(c.provider.ID), proxmox.ObservationStorage)
	mustf(t, err, "storage observation")
	var seen struct{ Storages []StorageObservation }
	mustf(t, decodeObservation(storages, &seen), "decode storages")
	if len(seen.Storages) != 2 {
		t.Fatalf("storages = %+v, want local and ceph", seen.Storages)
	}
	for _, s := range seen.Storages {
		if s.ID == "ceph" && (s.Node != "pve2" || s.Plugin != "rbd" || !s.Shared || s.Total != 500<<30 || s.Used != 50<<30 || len(s.Content) != 1) {
			t.Errorf("ceph = %+v", s)
		}
	}

	if !c.canPower("qemu/100") || !c.canPower("lxc/200") {
		t.Error("guests the token may power-manage do not advertise proxmox.vm.power")
	}
	if c.canPower("qemu/300") {
		t.Error("a template advertises proxmox.vm.power")
	}
	if _, advertised := capabilityOf(t, c, "node/pve1", CapabilityVMPower); advertised {
		t.Error("a cluster node advertises the guest power capability")
	}

	p := c.providerRow()
	if p.Status != ProviderStatusOK || p.LastSyncAt == nil || !p.LastSyncAt.Equal(c.clock.Now()) {
		t.Errorf("provider = status %q, last sync %v", p.Status, p.LastSyncAt)
	}
	if p.SpecRevision != c.provider.SpecRevision {
		t.Errorf("discovery changed the provider's spec_revision: %d -> %d", c.provider.SpecRevision, p.SpecRevision)
	}
}

func capabilityOf(t *testing.T, c *pveCluster, native, name string) (database.NodeCapability, bool) {
	t.Helper()
	caps, err := database.ListNodeCapabilities(context.Background(), c.db.Reader(), c.object(native).ID)
	mustf(t, err, "capabilities")
	for _, k := range caps {
		if k.Capability == name {
			return k, true
		}
	}
	return database.NodeCapability{}, false
}

func TestProxmoxSyncIsIdempotentAndAuditsEachDiscoveryOnce(t *testing.T) {
	c := newPVECluster(t)

	c.doSync()
	before := c.objects()
	c.clock.Advance(time.Minute)
	c.doSync()

	after := c.objects()
	if len(after) != len(before) {
		t.Fatalf("%d objects after the second sync, %d before", len(after), len(before))
	}
	for native, n := range before {
		if after[native].ID != n.ID || after[native].SpecRevision != n.SpecRevision {
			t.Errorf("%s changed identity or revision on a repeat: %+v -> %+v", native, n, after[native])
		}
	}
	if added := len(c.events(actionNodeAdd)); added != 5 {
		t.Errorf("node.add events = %d, want one per discovered object (5)", added)
	}
	if transitions := c.events(eventProviderSync); len(transitions) != 1 || transitions[0].Result != domain.ResultSucceeded {
		t.Errorf("provider.sync events = %+v, want the single first-sync transition", transitions)
	}
}

func TestProxmoxSyncAMigratedGuestKeepsItsRowAndMovesToTheNewPVENode(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()
	before := c.object("qemu/100")

	c.fake.MigrateGuest(100, "pve2")
	c.clock.Advance(time.Minute)
	c.doSync()

	after := c.object("qemu/100")
	if after.ID != before.ID || after.SpecRevision != before.SpecRevision {
		t.Errorf("migration changed the row: %+v -> %+v", before, after)
	}
	if after.Metadata["pve_node"] != "pve2" {
		t.Errorf("pve_node = %v, want pve2", after.Metadata["pve_node"])
	}
	if len(c.objects()) != 5 {
		t.Errorf("objects = %d, want 5 (no duplicate for the moved guest)", len(c.objects()))
	}
}

func TestProxmoxSyncARenamedGuestIsAChangeOfPolicyTarget(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()
	before := c.object("lxc/200")

	c.fake.RemoveGuest(200)
	c.fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "database", Status: "stopped"})
	c.doSync()

	after := c.object("lxc/200")
	if after.ID != before.ID || after.Name != "database" || after.SpecRevision != before.SpecRevision+1 {
		t.Errorf("after a rename: %+v (before %+v), want the same row, new name, spec_revision+1", after, before)
	}
	if updates := c.events(actionNodeUpdate); len(updates) != 1 {
		t.Errorf("node.update events = %d, want 1", len(updates))
	}
}

func TestProxmoxSyncAGuestThatIsGoneIsAbsentWhenTheTokenStillSeesItsPath(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()

	c.fake.RemoveGuest(200)
	c.clock.Advance(time.Minute)
	c.doSync()

	if got := c.status("lxc/200"); got.Presence != PresenceAbsent {
		t.Errorf("removed guest presence = %q, want absent", got.Presence)
	}
	if c.canPower("lxc/200") {
		t.Error("an absent guest still advertises proxmox.vm.power")
	}
	if got := c.status("qemu/100"); got.Presence != PresencePresent {
		t.Errorf("a guest that is still there is %q", got.Presence)
	}
	if _, kept := c.objects()["lxc/200"]; !kept {
		t.Error("the row of an absent guest was deleted")
	}
}

func TestProxmoxSyncARevokedACLMakesEverythingInaccessibleKeepsTheRowsAndDropsCapabilities(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()
	if !c.canPower("qemu/100") {
		t.Fatal("precondition: web is power-managed")
	}

	c.fake.Revoke(pveTokenUser, "/", pveRole)
	c.clock.Advance(time.Minute)
	c.doSync()

	if len(c.objects()) != 5 {
		t.Errorf("objects after revocation = %d, want all 5 rows kept", len(c.objects()))
	}
	for _, native := range []string{"node/pve1", "node/pve2", "qemu/100", "lxc/200", "qemu/300"} {
		if got := c.status(native); got.Presence != PresenceInaccessible {
			t.Errorf("%s presence = %q, want inaccessible (never absent: the token cannot tell)", native, got.Presence)
		}
	}
	if c.canPower("qemu/100") || c.canPower("lxc/200") {
		t.Error("capability proxmox.vm.power survived the loss of the permission")
	}
	if p := c.providerRow(); p.Status != ProviderStatusOK {
		t.Errorf("provider status = %q: the sync itself worked", p.Status)
	}

	c.fake.Grant(pveTokenUser, "/", pveRole, true)
	c.clock.Advance(time.Minute)
	c.doSync()
	if got := c.status("qemu/100"); got.Presence != PresencePresent || !c.canPower("qemu/100") {
		t.Errorf("after the ACL came back: %+v, can power %v", got, c.canPower("qemu/100"))
	}
}

func TestProxmoxSyncAGuestOutsideTheTokensPathsIsInaccessibleNotAbsent(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()

	c.fake.Revoke(pveTokenUser, "/", pveRole)
	for _, path := range []string{"/nodes", "/storage", "/vms/100"} {
		c.fake.Grant(pveTokenUser, path, pveRole, true)
	}
	c.clock.Advance(time.Minute)
	c.doSync()

	if got := c.status("qemu/100"); got.Presence != PresencePresent {
		t.Errorf("web, which the token still sees: %q", got.Presence)
	}
	if got := c.status("lxc/200"); got.Presence != PresenceInaccessible {
		t.Errorf("db, out of the token's sight: %q, want inaccessible", got.Presence)
	}
	if c.canPower("lxc/200") {
		t.Error("an inaccessible guest still advertises proxmox.vm.power")
	}
}

func TestProxmoxSyncAFailedReadIsRecordedAuditedOnTransitionsAndKeepsTheLastSync(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()
	synced := *c.providerRow().LastSyncAt

	c.fake.Inject(pvefake.Rule{
		Method: "GET", PathSuffix: "/cluster/resources", Times: 2,
		Fault: pvefake.Respond(500, `{"data":null,"message":"cluster is on fire\n"}`),
	})
	c.clock.Advance(time.Minute)
	first := c.sync.Sync(context.Background(), c.provider.ID)
	c.clock.Advance(time.Minute)
	second := c.sync.Sync(context.Background(), c.provider.ID)

	var failure *SyncFailure
	if !errors.As(first, &failure) || !errors.As(second, &failure) {
		t.Fatalf("Sync = %v, %v; want *SyncFailure both times", first, second)
	}
	p := c.providerRow()
	if p.Status != ProviderStatusError || p.LastSyncAt == nil || !p.LastSyncAt.Equal(synced) {
		t.Errorf("provider = status %q, last sync %v; want error with the last good sync %v", p.Status, p.LastSyncAt, synced)
	}
	report, ok := LatestSyncReport(context.Background(), c.db.Reader(), c.provider.ID)
	if !ok || report.OK || !strings.Contains(report.Error, "cluster is on fire") {
		t.Errorf("report = %+v", report)
	}
	if got := c.status("qemu/100"); got.Presence != PresencePresent {
		t.Errorf("a failed read changed what is known about a guest: %+v", got)
	}
	transitions := c.events(eventProviderSync)
	if len(transitions) != 2 || transitions[1].Result != domain.ResultFailed {
		t.Errorf("provider.sync events = %d (%+v), want the first sync and one failure, not one per attempt", len(transitions), transitions)
	}

	c.clock.Advance(time.Minute)
	c.doSync()
	if c.providerRow().Status != ProviderStatusOK || len(c.events(eventProviderSync)) != 3 {
		t.Errorf("recovery was not recorded: status %q, %d events", c.providerRow().Status, len(c.events(eventProviderSync)))
	}
}

func TestProxmoxSyncAMissingTokenIsARecordedFailureWithoutContactingTheCluster(t *testing.T) {
	c := newPVECluster(t, func(o *ProxmoxSyncOptions) {
		o.Token = func(context.Context, string) (audit.Secret, error) {
			return "", errors.New("load secret providers/pve/token: not found")
		}
	})

	err := c.sync.Sync(context.Background(), c.provider.ID)

	var failure *SyncFailure
	if !errors.As(err, &failure) {
		t.Fatalf("Sync = %v, want *SyncFailure", err)
	}
	report, _ := LatestSyncReport(context.Background(), c.db.Reader(), c.provider.ID)
	if !strings.Contains(report.Error, "API token is unavailable") {
		t.Errorf("report error = %q", report.Error)
	}
	if c.fake.Count("GET", "/cluster/resources") != 0 {
		t.Error("the cluster was contacted without a token")
	}
}

func TestProxmoxSyncAWrongTokenNeverAppearsInTheRecordedError(t *testing.T) {
	c := newPVECluster(t)
	c.token = pveTokenUser + "!sm=0123456789abcdef-not-the-secret"

	err := c.sync.Sync(context.Background(), c.provider.ID)

	var failure *SyncFailure
	if !errors.As(err, &failure) {
		t.Fatalf("Sync = %v, want *SyncFailure", err)
	}
	report, _ := LatestSyncReport(context.Background(), c.db.Reader(), c.provider.ID)
	if strings.Contains(report.Error, "0123456789abcdef") || strings.Contains(failure.Error(), "0123456789abcdef") {
		t.Errorf("the token secret leaked: %q", report.Error)
	}
}

func TestProxmoxSyncRunsOneSyncPerProviderAtATimeAndSharesItsOutcome(t *testing.T) {
	c := newPVECluster(t, func(o *ProxmoxSyncOptions) {
		o.Client = append(o.Client, proxmox.WithHTTPTimeout(400*time.Millisecond))
	})
	c.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: "/cluster/resources", Fault: pvefake.Hang()})

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Go(func() { errs[0] = c.sync.Sync(context.Background(), c.provider.ID) })
	waitFor(t, "the first read to reach the cluster", func() bool { return c.fake.Count("GET", "/cluster/resources") == 1 })
	wg.Go(func() { errs[1] = c.sync.Sync(context.Background(), c.provider.ID) })
	wg.Wait()

	var failure *SyncFailure
	if !errors.As(errs[0], &failure) || !errors.As(errs[1], &failure) {
		t.Fatalf("outcomes = %v, %v; want both to share the failed run", errs[0], errs[1])
	}
	if reads := c.fake.Count("GET", "/cluster/resources"); reads != 1 {
		t.Errorf("the cluster was read %d times, want exactly 1", reads)
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for !done() {
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestProxmoxSyncRunSyncsEveryIntervalAndStopsWithItsContext(t *testing.T) {
	c := newPVECluster(t, func(o *ProxmoxSyncOptions) { o.Tick = 5 * time.Millisecond })
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = c.sync.Run(ctx) }()

	waitFor(t, "the first sync", func() bool { return c.fake.Count("GET", "/cluster/resources") == 1 })
	time.Sleep(50 * time.Millisecond)
	if reads := c.fake.Count("GET", "/cluster/resources"); reads != 1 {
		t.Errorf("%d reads before the interval passed, want 1", reads)
	}
	// The first sync may still be recording its finish time when the clock
	// moves, so keep moving it past one interval until the next sync runs.
	waitFor(t, "the sync after the interval", func() bool {
		if c.fake.Count("GET", "/cluster/resources") >= 2 {
			return true
		}
		c.clock.Advance(31 * time.Second)
		return false
	})

	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

func TestProxmoxSyncSkipsAProviderRemovedFromTheFileButKeepsWhatItFound(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()

	mustf(t, c.reconciler(t).Reconcile(context.Background(), nil, nil), "remove the provider from the file")

	if p := c.providerRow(); p.Status != ProviderStatusRemoved {
		t.Errorf("status = %q, want removed", p.Status)
	}
	wantError(t, c.sync.Sync(context.Background(), c.provider.ID), smerr.CodeInvalidArgument, "")
	if len(c.objects()) != 5 {
		t.Errorf("objects = %d: removing a provider must not delete what it discovered", len(c.objects()))
	}
	reads := c.fake.Count("GET", "/cluster/resources")
	mustf(t, c.sync.pass(context.Background()), "pass")
	c.sync.Wait()
	if c.fake.Count("GET", "/cluster/resources") != reads {
		t.Error("a removed provider was synced")
	}
}

func TestProxmoxRefreshSyncsOnDemandForACallerWhoMayReadProviders(t *testing.T) {
	c := newPVECluster(t)

	view, err := c.sync.Refresh(context.Background(), c.caller(c.alice), c.provider.ID)

	mustf(t, err, "Refresh")
	if view.Name != "pve" || view.Status != ProviderStatusOK || view.LastSyncAt == nil {
		t.Errorf("view = %+v", view)
	}
	if len(c.objects()) != 5 {
		t.Errorf("objects = %d, want the cluster discovered", len(c.objects()))
	}
}

func TestProxmoxRefreshAnswersWithTheProviderEvenWhenTheClusterCannotBeRead(t *testing.T) {
	c := newPVECluster(t)
	c.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: "/cluster/resources", Fault: pvefake.Respond(500, `{"message":"down\n"}`)})

	view, err := c.sync.Refresh(context.Background(), c.caller(c.alice), c.provider.ID)

	mustf(t, err, "Refresh")
	if view.Status != ProviderStatusError {
		t.Errorf("status = %q, want error", view.Status)
	}
}

func TestProxmoxRefreshRefusesACallerWithoutProviderReadAndDoesNotContactTheCluster(t *testing.T) {
	c := newPVECluster(t)

	_, err := c.sync.Refresh(context.Background(), c.caller(c.dave), c.provider.ID)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if c.fake.Count("GET", "/cluster/resources") != 0 {
		t.Error("an unauthorized refresh reached the cluster")
	}
	if denials := c.events("policy.deny"); len(denials) != 1 {
		t.Errorf("denial events = %d, want the refusal audited", len(denials))
	}
}

func TestProxmoxRefreshRefusesAProviderThatIsNotProxmoxAndAnUnknownOne(t *testing.T) {
	c := newPVECluster(t)

	_, notPVE := c.sync.Refresh(context.Background(), c.caller(c.alice), c.fixture.provider.ID)
	_, unknown := c.sync.Refresh(context.Background(), c.caller(c.alice), c.ids.NewID())

	wantError(t, notPVE, smerr.CodeInvalidArgument, "")
	if smerr.CodeOf(unknown) != smerr.CodeNotFound {
		t.Errorf("unknown provider: %v, want NOT_FOUND", unknown)
	}
}
