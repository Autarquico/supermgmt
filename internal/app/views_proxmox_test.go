package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

func (c *pveCluster) inventory() *Inventory {
	c.t.Helper()
	inv, err := NewInventory(c.cfg, InventoryOptions{Store: c.store, Mode: config.ModeLocal})
	mustf(c.t, err, "NewInventory")
	return inv
}

func (c *pveCluster) nodeViews() map[string]wire.Node {
	c.t.Helper()
	page, err := c.inventory().ListNodes(context.Background(), c.caller(c.alice), wire.NodeQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit}})
	mustf(c.t, err, "ListNodes")
	out := map[string]wire.Node{}
	for _, v := range page.Items {
		out[v.Name] = v
	}
	return out
}

func (c *pveCluster) providerView() wire.Provider {
	c.t.Helper()
	providers, err := c.inventory().ListProviders(context.Background(), c.caller(c.alice))
	mustf(c.t, err, "ListProviders")
	for _, p := range providers {
		if p.Name == "pve" {
			return p
		}
	}
	c.t.Fatal("no provider pve")
	return wire.Provider{}
}

func TestNodeViewsCarryTheProxmoxIdentityStatusAndPresenceOfDiscoveredObjects(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()

	views := c.nodeViews()

	web := views["web"].Proxmox
	if web == nil || web.PVENode != "pve1" || web.VMID != 100 || web.Type != "qemu" || web.Status != "running" || web.Absent || web.Inaccessible || web.Template {
		t.Errorf("web = %+v", web)
	}
	if db := views["db"].Proxmox; db == nil || db.Type != "lxc" || db.PVENode != "pve2" || db.Status != "stopped" {
		t.Errorf("db = %+v", db)
	}
	if base := views["base"].Proxmox; base == nil || !base.Template {
		t.Errorf("base = %+v, want a template", base)
	}
	if node := views["pve1"].Proxmox; node == nil || node.Type != "node" || node.VMID != 0 || node.PVENode != "pve1" {
		t.Errorf("pve1 = %+v", node)
	}
}

func TestNodeViewsMarkAGoneGuestAbsentAndWhatTheTokenNoLongerSeesInaccessible(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()
	c.fake.RemoveGuest(200)
	c.clock.Advance(time.Minute)
	c.doSync()

	if db := c.nodeViews()["db"].Proxmox; db == nil || !db.Absent || db.Inaccessible {
		t.Errorf("removed guest = %+v, want absent only", db)
	}

	c.fake.Revoke(pveTokenUser, "/", pveRole)
	c.clock.Advance(time.Minute)
	_ = c.sync.Sync(context.Background(), c.provider.ID)

	if db := c.nodeViews()["db"].Proxmox; db == nil || !db.Absent || db.Inaccessible {
		t.Errorf("removed guest once every right is gone = %+v, want it to stay absent", db)
	}

	for _, path := range []string{"/nodes", "/storage", "/vms/100"} {
		c.fake.Grant(pveTokenUser, path, pveRole, true)
	}
	c.clock.Advance(time.Minute)
	c.doSync()

	views := c.nodeViews()
	if base := views["base"].Proxmox; base == nil || !base.Inaccessible || base.Absent {
		t.Errorf("guest out of the token's sight = %+v, want inaccessible only", base)
	}
	if web := views["web"].Proxmox; web == nil || web.Inaccessible || web.Absent {
		t.Errorf("guest the token still sees = %+v", web)
	}
}

func TestNodeViewsListTheStoragesOfTheirClusterMember(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()

	for name, view := range c.nodeViews() {
		if view.Proxmox == nil {
			continue
		}
		if (view.Proxmox.Type == "node") != (len(view.Proxmox.Storages) > 0) {
			t.Errorf("%s (%s) lists %d storages: only a cluster member has any", name, view.Proxmox.Type, len(view.Proxmox.Storages))
		}
		for _, st := range view.Proxmox.Storages {
			if st.ID == "" || st.TotalBytes <= 0 {
				t.Errorf("%s storage = %+v", name, st)
			}
		}
	}
}

func TestNodeViewsLeaveProxmoxNilForNodesProxmoxDidNotDiscover(t *testing.T) {
	c := newPVECluster(t)

	page, err := c.inventory().ListNodes(context.Background(), c.caller(c.alice), wire.NodeQuery{})

	mustf(t, err, "ListNodes")
	if len(page.Items) == 0 {
		t.Fatal("the fixture has no nodes")
	}
	for _, n := range page.Items {
		if n.Proxmox != nil {
			t.Errorf("node %s has proxmox %+v", n.Name, n.Proxmox)
		}
	}
}

func TestProviderViewsReportWhyTheLatestSyncFailedAndClearItOnRecovery(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()
	if got := c.providerView().LastError; got != "" {
		t.Fatalf("healthy provider last_error = %q", got)
	}

	c.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: "/cluster/resources", Times: 1, Fault: pvefake.Respond(500, `{"data":null,"message":"cluster is on fire\n"}`)})
	c.clock.Advance(time.Minute)
	_ = c.sync.Sync(context.Background(), c.provider.ID)

	if got := c.providerView().LastError; !strings.Contains(got, "cluster is on fire") || strings.Contains(got, "\n") {
		t.Errorf("last_error = %q", got)
	}

	c.clock.Advance(time.Minute)
	c.doSync()
	if got := c.providerView().LastError; got != "" {
		t.Errorf("last_error after recovery = %q", got)
	}
}

func TestSetupViewShowsTheTLSServerNameOfAProxmoxSetup(t *testing.T) {
	meta := runtimes.SetupMeta{SetupVersion: runtimes.SetupVersion, Proxmox: &runtimes.ProxmoxMeta{TLSServerName: "pve.lab.example"}}

	if got := setupView(meta).ProxmoxTLSServerName; got != "pve.lab.example" {
		t.Errorf("tls server name = %q", got)
	}
	if got := setupView(runtimes.SetupMeta{SetupVersion: runtimes.SetupVersion}).ProxmoxTLSServerName; got != "" {
		t.Errorf("a node set up without --proxmox shows %q", got)
	}
}

func TestNodeViewsCarryTheMetricsAClusterSyncRecordedForNodesAndGuests(t *testing.T) {
	c := newPVECluster(t)
	c.doSync()

	views := c.nodeViews()

	for _, name := range []string{"pve1", "web"} {
		m := views[name].Metrics
		if m == nil || m.MemoryTotalBytes <= 0 || m.DiskTotalBytes <= 0 {
			t.Errorf("%s metrics = %+v, want memory and disk from the sync", name, m)
		}
	}
}

func TestNodeViewsLeaveMetricsEmptyForANodeWhoseStatisticsPVEStripped(t *testing.T) {
	c := newPVECluster(t)
	c.fake.Revoke(pveTokenUser, "/", pveRole)
	for _, path := range []string{"/vms", "/storage"} {
		c.fake.Grant(pveTokenUser, path, pveRole, true)
	}
	c.doSync()

	views := c.nodeViews()

	if m := views["pve1"].Metrics; m != nil {
		t.Errorf("pve1 metrics = %+v, want none: the token cannot audit the node", m)
	}
	if m := views["web"].Metrics; m == nil || m.MemoryTotalBytes <= 0 {
		t.Errorf("web metrics = %+v", m)
	}
}
