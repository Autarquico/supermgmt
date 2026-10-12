package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
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
	if web == nil || *web != (wire.ProxmoxGuest{PVENode: "pve1", VMID: 100, Type: "qemu", Status: "running"}) {
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

func TestNodeViewsMarkAGoneGuestAbsentAndEverythingInaccessibleWhenTheACLIsRevoked(t *testing.T) {
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
	c.doSync()

	if web := c.nodeViews()["web"].Proxmox; web == nil || !web.Inaccessible || web.Absent {
		t.Errorf("guest after revocation = %+v, want inaccessible only", web)
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
