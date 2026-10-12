package tui

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	idPVE        domain.ID = "0192a000-0000-7000-8000-00000000e003"
	idPVELab     domain.ID = "0192a000-0000-7000-8000-00000000e004"
	idPVE1       domain.ID = "0192a000-0000-7000-8000-00000000f001"
	idPVE2       domain.ID = "0192a000-0000-7000-8000-00000000f002"
	idGuestWeb   domain.ID = "0192a000-0000-7000-8000-00000000f101"
	idGuestDB    domain.ID = "0192a000-0000-7000-8000-00000000f102"
	idGuestCache domain.ID = "0192a000-0000-7000-8000-00000000f103"
	idGuestBase  domain.ID = "0192a000-0000-7000-8000-00000000f104"
)

// withProxmox adds a two-node cluster to the fixture: web running, db gone
// (absent), cache out of the token's sight (inaccessible) and a template.
func withProxmox(f *fakeAPI) *fakeAPI {
	seen := epoch.Add(-time.Minute)
	guest := func(id domain.ID, name, pveNode string, g wire.ProxmoxGuest) wire.Node {
		g.PVENode = pveNode
		return wire.Node{
			ID: id, Name: name, Kind: "proxmox." + g.Type, Provider: "pve", ManagementState: domain.ManagementDiscovered,
			Reachability: domain.ReachabilityUnknown, LastSeenAt: &seen, Proxmox: &g,
			Capabilities: []wire.Capability{{Name: "proxmox.vm.power", Available: !g.Absent && !g.Inaccessible && !g.Template, CheckedAt: epoch}},
			Metrics:      &wire.Metrics{CPUPercent: 12, MemoryUsedBytes: 1, MemoryTotalBytes: 2, DiskUsedBytes: 3, DiskTotalBytes: 10},
		}
	}
	f.providers = append(f.providers,
		wire.Provider{ID: idPVE, Type: "proxmox", Name: "pve", Origin: domain.ProviderStatic, Status: "ok", LastSyncAt: &seen},
		wire.Provider{ID: idPVELab, Type: "proxmox", Name: "pve-lab", Origin: domain.ProviderStatic, Status: "error", LastSyncAt: &seen, LastError: "cluster is on fire"},
	)
	f.nodes = append(f.nodes,
		guest(idGuestWeb, "web", "pve1", wire.ProxmoxGuest{VMID: 100, Type: "qemu", Status: "running"}),
		guest(idPVE2, "pve2", "pve2", wire.ProxmoxGuest{Type: "node", Status: "online"}),
		guest(idGuestDB, "db", "pve2", wire.ProxmoxGuest{VMID: 200, Type: "lxc", Status: "unknown", Absent: true}),
		guest(idPVE1, "pve1", "pve1", wire.ProxmoxGuest{Type: "node", Status: "online"}),
		guest(idGuestBase, "base", "pve1", wire.ProxmoxGuest{VMID: 300, Type: "qemu", Status: "stopped", Template: true}),
		guest(idGuestCache, "cache", "pve2", wire.ProxmoxGuest{VMID: 210, Type: "lxc", Status: "unknown", Inaccessible: true}),
	)
	f.plan = wire.CreatedPlan{
		PlanID: idPlan, PlanHash: planHash, ExpiresAt: epoch.Add(24 * time.Hour),
		Plan:   []byte(`{"action":"proxmox.vm.power","risk":"high","steps":["Power off the guest at once"],"targets":[{"type":"node","id":"` + string(idGuestWeb) + `"}]}`),
		Policy: wire.Policy{Decision: "allow", ApprovalRequired: true, Quorum: 1},
	}
	return f
}

func TestGoldenProxmoxTree(t *testing.T) {
	screens := []struct {
		name string
		w, h int
		to   func(*harness)
	}{
		{"resources_proxmox_80x24", 80, 24, func(h *harness) { h.press("2"); h.selectNode("web") }},
		{"resources_proxmox_absent_120x30", 120, 30, func(h *harness) { h.press("2"); h.selectNode("db") }},
		{"resources_proxmox_inaccessible_120x30", 120, 30, func(h *harness) { h.press("2"); h.selectNode("cache") }},
		{"resources_proxmox_managed_120x30", 120, 30, func(h *harness) { h.press("2"); h.selectNode("web-1") }},
		{"node_proxmox_80x24", 80, 24, func(h *harness) { h.press("2"); h.selectNode("web"); h.press("enter") }},
		{"providers_proxmox_80x24", 80, 24, func(h *harness) { h.press("6") }},
		{"confirm_power_stop_80x24", 80, 24, func(h *harness) { h.press("/"); h.typeText("power web stop"); h.press("enter") }},
	}
	for _, tc := range screens {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, withProxmox(newFake()), tc.w, tc.h)
			h.start()
			tc.to(h)
			assertGolden(t, tc.name, h.view(), tc.w, tc.h)
		})
	}
}

func TestProxmoxGuestsFollowTheirClusterNodeInVMIDOrder(t *testing.T) {
	h := newHarness(t, withProxmox(newFake()), 80, 24)
	h.start()

	var order []string
	for _, n := range h.m.nodes {
		if n.Provider == "pve" {
			order = append(order, n.Name)
		}
	}

	want := []string{"pve1", "web", "base", "pve2", "db", "cache"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

func TestPowerStopFromThePaletteShowsItsRiskAndApprovalPathAndSubmitsOnlyOnConfirm(t *testing.T) {
	api := withProxmox(newFake())
	h := newHarness(t, api, 100, 28)
	h.start()

	h.press("/")
	h.typeText("power web stop")
	h.press("enter")

	if len(api.submitted) != 0 {
		t.Fatal("power stop submitted before any confirmation")
	}
	req := api.planRequests[0]
	if req.Action != "proxmox.vm.power" || req.Parameters["verb"] != "stop" || len(req.Targets) != 1 || req.Targets[0].ID != idGuestWeb {
		t.Errorf("plan request = %+v", req)
	}
	view := h.view()
	contains(t, view, "Risk: high")
	contains(t, view, "Needs 1 approval(s)")
	contains(t, view, "cuts the guest's power")

	h.press("y")
	if len(api.submitted) != 1 {
		t.Fatalf("submitted = %v, want the plan once", api.submitted)
	}
	contains(t, h.view(), "waiting for approval")
}

func TestPowerRefusesWhatCannotBePoweredBeforeAskingTheDaemon(t *testing.T) {
	tests := []struct{ command, want string }{
		{"power base start", "is a template"},
		{"power db start", "is gone from Proxmox (absent)"},
		{"power cache start", "is inaccessible"},
		{"power pve1 reboot", "is not a Proxmox VM or container"},
		{"power web-1 stop", "is not a Proxmox VM or container"},
		{"power web kill", `unknown power action "kill"`},
		{"power web", "usage: power <node>"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			api := withProxmox(newFake())
			h := newHarness(t, api, 120, 30)
			h.start()

			h.press("/")
			h.typeText(tt.command)
			h.press("enter")

			contains(t, h.view(), tt.want)
			if len(api.planRequests) != 0 {
				t.Errorf("plan requests = %+v, want none", api.planRequests)
			}
		})
	}
}

func TestRefreshProxmoxRefreshesOnlyProxmoxProvidersAndReloadsTheTree(t *testing.T) {
	api := withProxmox(newFake())
	api.refreshOutcome = map[domain.ID]wire.Provider{}
	h := newHarness(t, api, 120, 30)
	h.start()
	before := api.count("ListNodes")

	h.press("/")
	h.typeText("refresh proxmox pve")
	h.press("enter")

	if len(api.refreshed) != 1 || api.refreshed[0] != idPVE {
		t.Errorf("refreshed = %v, want only pve", api.refreshed)
	}
	contains(t, h.view(), "refreshed pve")
	if api.count("ListNodes") <= before {
		t.Error("the tree was not reloaded after the refresh")
	}
}

func TestRefreshProxmoxSaysWhyAClusterCouldNotBeRead(t *testing.T) {
	api := withProxmox(newFake())
	api.refreshOutcome = map[domain.ID]wire.Provider{
		idPVELab: {ID: idPVELab, Type: "proxmox", Name: "pve-lab", Status: "error", LastError: "cluster is on fire"},
	}
	h := newHarness(t, api, 120, 30)
	h.start()

	h.press("/")
	h.typeText("refresh proxmox")
	h.press("enter")

	if len(api.refreshed) != 2 {
		t.Errorf("refreshed = %v, want both Proxmox providers", api.refreshed)
	}
	contains(t, h.view(), "pve-lab: cluster is on fire")
}

func TestRefreshProxmoxWithoutAProxmoxProviderSaysSo(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 120, 30)
	h.start()

	h.press("/")
	h.typeText("refresh proxmox")
	h.press("enter")

	contains(t, h.view(), "no Proxmox provider is configured")
	if len(api.refreshed) != 0 {
		t.Errorf("refreshed = %v", api.refreshed)
	}
}

func TestRefreshProxmoxTimeoutDoesNotWarnAboutAppliedChanges(t *testing.T) {
	api := withProxmox(newFake())
	h := newHarness(t, api, 120, 30)
	h.start()
	api.hook("RefreshProvider", func(ctx context.Context) error { return context.DeadlineExceeded })

	h.press("/")
	h.typeText("refresh proxmox")
	h.press("enter")

	lacks(t, h.view(), "check Jobs")
	if h.m.acting {
		t.Error("the TUI stays locked after a failed refresh")
	}
}

func TestAnUnansweredProxmoxClusterNeverFreezesTheTUI(t *testing.T) {
	api := withProxmox(newFake())
	h := newHarness(t, api, 120, 30)
	h.m.opts.Timeout = 100 * time.Millisecond
	h.start()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	api.hook("RefreshProvider", func(context.Context) error { <-release; return nil })

	h.press("/")
	h.typeText("refresh proxmox pve")
	pending := h.send(keyMsg("enter"))
	go func() { _ = pending() }()

	for range 50 {
		completesWithin(t, 50*time.Millisecond, "a key press while the cluster does not answer", func() {
			_ = h.send(keyMsg("j"))
			_ = h.view()
		})
	}
}
