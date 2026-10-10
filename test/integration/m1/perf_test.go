package m1

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/tui"
)

const (
	perfNodes            = 500
	servicesPerNode      = 10 // 5,000 services in all
	cachedRenderBudget   = 500 * time.Millisecond
	perfKeyBudget        = 50 * time.Millisecond
	servicesBrowsedCount = 25
)

// scaleAPI serves a large fleet from memory. Methods the TUI does not call on
// the screens exercised here are left to the nil embedded interface and would
// panic, which makes an unexpected call loud.
type scaleAPI struct {
	tui.API
	nodes    []wire.Node
	services map[domain.ID][]wire.Service
}

func newScaleAPI() *scaleAPI {
	api := &scaleAPI{services: map[domain.ID][]wire.Service{}}
	now := monotonicNow()
	for i := range perfNodes {
		id := domain.ID(fmt.Sprintf("018f0000-0000-7000-8000-%012d", i+1))
		api.nodes = append(api.nodes, wire.Node{
			ID: id, Name: fmt.Sprintf("node-%03d", i), Kind: "ssh", Provider: "ssh", Environment: "production",
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityReachable,
			Capabilities: []wire.Capability{{Name: "node.ssh", Available: true}},
			Endpoint:     wire.Endpoint{Host: "10.0.0.1", Port: 22, User: "supermgmt", AdminUser: "admin"},
			Metrics:      &wire.Metrics{ObservedAt: now, CPUPercent: 12, MemoryUsedBytes: 1 << 30, MemoryTotalBytes: 4 << 30},
			LastSeenAt:   &now,
		})
		for k := range servicesPerNode {
			api.services[id] = append(api.services[id], wire.Service{
				ID: domain.ID(fmt.Sprintf("018f0001-0000-7000-8000-%06d%06d", i+1, k+1)), NodeID: id, Node: fmt.Sprintf("node-%03d", i),
				RuntimeType: domain.RuntimeSystemd, Kind: domain.ServiceSystemdUnit, NativeID: fmt.Sprintf("svc-%d.service", k),
				Name: fmt.Sprintf("svc-%d.service", k), Status: "active",
			})
		}
	}
	return api
}

func (a *scaleAPI) Me(context.Context) (wire.Me, error) { return wire.Me{DisplayName: "perf"}, nil }

func (a *scaleAPI) ListNodes(context.Context, wire.NodeQuery) (wire.Page[wire.Node], error) {
	return wire.Page[wire.Node]{Items: a.nodes}, nil
}

func (a *scaleAPI) GetNode(_ context.Context, id domain.ID, _ bool) (wire.Node, error) {
	for _, n := range a.nodes {
		if n.ID == id {
			return n, nil
		}
	}
	return wire.Node{}, fmt.Errorf("no node %s", id)
}

func (a *scaleAPI) ListServices(_ context.Context, node domain.ID, _ wire.PageQuery) (wire.Page[wire.Service], error) {
	return wire.Page[wire.Service]{Items: a.services[node]}, nil
}

func (a *scaleAPI) ListApprovals(context.Context, wire.PageQuery) (wire.Page[wire.Approval], error) {
	return wire.Page[wire.Approval]{}, nil
}

func (a *scaleAPI) ListJobs(context.Context, wire.JobQuery) (wire.Page[wire.Job], error) {
	return wire.Page[wire.Job]{}, nil
}

func (a *scaleAPI) ListEvents(context.Context, wire.EventQuery) (wire.Page[wire.Event], error) {
	return wire.Page[wire.Event]{}, nil
}

// Perf (§34): a cached dashboard renders in under 500 ms with 500 nodes and
// 5,000 services, and keys stay under the 50 ms budget at that size. The
// matching refresh bound (500 nodes, goroutines bounded by the worker pool) is
// internal/app.TestARefreshOfFiveHundredNodesKeepsTheProbesInFlightBounded.
func TestM1Perf_CachedDashboardRendersUnderBudgetAtFiveHundredNodes(t *testing.T) {
	api := newScaleAPI()
	d := newTUI(t, api, 160, 50)
	if !d.screenHas("500 nodes") {
		t.Fatalf("the dashboard does not count the 500 nodes:\n%s", d.screen())
	}

	render := func(what string) {
		t.Helper()
		start := monotonicNow()
		_ = d.m.View()
		if took := time.Since(start); took >= cachedRenderBudget {
			t.Errorf("rendering %s took %s, want < %s", what, took, cachedRenderBudget)
		}
	}
	render("the dashboard")

	d.press("2")
	render("the 500-node resource tree")

	for i := range servicesBrowsedCount { // walk services so the cache holds a share of the 5,000
		d.press("enter")
		d.press("v")
		render(fmt.Sprintf("the services of node %d", i))
		d.press("esc")
		d.press("esc")
		d.press("down")
	}

	d.press("1")
	render("the dashboard again, services cached")
	for _, key := range []string{"2", "down", "up", "enter", "esc", "3", "4", "5", "1"} {
		if took := d.pressTimed(key); took >= perfKeyBudget {
			t.Errorf("key %q took %s with 500 nodes loaded, want < %s", key, took, perfKeyBudget)
		}
	}
}
