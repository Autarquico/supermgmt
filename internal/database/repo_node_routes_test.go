package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func nodeRouteOf(f *fixture, node domain.Node, by domain.ID, hostname string) NodeRoute {
	return NodeRoute{
		ID: f.ids.NewID(), NodeID: node.ID, Hostname: hostname, Port: 8080,
		Access: "public", AccountID: "acct", Zone: "example.com", InstanceID: "inst", TunnelID: "tun", TunnelGeneration: 1,
		CreatedBy: by, CreatedAt: testEpoch,
	}
}

func nodeRouteWorld(ctx context.Context, f *fixture, q Querier) (domain.Node, domain.ID) {
	node := f.node(ctx, q, f.provider(ctx, q, "routes"), "n1")
	return node, f.identity(ctx, q, domain.ActorHuman, "alice").ID
}

func TestNodeRouteLifecycle(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		r := must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "app.example.com")))
		if r.Phase != NodeRouteProvisioning || r.Port != 8080 || r.TunnelGeneration != 1 || !r.PhaseStartedAt.Equal(testEpoch) {
			t.Fatalf("inserted = %+v", r)
		}
		later := testEpoch.Add(time.Minute)
		r = must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteProvisioning, NodeRouteIngressReady, NodeRouteObjects{DNSRecordID: "dns"}, later))
		r = must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteIngressReady, NodeRouteAccessReady, NodeRouteObjects{AccessAppID: "app"}, later))
		r = must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteAccessReady, NodeRouteActive, NodeRouteObjects{}, later))
		if r.Objects != (NodeRouteObjects{DNSRecordID: "dns", AccessAppID: "app"}) || !r.PhaseStartedAt.Equal(later) {
			t.Fatalf("active = %+v", r)
		}
		if got := must(GetLiveNodeRouteByHostname(ctx, q, "app.example.com")); got.ID != r.ID {
			t.Fatalf("by hostname = %s", got.ID)
		}

		r = must(MarkNodeRouteRemoving(ctx, q, r.ID, NodeRouteActive, later))
		r = must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteRemoving, NodeRouteDNSRemoved, NodeRouteObjects{}, later))
		r = must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteDNSRemoved, NodeRouteIngressRemoved, NodeRouteObjects{}, later))
		r = must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteIngressRemoved, NodeRouteRemoved, NodeRouteObjects{}, later))
		_, err := GetLiveNodeRouteByHostname(ctx, q, "app.example.com")
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteRemoved, NodeRouteProvisioning, NodeRouteObjects{}, later)
		if err == nil || !strings.Contains(err.Error(), "does not change phase") {
			t.Fatalf("a removed route moved: %v", err)
		}
		_, err = MarkNodeRouteRemoving(ctx, q, r.ID, NodeRouteRemoved, later)
		wantError(t, err, smerr.CodeInvalidArgument, "")
	})
}

func TestNodeRouteAdvanceIsFencedOnPhase(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		r := must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "app.example.com")))
		_, err := AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteIngressReady, NodeRouteAccessReady, NodeRouteObjects{}, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		var e *smerr.Error
		if !errors.As(err, &e) || e.Details["current_phase"] != "provisioning" || e.Details["expected_phase"] != "ingress_ready" {
			t.Fatalf("conflict details = %v", err)
		}
		_, err = AdvanceNodeRoutePhase(ctx, q, "missing", NodeRouteProvisioning, NodeRouteProvisioning, NodeRouteObjects{}, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestNodeRouteHaltAndResumeKeepPhaseStart(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		r := must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "app.example.com")))
		started := testEpoch.Add(time.Minute)
		r = must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteProvisioning, NodeRouteIngressReady, NodeRouteObjects{}, started))
		r = must(HaltNodeRoute(ctx, q, r.ID, NodeRouteIngressReady, NodeRouteConflict, "dns record owned by another", started.Add(time.Minute)))
		if r.Phase != NodeRouteConflict || r.HaltedPhase != NodeRouteIngressReady || r.LastError == "" {
			t.Fatalf("halted = %+v", r)
		}
		if got := must(CountLiveNodeRoutesByNode(ctx, q, r.NodeID)); got != 1 {
			t.Fatalf("a halted route must stay live, count = %d", got)
		}
		_, err := HaltNodeRoute(ctx, q, r.ID, NodeRouteConflict, NodeRouteFailed, "x", started)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		_, err = ResumeHaltedNodeRoute(ctx, q, r.ID, NodeRouteFailed, started)
		wantError(t, err, smerr.CodeConflict, "")

		r = must(ResumeHaltedNodeRoute(ctx, q, r.ID, NodeRouteConflict, started.Add(time.Hour)))
		if r.Phase != NodeRouteIngressReady || r.HaltedPhase != "" || r.LastError != "" || !r.PhaseStartedAt.Equal(started) {
			t.Fatalf("resumed = %+v", r)
		}
		r = must(HaltNodeRoute(ctx, q, r.ID, NodeRouteIngressReady, NodeRouteFailed, "boom", started))
		r = must(MarkNodeRouteRemoving(ctx, q, r.ID, NodeRouteFailed, started))
		if r.Phase != NodeRouteRemoving || r.HaltedPhase != "" {
			t.Fatalf("removing a halted route = %+v", r)
		}
	})
}

func TestNodeRouteHostnameIsUniqueAmongLiveRoutes(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		first := must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "app.example.com")))
		_, err := InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "app.example.com"))
		wantError(t, err, smerr.CodeConflict, "")

		must(MarkNodeRouteRemoving(ctx, q, first.ID, NodeRouteProvisioning, testEpoch))
		for _, p := range [][2]NodeRoutePhase{{NodeRouteRemoving, NodeRouteDNSRemoved}, {NodeRouteDNSRemoved, NodeRouteIngressRemoved}, {NodeRouteIngressRemoved, NodeRouteRemoved}} {
			must(AdvanceNodeRoutePhase(ctx, q, first.ID, p[0], p[1], NodeRouteObjects{}, testEpoch))
		}
		second := must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "app.example.com")))

		all := must(ListNodeRoutes(ctx, q, NodeRouteFilter{NodeID: node.ID, IncludeRemoved: true}))
		live := must(ListNodeRoutes(ctx, q, NodeRouteFilter{NodeID: node.ID}))
		if len(all) != 2 || len(live) != 1 || live[0].ID != second.ID {
			t.Fatalf("all = %d, live = %+v", len(all), live)
		}
		if got := must(ListNodeRoutes(ctx, q, NodeRouteFilter{NodeID: "other"})); len(got) != 0 {
			t.Fatalf("other node = %d", len(got))
		}
	})
}

func TestNodeRouteRejectsInvalidRows(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		for name, mutate := range map[string]func(*NodeRoute){
			"uppercase hostname": func(r *NodeRoute) { r.Hostname = "App.example.com" },
			"port zero":          func(r *NodeRoute) { r.Port = 0 },
			"port too high":      func(r *NodeRoute) { r.Port = 65536 },
			"unknown access":     func(r *NodeRoute) { r.Access = "everyone" },
			"empty tunnel":       func(r *NodeRoute) { r.TunnelID = "" },
			"zero generation":    func(r *NodeRoute) { r.TunnelGeneration = 0 },
			"unknown node":       func(r *NodeRoute) { r.NodeID = "missing" },
		} {
			r := nodeRouteOf(f, node, by, "app.example.com")
			mutate(&r)
			sp := "SAVEPOINT " + strings.ReplaceAll(name, " ", "_")
			if _, err := q.ExecContext(ctx, sp); err != nil {
				t.Fatal(err)
			}
			if _, err := InsertNodeRoute(ctx, q, r); err == nil {
				t.Errorf("%s: accepted", name)
			}
			if _, err := q.ExecContext(ctx, "ROLLBACK TO "+sp); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestNodeRouteIdentityAndObjectIDsAreWriteOnce(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		r := must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "app.example.com")))
		must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteProvisioning, NodeRouteIngressReady, NodeRouteObjects{DNSRecordID: "dns"}, testEpoch))

		_, err := AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteIngressReady, NodeRouteAccessReady, NodeRouteObjects{DNSRecordID: "other"}, testEpoch)
		if err == nil || !strings.Contains(err.Error(), "recorded object IDs") {
			t.Fatalf("a recorded DNS record ID changed: %v", err)
		}
		// the same ID again, or an empty one, is not a change
		must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteIngressReady, NodeRouteAccessReady, NodeRouteObjects{DNSRecordID: "dns"}, testEpoch))
		must(AdvanceNodeRoutePhase(ctx, q, r.ID, NodeRouteAccessReady, NodeRouteActive, NodeRouteObjects{}, testEpoch))

		for _, col := range []string{
			"hostname = 'x.example.com'", "port = 9", "access = 'owners'", "account_id = 'x'", "zone = 'x'",
			"instance_id = 'x'", "tunnel_id = 'x'", "tunnel_generation = 2", "node_id = 'x'",
		} {
			if _, err := q.ExecContext(ctx, `UPDATE app_routes SET `+col+` WHERE id = ?`, r.ID); err == nil {
				t.Errorf("UPDATE %s succeeded, want the identity to be frozen", col)
			}
		}
	})
}

func TestNodeRoutePortIsUniqueAmongLiveRoutesOfANode(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "a.example.com")))
		_, err := InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "b.example.com"))
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestGetLiveNodeRouteByNodePort(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node, by := nodeRouteWorld(ctx, f, q)
		_, err := GetLiveNodeRouteByNodePort(ctx, q, node.ID, 8080)
		wantError(t, err, smerr.CodeNotFound, "")

		route := must(InsertNodeRoute(ctx, q, nodeRouteOf(f, node, by, "a.example.com")))
		if got := must(GetLiveNodeRouteByNodePort(ctx, q, node.ID, 8080)); got.ID != route.ID {
			t.Fatalf("live route = %s, want %s", got.ID, route.ID)
		}
		_, err = GetLiveNodeRouteByNodePort(ctx, q, node.ID, 9090)
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = GetLiveNodeRouteByNodePort(ctx, q, "other", 8080)
		wantError(t, err, smerr.CodeNotFound, "")

		must(HaltNodeRoute(ctx, q, route.ID, NodeRouteProvisioning, NodeRouteConflict, "boom", testEpoch))
		if got := must(GetLiveNodeRouteByNodePort(ctx, q, node.ID, 8080)); got.ID != route.ID {
			t.Fatalf("a halted route must stay live, got %s", got.ID)
		}

		must(ResumeHaltedNodeRoute(ctx, q, route.ID, NodeRouteConflict, testEpoch))
		must(MarkNodeRouteRemoving(ctx, q, route.ID, NodeRouteProvisioning, testEpoch))
		for _, p := range [][2]NodeRoutePhase{{NodeRouteRemoving, NodeRouteDNSRemoved}, {NodeRouteDNSRemoved, NodeRouteIngressRemoved}, {NodeRouteIngressRemoved, NodeRouteRemoved}} {
			must(AdvanceNodeRoutePhase(ctx, q, route.ID, p[0], p[1], NodeRouteObjects{}, testEpoch))
		}
		_, err = GetLiveNodeRouteByNodePort(ctx, q, node.ID, 8080)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}
