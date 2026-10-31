package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func appRouteOf(f *fixture, target AppTarget, by domain.ID, hostname string) AppRoute {
	return AppRoute{
		ID: f.ids.NewID(), AppTargetID: target.ID, NodeID: target.NodeID, Hostname: hostname, Service: "web", Port: 8080,
		Access: "public", AccountID: "acct", Zone: "example.com", InstanceID: "inst", TunnelID: "tun", TunnelGeneration: 1,
		CreatedBy: by, CreatedAt: testEpoch,
	}
}

func appRouteWorld(ctx context.Context, f *fixture, q Querier) (AppTarget, domain.ID) {
	w := newAppsWorld(ctx, f, q)
	app := must(CreateApp(ctx, q, appsAppOf(f, "web")))
	target := must(CreateAppTarget(ctx, q, appsTargetOf(f, app, w, "sm-web-prod")))
	return target, f.identity(ctx, q, domain.ActorHuman, "alice").ID
}

func TestAppRouteLifecycle(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		target, by := appRouteWorld(ctx, f, q)
		r := must(InsertAppRoute(ctx, q, appRouteOf(f, target, by, "app.example.com")))
		if r.Phase != AppRouteWaiting || r.Port != 8080 || r.TunnelGeneration != 1 || !r.PhaseStartedAt.Equal(testEpoch) {
			t.Fatalf("inserted = %+v", r)
		}
		if got := must(ListWaitingAppRoutes(ctx, q, target.ID)); len(got) != 1 || got[0].ID != r.ID {
			t.Fatalf("waiting = %+v", got)
		}
		later := testEpoch.Add(time.Minute)
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteWaiting, AppRouteProvisioning, AppRouteObjects{}, later))
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteProvisioning, AppRouteIngressReady, AppRouteObjects{DNSRecordID: "dns"}, later))
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteIngressReady, AppRouteAccessReady, AppRouteObjects{AccessAppID: "app"}, later))
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteAccessReady, AppRouteActive, AppRouteObjects{}, later))
		if r.Objects != (AppRouteObjects{DNSRecordID: "dns", AccessAppID: "app"}) || !r.PhaseStartedAt.Equal(later) {
			t.Fatalf("active = %+v", r)
		}
		if got := must(ListWaitingAppRoutes(ctx, q, target.ID)); len(got) != 0 {
			t.Fatalf("waiting after activation = %d", len(got))
		}
		if got := must(GetLiveAppRouteByHostname(ctx, q, "app.example.com")); got.ID != r.ID {
			t.Fatalf("by hostname = %s", got.ID)
		}

		r = must(MarkAppRouteRemoving(ctx, q, r.ID, AppRouteActive, later))
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteRemoving, AppRouteDNSRemoved, AppRouteObjects{}, later))
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteDNSRemoved, AppRouteIngressRemoved, AppRouteObjects{}, later))
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteIngressRemoved, AppRouteRemoved, AppRouteObjects{}, later))
		_, err := GetLiveAppRouteByHostname(ctx, q, "app.example.com")
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteRemoved, AppRouteWaiting, AppRouteObjects{}, later)
		if err == nil || !strings.Contains(err.Error(), "does not change phase") {
			t.Fatalf("a removed route moved: %v", err)
		}
		_, err = MarkAppRouteRemoving(ctx, q, r.ID, AppRouteRemoved, later)
		wantError(t, err, smerr.CodeInvalidArgument, "")
	})
}

func TestAppRouteAdvanceIsFencedOnPhase(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		target, by := appRouteWorld(ctx, f, q)
		r := must(InsertAppRoute(ctx, q, appRouteOf(f, target, by, "app.example.com")))
		_, err := AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteProvisioning, AppRouteIngressReady, AppRouteObjects{}, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		e, _ := err.(*smerr.Error)
		if e == nil || e.Details["current_phase"] != "waiting" || e.Details["expected_phase"] != "provisioning" {
			t.Fatalf("conflict details = %v", err)
		}
		_, err = AdvanceAppRoutePhase(ctx, q, "missing", AppRouteWaiting, AppRouteProvisioning, AppRouteObjects{}, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestAppRouteHaltAndResumeKeepPhaseStart(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		target, by := appRouteWorld(ctx, f, q)
		r := must(InsertAppRoute(ctx, q, appRouteOf(f, target, by, "app.example.com")))
		started := testEpoch.Add(time.Minute)
		r = must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteWaiting, AppRouteProvisioning, AppRouteObjects{}, started))
		r = must(HaltAppRoute(ctx, q, r.ID, AppRouteProvisioning, AppRouteConflict, "dns record owned by another", started.Add(time.Minute)))
		if r.Phase != AppRouteConflict || r.HaltedPhase != AppRouteProvisioning || r.LastError == "" {
			t.Fatalf("halted = %+v", r)
		}
		if got := must(CountLiveAppRoutesByNode(ctx, q, r.NodeID)); got != 1 {
			t.Fatalf("a halted route must stay live, count = %d", got)
		}
		_, err := HaltAppRoute(ctx, q, r.ID, AppRouteConflict, AppRouteFailed, "x", started)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		_, err = ResumeHaltedAppRoute(ctx, q, r.ID, AppRouteFailed, started)
		wantError(t, err, smerr.CodeConflict, "")

		r = must(ResumeHaltedAppRoute(ctx, q, r.ID, AppRouteConflict, started.Add(time.Hour)))
		if r.Phase != AppRouteProvisioning || r.HaltedPhase != "" || r.LastError != "" || !r.PhaseStartedAt.Equal(started) {
			t.Fatalf("resumed = %+v", r)
		}
		r = must(HaltAppRoute(ctx, q, r.ID, AppRouteProvisioning, AppRouteFailed, "boom", started))
		r = must(MarkAppRouteRemoving(ctx, q, r.ID, AppRouteFailed, started))
		if r.Phase != AppRouteRemoving || r.HaltedPhase != "" {
			t.Fatalf("removing a halted route = %+v", r)
		}
	})
}

func TestAppRouteHostnameIsUniqueAmongLiveRoutes(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		target, by := appRouteWorld(ctx, f, q)
		first := must(InsertAppRoute(ctx, q, appRouteOf(f, target, by, "app.example.com")))
		_, err := InsertAppRoute(ctx, q, appRouteOf(f, target, by, "app.example.com"))
		wantError(t, err, smerr.CodeConflict, "")

		must(MarkAppRouteRemoving(ctx, q, first.ID, AppRouteWaiting, testEpoch))
		for _, p := range [][2]AppRoutePhase{{AppRouteRemoving, AppRouteDNSRemoved}, {AppRouteDNSRemoved, AppRouteIngressRemoved}, {AppRouteIngressRemoved, AppRouteRemoved}} {
			must(AdvanceAppRoutePhase(ctx, q, first.ID, p[0], p[1], AppRouteObjects{}, testEpoch))
		}
		second := must(InsertAppRoute(ctx, q, appRouteOf(f, target, by, "app.example.com")))

		all := must(ListAppRoutes(ctx, q, AppRouteFilter{TargetID: target.ID, IncludeRemoved: true}))
		live := must(ListAppRoutes(ctx, q, AppRouteFilter{NodeID: target.NodeID}))
		if len(all) != 2 || len(live) != 1 || live[0].ID != second.ID {
			t.Fatalf("all = %d, live = %+v", len(all), live)
		}
		if got := must(ListAppRoutes(ctx, q, AppRouteFilter{TargetID: "other"})); len(got) != 0 {
			t.Fatalf("other target = %d", len(got))
		}
	})
}

func TestAppRouteRejectsInvalidRows(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		target, by := appRouteWorld(ctx, f, q)
		otherNode := f.node(ctx, q, f.provider(ctx, q, "other"), "n2")
		for name, mutate := range map[string]func(*AppRoute){
			"uppercase hostname": func(r *AppRoute) { r.Hostname = "App.example.com" },
			"port zero":          func(r *AppRoute) { r.Port = 0 },
			"port too high":      func(r *AppRoute) { r.Port = 65536 },
			"unknown access":     func(r *AppRoute) { r.Access = "everyone" },
			"empty tunnel":       func(r *AppRoute) { r.TunnelID = "" },
			"zero generation":    func(r *AppRoute) { r.TunnelGeneration = 0 },
			"foreign node":       func(r *AppRoute) { r.NodeID = otherNode.ID },
		} {
			r := appRouteOf(f, target, by, "app.example.com")
			mutate(&r)
			sp := "SAVEPOINT " + strings.ReplaceAll(name, " ", "_")
			if _, err := q.ExecContext(ctx, sp); err != nil {
				t.Fatal(err)
			}
			if _, err := InsertAppRoute(ctx, q, r); err == nil {
				t.Errorf("%s: accepted", name)
			}
			if _, err := q.ExecContext(ctx, "ROLLBACK TO "+sp); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestAppRouteIdentityAndObjectIDsAreWriteOnce(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		target, by := appRouteWorld(ctx, f, q)
		r := must(InsertAppRoute(ctx, q, appRouteOf(f, target, by, "app.example.com")))
		must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteWaiting, AppRouteProvisioning, AppRouteObjects{DNSRecordID: "dns"}, testEpoch))

		_, err := AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteProvisioning, AppRouteIngressReady, AppRouteObjects{DNSRecordID: "other"}, testEpoch)
		if err == nil || !strings.Contains(err.Error(), "recorded object IDs") {
			t.Fatalf("a recorded DNS record ID changed: %v", err)
		}
		// the same ID again, or an empty one, is not a change
		must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteProvisioning, AppRouteIngressReady, AppRouteObjects{DNSRecordID: "dns"}, testEpoch))
		must(AdvanceAppRoutePhase(ctx, q, r.ID, AppRouteIngressReady, AppRouteAccessReady, AppRouteObjects{}, testEpoch))

		for _, col := range []string{
			"hostname = 'x.example.com'", "service = 'x'", "port = 9", "access = 'owners'", "account_id = 'x'", "zone = 'x'",
			"instance_id = 'x'", "tunnel_id = 'x'", "tunnel_generation = 2", "node_id = 'x'", "app_target_id = 'x'",
		} {
			if _, err := q.ExecContext(ctx, `UPDATE app_routes SET `+col+` WHERE id = ?`, r.ID); err == nil {
				t.Errorf("UPDATE %s succeeded, want the identity to be frozen", col)
			}
		}
	})
}
