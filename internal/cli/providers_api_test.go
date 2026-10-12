package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/installer"
)

func providerFixture() (healthy, broken wire.Provider) {
	synced := time.Date(2026, 10, 12, 8, 30, 0, 0, time.UTC)
	healthy = wire.Provider{ID: newTestID(), Type: "proxmox", Name: "pve", Origin: domain.ProviderStatic, Status: "ok", LastSyncAt: &synced}
	broken = wire.Provider{
		ID: newTestID(), Type: "proxmox", Name: "pve-lab", Origin: domain.ProviderStatic, Status: "error",
		LastSyncAt: &synced, LastError: "cluster is on fire",
	}
	return healthy, broken
}

// providersAPI serves the two providers; a refresh answers with what the test
// says the sync left.
func providersAPI(t *testing.T, healthy, broken wire.Provider) *fakeAPI {
	t.Helper()
	routes := map[string]http.HandlerFunc{
		"GET " + wire.PathProviders: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Provider]{Items: []wire.Provider{healthy, broken}})
		},
	}
	for _, p := range []wire.Provider{healthy, broken} {
		routes["POST "+wire.Path(wire.PathProviderRefresh, string(p.ID))] = func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, p) }
	}
	return newFakeAPI(t, router(routes))
}

func TestProvidersListShowsStatusLastSyncAndWhyItFailed(t *testing.T) {
	healthy, broken := providerFixture()
	f := providersAPI(t, healthy, broken)

	r := f.run("providers", "list")

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{"pve-lab", "error", "2026-10-12T08:30:00Z", "cluster is on fire", "pve  "} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestProvidersGetResolvesByNameOrIdAndRefusesAnUnknownProvider(t *testing.T) {
	healthy, broken := providerFixture()
	f := providersAPI(t, healthy, broken)

	byName := f.run("providers", "get", "pve-lab")
	byID := f.run("providers", "get", string(healthy.ID))
	missing := f.run("providers", "get", "nope")

	if byName.code != 0 || !strings.Contains(byName.stdout, "last error:") || !strings.Contains(byName.stdout, "cluster is on fire") {
		t.Errorf("by name: code=%d out=%q", byName.code, byName.stdout)
	}
	if byID.code != 0 || !strings.Contains(byID.stdout, "name:") {
		t.Errorf("by id: code=%d out=%q", byID.code, byID.stdout)
	}
	if missing.code != exitInternal || !strings.Contains(missing.stderr, `no provider "nope"`) {
		t.Errorf("missing: code=%d stderr=%q", missing.code, missing.stderr)
	}
}

func TestProvidersRefreshReportsTheSyncAndExitsWithTheConnectivityCodeWhenItFailed(t *testing.T) {
	healthy, broken := providerFixture()
	tests := []struct {
		name     string
		provider wire.Provider
		wantCode int
		wantOut  string
	}{
		{"ok", healthy, 0, "ok"},
		{"cluster unreadable", broken, installer.ExitConnectivity, "cluster is on fire"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := providersAPI(t, healthy, broken)

			r := f.run("providers", "refresh", tt.provider.Name)

			if r.code != tt.wantCode || !strings.Contains(r.stdout, tt.wantOut) {
				t.Errorf("code=%d out=%q", r.code, r.stdout)
			}
			if len(f.Mutations()) != 1 || f.Mutations()[0].Path != wire.Path(wire.PathProviderRefresh, string(tt.provider.ID)) {
				t.Errorf("mutations = %+v", f.Mutations())
			}
		})
	}
}

func TestProvidersCommandsFailWithThePrerequisiteExitWhenNoDaemonRuns(t *testing.T) {
	f := newFakeAPI(t, nil)

	if r := f.run("providers", "list"); r.code != exitPrerequisite {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
}
