package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

func filePVE(endpoint string) config.Provider {
	return config.Provider{Proxmox: &config.ProxmoxProvider{
		Type: "proxmox", Name: "pve", Endpoint: endpoint, CredentialRef: pveTokenRef,
		VerifyTLS: true, CAFile: "/etc/supermgmt/pve-root-ca.pem", SyncInterval: 45 * time.Second,
	}}
}

func (f *fixture) pveProvider() (domain.Provider, bool) {
	f.t.Helper()
	providers, err := database.ListProviders(context.Background(), f.db.Reader())
	mustf(f.t, err, "ListProviders")
	for _, p := range providers {
		if p.Name == "pve" {
			return p, true
		}
	}
	return domain.Provider{}, false
}

func TestReconcileCreatesTheStaticProxmoxProviderWithWhatDiscoveryNeeds(t *testing.T) {
	f := newFixture(t)

	mustf(t, f.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{filePVE("https://pve.lan:8006")}), "Reconcile")

	p, ok := f.pveProvider()
	if !ok {
		t.Fatal("provider not created")
	}
	if p.Type != "proxmox" || p.Origin != domain.ProviderStatic || p.Endpoint != "https://pve.lan:8006" || p.CredentialRef != pveTokenRef || p.Status != "" {
		t.Errorf("provider = %+v", p)
	}
	if p.Config["ca_file"] != "/etc/supermgmt/pve-root-ca.pem" || p.Config["sync_interval"] != "45s" || ProviderSyncInterval(p) != 45*time.Second {
		t.Errorf("config = %v, interval %s", p.Config, ProviderSyncInterval(p))
	}
	if added := f.events(eventProviderAdd); len(added) != 1 {
		t.Errorf("provider.add events = %d, want 1", len(added))
	}
	if nodes := mustNodes(t, f); len(nodes) != 1 { // only the fixture's own node: discovery finds guests
		t.Errorf("reconciling created %d nodes, want none", len(nodes)-1)
	}
}

func TestReconcileLeavesAnUnchangedProxmoxProviderAloneAndBumpsTheRevisionOnAChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{filePVE("https://pve.lan:8006")}), "first")
	first, _ := f.pveProvider()

	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{filePVE("https://pve.lan:8006")}), "repeat")
	repeated, _ := f.pveProvider()
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{filePVE("https://pve2.lan:8006")}), "changed")
	changed, _ := f.pveProvider()

	if repeated.SpecRevision != first.SpecRevision || len(f.events(eventProviderUpdate)) != 1 {
		t.Errorf("an unchanged file bumped spec_revision to %d", repeated.SpecRevision)
	}
	if changed.SpecRevision != first.SpecRevision+1 || changed.Endpoint != "https://pve2.lan:8006" {
		t.Errorf("after the change: %+v", changed)
	}
}

func TestReconcileDoesNotResetTheObservedStatusOfAProxmoxProvider(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{filePVE("https://pve.lan:8006")}), "first")
	p, _ := f.pveProvider()
	synced := f.clock.Now()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetProviderStatus(ctx, tx, p.ID, ProviderStatusOK, &synced)
	})

	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{filePVE("https://pve2.lan:8006")}), "changed")

	after, _ := f.pveProvider()
	if after.Status != ProviderStatusOK || after.LastSyncAt == nil || !after.LastSyncAt.Equal(synced) {
		t.Errorf("a configuration change wiped the sync state: %+v", after)
	}
}

func TestReconcileStopsAProxmoxProviderThatLeftTheFileAndRestoresItWhenItReturns(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{filePVE("https://pve.lan:8006")}), "first")

	mustf(t, f.reconciler(t).Reconcile(ctx, nil, nil), "removed")
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, nil), "removed again")
	removed, ok := f.pveProvider()
	removals := len(f.events(eventProviderRemove))
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{filePVE("https://pve.lan:8006")}), "returned")
	returned, _ := f.pveProvider()

	if !ok || removed.Status != ProviderStatusRemoved || removals != 1 {
		t.Errorf("after removal: %+v (%d provider.remove events); the row must stay and be audited once", removed, removals)
	}
	if returned.Status != "" || returned.SpecRevision != removed.SpecRevision {
		t.Errorf("after it returned: %+v", returned)
	}
}

func TestReconcileRefusesAProxmoxProviderWhoseNameBelongsToAnotherProvider(t *testing.T) {
	f := newFixture(t)
	taken := filePVE("https://pve.lan:8006")
	taken.Proxmox.Name = f.provider.Name // created through the API in the fixture

	err := f.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{taken})

	if err == nil || !strings.Contains(err.Error(), "not a static Proxmox provider") {
		t.Errorf("err = %v", err)
	}
}
