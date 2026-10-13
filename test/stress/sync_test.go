//go:build stress

package stress

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
)

const (
	syncStressTokenRef = "secret://providers/pve/token"
	syncStressCallers  = 24
)

type syncStressRig struct {
	db       *database.DB
	fake     *pvefake.Fake
	sync     *app.ProxmoxSync
	provider domain.Provider
}

// newSyncStressRig is a two-node fake PVE cluster, a configured provider and a
// ProxmoxSync that reaches it; readTimeout bounds one HTTP exchange.
func newSyncStressRig(t *testing.T, readTimeout time.Duration) *syncStressRig {
	t.Helper()
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	ids := domaintest.NewSequentialIDs()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pol, err := policy.Default()
	if err != nil {
		t.Fatalf("policy.Default: %v", err)
	}
	cfg := app.Config{DB: db, Clock: clock, IDs: ids, Policy: pol, Credentials: auth.CredentialStatus{DB: db, Clock: clock}}

	fake := pvefake.New(t)
	fake.AddNode("pve1")
	fake.AddNode("pve2")
	fake.AddGuest(pvefake.Guest{Node: "pve1", Type: "qemu", VMID: 100, Name: "web", Status: "running", MaxCPU: 2, MaxMem: 2 << 30, MaxDisk: 16 << 30})
	fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "db", Status: "stopped", MaxCPU: 1, MaxMem: 1 << 30, MaxDisk: 8 << 30})
	fake.SetRole("SMDiscovery", "VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit", "VM.PowerMgmt")
	token := fake.AddToken("sm@pve", "sm", false)
	fake.Grant("sm@pve", "/", "SMDiscovery", true)

	caFile := filepath.Join(t.TempDir(), "pve-root-ca.pem")
	if err := os.WriteFile(caFile, fake.CAPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	reconciler, err := app.NewStaticReconciler(cfg, config.ModeLocal)
	if err != nil {
		t.Fatalf("NewStaticReconciler: %v", err)
	}
	err = reconciler.Activate(ctx, app.ConfigSources{Config: []byte("providers: [pve]")}, nil, []config.Provider{{Proxmox: &config.ProxmoxProvider{
		Type: "proxmox", Name: "pve", Endpoint: fake.Endpoint(), CredentialRef: syncStressTokenRef,
		VerifyTLS: true, CAFile: caFile, SyncInterval: 30 * time.Second,
	}}})
	if err != nil {
		t.Fatalf("configure the provider: %v", err)
	}

	rig := &syncStressRig{db: db, fake: fake}
	rig.sync, err = app.NewProxmoxSync(cfg, app.ProxmoxSyncOptions{
		Token: func(_ context.Context, ref string) (audit.Secret, error) {
			if ref != syncStressTokenRef {
				return "", errors.New("unexpected credential reference " + ref)
			}
			return audit.Secret(token), nil
		},
		Client: []proxmox.Option{
			proxmox.WithHTTPTimeout(readTimeout),
			proxmox.WithNetguardOptions(netguard.WithTestDialer(fake.Dial)),
		},
	})
	if err != nil {
		t.Fatalf("NewProxmoxSync: %v", err)
	}
	providers, err := database.ListProviders(ctx, db.Reader())
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	for _, p := range providers {
		if p.Name == "pve" {
			rig.provider = p
		}
	}
	if rig.provider.ID == "" {
		t.Fatal("no provider named pve")
	}
	return rig
}

func (r *syncStressRig) discoveredObjects(t *testing.T) int {
	t.Helper()
	nodes, err := database.ListNodes(context.Background(), r.db.Reader())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	n := 0
	for _, node := range nodes {
		if node.ProviderID == r.provider.ID {
			n++
		}
	}
	return n
}

func syncStressWaitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	for range 2500 {
		if done() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSyncStress_CallersArrivingDuringARunShareItsOutcomeAndTheClusterIsReadOnce(t *testing.T) {
	rig := newSyncStressRig(t, time.Second)
	rig.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: "/cluster/resources", Fault: pvefake.Hang()})

	errs := make([]error, syncStressCallers)
	var wg sync.WaitGroup
	wg.Go(func() { errs[0] = rig.sync.Sync(context.Background(), rig.provider.ID) })
	syncStressWaitFor(t, "the first read to reach the cluster", func() bool { return rig.fake.Count("GET", "/cluster/resources") == 1 })
	for i := 1; i < syncStressCallers; i++ {
		wg.Go(func() { errs[i] = rig.sync.Sync(context.Background(), rig.provider.ID) })
	}
	wg.Wait()

	for i, err := range errs {
		var failure *app.SyncFailure
		if !errors.As(err, &failure) {
			t.Errorf("caller %d got %v; want the shared failed run", i, err)
		}
	}
	if reads := rig.fake.Count("GET", "/cluster/resources"); reads != 1 {
		t.Errorf("the cluster was read %d times, want exactly 1", reads)
	}
}

func TestSyncStress_ManyCallersSyncingRepeatedlyAllSucceedAndDiscoverTheSameObjects(t *testing.T) {
	rig := newSyncStressRig(t, 5*time.Second)
	if err := rig.sync.Sync(context.Background(), rig.provider.ID); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	want := rig.discoveredObjects(t)
	if want == 0 {
		t.Fatal("the first sync discovered nothing")
	}

	var wg sync.WaitGroup
	for range syncStressCallers {
		wg.Go(func() {
			for range 5 {
				if err := rig.sync.Sync(context.Background(), rig.provider.ID); err != nil {
					t.Errorf("Sync: %v", err)
				}
			}
		})
	}
	wg.Wait()

	if got := rig.discoveredObjects(t); got != want {
		t.Errorf("discovered objects = %d, want the %d of the first sync", got, want)
	}
}

func TestSyncStress_ACallerThatArrivesAfterAFailedRunStartsANewOne(t *testing.T) {
	rig := newSyncStressRig(t, 300*time.Millisecond)
	rig.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: "/cluster/resources", Times: 2, Fault: pvefake.Hang()})

	var failure *app.SyncFailure
	for range 2 {
		if err := rig.sync.Sync(context.Background(), rig.provider.ID); !errors.As(err, &failure) {
			t.Fatalf("Sync = %v; want a SyncFailure", err)
		}
	}
	if reads := rig.fake.Count("GET", "/cluster/resources"); reads != 2 {
		t.Errorf("the cluster was read %d times for two sequential syncs, want 2", reads)
	}
}
