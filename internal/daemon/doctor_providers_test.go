package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

type doctorBox struct {
	t       *testing.T
	b       *builder
	clock   *domaintest.FakeClock
	pve     domain.Provider
	startAt time.Time
}

func newDoctorBox(t *testing.T) *doctorBox {
	t.Helper()
	ctx := context.Background()
	start := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	clock := domaintest.NewFakeClock(start)
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	box := &doctorBox{t: t, clock: clock, startAt: start, b: &builder{db: db, o: Options{Clock: clock}}}
	box.pve = box.addProvider("pve", "proxmox", map[string]any{"sync_interval": "30s"})
	return box
}

func (d *doctorBox) addProvider(name, typ string, config map[string]any) domain.Provider {
	d.t.Helper()
	var p domain.Provider
	err := d.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		var err error
		p, err = database.CreateProvider(ctx, tx, domain.Provider{
			ID: domain.UUIDv7Generator{}.NewID(), Type: typ, Name: name, Origin: domain.ProviderStatic,
			Config: config, CreatedAt: d.startAt, UpdatedAt: d.startAt,
		})
		return err
	})
	if err != nil {
		d.t.Fatal(err)
	}
	return p
}

func (d *doctorBox) setStatus(p domain.Provider, status string, syncedAt *time.Time) {
	d.t.Helper()
	err := d.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.SetProviderStatus(ctx, tx, p.ID, status, syncedAt)
	})
	if err != nil {
		d.t.Fatal(err)
	}
}

func (d *doctorBox) reportFailure(p domain.Provider, message string) {
	d.t.Helper()
	err := d.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.RecordObservation(ctx, tx, database.Observation{
			ID: domain.UUIDv7Generator{}.NewID(), ResourceType: domain.ResourceProvider, ResourceID: p.ID,
			Kind: app.ObservationProxmoxSync, Value: app.SyncReport{Error: message}, ObservedAt: d.clock.Now(),
		})
	})
	if err != nil {
		d.t.Fatal(err)
	}
}

func (d *doctorBox) check() (status, detail string) {
	d.t.Helper()
	got := d.b.checkProviders(context.Background())
	if got.Name != "providers" {
		d.t.Fatalf("check name = %q", got.Name)
	}
	return got.Status, got.Detail
}

func TestDoctorProvidersIsOKWhenNoneIsConfigured(t *testing.T) {
	d := newDoctorBox(t)
	d.setStatus(d.pve, app.ProviderStatusRemoved, nil)
	d.addProvider("web", "ssh", nil)

	status, detail := d.check()

	if status != checkOK || !strings.Contains(detail, "no Proxmox provider") {
		t.Errorf("check = %s %q", status, detail)
	}
}

func TestDoctorProvidersWarnsUntilTheFirstSyncAndPassesAfterIt(t *testing.T) {
	d := newDoctorBox(t)

	before, detail := d.check()
	if before != checkWarn || !strings.Contains(detail, "pve: waiting for the first sync") {
		t.Errorf("before the first sync: %s %q", before, detail)
	}

	now := d.clock.Now()
	d.setStatus(d.pve, app.ProviderStatusOK, &now)
	after, detail := d.check()
	if after != checkOK || !strings.Contains(detail, "pve: synced "+now.Format(time.RFC3339)) {
		t.Errorf("after the first sync: %s %q", after, detail)
	}
}

func TestDoctorProvidersWarnsWhenTheLastSyncIsStale(t *testing.T) {
	d := newDoctorBox(t)
	synced := d.clock.Now()
	d.setStatus(d.pve, app.ProviderStatusOK, &synced)

	d.clock.Advance(89 * time.Second)
	fresh, _ := d.check()
	d.clock.Advance(2 * time.Second)
	stale, detail := d.check()

	if fresh != checkOK || stale != checkWarn || !strings.Contains(detail, "last synced 1m31s ago") {
		t.Errorf("within three intervals: %s; past them: %s %q", fresh, stale, detail)
	}
}

func TestDoctorProvidersFailsWithTheLastErrorAndNamesTheProvider(t *testing.T) {
	d := newDoctorBox(t)
	now := d.clock.Now()
	d.setStatus(d.pve, app.ProviderStatusError, &now)
	d.reportFailure(d.pve, "HTTP 401: invalid token")
	other := d.addProvider("pve-lab", "proxmox", nil)
	d.setStatus(other, app.ProviderStatusOK, &now)

	status, detail := d.check()

	if status != checkFail || !strings.Contains(detail, "pve: the last sync failed: HTTP 401: invalid token") || !strings.Contains(detail, "pve-lab: synced") {
		t.Errorf("check = %s %q; the worst provider decides and every provider is named", status, detail)
	}
}

func (d *doctorBox) reportSkew(p domain.Provider, skew time.Duration, unknown bool) {
	d.t.Helper()
	err := d.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.RecordObservation(ctx, tx, database.Observation{
			ID: domain.UUIDv7Generator{}.NewID(), ResourceType: domain.ResourceProvider, ResourceID: p.ID,
			Kind: app.ObservationProxmoxSync, Value: app.SyncReport{ClockSkew: skew, ClockSkewUnknown: unknown}, ObservedAt: d.clock.Now(),
		})
	})
	if err != nil {
		d.t.Fatal(err)
	}
}

func TestDoctorProviders_SkewWarns(t *testing.T) {
	for _, tt := range []struct {
		name    string
		skew    time.Duration
		unknown bool
		want    string
	}{
		{"PVE 61 s ahead", 61 * time.Second, false, checkWarn},
		{"PVE 61 s behind", -61 * time.Second, false, checkWarn},
		{"exactly 60 s", 60 * time.Second, false, checkOK},
		{"in sync", 2 * time.Second, false, checkOK},
		{"unknown skew says nothing", 0, true, checkOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := newDoctorBox(t)
			now := d.clock.Now()
			d.setStatus(d.pve, app.ProviderStatusOK, &now)
			d.reportSkew(d.pve, tt.skew, tt.unknown)

			status, detail := d.check()

			if status != tt.want {
				t.Fatalf("check = %s %q, want %s", status, detail, tt.want)
			}
			if tt.want == checkWarn && !strings.Contains(detail, "pve: synced") {
				t.Errorf("detail = %q must still name the provider and its sync", detail)
			}
		})
	}
}
