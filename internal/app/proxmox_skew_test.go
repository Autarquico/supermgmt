package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
)

func TestProxmoxSync_ClockSkew(t *testing.T) {
	const behind = 90 * time.Second
	c := newPVECluster(t)
	c.clock.Set(time.Now().Add(-behind)) //nolint:forbidigo // the fake PVE stamps Date with the real clock

	c.doSync()

	report, ok := LatestSyncReport(t.Context(), c.db.Reader(), c.provider.ID)
	// The Date header has one-second resolution and the real clock moves on.
	if !ok || report.ClockSkewUnknown || report.ClockSkew < behind-2*time.Second || report.ClockSkew > behind+5*time.Second {
		t.Fatalf("report = %+v, want PVE ahead of the local clock by about %s", report, behind)
	}
}

// datedClient is a proxmox.Client whose inventory answer carries a PVE clock.
type datedClient struct {
	proxmox.Client
	pveNow time.Time
}

func (d datedClient) ResourcesAt(context.Context) (proxmox.Inventory, time.Time, error) {
	return proxmox.Inventory{}, d.pveNow, nil
}

// undatedClient is a proxmox.Client that cannot report a clock at all.
type undatedClient struct{ proxmox.Client }

func (undatedClient) Resources(context.Context) (proxmox.Inventory, error) {
	return proxmox.Inventory{}, nil
}

func TestReadInventory_SkewIsPVEMinusLocalAndUnknownIsNeverZeroSkew(t *testing.T) {
	local := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	sync := &ProxmoxSync{cfg: Config{Clock: domaintest.NewFakeClock(local)}}
	tests := []struct {
		name      string
		client    proxmox.Client
		wantSkew  time.Duration
		wantKnown bool
	}{
		{"PVE ahead", datedClient{pveNow: local.Add(75 * time.Second)}, 75 * time.Second, true},
		{"PVE behind", datedClient{pveNow: local.Add(-30 * time.Second)}, -30 * time.Second, true},
		{"no Date header", datedClient{}, 0, false},
		{"client without a clock", undatedClient{}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, skew, known, err := sync.readInventory(t.Context(), tt.client)

			if err != nil || skew != tt.wantSkew || known != tt.wantKnown {
				t.Fatalf("skew = %s, known = %v, err = %v; want %s, %v", skew, known, err, tt.wantSkew, tt.wantKnown)
			}
		})
	}
}

func TestSyncReportSameAs_OnlyAMovedSkewOrAChangedKnowledgeIsNews(t *testing.T) {
	base := SyncReport{OK: true, ClockSkew: 10 * time.Second}
	tests := []struct {
		name  string
		other SyncReport
		want  bool
	}{
		{"jitter", SyncReport{OK: true, ClockSkew: 12 * time.Second}, true},
		{"moved", SyncReport{OK: true, ClockSkew: 20 * time.Second}, false},
		{"became unknown", SyncReport{OK: true, ClockSkewUnknown: true}, false},
		{"another error", SyncReport{OK: true, ClockSkew: 10 * time.Second, Error: "x"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base.sameAs(tt.other); got != tt.want {
				t.Fatalf("sameAs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxmoxCorrelationWindowUsesTheClientsExportedDefaultTimeout(t *testing.T) {
	c := newPVECluster(t)
	evidence, err := NewProxmoxEvidence(c.cfg, c.sync, 0)
	mustf(t, err, "NewProxmoxEvidence")

	if evidence.httpTimeout != proxmox.DefaultTimeout {
		t.Fatalf("correlation timeout = %s, want proxmox.DefaultTimeout (%s)", evidence.httpTimeout, proxmox.DefaultTimeout)
	}
}
