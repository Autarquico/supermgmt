package app

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

func TestEnableRepairsAnObjectThatVanishedFromCloudflare(t *testing.T) {
	tests := []struct {
		kind   string
		vanish func(t *testing.T, ts *tunnelSetting, o database.TunnelObjects)
		id     func(o database.TunnelObjects) string
	}{
		{"DNS record", func(t *testing.T, ts *tunnelSetting, o database.TunnelObjects) {
			mustf(t, ts.chaos.CloudflareAPI.DeleteDNSRecord(context.Background(), ts.zoneID(), o.DNSRecordID), "delete DNS record")
		}, func(o database.TunnelObjects) string { return o.DNSRecordID }},
		{"Access application", func(t *testing.T, ts *tunnelSetting, o database.TunnelObjects) {
			mustf(t, ts.chaos.CloudflareAPI.DeleteDNSRecord(context.Background(), ts.zoneID(), o.DNSRecordID), "delete DNS record")
			mustf(t, ts.chaos.CloudflareAPI.DeleteAccessApp(context.Background(), o.AccessAppID), "delete Access application")
		}, func(o database.TunnelObjects) string { return o.AccessAppID }},
		{"tunnel", func(t *testing.T, ts *tunnelSetting, o database.TunnelObjects) {
			mustf(t, ts.chaos.CloudflareAPI.DeleteTunnel(context.Background(), o.TunnelID), "delete tunnel")
		}, func(o database.TunnelObjects) string { return o.TunnelID }},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			ts := newEnabledTunnel(t)
			old := ts.operations()[0].Objects
			tc.vanish(t, ts, old)

			ts.plan()
			ts.converge(3)

			ts.wantOneOfEach()
			ts.wantRecorded()
			if now := ts.operations()[0].Objects; tc.id(now) == "" || tc.id(now) == tc.id(old) {
				t.Errorf("recorded %s ID %q, want a new one (was %q)", tc.kind, tc.id(now), tc.id(old))
			}
			named := false
			for _, e := range ts.events("cloudflare.object.vanished") {
				named = named || strings.Contains(string(mustJSON(t, e.Data)), tc.id(old))
			}
			if !named {
				t.Errorf("no audited vanished event names the old %s ID %q", tc.kind, tc.id(old))
			}
			if got := ts.operations()[0].Phase; got != database.PhaseCommitted {
				t.Errorf("phase = %s, want committed", got)
			}
		})
	}
}

func TestARerunUpdatesTheAccessApplicationOnlyWhenTheIdentityProvidersChanged(t *testing.T) {
	ts := newEnabledTunnel(t)
	updates := func() int {
		n := 0
		for _, m := range ts.cf.Mutations() {
			if m.Op == cffake.OpAppUpdate && m.Committed {
				n++
			}
		}
		return n
	}

	ts.plan()
	mustf(t, ts.attempt(), "rerun with the same providers")
	if got := updates(); got != 0 {
		t.Fatalf("%d Access application updates with unchanged providers, want none", got)
	}

	const other = "22222222-2222-4222-8222-222222222222"
	ts.handler.tunnel.opts.Config.AccessIdentityProviders = []string{other}
	ts.plan()
	mustf(t, ts.attempt(), "rerun with other providers")

	if got := updates(); got != 1 {
		t.Fatalf("%d Access application updates after the change, want 1", got)
	}
	apps := ts.cf.Snapshot().Apps
	if len(apps) != 1 || len(apps[0].AllowedIdPs) != 1 || apps[0].AllowedIdPs[0] != other {
		t.Errorf("Access application = %+v, want the new identity provider", apps)
	}
	if got := len(ts.events("cloudflare.access_app.updated")); got != 1 {
		t.Errorf("%d access_app.updated events, want 1", got)
	}
}

// An empty access_identity_providers means one-time PIN: Cloudflare stores the
// PIN provider's ID, and a re-run must compare against that, not against [].
func TestARerunWithOneTimePINMakesNoAccessApplicationUpdate(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.handler.tunnel.opts.Config.AccessIdentityProviders = nil
	ts.plan()
	mustf(t, ts.attempt(), "tunnel setup with one-time PIN")

	ts.plan()
	mustf(t, ts.attempt(), "rerun with one-time PIN")

	for _, m := range ts.cf.Mutations() {
		if m.Op == cffake.OpAppUpdate && m.Committed {
			t.Fatal("a rerun with an unchanged empty provider list updated the Access application")
		}
	}
	if apps := ts.cf.Snapshot().Apps; len(apps) != 1 || len(apps[0].AllowedIdPs) != 1 {
		t.Errorf("Access application = %+v, want exactly the one-time PIN provider", apps)
	}
}
