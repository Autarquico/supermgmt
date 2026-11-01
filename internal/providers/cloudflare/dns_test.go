package cloudflare

import (
	"context"
	"net/http"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

const movedHost = "ssh-web1.example.test"

func seededRecord(t *testing.T) (*cffake.Fake, *Client, string, cffake.DNSRecord) {
	t.Helper()
	f, c := newEnv(t)
	_, zoneID := f.Zone()
	return f, c, zoneID, f.SeedDNSRecord(movedHost, TunnelTarget("tun-1"), "marker")
}

func contentOf(t *testing.T, c *Client, zoneID, id string) string {
	t.Helper()
	return must[DNSRecord](t)(c.GetDNSRecord(ctx(t), zoneID, id)).Content
}

func TestUpdateDNSRecord_ChangesOnlyContent(t *testing.T) {
	f, c, zoneID, seed := seededRecord(t)
	got := must[DNSRecord](t)(c.UpdateDNSRecord(ctx(t), zoneID, seed.ID, TunnelTarget("TUN-2")))
	if got.ID != seed.ID || got.Content != TunnelTarget("tun-2") || got.Comment != "marker" || got.Type != "CNAME" || !got.Proxied || got.Name != movedHost {
		t.Fatalf("updated record = %+v", got)
	}
	if read := must[DNSRecord](t)(c.GetDNSRecord(ctx(t), zoneID, seed.ID)); read != got {
		t.Errorf("GetDNSRecord = %+v, want %+v", read, got)
	}
	if recs := f.DNSRecords(); len(recs) != 1 || recs[0].ID != seed.ID || recs[0].Comment != "marker" {
		t.Errorf("zone = %+v", recs)
	}
	log := f.Mutations()
	if len(log) != 1 || log[0].Op != cffake.OpDNSUpdate || log[0].Method != http.MethodPatch || !log[0].Committed {
		t.Errorf("mutations = %+v", log)
	}
}

func TestDNSRecord_NotFoundAndInvalid(t *testing.T) {
	_, c, zoneID, seed := seededRecord(t)
	missing := "0000000000000000000000000000ffff"
	if _, err := c.GetDNSRecord(ctx(t), zoneID, missing); !IsNotFound(err) {
		t.Errorf("GetDNSRecord of a missing record = %v", err)
	}
	if _, err := c.UpdateDNSRecord(ctx(t), zoneID, missing, TunnelTarget("t")); !IsNotFound(err) {
		t.Errorf("UpdateDNSRecord of a missing record = %v", err)
	}
	for name, call := range map[string]func() error{
		"get id":      func() error { _, err := c.GetDNSRecord(ctx(t), zoneID, "../x"); return err },
		"get zone":    func() error { _, err := c.GetDNSRecord(ctx(t), "../z", seed.ID); return err },
		"update id":   func() error { _, err := c.UpdateDNSRecord(ctx(t), zoneID, "a/b", TunnelTarget("t")); return err },
		"update zone": func() error { _, err := c.UpdateDNSRecord(ctx(t), "../z", seed.ID, TunnelTarget("t")); return err },
		"content":     func() error { _, err := c.UpdateDNSRecord(ctx(t), zoneID, seed.ID, "a b"); return err },
		"no content":  func() error { _, err := c.UpdateDNSRecord(ctx(t), zoneID, seed.ID, ""); return err },
	} {
		if smerr.CodeOf(call()) != smerr.CodeInvalidArgument {
			t.Errorf("%s: invalid input was not refused", name)
		}
	}
	if got := contentOf(t, c, zoneID, seed.ID); got != TunnelTarget("tun-1") {
		t.Errorf("content = %q after refused updates", got)
	}
}

func TestUpdateDNSRecord_FailBeforeChangesNothing(t *testing.T) {
	f, c, zoneID, seed := seededRecord(t)
	f.Inject(cffake.OpDNSUpdate, cffake.FailBefore, 1)
	if _, err := c.UpdateDNSRecord(ctx(t), zoneID, seed.ID, TunnelTarget("tun-2")); !IsAmbiguous(err) {
		t.Fatalf("failed update = %v", err)
	}
	if got := contentOf(t, c, zoneID, seed.ID); got != TunnelTarget("tun-1") {
		t.Errorf("content = %q", got)
	}
	if f.CommittedMutations() != 0 {
		t.Error("a failed update was logged as committed")
	}
}

func TestUpdateDNSRecord_LostResponseStillApplies(t *testing.T) {
	f, c, zoneID, seed := seededRecord(t)
	f.Inject(cffake.OpDNSUpdate, cffake.LostResponse, 1)
	if _, err := c.UpdateDNSRecord(ctx(t), zoneID, seed.ID, TunnelTarget("tun-2")); !IsAmbiguous(err) {
		t.Fatalf("update with a lost response = %v", err)
	}
	if got := contentOf(t, c, zoneID, seed.ID); got != TunnelTarget("tun-2") {
		t.Errorf("content = %q, want the change applied", got)
	}
	if f.CommittedMutations() != 1 {
		t.Errorf("committed = %d", f.CommittedMutations())
	}
}

func TestUpdateDNSRecord_ApplyLaterAnswersNowChangesAtRelease(t *testing.T) {
	f, c, zoneID, seed := seededRecord(t)
	f.Inject(cffake.OpDNSUpdate, cffake.ApplyLater, 1)
	got := must[DNSRecord](t)(c.UpdateDNSRecord(ctx(t), zoneID, seed.ID, TunnelTarget("tun-2")))
	if got.Content != TunnelTarget("tun-2") {
		t.Errorf("answer = %+v", got)
	}
	if now := contentOf(t, c, zoneID, seed.ID); now != TunnelTarget("tun-1") || f.CommittedMutations() != 0 {
		t.Fatalf("content = %q, committed = %d before release", now, f.CommittedMutations())
	}
	if n := f.ReleaseDeferred(); n != 1 {
		t.Fatalf("released %d", n)
	}
	if now := contentOf(t, c, zoneID, seed.ID); now != TunnelTarget("tun-2") || f.CommittedMutations() != 1 {
		t.Errorf("content = %q, committed = %d after release", now, f.CommittedMutations())
	}
	if n := f.ReleaseDeferred(); n != 0 {
		t.Errorf("second release applied %d", n)
	}
}

func TestUpdateDNSRecord_HangApplyLaterLandsAfterCancellation(t *testing.T) {
	f, c, zoneID, seed := seededRecord(t)
	f.Inject(cffake.OpDNSUpdate, cffake.HangApplyLater, 1)
	cctx, cancel := context.WithTimeout(ctx(t), 200*time.Millisecond)
	defer cancel()
	if _, err := c.UpdateDNSRecord(cctx, zoneID, seed.ID, TunnelTarget("tun-2")); err == nil || !IsAmbiguous(err) {
		t.Fatalf("cancelled update = %v, want an ambiguous error", err)
	}
	if got := contentOf(t, c, zoneID, seed.ID); got != TunnelTarget("tun-1") {
		t.Fatalf("content = %q before release", got)
	}
	if n := f.ReleaseDeferred(); n != 1 {
		t.Fatalf("released %d", n)
	}
	if got := contentOf(t, c, zoneID, seed.ID); got != TunnelTarget("tun-2") {
		t.Errorf("content = %q after release", got)
	}
}

func TestReleaseDeferred_RecordGoneChangesNothing(t *testing.T) {
	f, c, zoneID, seed := seededRecord(t)
	f.Inject(cffake.OpDNSUpdate, cffake.ApplyLater, 1)
	must[DNSRecord](t)(c.UpdateDNSRecord(ctx(t), zoneID, seed.ID, TunnelTarget("tun-2")))
	if err := c.DeleteDNSRecord(ctx(t), zoneID, seed.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.ReleaseDeferred(); n != 0 {
		t.Errorf("released %d onto a deleted record", n)
	}
}

func TestApplyLater_OtherEndpointsServeNormally(t *testing.T) {
	f, c, zoneID, seed := seededRecord(t)
	f.Inject(cffake.OpDNSDelete, cffake.ApplyLater, 1)
	if err := c.DeleteDNSRecord(ctx(t), zoneID, seed.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.DNSRecords()) != 0 || f.ReleaseDeferred() != 0 {
		t.Error("an endpoint that cannot defer held its change back")
	}
}
