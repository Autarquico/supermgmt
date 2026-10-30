package database

import (
	"context"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (f *fixture) enrollment(ctx context.Context, q Querier, name string) TunnelEnrollment {
	f.t.Helper()
	return must(CreateTunnelEnrollment(ctx, q, TunnelEnrollment{
		ID: f.ids.NewID(), Name: name, Tags: []string{"edge"}, AccountID: "acct", Zone: "example.com",
		InstanceID: "inst", Hostname: "ssh-" + name + ".example.com", ExpiresAt: testEpoch.Add(time.Hour),
		Identity:  EnrollmentIdentity{PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:abc", CredentialRef: "secret://id#1"},
		CreatedAt: testEpoch,
	}))
}

func TestTunnelEnrollmentLifecycle(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		e := f.enrollment(ctx, q, "vps1")
		if e.Phase != PhaseStarted || len(e.Tags) != 1 || e.Identity.Fingerprint != "SHA256:abc" || !e.PhaseStartedAt.Equal(testEpoch) {
			t.Fatalf("created = %+v", e)
		}
		later := testEpoch.Add(time.Minute)
		e = must(AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseStarted, PhaseTunnelCreated, TunnelObjects{TunnelID: "tun"}, later))
		e = must(AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseTunnelCreated, PhaseDNSCreated, TunnelObjects{DNSRecordID: "dns", AccessAppID: "app"}, later))
		if e.Objects != (TunnelObjects{TunnelID: "tun", DNSRecordID: "dns", AccessAppID: "app"}) || !e.PhaseStartedAt.Equal(later) {
			t.Fatalf("advanced = %+v", e)
		}
		if got := must(OpenTunnelEnrollmentByName(ctx, q, "vps1")); got.ID != e.ID {
			t.Fatalf("by name = %s", got.ID)
		}
		if all := must(ListOpenTunnelEnrollments(ctx, q)); len(all) != 1 {
			t.Fatalf("open = %d", len(all))
		}

		e = must(RecordScannedHostKey(ctx, q, e.ID, "ssh-ed25519 HOSTKEY", later))
		e = must(ConfirmTunnelEnrollment(ctx, q, e.ID, "ssh-ed25519 HOSTKEY", later))
		if e.Phase != PhaseConfirmed || e.ConfirmedHostKey != e.ScannedHostKey {
			t.Fatalf("confirmed = %+v", e)
		}
		e = must(EndTunnelEnrollment(ctx, q, e.ID, PhaseConfirmed, PhaseCommitted, later))
		if !EnrollmentFinished(e.Phase) {
			t.Fatalf("phase = %s", e.Phase)
		}
		_, err := OpenTunnelEnrollmentByName(ctx, q, "vps1")
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseCommitted, PhaseStarted, TunnelObjects{}, later)
		if err == nil || !strings.Contains(err.Error(), "does not change phase") {
			t.Fatalf("a finished enrollment moved: %v", err)
		}
	})
}

func TestTunnelEnrollmentObjectIDsAreWriteOnce(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		e := f.enrollment(ctx, q, "vps1")
		must(AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseStarted, PhaseTunnelCreated, TunnelObjects{TunnelID: "tun"}, testEpoch))

		_, err := AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseTunnelCreated, PhaseIngressSet, TunnelObjects{TunnelID: "other"}, testEpoch)
		if err == nil || !strings.Contains(err.Error(), "recorded object IDs") {
			t.Fatalf("a recorded tunnel ID changed: %v", err)
		}
		// the same ID again, or an empty one, is not a change
		must(AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseTunnelCreated, PhaseIngressSet, TunnelObjects{TunnelID: "tun"}, testEpoch))
		got := must(AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseIngressSet, PhaseAccessReady, TunnelObjects{}, testEpoch))
		if got.Objects.TunnelID != "tun" {
			t.Fatalf("tunnel id = %q", got.Objects.TunnelID)
		}

		for _, stmt := range []string{
			`UPDATE tunnel_enrollments SET identity_public_key = 'x' WHERE id = ?`,
			`UPDATE tunnel_enrollments SET name = 'x' WHERE id = ?`,
			`UPDATE tunnel_enrollments SET dns_record_id = 'a' WHERE id = ?`, // allowed once: tested below
		} {
			_, err := q.ExecContext(ctx, stmt, e.ID)
			if strings.Contains(stmt, "dns_record_id") {
				if err != nil {
					t.Fatalf("first write of an ID: %v", err)
				}
				continue
			}
			if err == nil {
				t.Errorf("%q succeeded, want the identity snapshot and name to be immutable", stmt)
			}
		}
		_, err = q.ExecContext(ctx, `UPDATE tunnel_enrollments SET dns_record_id = 'b' WHERE id = ?`, e.ID)
		if err == nil {
			t.Error("a recorded DNS record ID was replaced")
		}
	})
}

func TestOneOpenEnrollmentPerName(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		first := f.enrollment(ctx, q, "vps1")
		f.enrollment(ctx, q, "vps2") // another name is unaffected

		dup := TunnelEnrollment{
			ID: f.ids.NewID(), Name: "vps1", AccountID: "a", Zone: "z", InstanceID: "i", Hostname: "h",
			ExpiresAt: testEpoch.Add(time.Hour), CreatedAt: testEpoch,
			Identity: EnrollmentIdentity{PublicKey: "k", Fingerprint: "f", CredentialRef: "r"},
		}
		_, err := CreateTunnelEnrollment(ctx, q, dup)
		wantError(t, err, smerr.CodeConflict, "")

		// a halted enrollment keeps the name: its Cloudflare objects may exist
		must(HaltTunnelEnrollment(ctx, q, first.ID, PhaseStarted, PhaseConflict, "taken", testEpoch))
		_, err = CreateTunnelEnrollment(ctx, q, dup)
		wantError(t, err, smerr.CodeConflict, "")

		// removal in progress still holds it; the end releases it
		first = must(ResumeHaltedTunnelEnrollment(ctx, q, first.ID, PhaseConflict, testEpoch))
		first = must(StartTunnelEnrollmentRemoval(ctx, q, first.ID, PhaseStarted, "expired", testEpoch))
		if first.Phase != PhaseRemoving || first.TerminalReason != "expired" {
			t.Fatalf("removing = %+v", first)
		}
		_, err = CreateTunnelEnrollment(ctx, q, dup)
		wantError(t, err, smerr.CodeConflict, "")
		for _, step := range [][2]TunnelPhase{{PhaseRemoving, PhaseRouteClosed}, {PhaseRouteClosed, PhaseAccessRemoved}, {PhaseAccessRemoved, PhaseTunnelDeleted}} {
			must(AdvanceTunnelEnrollment(ctx, q, first.ID, step[0], step[1], TunnelObjects{}, testEpoch))
		}
		must(EndTunnelEnrollment(ctx, q, first.ID, PhaseTunnelDeleted, PhaseExpired, testEpoch))
		must(CreateTunnelEnrollment(ctx, q, dup))
	})
}

func TestConfirmTunnelEnrollmentIsACompareAndSwap(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		e := f.enrollment(ctx, q, "vps1")
		_, err := ConfirmTunnelEnrollment(ctx, q, e.ID, "ssh-ed25519 A", testEpoch)
		wantError(t, err, smerr.CodeConflict, "") // nothing scanned yet

		must(AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseStarted, PhaseDNSCreated, TunnelObjects{}, testEpoch))
		must(RecordScannedHostKey(ctx, q, e.ID, "ssh-ed25519 A", testEpoch))
		_, err = ConfirmTunnelEnrollment(ctx, q, e.ID, "ssh-ed25519 B", testEpoch)
		wantError(t, err, smerr.CodeConflict, "") // not the key the operator saw

		// a rescan replaces an unconfirmed key, and the old confirmation then loses
		must(RecordScannedHostKey(ctx, q, e.ID, "ssh-ed25519 B", testEpoch))
		_, err = ConfirmTunnelEnrollment(ctx, q, e.ID, "ssh-ed25519 A", testEpoch)
		wantError(t, err, smerr.CodeConflict, "")

		// a cancel that got there first wins
		must(StartTunnelEnrollmentRemoval(ctx, q, e.ID, PhaseScanned, "cancelled", testEpoch))
		_, err = ConfirmTunnelEnrollment(ctx, q, e.ID, "ssh-ed25519 B", testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		if got := must(GetTunnelEnrollment(ctx, q, e.ID)); got.ConfirmedHostKey != "" || got.Phase != PhaseRemoving {
			t.Fatalf("a refused confirmation changed the record: %+v", got)
		}
		_, err = RecordScannedHostKey(ctx, q, e.ID, "ssh-ed25519 C", testEpoch)
		wantError(t, err, smerr.CodeConflict, "") // a confirmed or removed enrollment is not rescanned
	})
}

func TestConfirmedHostKeyIsWriteOnceAndMatchesTheScan(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		e := f.enrollment(ctx, q, "vps1")
		must(AdvanceTunnelEnrollment(ctx, q, e.ID, PhaseStarted, PhaseDNSCreated, TunnelObjects{}, testEpoch))
		must(RecordScannedHostKey(ctx, q, e.ID, "ssh-ed25519 A", testEpoch))
		must(ConfirmTunnelEnrollment(ctx, q, e.ID, "ssh-ed25519 A", testEpoch))
		for _, stmt := range []string{
			`UPDATE tunnel_enrollments SET confirmed_host_key = 'ssh-ed25519 Z', scanned_host_key = 'ssh-ed25519 Z' WHERE id = ?`,
			`UPDATE tunnel_enrollments SET scanned_host_key = 'ssh-ed25519 Z' WHERE id = ?`,
		} {
			if _, err := q.ExecContext(ctx, stmt, e.ID); err == nil {
				t.Errorf("%q succeeded after the confirmation", stmt)
			}
		}
	})
}

func TestImportCommittedTunnelOperation(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node := f.tunnelNode(ctx, q, "n1")
		op := must(ImportCommittedTunnelOperation(ctx, q, TunnelOperation{
			ID: f.ids.NewID(), NodeID: node.ID, AccountID: "acct", Zone: "example.com", InstanceID: "inst",
			Hostname: "ssh-n1.example.com", CreatedAt: testEpoch,
			Objects: TunnelObjects{TunnelID: "tun", DNSRecordID: "dns", AccessAppID: "app"},
		}))
		if op.Phase != PhaseCommitted || op.Kind != TunnelEnable || op.Generation != 1 ||
			op.Objects != (TunnelObjects{TunnelID: "tun", DNSRecordID: "dns", AccessAppID: "app"}) {
			t.Fatalf("imported = %+v", op)
		}
		_, err := ActiveTunnelOperation(ctx, q, node.ID)
		wantError(t, err, smerr.CodeNotFound, "") // finished: it holds nothing

		// the node can run the next operation, whose generation follows
		next := f.tunnelOp(ctx, q, node, TunnelDisable)
		if next.Generation != 2 {
			t.Fatalf("next generation = %d", next.Generation)
		}
		// and the imported IDs stay put
		_, err = q.ExecContext(ctx, `UPDATE tunnel_operations SET tunnel_id = 'other' WHERE id = ?`, op.ID)
		if err == nil {
			t.Error("an imported object ID was replaced")
		}
	})
}
