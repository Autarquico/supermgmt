package app

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

const enrollmentTestID domain.ID = "01970000-0000-7000-8000-0000000000e1"

// enrollmentRun is a run over a tunnel_enrollments row, for a node that has no row yet.
func (ts *tunnelSetting) enrollmentRun() (*tunnelRun, *enrollmentRecord) {
	ts.t.Helper()
	ctx := context.Background()
	ts.plan()
	claimed, ok := ts.claim()
	if !ok {
		ts.t.Fatal("no job to claim")
	}
	hostname, err := tunnelHostnameOf("vps1", cffake.DefaultZone)
	mustf(ts.t, err, "hostname")
	now := ts.clock.Now()
	var enrollment database.TunnelEnrollment
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		enrollment, err = database.CreateTunnelEnrollment(ctx, tx, database.TunnelEnrollment{
			ID: enrollmentTestID, Name: "vps1", AccountID: ts.cfg.AccountID, Zone: ts.cfg.Zone, Hostname: hostname,
			InstanceID: "inst", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			Identity: database.EnrollmentIdentity{PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:x", CredentialRef: "secret://id#1"},
		})
		return err
	})
	node := domain.Node{ID: enrollmentTestID, Name: "vps1"}
	r, err := ts.handler.tunnel.newRun(ctx, claimed.Lease, claimed.Job, node, hostname)
	mustf(ts.t, err, "newRun")
	rec := newEnrollmentRecord(enrollment, claimed.Lease, r.write, ts.clock.Now)
	r.rec = rec
	return r, rec
}

func cloudflareOps(f *cffake.Fake) []cffake.Op {
	var ops []cffake.Op
	for _, m := range f.Mutations() {
		ops = append(ops, m.Op)
	}
	return ops
}

// provisionCloudflare does the same over a tunnel_enrollments record as over the node's operation: the
// order tunnel, ingress, Access application, DNS, with every ID recorded.
func TestProvisionCloudflareOverAnEnrollmentRecord(t *testing.T) {
	ts := newTunnelSetting(t)
	r, rec := ts.enrollmentRun()

	token, err := r.provisionCloudflare(context.Background())
	mustf(t, err, "provisionCloudflare")
	if token == "" {
		t.Error("no connector token returned")
	}

	snap := ts.cf.Snapshot()
	if len(snap.Tunnels) != 1 || len(snap.Apps) != 1 || len(snap.DNSRecords) != 1 {
		t.Fatalf("objects: %d tunnels, %d apps, %d dns; want 1 each", len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords))
	}
	stored, err := database.GetTunnelEnrollment(context.Background(), ts.db.Reader(), enrollmentTestID)
	mustf(t, err, "GetTunnelEnrollment")
	want := database.TunnelObjects{TunnelID: snap.Tunnels[0].ID, AccessAppID: snap.Apps[0].ID, DNSRecordID: snap.DNSRecords[0].ID}
	if stored.Objects != want || rec.Objects() != want {
		t.Errorf("recorded %+v (in memory %+v), want %+v", stored.Objects, rec.Objects(), want)
	}
	if stored.Phase != database.PhaseDNSCreated {
		t.Errorf("phase = %s, want dns_created (waiting for the node)", stored.Phase)
	}
	if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		t.Errorf("routable without Access: %v", routable)
	}
	order := cloudflareOps(ts.cf)
	tunnelAt, ingressAt := indexOf(order, cffake.OpTunnelCreate), indexOf(order, cffake.OpTunnelConfigPut)
	appAt, dnsAt := indexOf(order, cffake.OpAppCreate), indexOf(order, cffake.OpDNSCreate)
	if tunnelAt < 0 || tunnelAt >= ingressAt || ingressAt >= appAt || appAt >= dnsAt {
		t.Errorf("mutation order %v, want tunnel, ingress, Access application, DNS", order)
	}

	// a second pass finds everything recorded and mutates nothing
	before := len(ts.cf.Mutations())
	_, err = r.provisionCloudflare(context.Background())
	mustf(t, err, "second provisionCloudflare")
	if got := len(ts.cf.Mutations()); got != before {
		t.Errorf("a converged record made %d more mutations", got-before)
	}
}

// The enrollment and the node's operation take the same Cloudflare steps.
func TestEnrollmentAndOperationRecordsMutateCloudflareIdentically(t *testing.T) {
	op := newTunnelSetting(t)
	op.plan()
	mustf(t, op.attempt(), "tunnel setup")

	enrolled := newTunnelSetting(t)
	r, _ := enrolled.enrollmentRun()
	_, err := r.provisionCloudflare(context.Background())
	mustf(t, err, "provisionCloudflare")

	if got, want := cloudflareOps(enrolled.cf), cloudflareOps(op.cf); !slices.Equal(got, want) {
		t.Errorf("enrollment mutations %v, operation mutations %v", got, want)
	}
}

// A conflicting object halts the enrollment and keeps its phase, as it halts an operation.
func TestEnrollmentRecordHaltsOnAnOwnershipConflict(t *testing.T) {
	ts := newTunnelSetting(t)
	r, rec := ts.enrollmentRun()
	ctx := context.Background()
	err := r.fail(ctx, newOwnershipConflict("tunnel", "x"))
	if err == nil {
		t.Fatal("fail returned nil")
	}
	stored, err := database.GetTunnelEnrollment(ctx, ts.db.Reader(), enrollmentTestID)
	mustf(t, err, "GetTunnelEnrollment")
	if stored.Phase != database.PhaseConflict || stored.HaltedPhase != database.PhaseStarted || stored.LastError == "" {
		t.Errorf("halted = %+v", stored)
	}
	if rec.Phase() != database.PhaseStarted {
		t.Errorf("in-memory phase = %s", rec.Phase())
	}
}
