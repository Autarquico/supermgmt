package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// holdName opens a tunnel enrollment for name, as the start of `sm nodes add --tunnel` does.
func holdName(t *testing.T, f *fixture, name string) domain.ID {
	t.Helper()
	id, now := f.ids.NewID(), f.clock.Now()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.CreateTunnelEnrollment(ctx, tx, database.TunnelEnrollment{
			ID: id, Name: name, AccountID: "acct", Zone: "example.test", Hostname: "ssh-" + name + ".example.test",
			InstanceID: "inst", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			Identity: database.EnrollmentIdentity{PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:x", CredentialRef: "secret://id#1"},
		})
		return err
	})
	return id
}

func releaseName(t *testing.T, f *fixture, id domain.ID) {
	t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.EndTunnelEnrollment(ctx, tx, id, database.PhaseStarted, database.PhaseCancelled, f.clock.Now())
		return err
	})
}

func TestAnOpenEnrollmentReservesItsNameAgainstAnOrdinaryAdd(t *testing.T) {
	n := newNodeFixture(t)
	id := holdName(t, n.fixture, "edge-9")
	nodes := len(mustNodes(t, n.fixture))

	_, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), n.addRequest("edge-9", ""))

	if smerr.CodeOf(err) != smerr.CodeConflict || !strings.Contains(err.Error(), "tunnel enrollment") {
		t.Fatalf("error = %v, want a conflict naming the open tunnel enrollment", err)
	}
	if len(mustNodes(t, n.fixture)) != nodes {
		t.Error("a node was created under the reserved name")
	}

	releaseName(t, n.fixture, id)
	n.addApplied("edge-9", "")
}

func TestRequireNameFreeIgnoresTheEnrollmentThatBecomesTheNode(t *testing.T) {
	n := newNodeFixture(t)
	id := holdName(t, n.fixture, "edge-9")
	ctx, q := context.Background(), n.db.Reader()

	if err := requireNameFree(ctx, q, "edge-9", ""); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("at the start of another enrollment: error = %v, want a conflict", err)
	}
	if err := requireNameFree(ctx, q, "edge-9", id); err != nil {
		t.Errorf("inside the commit of the enrollment itself: %v", err)
	}
	if err := requireNameFree(ctx, q, "edge-9", n.ids.NewID()); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("another enrollment's commit: error = %v, want a conflict", err)
	}

	n.addApplied("taken", "")
	if err := requireNameFree(ctx, n.db.Reader(), "taken", id); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("a provider's name: error = %v, want a conflict even at commit", err)
	}
}

func TestAJoinTokenEnrollmentSkipsAnOpenEnrollmentsName(t *testing.T) {
	e := newEnrollmentFixture(t)
	holdName(t, e.fixture, "edge-1")
	issued := e.issue(wire.EnrollmentRequest{MaxNodes: 1})

	enrolled, err := e.enroll(enrollAs(issued.Token, "edge-1"))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	node, err := database.GetNode(context.Background(), e.db.Reader(), enrolled.NodeID)
	mustf(t, err, "GetNode")
	if !strings.HasPrefix(node.Name, "edge-1-") {
		t.Errorf("name = %q, want edge-1-<digest>: the name is reserved by the open enrollment", node.Name)
	}
}

// Repairing the instance policies also re-attaches the Access application of an enrollment that has no node.
func TestPolicyRepairCoversTheAccessApplicationOfAnOpenEnrollment(t *testing.T) {
	ts, r, _ := provisionedEnrollment(t)
	ctx := context.Background()
	state := ts.state()
	replacement := ts.cf.SeedPolicy(cloudflare.OwnersPolicyName(r.instanceID), "owner@example.test")
	state.OwnersPolicyID = replacement.ID

	mustf(t, r.reattachAccessApps(ctx, state), "reattachAccessApps")

	apps := ts.cf.Snapshot().Apps
	want := []string{state.ServicePolicyID, replacement.ID}
	if len(apps) != 1 || len(apps[0].PolicyIDs) != 2 || apps[0].PolicyIDs[0] != want[0] || apps[0].PolicyIDs[1] != want[1] {
		t.Fatalf("Access application policies = %+v, want %v", apps, want)
	}
	if len(ts.events("cloudflare.access_app.updated")) != 1 {
		t.Errorf("%d access_app.updated events, want 1", len(ts.events("cloudflare.access_app.updated")))
	}

	before := len(ts.cf.Mutations())
	mustf(t, r.reattachAccessApps(ctx, state), "second reattachAccessApps")
	if got := len(ts.cf.Mutations()); got != before {
		t.Errorf("an application already right was updated again (%d mutations)", got-before)
	}
}
