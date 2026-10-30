package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// A node that never answers directly is enrolled end to end: the Cloudflare side before any node row, the
// node line, the scan over the tunnel, the operator's confirmation, the proof and the commit.
func TestEnrollmentFromStartToCommitNeverDialsTheNodeDirectly(t *testing.T) {
	es := newEnrollSetting(t)
	baseNodes := es.nodeCount()

	view := es.start()
	if view.Phase != string(database.PhaseStarted) || view.Hostname != "ssh-vps1."+cffake.DefaultZone {
		t.Fatalf("view = %+v", view)
	}
	instance, err := database.GetInstance(context.Background(), es.db.Reader())
	mustf(t, err, "GetInstance")
	wantLine := "curl -fsSL https://raw.githubusercontent.com/autarquico/supermgmt/main/scripts/join.sh | sudo sh -s -- --tunnel --instance " +
		instance.ID.String() + " --authorized-key '" + es.identity.AuthorizedKey + "'"
	if view.JoinLine != wantLine {
		t.Errorf("join line = %q\nwant        %q", view.JoinLine, wantLine)
	}
	if _, found := es.nodeNamed("vps1"); found {
		t.Fatal("a node row exists at the start")
	}

	// the Cloudflare side is built without any node row; the node is not up yet
	if failures := es.work(); len(failures) != 0 {
		t.Fatalf("provisioning failed: %v", failures)
	}
	row := es.enrollmentRow(view.ID)
	if row.Phase != database.PhaseDNSCreated || !strings.Contains(row.LastError, "waiting for the node") {
		t.Fatalf("phase = %s (%q), want dns_created waiting for the node", row.Phase, row.LastError)
	}
	if es.nodeCount() != baseNodes {
		t.Fatal("a node row exists before the commit")
	}
	order := cloudflareOps(es.cf)
	tunnelAt, ingressAt := indexOf(order, cffake.OpTunnelCreate), indexOf(order, cffake.OpTunnelConfigPut)
	appAt, dnsAt := indexOf(order, cffake.OpAppCreate), indexOf(order, cffake.OpDNSCreate)
	if tunnelAt < 0 || tunnelAt >= ingressAt || ingressAt >= appAt || appAt >= dnsAt {
		t.Errorf("mutation order %v, want tunnel, ingress, Access application, DNS", order)
	}
	if routable := es.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		t.Errorf("routable without Access: %v", routable)
	}
	token := es.tokenOf("vps1")

	// the node's connector comes up: the scan persists its key and waits for the operator
	key := es.nodeComesUp()
	row = es.settle(view.ID, 3)
	if row.Phase != database.PhaseScanned || row.ScannedHostKey != key || row.LastError != "" {
		t.Fatalf("after the scan: %s %q (%q)", row.Phase, row.ScannedHostKey, row.LastError)
	}
	shown, err := es.svc.Get(context.Background(), es.admin(), "vps1")
	mustf(t, err, "Get")
	if want, _ := sshnode.Fingerprint(key); shown.HostKeyFingerprint != want || shown.HostPublicKey != key {
		t.Errorf("view shows %q / %q, want the scanned key", shown.HostPublicKey, shown.HostKeyFingerprint)
	}

	confirmed, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
	mustf(t, err, "Confirm")
	if confirmed.Phase != string(database.PhaseConfirmed) {
		t.Fatalf("confirmed phase = %s", confirmed.Phase)
	}
	row = es.settle(view.ID, 3)
	if row.Phase != database.PhaseCommitted {
		t.Fatalf("phase = %s (%q), want committed", row.Phase, row.LastError)
	}

	node, found := es.nodeNamed("vps1")
	if !found || es.nodeCount() != baseNodes+1 {
		t.Fatalf("node found = %v, nodes = %d", found, es.nodeCount())
	}
	wantEndpoint := domain.NodeEndpoint{
		Host: row.Hostname, Port: 22, User: "supermgmt", HostPublicKey: key,
		Transport: domain.TransportCloudflare, TunnelHostname: row.Hostname,
	}
	if node.ID != view.ID || node.Endpoint != wantEndpoint || node.Endpoint.AdminUser != "" {
		t.Errorf("node = %+v", node)
	}
	if node.CredentialRef != row.Identity.CredentialRef || !tunnelOnly(node) || node.Kind != "ssh" || node.ManagementState != domain.ManagementManaged {
		t.Errorf("credential %q tunnel_only %v kind %q state %q", node.CredentialRef, tunnelOnly(node), node.Kind, node.ManagementState)
	}
	op, err := database.ActiveTunnelOperation(context.Background(), es.db.Reader(), node.ID)
	wantCode(t, err, smerr.CodeNotFound) // nothing is held: the imported operation is committed
	ops, err := database.ListTunnelOperations(context.Background(), es.db.Reader(), node.ID)
	mustf(t, err, "ListTunnelOperations")
	if len(ops) != 1 || ops[0].Phase != database.PhaseCommitted || ops[0].Objects != row.Objects || ops[0].Objects.TunnelID == "" {
		t.Errorf("tunnel operations = %+v (active %+v), enrollment objects %+v", ops, op, row.Objects)
	}
	added := es.events(actionNodeAdd)
	if len(added) != 1 || added[0].Data["transport"] != "cloudflare" || added[0].Data["host_key_fingerprint"] == "" {
		t.Errorf("node.add events = %+v", added)
	}

	// the node was never dialled by address, in the scan or in the proof
	if len(es.scanned) == 0 {
		t.Fatal("no scan")
	}
	for _, target := range es.scanned {
		if target.Transport != domain.TransportCloudflare || target.Host != row.Hostname || target.TunnelHostname != row.Hostname || target.Port != 22 {
			t.Errorf("scan target = %+v", target)
		}
	}
	proven := 0
	for _, target := range es.dialer.targets() {
		if target.NodeID == node.ID {
			proven++
			if target.Transport != domain.TransportCloudflare || target.Host != row.Hostname || target.HostKey != key || target.User != "supermgmt" ||
				target.CredentialRef != row.Identity.CredentialRef {
				t.Errorf("proof target = %+v", target)
			}
		}
	}
	if proven == 0 {
		t.Error("the node was not proven")
	}

	// the token is gone after the commit, and was in no row, audit event, job or view
	_, err = es.svc.Token(context.Background(), es.admin(), "vps1")
	wantCode(t, err, smerr.CodeConflict)
	if stored, _ := es.secrets.Get(context.Background(), secrets.Ref{Name: enrollmentTokenPrefix + view.ID.String()}); stored != retiredCredential {
		t.Errorf("the stored token is still readable after the commit")
	}
	if everything := es.everything(view.ID); strings.Contains(everything, token.Reveal()) {
		t.Error("the connector token is in an audit event, a job, a plan, the row or a view")
	}
}

// An approved plan starts the enrollment; no node row is inserted by the approval.
func TestAnApprovedPlanStartsTheEnrollmentInsteadOfInsertingANode(t *testing.T) {
	es := newEnrollSetting(t)
	baseNodes := es.nodeCount()

	res, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps1", Environment: "prod"})
	mustf(t, err, "Start")
	if res.Pending == nil || res.Applied != nil {
		t.Fatalf("a production enrollment is not parked for approval: %+v", res)
	}
	if _, err := database.OpenTunnelEnrollmentByName(context.Background(), es.db.Reader(), "vps1"); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Fatalf("the enrollment exists before its approval: %v", err)
	}
	if len(es.cf.Mutations()) != 0 {
		t.Fatal("Cloudflare was touched before the approval")
	}
	es.approveToQuorum(res.Pending.Job)

	if failures := es.work(); len(failures) != 0 {
		t.Fatalf("approved job failed: %v", failures)
	}
	row, err := database.OpenTunnelEnrollmentByName(context.Background(), es.db.Reader(), "vps1")
	mustf(t, err, "OpenTunnelEnrollmentByName")
	if row.Phase != database.PhaseDNSCreated || row.EnvironmentID != es.env.ID {
		t.Errorf("enrollment = %s in environment %q", row.Phase, row.EnvironmentID)
	}
	if es.nodeCount() != baseNodes {
		t.Error("the approval inserted a node")
	}
	if got := es.events(eventEnrollmentStarted); len(got) != 1 {
		t.Errorf("%d enrollment_started events, want 1", len(got))
	}
}

// Everything that can be refused is refused before Cloudflare is touched.
func TestAStartThatCannotSucceedTouchesNothing(t *testing.T) {
	es := newEnrollSetting(t)
	es.start()
	cases := []struct {
		name string
		do   func() error
		code smerr.Code
	}{
		{"name of a provider", func() error {
			_, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: es.provider.Name})
			return err
		}, smerr.CodeConflict},
		{"name of an open enrollment", func() error {
			_, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps1"})
			return err
		}, smerr.CodeConflict},
		{"name that is no hostname", func() error {
			_, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps.one"})
			return err
		}, smerr.CodeInvalidArgument},
		{"more than a day", func() error {
			_, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps2", ExpiresIn: 25 * time.Hour})
			return err
		}, smerr.CodeInvalidArgument},
		{"unknown environment", func() error {
			_, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps2", Environment: "nowhere"})
			return err
		}, smerr.CodeInvalidArgument},
		{"not allowed", func() error {
			_, err := es.svc.Start(context.Background(), es.caller(es.dave), StartTunnelEnrollment{Name: "vps2"})
			return err
		}, smerr.CodePolicyDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantCode(t, c.do(), c.code) })
	}
	if got := len(es.cf.Mutations()); got != 0 {
		t.Errorf("%d Cloudflare mutations from refused starts", got)
	}
}

func TestAStartWithoutACloudflareBlockNamesTheSettings(t *testing.T) {
	es := newEnrollSetting(t)
	svc := es.newService(nil)
	_, err := svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps2"})
	wantCode(t, err, smerr.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "cloudflare: block") {
		t.Errorf("error = %v, want the settings named", err)
	}
	if len(es.cf.Mutations()) != 0 {
		t.Error("Cloudflare was touched")
	}
}

// A key other than the scanned one ends the enrollment with SSH_HOST_KEY_MISMATCH, pins nothing and removes
// the Cloudflare objects.
func TestAWrongKeyEndsTheEnrollmentWithAMismatchAndCleansUp(t *testing.T) {
	for name, decide := range map[string]func(*enrollSetting, string) error{
		"another key": func(es *enrollSetting, _ string) error {
			_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", newAuthorizedKey())
			return err
		},
		"refused": func(es *enrollSetting, _ string) error {
			_, err := es.svc.Refuse(context.Background(), es.admin(), "vps1")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			es := newEnrollSetting(t)
			baseNodes := es.nodeCount()
			view, key := es.scannedEnrollment()

			wantCode(t, decide(es, key), smerr.CodeSSHHostKeyMismatch)
			if got := es.enrollmentRow(view.ID); got.Phase != database.PhaseMismatch || got.ConfirmedHostKey != "" {
				t.Fatalf("enrollment = %s, confirmed %q", got.Phase, got.ConfirmedHostKey)
			}
			row := es.settle(view.ID, 3)
			if row.Phase != database.PhaseCancelled || row.TerminalReason != string(smerr.CodeSSHHostKeyMismatch) || row.ConfirmedHostKey != "" {
				t.Fatalf("enrollment = %s / %q", row.Phase, row.TerminalReason)
			}
			es.wantNothingLeft()
			if es.nodeCount() != baseNodes {
				t.Error("a node row was written")
			}
			if _, err := database.OpenTunnelEnrollmentByName(context.Background(), es.db.Reader(), "vps1"); smerr.CodeOf(err) != smerr.CodeNotFound {
				t.Errorf("the name is still held: %v", err)
			}
		})
	}
}

// The confirmation is a compare-and-swap that a cancel, an expiry or a commit can win.
func TestConfirmationRacesWithCancelAndExpiry(t *testing.T) {
	t.Run("cancel before confirm", func(t *testing.T) {
		es := newEnrollSetting(t)
		view, key := es.scannedEnrollment()
		_, err := es.svc.Cancel(context.Background(), es.admin(), "vps1")
		mustf(t, err, "Cancel")
		_, err = es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		wantCode(t, err, smerr.CodeConflict)
		row := es.settle(view.ID, 3)
		if row.Phase != database.PhaseCancelled || row.TerminalReason != reasonCancelled {
			t.Fatalf("enrollment = %s / %q", row.Phase, row.TerminalReason)
		}
		es.wantNothingLeft()
		if _, found := es.nodeNamed("vps1"); found {
			t.Error("a cancelled enrollment became a node")
		}
	})
	t.Run("cancel between confirm and commit", func(t *testing.T) {
		es := newEnrollSetting(t)
		view, key := es.scannedEnrollment()
		_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		mustf(t, err, "Confirm")
		_, err = es.svc.Cancel(context.Background(), es.admin(), "vps1")
		mustf(t, err, "Cancel")

		row := es.settle(view.ID, 3)
		if row.Phase != database.PhaseCancelled {
			t.Fatalf("phase = %s, want cancelled: a cancel beats the commit", row.Phase)
		}
		es.wantNothingLeft()
		if _, found := es.nodeNamed("vps1"); found {
			t.Error("a cancelled enrollment became a node")
		}
	})
	t.Run("expiry between confirm and commit", func(t *testing.T) {
		es := newEnrollSetting(t)
		view, key := es.scannedEnrollment()
		_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		mustf(t, err, "Confirm")
		es.clock.Advance(2 * time.Hour)

		row := es.settle(view.ID, 3)
		if row.Phase != database.PhaseExpired {
			t.Fatalf("phase = %s, want expired: an expired enrollment cannot be committed", row.Phase)
		}
		es.wantNothingLeft()
		if _, found := es.nodeNamed("vps1"); found {
			t.Error("an expired enrollment became a node")
		}
	})
	t.Run("confirm after the commit", func(t *testing.T) {
		es := newEnrollSetting(t)
		view, key := es.scannedEnrollment()
		_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		mustf(t, err, "Confirm")
		es.settle(view.ID, 3)
		_, err = es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		wantCode(t, err, smerr.CodeConflict)
		_, err = es.svc.Cancel(context.Background(), es.admin(), "vps1")
		wantCode(t, err, smerr.CodeConflict)
	})
	t.Run("confirm before the scan", func(t *testing.T) {
		es := newEnrollSetting(t)
		es.start()
		es.work()
		_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", newAuthorizedKey())
		wantCode(t, err, smerr.CodeConflict)
	})
}

// The proof and the commit use the identity snapshotted at the start, however the instance's identity
// changes afterwards.
func TestAnIdentityRotatedAfterTheStartDoesNotChangeTheEnrollment(t *testing.T) {
	es := newEnrollSetting(t)
	view := es.start()
	before := es.identity
	snapshotRef := pinnedIdentityRef(before)

	es.identity = secrets.Identity{
		Ref: secrets.Ref{Name: secrets.SSHIdentityName, Version: 2}, AuthorizedKey: newAuthorizedKey(), FingerprintSHA256: "SHA256:rotated",
	}
	es.work()
	key := es.nodeComesUp()
	es.settle(view.ID, 3)
	_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
	mustf(t, err, "Confirm")
	row := es.settle(view.ID, 3)
	if row.Phase != database.PhaseCommitted {
		t.Fatalf("phase = %s", row.Phase)
	}
	if row.Identity.PublicKey != before.AuthorizedKey || row.Identity.CredentialRef != snapshotRef {
		t.Errorf("snapshot = %+v, want %q / %q", row.Identity, before.AuthorizedKey, snapshotRef)
	}
	node, _ := es.nodeNamed("vps1")
	if node.CredentialRef != snapshotRef {
		t.Errorf("node credential = %q, want the snapshot %q", node.CredentialRef, snapshotRef)
	}
	for _, target := range es.dialer.targets() {
		if target.NodeID == node.ID && target.CredentialRef != snapshotRef {
			t.Errorf("proof used credential %q, want the snapshot %q", target.CredentialRef, snapshotRef)
		}
	}
	shown, err := es.svc.Get(context.Background(), es.admin(), "vps1")
	mustf(t, err, "Get")
	if !strings.Contains(shown.JoinLine, before.AuthorizedKey) || strings.Contains(shown.JoinLine, es.identity.AuthorizedKey) {
		t.Errorf("join line after the rotation = %q", shown.JoinLine)
	}
}

// A restart after the confirmation resumes the commit with exactly the confirmed key; a different key at
// the proof ends the enrollment as a mismatch.
func TestARestartAfterTheConfirmationCommitsTheConfirmedKey(t *testing.T) {
	t.Run("the same key", func(t *testing.T) {
		es := newEnrollSetting(t)
		view, key := es.scannedEnrollment()
		_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		mustf(t, err, "Confirm")
		es.restart()

		row := es.settle(view.ID, 3)
		node, found := es.nodeNamed("vps1")
		if row.Phase != database.PhaseCommitted || !found || node.Endpoint.HostPublicKey != key {
			t.Fatalf("phase = %s, node %v pinned %q, want %q", row.Phase, found, node.Endpoint.HostPublicKey, key)
		}
	})
	t.Run("another key at the proof", func(t *testing.T) {
		es := newEnrollSetting(t)
		view, key := es.scannedEnrollment()
		_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		mustf(t, err, "Confirm")
		es.restart()
		es.dialer.through("supermgmt").down("probe", smerr.New(smerr.CodeSSHHostKeyMismatch, "", "host key changed"))

		row := es.settle(view.ID, 4)
		if row.Phase != database.PhaseCancelled || row.TerminalReason != string(smerr.CodeSSHHostKeyMismatch) {
			t.Fatalf("enrollment = %s / %q, want cancelled by a mismatch", row.Phase, row.TerminalReason)
		}
		if _, found := es.nodeNamed("vps1"); found {
			t.Error("a node with a different key was written")
		}
		es.wantNothingLeft()
	})
	t.Run("the node is not answering yet", func(t *testing.T) {
		es := newEnrollSetting(t)
		view, key := es.scannedEnrollment()
		_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
		mustf(t, err, "Confirm")
		es.dialer.through("supermgmt").down("probe", transportDown())

		row := es.settle(view.ID, 2)
		if row.Phase != database.PhaseConfirmed || !strings.Contains(row.LastError, "waiting for the node") {
			t.Fatalf("enrollment = %s (%q), want confirmed and still waiting", row.Phase, row.LastError)
		}
		es.dialer.through("supermgmt").reply("probe", linuxProbe)
		if row = es.settle(view.ID, 3); row.Phase != database.PhaseCommitted {
			t.Fatalf("phase = %s, want committed once the node answers", row.Phase)
		}
	})
}

// An enrollment nobody completes is taken down in the disable order, keeps the instance's objects, releases
// its name and never writes a node.
func TestAnExpiredEnrollmentIsTakenDownAndTheNameReleased(t *testing.T) {
	es := newEnrollSetting(t)
	baseNodes := es.nodeCount()
	view := es.start()
	es.work()
	token := es.tokenOf("vps1")
	shared, base := es.instanceObjects(), len(es.cf.Mutations())

	es.clock.Advance(90 * time.Minute)
	row := es.settle(view.ID, 3)
	if row.Phase != database.PhaseExpired || row.TerminalReason != reasonExpired {
		t.Fatalf("enrollment = %s / %q", row.Phase, row.TerminalReason)
	}
	if got := es.committedOps(base); !equalOps(got, teardownOps) {
		t.Errorf("Cloudflare mutations = %v, want %v", got, teardownOps)
	}
	es.wantNothingLeft()
	if after := es.instanceObjects(); len(after.policies) != len(shared.policies) || len(after.tokens) != len(shared.tokens) {
		t.Error("the instance's policies or service token changed")
	}
	if es.nodeCount() != baseNodes {
		t.Error("a node row exists")
	}
	if _, err := es.svc.Token(context.Background(), es.admin(), "vps1"); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("token after the expiry: %v", err)
	}
	if stored, _ := es.secrets.Get(context.Background(), secrets.Ref{Name: enrollmentTokenPrefix + view.ID.String()}); stored != retiredCredential || strings.Contains(string(stored), token.Reveal()) {
		t.Error("the token is still stored after the expiry")
	}
	if _, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps1"}); err != nil {
		t.Errorf("the name was not released: %v", err)
	}
}

// An enrollment whose job ran out of attempts is halted, visible and held, not silently terminal; a cancel
// still cleans it up.
func TestAnEnrollmentWhoseJobsRunOutOfAttemptsIsHalted(t *testing.T) {
	es := newEnrollSetting(t)
	es.cf.Plan(func(cffake.Mutation) cffake.Fault { return cffake.FailBefore })
	view := es.start()

	failures := 0
	for range 3 {
		failures += len(es.work())
		es.clock.Advance(10 * time.Minute)
	}
	if failures != 3 {
		t.Fatalf("%d failed attempts, want 3", failures)
	}
	row := es.enrollmentRow(view.ID)
	if row.Phase != database.PhaseFailed || row.LastError == "" || row.HaltedPhase == "" {
		t.Fatalf("enrollment = %s (%q) halted at %q", row.Phase, row.LastError, row.HaltedPhase)
	}
	if got := es.events(eventEnrollmentHalted); len(got) != 1 {
		t.Errorf("%d halted events", len(got))
	}
	es.cf.Plan(func(cffake.Mutation) cffake.Fault { return cffake.NoFault })
	es.tick()
	if got := es.enrollmentRow(view.ID); got.Phase != database.PhaseFailed {
		t.Errorf("a halted enrollment moved to %s without anybody asking", got.Phase)
	}
	if _, err := es.svc.Start(context.Background(), es.admin(), StartTunnelEnrollment{Name: "vps1"}); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("the halted enrollment does not hold its name: %v", err)
	}

	_, err := es.svc.Cancel(context.Background(), es.admin(), "vps1")
	mustf(t, err, "Cancel")
	if row = es.settle(view.ID, 3); row.Phase != database.PhaseCancelled {
		t.Fatalf("phase = %s, want cancelled", row.Phase)
	}
	es.wantNothingLeft()
}

// Provisioning interrupted after any mutation resumes from the record without duplicating an object.
func TestProvisioningCrashedAfterEachMutationResumesWithoutDuplicates(t *testing.T) {
	baseline := newEnrollSetting(t)
	baseline.start()
	baseline.work()
	total := baseline.chaos.count
	want := baseline.cf.Snapshot()

	for k := 1; k <= total; k++ {
		t.Run(fmt.Sprintf("mutation %d of %d", k, total), func(t *testing.T) {
			es := newEnrollSetting(t)
			view := es.start()
			es.arm("crash", k)

			job, err, ran := es.runJob()
			if !ran || err == nil {
				t.Fatalf("the crash did not surface: ran %v, err %v", ran, err)
			}
			interruptAndRequeue(t, es.fixture, job.ID)
			if failures := es.work(); len(failures) != 0 {
				t.Fatalf("resumed run failed: %v", failures)
			}

			snap := es.cf.Snapshot()
			if len(snap.Tunnels) != len(want.Tunnels) || len(snap.Apps) != len(want.Apps) || len(snap.DNSRecords) != len(want.DNSRecords) ||
				len(snap.Policies) != len(want.Policies) || len(snap.ServiceTokens) != len(want.ServiceTokens) {
				t.Errorf("objects after the crash: %+v, want the counts of %+v", snap, want)
			}
			row := es.enrollmentRow(view.ID)
			if row.Phase != database.PhaseDNSCreated || row.Objects.TunnelID == "" || row.Objects.AccessAppID == "" || row.Objects.DNSRecordID == "" {
				t.Errorf("enrollment = %s %+v", row.Phase, row.Objects)
			}
			es.tokenOf("vps1")
		})
	}
}

// A connector token that is missing from the store when the node is scanned is read again from the tunnel.
func TestAMissingConnectorTokenIsReadAgainFromTheTunnel(t *testing.T) {
	es := newEnrollSetting(t)
	view := es.start()
	es.work()
	want := es.tokenOf("vps1")
	es.secrets.mu.Lock()
	delete(es.secrets.vals, enrollmentTokenPrefix+view.ID.String())
	es.secrets.mu.Unlock()
	if _, err := es.svc.Token(context.Background(), es.admin(), "vps1"); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("token without a stored secret: %v", err)
	}

	es.tick()
	if got := es.tokenOf("vps1"); got != want {
		t.Error("the restored token differs from the tunnel's")
	}
}

// A restart resumes the scan: a new service and scheduler over the same database submit the job at once.
func TestARestartResumesTheScan(t *testing.T) {
	es := newEnrollSetting(t)
	view := es.start()
	es.work()
	scansBefore := len(es.scanned)
	es.restart()
	key := es.nodeComesUp()

	mustf(t, es.sched.Tick(context.Background()), "Tick") // no clock movement: a new scheduler submits at once
	es.work()
	row := es.enrollmentRow(view.ID)
	if row.Phase != database.PhaseScanned || row.ScannedHostKey != key || len(es.scanned) <= scansBefore {
		t.Fatalf("phase %s, scanned %q", row.Phase, row.ScannedHostKey)
	}
}

// The scheduler does not stack jobs on an enrollment that has one, and backs off between scans.
func TestTheSchedulerSubmitsOneJobAtATimeWithBackoff(t *testing.T) {
	es := newEnrollSetting(t)
	es.start()
	es.work()

	count := func() int {
		var n int
		mustf(t, es.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM jobs WHERE state = 'queued'`).Scan(&n), "count")
		return n
	}
	es.clock.Advance(time.Minute)
	mustf(t, es.sched.Tick(context.Background()), "Tick")
	mustf(t, es.sched.Tick(context.Background()), "second Tick")
	if got := count(); got != 1 {
		t.Fatalf("%d queued jobs after two ticks, want 1", got)
	}
	es.work()
	scans := len(es.scanned)
	mustf(t, es.sched.Tick(context.Background()), "Tick")
	if got := count(); got != 0 {
		t.Errorf("a job was submitted inside the backoff")
	}
	es.clock.Advance(10 * time.Second)
	mustf(t, es.sched.Tick(context.Background()), "Tick")
	es.work()
	if len(es.scanned) != scans+1 {
		t.Errorf("%d scans, want %d", len(es.scanned), scans+1)
	}
}

// The commit checks the name again inside its transaction.
func TestTheCommitChecksTheNameAgain(t *testing.T) {
	es := newEnrollSetting(t)
	view, key := es.scannedEnrollment()
	_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
	mustf(t, err, "Confirm")
	es.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: es.ids.NewID(), Type: "ssh", Name: "vps1", Origin: domain.ProviderAPI, CreatedAt: es.clock.Now(), UpdatedAt: es.clock.Now(),
		})
		return err
	})

	failures := es.tick()
	if len(failures) == 0 || smerr.CodeOf(failures[0]) != smerr.CodeConflict {
		t.Fatalf("failures = %v, want a conflict on the name", failures)
	}
	if got := es.enrollmentRow(view.ID); got.Phase == database.PhaseCommitted {
		t.Error("committed over a taken name")
	}
	if _, found := es.nodeNamed("vps1"); found {
		t.Error("a node was written over a taken name")
	}
}

// The refusal to disable a tunnel-only node comes when the plan is asked for.
func TestDisablingATunnelOnlyNodeIsRefusedWhenPlanning(t *testing.T) {
	es := newEnrollSetting(t)
	view, key := es.scannedEnrollment()
	_, err := es.svc.Confirm(context.Background(), es.admin(), "vps1", key)
	mustf(t, err, "Confirm")
	es.settle(view.ID, 3)
	plansBefore := len(es.events("plan.create"))

	_, err = es.plans.Create(context.Background(), es.admin(), PlanRequest{
		Action: policy.ActionNodeTunnelDisable, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: view.ID},
	})
	wantCode(t, err, smerr.CodeCapabilityUnavailable)
	if !strings.Contains(err.Error(), "no direct path") {
		t.Errorf("error = %v", err)
	}
	if got := len(es.events("plan.create")); got != plansBefore {
		t.Errorf("a plan was created")
	}
}

// Reading the list and the token needs the right to do so; the list shows only open enrollments.
func TestReadsAndTheTokenAreAuthorized(t *testing.T) {
	es := newEnrollSetting(t)
	es.start()
	es.work()

	_, err := es.svc.Token(context.Background(), es.caller(es.dave), "vps1")
	wantCode(t, err, smerr.CodePolicyDenied)
	_, err = es.svc.Get(context.Background(), es.caller(es.dave), "vps1")
	wantCode(t, err, smerr.CodePolicyDenied)
	_, err = es.svc.Cancel(context.Background(), es.caller(es.dave), "vps1")
	wantCode(t, err, smerr.CodePolicyDenied)
	_, err = es.svc.Confirm(context.Background(), es.caller(es.dave), "vps1", newAuthorizedKey())
	wantCode(t, err, smerr.CodePolicyDenied)

	views, err := es.svc.List(context.Background(), es.admin())
	mustf(t, err, "List")
	if len(views) != 1 || views[0].Name != "vps1" {
		t.Errorf("list = %+v", views)
	}
	if none, err := es.svc.List(context.Background(), es.caller(es.dave)); err != nil || len(none) != 0 {
		t.Errorf("list for an identity without roles = %+v, %v", none, err)
	}
}

// The connector token is a credential: an mcp actor with the admin role and writes enabled can follow the
// enrollment, but never read its token.
func TestAnMCPActorNeverGetsTheConnectorToken(t *testing.T) {
	es := newEnrollSetting(t)
	es.start()
	es.work()
	es.svc.cfg.MCPWritesEnabled = true
	var assistant domain.ID
	es.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = es.fixture.identity(ctx, tx, "assistant", domain.ActorMCP, es.role(ctx, tx, "admin"))
		return nil
	})

	if _, err := es.svc.Get(context.Background(), es.caller(assistant), "vps1"); err != nil {
		t.Fatalf("Get as mcp: %v", err)
	}
	_, err := es.svc.Token(context.Background(), es.caller(assistant), "vps1")
	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonMCPActionForbidden)
	if _, err := es.svc.Token(context.Background(), es.admin(), "vps1"); err != nil {
		t.Errorf("Token as the admin: %v", err)
	}
}

func equalOps(a, b []cffake.Op) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func transportDown() error { return smerr.New(smerr.CodeInternal, "", "connection refused") }

// Only the job that can still initialise the service token and policies takes the instance-wide Cloudflare
// lock; the jobs that wait, scan, commit and tear down take only the node's own.
func TestOnlyTheProvisioningJobTakesTheInstanceLock(t *testing.T) {
	es := newEnrollSetting(t)
	es.start()
	takesInstance := func() bool {
		claimed, ok := es.claim()
		if !ok {
			t.Fatal("no job to claim")
		}
		specs, err := LockPlanner{}.PlanLocks(context.Background(), es.db.Reader(), claimed.Job)
		mustf(t, err, "PlanLocks")
		mustf(t, es.apply.Run(context.Background(), claimed.Lease), "Run")
		mustf(t, es.store.Succeed(context.Background(), claimed.Lease), "Succeed")
		return slices.Contains(specs, cloudflareInstanceLock)
	}
	if !takesInstance() {
		t.Error("the provisioning job does not take the instance lock")
	}
	es.clock.Advance(time.Minute)
	mustf(t, es.sched.Tick(context.Background()), "Tick")
	if takesInstance() {
		t.Error("the scan job takes the instance lock")
	}
}
