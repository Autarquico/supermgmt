package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// brokenConnector is what the pool reports when cloudflared cannot carry the
// stream: the carrier's scrubbed diagnostics ride along in the text.
func brokenConnector() error {
	return smerr.Wrap(ssh.CarrierFailure(io.EOF), smerr.CodeNodeUnreachable, "", "ssh handshake (ERR tunnel not found secret=hunter2)")
}

// failingNode is a node whose every command fails with err.
func failingNode(t *testing.T, err error) *fakeNode {
	t.Helper()
	n := newFakeNode(t)
	n.fallback = func(templates.Command) (transport.Result, error) { return transport.Result{}, err }
	return n
}

// directAdminDials counts the admin sessions opened over direct SSH so far.
func (ts *tunnelSetting) directAdminDials() int {
	n := 0
	for _, target := range ts.dialer.targets() {
		if target.User == "admin" && target.Transport.Effective() == domain.TransportDirect {
			n++
		}
	}
	return n
}

// rerunWithTunnelAdmin makes the admin session over the tunnel fail with err
// and reruns the tunnel setup of the enabled node.
func (ts *tunnelSetting) rerunWithTunnelAdmin(err error) error {
	ts.t.Helper()
	ts.dialer.tunnel["admin"] = failingNode(ts.t, err)
	ts.plan()
	return ts.attempt()
}

func (ts *tunnelSetting) wantStillThroughTheTunnel(before domain.Node) {
	ts.t.Helper()
	got := ts.currentNode()
	if got.Endpoint.Transport != domain.TransportCloudflare || got.Endpoint.TunnelHostname != ts.hostname() || got.SpecRevision != before.SpecRevision {
		ts.t.Errorf("endpoint = %s %q rev %d, want cloudflare %q rev %d", got.Endpoint.Transport, got.Endpoint.TunnelHostname, got.SpecRevision,
			ts.hostname(), before.SpecRevision)
	}
}

func TestASetupOverAHealthyTunnelNeverFallsBackToDirect(t *testing.T) {
	ts := newEnabledTunnel(t)
	dials := ts.directAdminDials()

	ts.plan()
	mustf(t, ts.attempt(), "rerun over a healthy tunnel")

	if got := ts.directAdminDials() - dials; got != 0 {
		t.Errorf("%d admin sessions over direct SSH, want none", got)
	}
	if got := len(ts.events(eventTunnelSetupDirect)); got != 0 {
		t.Errorf("%d fallback events, want none", got)
	}
}

func TestARerunRepairsABrokenConnectorOverDirectSSHAndVerifiesOverTheTunnel(t *testing.T) {
	ts := newEnabledTunnel(t)
	before := ts.currentNode()
	dials := ts.directAdminDials()
	filesBefore := len(ts.files)

	mustf(t, ts.rerunWithTunnelAdmin(brokenConnector()), "rerun with a broken connector")

	if got := ts.directAdminDials() - dials; got < 1 {
		t.Errorf("%d admin sessions over direct SSH, want the bootstrap session", got)
	}
	ts.wantStillThroughTheTunnel(before)
	if got := ts.operations()[0].Phase; got != database.PhaseCommitted {
		t.Errorf("phase = %s, want committed", got)
	}
	if len(ts.files) != filesBefore {
		t.Errorf("node files = %d, want %d", len(ts.files), filesBefore)
	}
	fallbacks := ts.events(eventTunnelSetupDirect)
	if len(fallbacks) != 1 {
		t.Fatalf("%d fallback events, want 1", len(fallbacks))
	}
	data := string(mustJSON(t, fallbacks[0].Data))
	if !strings.Contains(data, reasonCarrierFailure) {
		t.Errorf("event data %s lacks the reason", data)
	}
	for _, leak := range []string{"hunter2", "tunnel not found", "EOF"} {
		if strings.Contains(data, leak) {
			t.Errorf("event data %s carries the carrier's words %q", data, leak)
		}
	}
	verifiedThroughTunnel := false
	for _, target := range ts.dialer.targets() {
		verifiedThroughTunnel = verifiedThroughTunnel || (target.User == "supermgmt" && target.Transport == domain.TransportCloudflare)
	}
	if !verifiedThroughTunnel {
		t.Error("the dedicated account was never verified over the tunnel")
	}
}

func TestAnAccessDenialOrAnAuthenticationFailureOverTheTunnelDoesNotFallBack(t *testing.T) {
	tests := map[string]error{
		"Access denied": smerr.New(smerr.CodeNodeUnreachable, "",
			"Cloudflare Access did not admit the service token for "+"ssh-web-1.example.test"+": check that the token is in the application's service policy"),
		"authentication failed": smerr.Wrap(errors.New("unable to authenticate"), smerr.CodeNodeUnreachable, "",
			"ssh authentication failed for user admin: the node does not accept the offered keys"),
		"host key mismatch": smerr.Wrap(ssh.CarrierFailure(io.EOF), smerr.CodeSSHHostKeyMismatch, "", "ssh host key does not match the pinned key"),
		"timeout":           smerr.Wrap(ssh.CarrierFailure(context.DeadlineExceeded), smerr.CodeNodeUnreachable, "", "ssh handshake timed out"),
	}
	for name, tunnelErr := range tests {
		t.Run(name, func(t *testing.T) {
			ts := newEnabledTunnel(t)
			before := ts.currentNode()
			dials := ts.directAdminDials()

			err := ts.rerunWithTunnelAdmin(tunnelErr)

			if err == nil {
				t.Fatal("setup succeeded, want the tunnel failure")
			}
			if got := ts.directAdminDials() - dials; got != 0 {
				t.Errorf("%d admin sessions over direct SSH, want none", got)
			}
			if got := len(ts.events(eventTunnelSetupDirect)); got != 0 {
				t.Errorf("%d fallback events, want none", got)
			}
			ts.wantStillThroughTheTunnel(before)
		})
	}
}

func TestAFallbackWithTheDirectRouteAlsoDownNamesBothPaths(t *testing.T) {
	ts := newEnabledTunnel(t)
	before := ts.currentNode()
	ts.dialer.route(ts.node.ID, failingNode(t, smerr.New(smerr.CodeNodeUnreachable, "", "ssh dial: connection refused")))

	err := ts.rerunWithTunnelAdmin(brokenConnector())

	if err == nil {
		t.Fatal("setup succeeded with both routes down")
	}
	for _, path := range []string{"through the tunnel", "direct SSH", "tunnel not found", "connection refused"} {
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error %q does not name %q", err, path)
		}
	}
	ts.wantStillThroughTheTunnel(before)
}

func TestAFallbackRefusesAHostKeyThatDoesNotMatchOnTheDirectRoute(t *testing.T) {
	ts := newEnabledTunnel(t)
	before := ts.currentNode()
	direct := failingNode(t, smerr.New(smerr.CodeSSHHostKeyMismatch, "", "ssh host key does not match the pinned key"))
	ts.dialer.route(ts.node.ID, direct)

	err := ts.rerunWithTunnelAdmin(brokenConnector())

	if got := smerr.CodeOf(err); got != smerr.CodeSSHHostKeyMismatch {
		t.Fatalf("error code = %s (%v), want %s", got, err, smerr.CodeSSHHostKeyMismatch)
	}
	if !strings.Contains(err.Error(), "over direct SSH, after the tunnel could not carry the stream") || strings.Contains(err.Error(), "could not be reached") {
		t.Errorf("error %q must say the refusal came from direct SSH and not claim both routes are unreachable", err)
	}
	if n := len(direct.ran()); n != 1 {
		t.Errorf("%d commands ran over the direct route after the refusal, want only the first", n)
	}
	ts.wantStillThroughTheTunnel(before)
}

func TestAFallbackWhoseKeyTheDirectRouteRejectsSaysItCameFromDirectSSH(t *testing.T) {
	ts := newEnabledTunnel(t)
	before := ts.currentNode()
	rejected := smerr.Wrap(ssh.AuthRejected(errors.New("ssh: unable to authenticate")), smerr.CodeNodeUnreachable, "",
		"ssh authentication failed for user alex: the node does not accept the offered keys")
	ts.dialer.route(ts.node.ID, failingNode(t, rejected))

	err := ts.rerunWithTunnelAdmin(brokenConnector())

	if !ssh.IsAuthRejected(err) {
		t.Fatalf("error %v lost the authentication refusal", err)
	}
	if !strings.Contains(err.Error(), "over direct SSH, after the tunnel could not carry the stream") || strings.Contains(err.Error(), "could not be reached") {
		t.Errorf("error %q must say the refusal came from direct SSH and not claim both routes are unreachable", err)
	}
	ts.wantStillThroughTheTunnel(before)
}

func TestARepairedInstallThatFailsVerificationOverTheTunnelIsNotCommitted(t *testing.T) {
	ts := newEnabledTunnel(t)
	before := ts.currentNode()
	enabled := len(ts.events(eventTunnelEnabled))
	ts.dialer.tunnel["supermgmt"] = failingNode(t, brokenConnector())

	err := ts.rerunWithTunnelAdmin(brokenConnector())

	if err == nil {
		t.Fatal("setup succeeded though the tunnel still cannot carry the dedicated account")
	}
	if got := len(ts.events(eventTunnelSetupDirect)); got != 1 {
		t.Errorf("%d fallback events, want 1", got)
	}
	if got := len(ts.events(eventTunnelEnabled)); got != enabled {
		t.Errorf("%d enabled events, want %d: nothing may commit", got, enabled)
	}
	ts.wantStillThroughTheTunnel(before)
}

func TestOnlyATunnelSetupOfACommittedCloudflareNodeMayFallBack(t *testing.T) {
	run := &tunnelRun{}
	tunnelled := domain.Node{Endpoint: domain.NodeEndpoint{Transport: domain.TransportCloudflare}}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		run  *tunnelRun
		node domain.Node
		err  error
		want bool
	}{
		{"carrier failure of a tunnel setup", context.Background(), run, tunnelled, brokenConnector(), true},
		{"plain setup", context.Background(), nil, tunnelled, brokenConnector(), false},
		{"node still direct", context.Background(), run, domain.Node{}, brokenConnector(), false},
		{"setup cancelled", cancelled, run, tunnelled, brokenConnector(), false},
		{"unmarked unreachable", context.Background(), run, tunnelled, smerr.New(smerr.CodeNodeUnreachable, "", "Access refused"), false},
	}
	for _, tc := range tests {
		if got := mayFallBackToDirect(tc.ctx, tc.run, tc.node, tc.err); got != tc.want {
			t.Errorf("%s: mayFallBackToDirect = %v, want %v", tc.name, got, tc.want)
		}
	}
}
