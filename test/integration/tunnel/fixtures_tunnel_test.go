//go:build fixtures

package tunnel

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// The scenarios of docs/specs/cloudflare-tunnel-transport.md that need a real
// node: the Debian 13 systemd fixture, cffake for the Cloudflare API and the
// cloudflared stand-in (test/fixtures/cloudflared-fake) as the carrier. They
// prove the seams and the state machine against a real sshd, sudo and systemd;
// whether Cloudflare itself admits the token is the real-account checklist.

func TestTunnelLifecycleOnTheFixtureWithTheDirectRouteBlocked(t *testing.T) {
	f := newTunnelFixture(t, fixtureOptions{})

	f.mustSucceed(f.setup(false), "setup over the direct route")
	if err := f.restartDemo("tunnel-before"); err != nil {
		t.Fatalf("a service action over the direct route before the tunnel: %v", err)
	}

	f.mustSucceed(f.setup(true), "setup --tunnel")
	hostname := f.refresh().Endpoint.TunnelHostname

	t.Run("the transport reads cloudflare and every Cloudflare object carries the instance marker", func(t *testing.T) {
		node := f.refresh()
		if node.Endpoint.Transport != domain.TransportCloudflare || hostname != "ssh-"+nodeName+"."+zoneOf(f.cf) {
			t.Fatalf("endpoint = %+v, want transport cloudflare on ssh-%s.%s", node.Endpoint, nodeName, zoneOf(f.cf))
		}
		snap := f.cf.Snapshot()
		if len(snap.Tunnels) != 1 || len(snap.Apps) != 1 || len(snap.DNSRecords) != 1 || len(snap.Policies) != 2 || len(snap.ServiceTokens) != 1 {
			t.Fatalf("objects = %d tunnels, %d apps, %d dns, %d policies, %d tokens; want 1, 1, 1, 2, 1",
				len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords), len(snap.Policies), len(snap.ServiceTokens))
		}
		instance := string(f.instanceRef().ID)
		marker := cloudflare.DNSComment(instance, string(node.ID))
		if rec := snap.DNSRecords[0]; rec.Name != hostname || !rec.Proxied || rec.Comment != marker {
			t.Errorf("dns record = %+v, want a proxied record for %s marked %q", rec, hostname, marker)
		}
		if snap.Tunnels[0].Name != cloudflare.TunnelName(instance, string(node.ID)) ||
			!slices.Contains(snap.Tunnels[0].Ingress, cffake.Ingress{Hostname: hostname, Service: "ssh://localhost:22"}) {
			t.Errorf("tunnel = %+v, want the instance's name and an ssh ingress for %s", snap.Tunnels[0], hostname)
		}
		if snap.Apps[0].Name != cloudflare.AccessAppName(instance, string(node.ID)) || snap.Apps[0].Domain != hostname {
			t.Errorf("access app = %+v, want the instance's name on %s", snap.Apps[0], hostname)
		}
		if routable := f.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
			t.Errorf("hostnames routable without Access at some point: %v", routable)
		}
	})

	t.Run("cloudflared runs on the node from a root-only token file and its argv carries no credential", func(t *testing.T) {
		if got := sh(t, f.docker, "systemctl is-active "+tunnelSvc); got != "active" {
			t.Fatalf("%s is %q, want active", tunnelSvc, got)
		}
		if got := sh(t, f.docker, "stat -c '%U:%G %a' /etc/supermgmt/cloudflared/token"); got != "root:root 600" {
			t.Errorf("token file = %q, want root:root 600", got)
		}
		if got := sh(t, f.docker, "stat -c '%U:%G %a' /etc/supermgmt/cloudflared"); got != "root:root 700" {
			t.Errorf("token directory = %q, want root:root 700", got)
		}
		argv := stubRecord(t, f.docker, "argv")
		if !strings.Contains(argv, "--token-file "+credentialPath) || strings.Contains(argv, "--token ") {
			t.Errorf("cloudflared argv = %q, want --token-file <its credential> and no --token", argv)
		}
		if size := stubRecord(t, f.docker, "token-file-size"); size == "-1" || size == "0" {
			t.Errorf("the token file the service saw has size %s, want the token", size)
		}
		unit := sh(t, f.docker, "systemctl cat "+tunnelSvc)
		if strings.Contains(unit, "TUNNEL_TOKEN") || strings.Contains(unit, "Environment=") {
			t.Errorf("the unit carries a credential in its environment:\n%s", unit)
		}
	})

	f.blockDirectRoute()

	t.Run("the direct route is dead", func(t *testing.T) {
		if err := f.directRouteIsDead(); err == nil {
			t.Fatal("a direct session to the blocked address succeeded; the block proves nothing")
		}
	})

	t.Run("probes, service actions and logs keep working through the tunnel", func(t *testing.T) {
		f.mustSucceed(f.run("node.probe", nodeRef(f.node), nil), "probe through the tunnel")
		if err := f.restartDemo("tunnel-blocked"); err != nil {
			t.Errorf("a service action through the tunnel: %v", err)
		}
		if err := f.readLogs(); err != nil {
			t.Errorf("logs through the tunnel: %v", err)
		}
	})

	t.Run("the carrier ran with the explicit argv and a minimal environment", func(t *testing.T) {
		records := f.carrierRecords()
		if len(records) == 0 {
			t.Fatal("no carrier process was started: the node was not reached through the tunnel")
		}
		for _, r := range records {
			if len(r.Argv) != 5 || r.Argv[1] != "access" || r.Argv[2] != "ssh" || r.Argv[3] != "--hostname" || r.Argv[4] != hostname {
				t.Errorf("carrier argv = %q, want [cloudflared access ssh --hostname %s]", r.Argv, hostname)
			}
			var keys []string
			for _, kv := range r.Env {
				k, _, _ := strings.Cut(kv, "=")
				keys = append(keys, k)
			}
			slices.Sort(keys)
			if want := []string{"HOME", "TUNNEL_SERVICE_TOKEN_ID", "TUNNEL_SERVICE_TOKEN_SECRET"}; !slices.Equal(keys, want) {
				t.Errorf("carrier environment = %v, want exactly %v", keys, want)
			}
		}
	})

	t.Run("a rotation keeps fresh connections succeeding and deletes the old token last", func(t *testing.T) {
		oldToken := f.cf.ServiceTokens()[0]
		var failures, probes atomic.Int64
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				f.pool.InvalidateNode(f.node.ID) // every probe dials afresh, so it presents the token stored right now
				probes.Add(1)
				if err := f.readLogs(); err != nil {
					failures.Add(1)
					t.Logf("probe during rotation: %v", err)
				}
			}
		})
		job := f.run("cloudflare.access_token.rotate", f.instanceRef(), nil)
		close(stop)
		wg.Wait()
		f.mustSucceed(job, "rotation")
		if probes.Load() == 0 || failures.Load() != 0 {
			t.Errorf("%d of %d probes failed during the rotation, want none (and at least one probe)", failures.Load(), probes.Load())
		}
		tokens := f.cf.ServiceTokens()
		if len(tokens) != 1 || tokens[0].ID == oldToken.ID {
			t.Fatalf("tokens after rotation = %+v, want only a new one (old %s)", tokens, oldToken.ID)
		}
		for _, p := range f.cf.Policies() {
			if p.Decision == "non_identity" && !slices.Equal(p.ServiceTokenIDs, []string{tokens[0].ID}) {
				t.Errorf("service policy %s admits %v, want only the new token %s", p.Name, p.ServiceTokenIDs, tokens[0].ID)
			}
		}
		mutations := f.cf.Mutations()
		if last := mutations[len(mutations)-1]; last.Op != cffake.OpServiceTokenDel || !last.Committed {
			t.Errorf("the last Cloudflare mutation = %+v, want the committed deletion of the old token", last)
		}
		if err := f.readLogs(); err != nil {
			t.Errorf("a fresh connection after the rotation: %v", err)
		}
	})

	t.Run("disable returns the node to a verified direct path and removes only setup's files", func(t *testing.T) {
		f.restoreDirectRoute()
		before := len(f.cf.Mutations())
		tokenBefore := f.cf.ServiceTokens()
		policiesBefore := len(f.cf.Policies())

		f.mustSucceed(f.run("node.tunnel.disable", nodeRef(f.node), nil), "tunnel disable")

		node := f.refresh()
		if node.Endpoint.Transport.Effective() != domain.TransportDirect || node.Endpoint.TunnelHostname != "" {
			t.Errorf("endpoint after disable = %+v, want direct without a hostname", node.Endpoint)
		}
		if out, err := trySh(t, f.docker, "systemctl cat "+tunnelSvc); err == nil {
			t.Errorf("the tunnel unit is still installed:\n%s", out)
		}
		if out, err := trySh(t, f.docker, "ls /etc/supermgmt/cloudflared"); err == nil {
			t.Errorf("the token directory is still there: %s", out)
		}
		if got := sh(t, f.docker, "dpkg-query -W -f='${db:Status-Abbrev}' cloudflared"); !strings.HasPrefix(got, "ii") {
			t.Errorf("cloudflared package = %q, want it left alone (setup did not install it)", got)
		}
		if got := sh(t, f.docker, "test -x /usr/bin/cloudflared && echo kept"); got != "kept" {
			t.Errorf("the cloudflared binary was removed: %q", got)
		}
		if got := sh(t, f.docker, "systemctl is-active sm-demo.service"); got != "active" {
			t.Errorf("sm-demo.service = %q, want untouched", got)
		}

		snap := f.cf.Snapshot()
		if len(snap.Tunnels) != 0 || len(snap.Apps) != 0 || len(snap.DNSRecords) != 0 {
			t.Errorf("objects left after disable: %d tunnels, %d apps, %d dns; want none", len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords))
		}
		if len(snap.ServiceTokens) != len(tokenBefore) || len(snap.ServiceTokens) != 1 || len(snap.Policies) != policiesBefore {
			t.Errorf("instance objects after disable: %d tokens, %d policies; want the instance's token and policies to stay", len(snap.ServiceTokens), len(snap.Policies))
		}
		assertOrder(t, f.cf.Mutations()[before:], cffake.OpDNSDelete, cffake.OpAppDelete, cffake.OpTunnelDelete)
		if routable := f.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
			t.Errorf("hostnames routable without Access at some point: %v", routable)
		}
		f.mustSucceed(f.run("node.probe", nodeRef(f.node), nil), "probe over the direct route again")
	})
}

// assertOrder fails unless the committed mutations contain ops in this order.
func assertOrder(t *testing.T, mutations []cffake.Applied, ops ...cffake.Op) {
	t.Helper()
	next := 0
	for _, m := range mutations {
		if m.Committed && next < len(ops) && m.Op == ops[next] {
			next++
		}
	}
	if next != len(ops) {
		var got []cffake.Op
		for _, m := range mutations {
			if m.Committed {
				got = append(got, m.Op)
			}
		}
		t.Errorf("committed mutations %v do not contain %v in order", got, ops)
	}
}

// Scenario "the switch happens only after the tunnel is proven".
func TestTunnelVerificationFailuresLeaveTheNodeDirect(t *testing.T) {
	f := newTunnelFixture(t, fixtureOptions{})
	f.mustSucceed(f.setup(false), "setup over the direct route")

	// Warm a direct connection: it must not be able to satisfy the verification.
	f.mustSucceed(f.run("node.probe", nodeRef(f.node), nil), "probe")

	wantDirect := func(t *testing.T, what string) {
		t.Helper()
		if node := f.refresh(); node.Endpoint.Transport.Effective() != domain.TransportDirect || node.Endpoint.TunnelHostname != "" {
			t.Errorf("%s: endpoint = %+v, want the transport left direct", what, node.Endpoint)
		}
	}

	t.Run("a tunnel that reaches a different host key fails and nothing is repinned", func(t *testing.T) {
		other := startDocker(t)
		f.carrierForwardsTo(other)
		job := f.setup(true)
		if job.State == domain.JobSucceeded {
			t.Fatal("setup --tunnel succeeded through a tunnel that reaches another machine")
		}
		t.Logf("outcome: %s", outcome(job, nil))
		wantDirect(t, "different host key")
		if got := f.refresh().Endpoint.HostPublicKey; got != authorizedKey(f.docker.HostKey) {
			t.Errorf("the pinned host key changed to %q", got)
		}
		if job.Error != nil && !strings.Contains(strings.ToLower(job.Error.Message), "verif") && !strings.Contains(strings.ToLower(job.Error.Message), "host key") {
			t.Errorf("the failure does not name the step: %q", job.Error.Message)
		}
	})

	t.Run("an Access that denies the service token fails before any carrier is started", func(t *testing.T) {
		f.carrierForwardsTo(f.docker)
		before := f.carrierStarts()
		f.denyAccess.Store(true)
		job := f.setup(true)
		f.denyAccess.Store(false)
		if job.State == domain.JobSucceeded {
			t.Fatal("setup --tunnel succeeded although Access denied the token")
		}
		t.Logf("outcome: %s", outcome(job, nil))
		wantDirect(t, "access denied")
		if started := f.carrierStarts() - before; started != 0 {
			t.Errorf("%d carriers were started although Access redirected to login", started)
		}
	})

	t.Run("the interrupted operation resumes and converges once the tunnel is right", func(t *testing.T) {
		f.carrierForwardsTo(f.docker)
		f.mustSucceed(f.setup(true), "setup --tunnel after the failures")
		if node := f.refresh(); node.Endpoint.Transport != domain.TransportCloudflare {
			t.Fatalf("endpoint = %+v, want cloudflare", node.Endpoint)
		}
		snap := f.cf.Snapshot()
		if len(snap.Tunnels) != 1 || len(snap.Apps) != 1 || len(snap.DNSRecords) != 1 || len(snap.ServiceTokens) != 1 {
			t.Errorf("objects after the retries = %d tunnels, %d apps, %d dns, %d tokens; want exactly one of each",
				len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords), len(snap.ServiceTokens))
		}
	})
}
