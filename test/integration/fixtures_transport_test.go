//go:build fixtures

package integration

import (
	"context"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	sshtransport "github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// rawCommand is a command line no template renders. Limits and timeouts need
// output and durations the catalog never produces.
func rawCommand(line string, maxBytes, maxLines int) templates.Command {
	return templates.Command{Template: "test.raw", Line: line, MaxBytes: maxBytes, MaxLines: maxLines}
}

func TestFixturesTransport_PinnedHostKeyConnectsThroughTheAgent(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), newIdentity(t))
	ex := h.pool.For(n.target(fixture.AdminUser))

	res := run(t, ex, "setup.verify_id", nil)
	if got := strings.TrimSpace(string(res.Stdout)); got != fixture.AdminUser {
		t.Errorf("id -un = %q; want %s", got, fixture.AdminUser)
	}
	if st := h.pool.State(n.id); st.Status != sshtransport.ConnIdle {
		t.Errorf("state after a command = %v; want idle (connection kept for reuse)", st.Status)
	}
}

func TestFixturesTransport_ChangedHostKeyIsRefused(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), newIdentity(t))

	imposter := newIdentity(t)
	target := n.target(fixture.AdminUser)
	target.HostKey = imposter.public
	c, err := templates.Render("setup.verify_id", nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	_, err = h.pool.For(target).Run(t.Context(), c)
	if codeOf(err) != smerr.CodeSSHHostKeyMismatch {
		t.Fatalf("run against a node whose key differs from the pin: %v; want SSH_HOST_KEY_MISMATCH", err)
	}
	if st := h.pool.State(n.id); st.Status == sshtransport.ConnConnected || st.Status == sshtransport.ConnIdle {
		t.Errorf("state = %v; a refused host key must leave no live connection", st.Status)
	}

	t.Run("correcting the pin connects again", func(t *testing.T) {
		h.clock.Advance(time.Minute) // past the backoff the failure started
		res := run(t, h.pool.For(n.target(fixture.AdminUser)), "setup.verify_id", nil)
		if got := strings.TrimSpace(string(res.Stdout)); got != fixture.AdminUser {
			t.Errorf("id -un = %q; want %s", got, fixture.AdminUser)
		}
	})
}

func TestFixturesTransport_ScanHostKeyReportsTheKeyTheNodePresents(t *testing.T) {
	n := startNode(t, fixture.Options{})
	got, err := sshtransport.ScanHostKey(t.Context(), n.Host, n.Port)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got.Authorized != n.hostKeyPin {
		t.Errorf("scanned key = %q; want the injected host key %q", got.Authorized, n.hostKeyPin)
	}
	if want := cryptossh.FingerprintSHA256(n.HostKey); got.FingerprintSHA256 != want {
		t.Errorf("fingerprint = %q; want %q", got.FingerprintSHA256, want)
	}
}

func TestFixturesTransport_AgentFailuresAreTyped(t *testing.T) {
	n := startNode(t, fixture.Options{})
	c, err := templates.Render("setup.verify_id", nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	t.Run("no agent socket is CAPABILITY_UNAVAILABLE", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", "")
		h := newHarness(t, defaultPoolConfig(), newIdentity(t))
		_, err := h.pool.For(n.target(fixture.AdminUser)).Run(t.Context(), c)
		if codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("run without an agent: %v; want CAPABILITY_UNAVAILABLE", err)
		}
	})

	t.Run("an agent without the authorized key is refused by the node", func(t *testing.T) {
		useAgent(t, newIdentity(t).signer)
		h := newHarness(t, defaultPoolConfig(), newIdentity(t))
		_, err := h.pool.For(n.target(fixture.AdminUser)).Run(t.Context(), c)
		if codeOf(err) != smerr.CodeNodeUnreachable {
			t.Errorf("run with an unauthorized key: %v; want NODE_UNREACHABLE", err)
		}
	})
}

// acceptCounter listens on loopback and closes every connection at once, so a
// dial attempt is observable and always fails.
type acceptCounter struct {
	l     net.Listener
	count atomic.Int32
}

func newAcceptCounter(t *testing.T) *acceptCounter {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	a := &acceptCounter{l: l}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			a.count.Add(1)
			_ = c.Close()
		}
	}()
	return a
}

func (a *acceptCounter) target(t *testing.T, pin string) sshtransport.Target {
	t.Helper()
	host, portText, _ := net.SplitHostPort(a.l.Addr().String())
	port, _ := strconv.Atoi(portText)
	return sshtransport.Target{
		NodeID: "unreachable", Host: host, Port: port, User: fixture.AdminUser, HostKey: pin, CredentialRef: agentRef,
	}
}

// waitForCount polls until the counter reaches want or fails the test.
func (a *acceptCounter) waitForCount(t *testing.T, want int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for a.count.Load() < want {
		select {
		case <-ctx.Done():
			t.Fatalf("accepted %d connections; want %d", a.count.Load(), want)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestFixturesTransport_UnreachableNodeBacksOffExponentiallyUpToFiveMinutes(t *testing.T) {
	useAgent(t, newIdentity(t).signer)
	dead := newAcceptCounter(t)
	pin := newIdentity(t).public
	h := newHarness(t, defaultPoolConfig(), newIdentity(t))
	target := dead.target(t, pin)
	ex := h.pool.For(target)
	c, _ := templates.Render("setup.verify_id", nil)

	attempt := func() error {
		_, err := ex.Run(t.Context(), c)
		return err
	}
	if err := attempt(); codeOf(err) != smerr.CodeNodeUnreachable {
		t.Fatalf("first attempt: %v; want NODE_UNREACHABLE", err)
	}
	dead.waitForCount(t, 1)
	st := h.pool.State(target.NodeID)
	if st.Status != sshtransport.ConnBackoff || !st.NextDialAt.Equal(fixtureEpoch.Add(time.Second)) {
		t.Fatalf("state = %+v; want backoff until +1s", st)
	}

	if err := attempt(); codeOf(err) != smerr.CodeNodeUnreachable {
		t.Errorf("attempt inside the backoff window: %v; want the recorded NODE_UNREACHABLE", err)
	}
	if dead.count.Load() != 1 {
		t.Errorf("dials = %d; an attempt inside the backoff window must not dial", dead.count.Load())
	}

	delay := time.Second
	for want := int32(2); delay < 5*time.Minute; want++ {
		h.clock.Advance(delay)
		_ = attempt()
		dead.waitForCount(t, want)
		delay = min(delay*2, 5*time.Minute)
		st = h.pool.State(target.NodeID)
		if got := st.NextDialAt.Sub(h.clock.Now()); got != delay {
			t.Fatalf("after dial %d the next dial is in %v; want %v", want, got, delay)
		}
	}
	h.clock.Advance(5 * time.Minute)
	_ = attempt()
	if got := h.pool.State(target.NodeID).NextDialAt.Sub(h.clock.Now()); got != 5*time.Minute {
		t.Errorf("backoff = %v; want it capped at 5m", got)
	}
}

func TestFixturesTransport_BackoffHoldsNoDialSlot(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	cfg := defaultPoolConfig()
	cfg.MaxDialsInFlight = 1
	h := newHarness(t, cfg, newIdentity(t))
	dead := newAcceptCounter(t)
	c, _ := templates.Render("setup.verify_id", nil)

	if _, err := h.pool.For(dead.target(t, newIdentity(t).public)).Run(t.Context(), c); err == nil {
		t.Fatal("dial of the dead endpoint succeeded")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := h.pool.For(n.target(fixture.AdminUser)).Run(ctx, c); err != nil {
		t.Errorf("a healthy node behind a backed-off one: %v; the single dial slot must be free", err)
	}
}

func TestFixturesTransport_PausedNodeTimesOutAndRecovers(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	cfg := defaultPoolConfig()
	cfg.ConnectTimeout = time.Second
	h := newHarness(t, cfg, newIdentity(t))
	ex := h.pool.For(n.target(fixture.AdminUser))
	c, _ := templates.Render("setup.verify_id", nil)

	if err := n.Pause(t.Context()); err != nil {
		t.Fatalf("pause: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, err := ex.Run(ctx, c)
	if codeOf(err) != smerr.CodeNodeUnreachable || ctx.Err() != nil {
		t.Fatalf("run against a paused node: %v (ctx %v); want NODE_UNREACHABLE from the connect timeout", err, ctx.Err())
	}
	if st := h.pool.State(n.id); st.Status != sshtransport.ConnBackoff {
		t.Errorf("state = %v; want backoff", st.Status)
	}

	if err := n.Unpause(t.Context()); err != nil {
		t.Fatalf("unpause: %v", err)
	}
	h.clock.Advance(time.Minute)
	if _, err := ex.Run(ctx, c); err != nil {
		t.Errorf("run after the node came back and the backoff elapsed: %v", err)
	}
}

func TestFixturesTransport_OutputIsBoundedAndSanitized(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), newIdentity(t))
	ex := h.pool.For(n.target(fixture.AdminUser))
	ctx := t.Context()

	t.Run("bytes beyond max_bytes are dropped and flagged", func(t *testing.T) {
		res, err := ex.Run(ctx, rawCommand("head -c 200000 /dev/zero | tr '\\0' a", 1000, 0))
		if err != nil || !res.Truncated || len(res.Stdout) > 1000 {
			t.Errorf("got %d bytes, truncated=%v, err=%v; want <= 1000 bytes, truncated", len(res.Stdout), res.Truncated, err)
		}
	})

	t.Run("lines beyond max_lines are dropped and flagged", func(t *testing.T) {
		res, err := ex.Run(ctx, rawCommand("seq 1 100000", 1<<20, 10))
		if err != nil || !res.Truncated || strings.Count(string(res.Stdout), "\n") != 10 {
			t.Errorf("got %d lines, truncated=%v, err=%v; want 10 lines, truncated", strings.Count(string(res.Stdout), "\n"), res.Truncated, err)
		}
	})

	t.Run("a command that writes more than the limit still finishes", func(t *testing.T) {
		res, err := ex.Run(ctx, rawCommand("seq 1 200000; echo finished >&2", 4096, 0))
		if err != nil || res.ExitStatus != 0 {
			t.Errorf("exit %d, err %v; want a clean exit despite the discarded output", res.ExitStatus, err)
		}
	})

	t.Run("ANSI, C0 and C1 controls never reach the caller", func(t *testing.T) {
		res, err := ex.Run(ctx, rawCommand(`printf '\033[31mred\033[0m\033]0;title\007 \001bell\r\n\302\205next\n'`, 4096, 10))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		for _, b := range res.Stdout {
			if b == 0x1b || b == 0x07 || b == 0x01 || b == '\r' {
				t.Errorf("control byte %#x survived in %q", b, res.Stdout)
			}
		}
		if !strings.Contains(string(res.Stdout), "red") || !strings.Contains(string(res.Stdout), "next") {
			t.Errorf("printable text lost: %q", res.Stdout)
		}
	})

	t.Run("a non-zero exit status is a result, not an error", func(t *testing.T) {
		res, err := ex.Run(ctx, rawCommand("exit 7", 64, 1))
		if err != nil || res.ExitStatus != 7 {
			t.Errorf("exit %d, err %v; want 7, nil", res.ExitStatus, err)
		}
	})
}

func TestFixturesTransport_CommandDeadlineIsEnforced(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)

	t.Run("the command's own deadline", func(t *testing.T) {
		h := newHarness(t, defaultPoolConfig(), newIdentity(t))
		c := rawCommand("sleep 30", 64, 1)
		c.Deadline = time.Second
		_, err := h.pool.For(n.target(fixture.AdminUser)).Run(t.Context(), c)
		if codeOf(err) != smerr.CodeTimeout {
			t.Errorf("sleep 30 with a 1s deadline: %v; want TIMEOUT", err)
		}
	})

	t.Run("ssh.command_timeout when the command sets none", func(t *testing.T) {
		cfg := defaultPoolConfig()
		cfg.CommandTimeout = time.Second
		h := newHarness(t, cfg, newIdentity(t))
		_, err := h.pool.For(n.target(fixture.AdminUser)).Run(t.Context(), rawCommand("sleep 30", 64, 1))
		if codeOf(err) != smerr.CodeTimeout {
			t.Errorf("sleep 30 with a 1s command_timeout: %v; want TIMEOUT", err)
		}
	})

	t.Run("the connection survives a timed-out command", func(t *testing.T) {
		cfg := defaultPoolConfig()
		cfg.CommandTimeout = time.Second
		h := newHarness(t, cfg, newIdentity(t))
		ex := h.pool.For(n.target(fixture.AdminUser))
		_, _ = ex.Run(t.Context(), rawCommand("sleep 30", 64, 1))
		res := run(t, ex, "setup.verify_id", nil)
		if got := strings.TrimSpace(string(res.Stdout)); got != fixture.AdminUser {
			t.Errorf("id -un after a timeout = %q; want %s", got, fixture.AdminUser)
		}
	})
}

func TestFixturesTransport_SessionsPerConnectionAreLimited(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	cfg := defaultPoolConfig()
	cfg.MaxSessionsPerConnection = 2
	h := newHarness(t, cfg, newIdentity(t))
	ex := h.pool.For(n.target(fixture.AdminUser))
	// Warm the connection so the four commands below only compete for sessions.
	run(t, ex, "setup.verify_id", nil)

	const commands = 4
	starts := make([]int64, commands)
	var wg sync.WaitGroup
	for i := range commands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := ex.Run(t.Context(), rawCommand("date +%s%N; sleep 2", 64, 2))
			if err != nil {
				t.Errorf("command %d: %v", i, err)
				return
			}
			starts[i], _ = strconv.ParseInt(strings.TrimSpace(string(res.Stdout)), 10, 64)
		}()
	}
	wg.Wait()

	slices.Sort(starts)
	if gap := time.Duration(starts[2] - starts[0]); gap < 1500*time.Millisecond {
		t.Errorf("third command started %v after the first; with 2 sessions it must wait for a slot (~2s)", gap)
	}
	if gap := time.Duration(starts[1] - starts[0]); gap > time.Second {
		t.Errorf("second command started %v after the first; the two free sessions must run together", gap)
	}
}

func TestFixturesTransport_ConnectionsAreCappedWithLeastRecentlyUsedEviction(t *testing.T) {
	a := startNode(t, fixture.Options{})
	b := startNode(t, fixture.Options{})
	useAgent(t, a.ClientSigner, b.ClientSigner)
	cfg := defaultPoolConfig()
	cfg.MaxConnections = 1
	h := newHarness(t, cfg, newIdentity(t))

	run(t, h.pool.For(a.target(fixture.AdminUser)), "setup.verify_id", nil)
	h.clock.Advance(time.Second)
	run(t, h.pool.For(b.target(fixture.AdminUser)), "setup.verify_id", nil)

	if st := h.pool.State(a.id); st.Status == sshtransport.ConnIdle || st.Status == sshtransport.ConnConnected {
		t.Errorf("node A state = %v; its idle connection must be closed to admit node B", st.Status)
	}
	if st := h.pool.State(b.id); st.Status != sshtransport.ConnIdle {
		t.Errorf("node B state = %v; want idle", st.Status)
	}
	run(t, h.pool.For(a.target(fixture.AdminUser)), "setup.verify_id", nil) // evicted nodes dial again
}

func TestFixturesTransport_IdleConnectionsAreClosedAfterTheTTL(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	cfg := defaultPoolConfig()
	cfg.IdleConnectionTTL = 2 * time.Second
	h := newHarness(t, cfg, newIdentity(t))
	run(t, h.pool.For(n.target(fixture.AdminUser)), "setup.verify_id", nil)

	h.clock.Advance(time.Hour)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for h.pool.State(n.id).Status == sshtransport.ConnIdle {
		select {
		case <-ctx.Done():
			t.Fatal("the idle connection was not closed after idle_connection_ttl")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
