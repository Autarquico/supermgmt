package ssh

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func requireCode(t *testing.T, err error, want smerr.Code) {
	t.Helper()
	if err == nil || smerr.CodeOf(err) != want {
		t.Fatalf("got %v, want code %s", err, want)
	}
}

func TestRunReturnsOutputAndExitStatus(t *testing.T) {
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(cmd string, _ []byte) reply {
			if cmd == "fail" {
				return reply{stdout: "partial", stderr: "boom", status: 7}
			}
			return reply{stdout: "hello " + cmd}
		}
	})
	out, err := r.run("world")
	if err != nil || out != "hello world" {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	res, err := r.pool.For(r.target()).Run(context.Background(), templates.Command{Line: "fail", MaxBytes: 100})
	if err != nil {
		t.Fatalf("a non-zero exit must be a Result, got error %v", err)
	}
	if res.ExitStatus != 7 || string(res.Stdout) != "partial" || string(res.Stderr) != "boom" {
		t.Errorf("result = %+v", res)
	}
}

func TestStdinReachesTheCommand(t *testing.T) {
	var got []byte
	var mu sync.Mutex
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(_ string, stdin []byte) reply {
			mu.Lock()
			got = stdin
			mu.Unlock()
			return reply{}
		}
	})
	_, err := r.pool.For(r.target()).Run(context.Background(), templates.Command{Line: "install", Stdin: []byte("file body"), MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(got) != "file body" {
		t.Errorf("stdin = %q", got)
	}
}

func TestOutputIsSanitizedAtTheBoundary(t *testing.T) {
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(string, []byte) reply {
			return reply{stdout: "ok\x1b[31mred\x1b[0m\x1b]0;title\x07\r\nnext\x00\xff\n"}
		}
	})
	out, err := r.run("x")
	if err != nil {
		t.Fatal(err)
	}
	if out != "okred\nnext�\n" {
		t.Errorf("out = %q", out)
	}
}

func TestOutputLimitsTruncateAndSayso(t *testing.T) {
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(string, []byte) reply { return reply{stdout: "a\nb\nc\nd\n"} }
	})
	tests := map[string]struct {
		cmd   templates.Command
		want  string
		trunc bool
	}{
		"bytes": {templates.Command{Line: "x", MaxBytes: 5}, "a\nb\nc", true},
		"lines": {templates.Command{Line: "x", MaxBytes: 100, MaxLines: 2}, "a\nb\n", true},
		"fits":  {templates.Command{Line: "x", MaxBytes: 100, MaxLines: 4}, "a\nb\nc\nd\n", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := r.pool.For(r.target()).Run(context.Background(), tt.cmd)
			if err != nil {
				t.Fatal(err)
			}
			if string(res.Stdout) != tt.want || res.Truncated != tt.trunc {
				t.Errorf("stdout=%q truncated=%v, want %q %v", res.Stdout, res.Truncated, tt.want, tt.trunc)
			}
		})
	}
}

func TestOneConnectionServesManyCommands(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	for range 5 {
		if _, err := r.run("x"); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.server.connections.Load(); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
}

func TestPinnedKeyIsTheOnlyTrustAnchor(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	target := r.target()
	target.HostKey = strings.TrimSpace(string(marshalAuthorized(newSigner(t))))
	_, err := r.pool.For(target).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
	requireCode(t, err, smerr.CodeSSHHostKeyMismatch)
	if n := r.server.authAttempts.Load(); n != 0 {
		t.Errorf("credentials were offered to an untrusted host (%d attempts)", n)
	}
}

func TestServerWithoutThePinnedKeyTypeIsAMismatch(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	target := r.target()
	target.HostKey = rsaAuthorizedKey(t)
	_, err := r.pool.For(target).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
	requireCode(t, err, smerr.CodeSSHHostKeyMismatch)
}

func TestMalformedPinnedKeyIsInvalid(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	for _, bad := range []string{"", "not a key", r.server.pinned() + "\n" + r.server.pinned()} {
		target := r.target()
		target.HostKey = bad
		_, err := r.pool.For(target).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
		requireCode(t, err, smerr.CodeInvalidArgument)
	}
}

func TestRejectedCredentialIsNodeUnreachableNamingTheUser(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	r.pool.creds = &staticCreds{signer: newSigner(t)}
	_, err := r.run("x")
	requireCode(t, err, smerr.CodeNodeUnreachable)
	if !strings.Contains(err.Error(), "authentication failed for user supermgmt") {
		t.Errorf("err = %v", err)
	}
}

func TestInvalidTargetsAreRefusedBeforeDialing(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	for name, mutate := range map[string]func(*Target){
		"option-like host": func(t *Target) { t.Host = "-oProxyCommand=x" },
		"empty host":       func(t *Target) { t.Host = "" },
		"zero port":        func(t *Target) { t.Port = 0 },
		"huge port":        func(t *Target) { t.Port = 70000 },
		"option-like user": func(t *Target) { t.User = "-l" },
		"empty user":       func(t *Target) { t.User = "" },
	} {
		t.Run(name, func(t *testing.T) {
			target := r.target()
			mutate(&target)
			_, err := r.pool.For(target).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
			requireCode(t, err, smerr.CodeInvalidArgument)
		})
	}
	if n := r.server.connections.Load(); n != 0 {
		t.Errorf("%d connections made", n)
	}
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestUnreachableNodeBacksOffExponentiallyWithoutDialing(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	var accepted int
	var mu sync.Mutex
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted++
			mu.Unlock()
			_ = c.Close() // not an SSH server
		}
	}()
	count := func() int { mu.Lock(); defer mu.Unlock(); return accepted }

	target := r.target()
	target.Port = l.Addr().(*net.TCPAddr).Port
	exec := r.pool.For(target)
	run := func() error {
		_, err := exec.Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
		return err
	}

	start := r.clock.Now()
	requireCode(t, run(), smerr.CodeNodeUnreachable)
	state := r.pool.State(r.nodeID)
	if state.Status != ConnBackoff || !state.NextDialAt.Equal(start.Add(time.Second)) || state.LastError == nil {
		t.Fatalf("state = %+v", state)
	}
	requireCode(t, run(), smerr.CodeNodeUnreachable)
	if n := count(); n != 1 {
		t.Fatalf("%d dials during backoff, want 1", n)
	}

	r.clock.Advance(time.Second)
	requireCode(t, run(), smerr.CodeNodeUnreachable)
	if n := count(); n != 2 {
		t.Fatalf("%d dials after backoff, want 2", n)
	}
	if got := r.pool.State(r.nodeID).NextDialAt; !got.Equal(r.clock.Now().Add(2 * time.Second)) {
		t.Errorf("second backoff ends at %v, want +2s", got)
	}
}

func TestBackoffDoublesAndCapsAtFiveMinutes(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, w := range want {
		if got := backoffDelay(i + 1); got != w {
			t.Errorf("backoffDelay(%d) = %v, want %v", i+1, got, w)
		}
	}
	for _, n := range []int{10, 50, 1000} {
		if got := backoffDelay(n); got != 5*time.Minute {
			t.Errorf("backoffDelay(%d) = %v, want 5m", n, got)
		}
	}
}

func TestBackoffHoldsNoDialSlotAndOtherNodesStillConnect(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxDialsInFlight = 1
	r := newRig(t, cfg, nil)
	dead := r.target()
	dead.Port = closedPort(t)
	dead.NodeID = domain.ID("00000000-0001-7000-8000-0000000000aa")

	_, err := r.pool.For(dead).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
	requireCode(t, err, smerr.CodeNodeUnreachable)
	if n := len(r.pool.dials); n != 0 {
		t.Fatalf("%d dial slots held while backing off", n)
	}
	if _, err := r.run("x"); err != nil {
		t.Fatalf("healthy node blocked by a dead one: %v", err)
	}
}

func TestDialsInFlightAreBounded(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxDialsInFlight = 2
	r := newRig(t, cfg, func(s *testServer) { s.handshakeDelay = 80 * time.Millisecond })

	var wg sync.WaitGroup
	ids := domaintest.NewSequentialIDs()
	for range 6 {
		target := r.target()
		target.NodeID = ids.NewID()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.pool.For(target).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// Measured on the client, inside the dial slot. The server-side count
	// would also see a finished handshake still unwinding while the next
	// dial has started, which is not a violation.
	if peak := r.pool.creds.(*staticCreds).maxInFlight.Load(); peak > 2 {
		t.Errorf("%d concurrent dials, limit is 2", peak)
	}
	if n := r.server.connections.Load(); n != 6 {
		t.Errorf("%d connections, want 6", n)
	}
}

func TestConcurrentCommandsOnOneNodeShareOneDial(t *testing.T) {
	r := newRig(t, defaultConfig(), func(s *testServer) { s.handshakeDelay = 50 * time.Millisecond })
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.run("x"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := r.server.connections.Load(); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
}

func TestSessionsPerConnectionAreBounded(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxSessionsPerConnection = 2
	release := make(chan struct{})
	r := newRig(t, cfg, func(s *testServer) {
		s.handler = func(string, []byte) reply { return reply{wait: release} }
	})
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.run("x"); err != nil {
				t.Error(err)
			}
		}()
	}
	eventually(t, "two sessions running", func() bool { return r.server.inSessions.Load() == 2 })
	time.Sleep(100 * time.Millisecond)
	if peak := r.server.maxSessions.Load(); peak != 2 {
		t.Errorf("peak sessions = %d, want 2", peak)
	}
	if st := r.pool.State(r.nodeID); st.Status != ConnConnected {
		t.Errorf("state with sessions in flight = %v", st.Status)
	}
	close(release)
	wg.Wait()
	if st := r.pool.State(r.nodeID); st.Status != ConnIdle {
		t.Errorf("state after completion = %v", st.Status)
	}
}

func TestCommandTimeoutIsTimeoutAndKeepsTheConnection(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(cmd string, _ []byte) reply {
			if cmd == "hang" {
				return reply{wait: block}
			}
			return reply{stdout: "alive"}
		}
	})
	_, err := r.pool.For(r.target()).Run(context.Background(), templates.Command{Line: "hang", Deadline: 100 * time.Millisecond, MaxBytes: 10})
	requireCode(t, err, smerr.CodeTimeout)
	out, err := r.run("again")
	if err != nil || out != "alive" {
		t.Fatalf("after timeout: %q, %v", out, err)
	}
	if n := r.server.connections.Load(); n != 1 {
		t.Errorf("a timed-out command cost %d connections, want 1", n)
	}
}

func TestMutatingCommandsGetTheirRemoteGraceOnTop(t *testing.T) {
	p := NewPool(PoolConfig{CommandTimeout: 30 * time.Second}, nil, domaintest.NewFakeClock(time.Time{}))
	t.Cleanup(p.Close)
	read := templates.Command{}
	mutating := templates.Command{Mutating: true, Deadline: 2 * time.Minute}
	if got := p.commandLimit(read); got != 30*time.Second {
		t.Errorf("read limit = %v", got)
	}
	if got := p.commandLimit(mutating); got != 2*time.Minute+templates.KillAfter+commandSlack {
		t.Errorf("mutating limit = %v", got)
	}
}

func TestCancelledContextStopsTheCommand(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(string, []byte) reply { return reply{wait: block} }
	})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := r.pool.For(r.target()).Run(ctx, templates.Command{Line: "x", MaxBytes: 10})
		errc <- err
	}()
	eventually(t, "command running", func() bool { return r.server.inSessions.Load() == 1 })
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestDroppedConnectionIsReplacedOnTheNextCommand(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	r.server.dropConnections()
	// Whether or not the client noticed yet, the next command must succeed.
	if _, err := r.run("x"); err != nil {
		t.Fatalf("command after a dropped connection: %v", err)
	}
	if n := r.server.connections.Load(); n != 2 {
		t.Errorf("%d connections, want 2", n)
	}
}

func TestConnectionLostMidCommandIsNodeUnreachableAndNotRetried(t *testing.T) {
	var runs int
	var mu sync.Mutex
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(string, []byte) reply {
			mu.Lock()
			runs++
			mu.Unlock()
			s.dropConnections()
			return reply{wait: make(chan struct{})}
		}
	})
	_, err := r.run("mutate")
	requireCode(t, err, smerr.CodeNodeUnreachable)
	mu.Lock()
	defer mu.Unlock()
	if runs != 1 {
		t.Errorf("command ran %d times; a started command must never be retried", runs)
	}
}

func TestUnansweredKeepalivesCloseTheConnection(t *testing.T) {
	cfg := defaultConfig()
	cfg.KeepaliveInterval = 50 * time.Millisecond
	r := newRig(t, cfg, func(s *testServer) { s.ignoreKeepalives = true })
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "dead connection dropped", func() bool { return r.pool.State(r.nodeID).Status == ConnUnknown })
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	if n := r.server.connections.Load(); n != 2 {
		t.Errorf("%d connections, want 2", n)
	}
}

func TestAnsweredKeepalivesKeepTheConnection(t *testing.T) {
	cfg := defaultConfig()
	cfg.KeepaliveInterval = 30 * time.Millisecond
	r := newRig(t, cfg, nil)
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	if n := r.server.connections.Load(); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
}

func TestIdleConnectionsCloseAfterTheTTL(t *testing.T) {
	cfg := defaultConfig()
	cfg.IdleConnectionTTL = 10 * time.Minute
	r := newRig(t, cfg, nil)
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(9 * time.Minute)
	r.pool.reapIdle()
	if st := r.pool.State(r.nodeID); st.Status != ConnIdle {
		t.Fatalf("closed before the TTL: %v", st.Status)
	}
	r.clock.Advance(time.Minute)
	r.pool.reapIdle()
	if st := r.pool.State(r.nodeID); st.Status != ConnUnknown {
		t.Errorf("still open after the TTL: %v", st.Status)
	}
}

func TestMaxConnectionsEvictsTheLeastRecentlyUsedIdleOne(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxConnections = 2
	r := newRig(t, cfg, nil)
	ids := domaintest.NewSequentialIDs()
	var targets []Target
	for range 3 {
		tg := r.target()
		tg.NodeID = ids.NewID()
		targets = append(targets, tg)
	}
	for _, tg := range targets[:2] {
		if _, err := r.pool.For(tg).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10}); err != nil {
			t.Fatal(err)
		}
		r.clock.Advance(time.Second)
	}
	if _, err := r.pool.For(targets[2]).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10}); err != nil {
		t.Fatal(err)
	}
	states := []ConnStatus{r.pool.State(targets[0].NodeID).Status, r.pool.State(targets[1].NodeID).Status, r.pool.State(targets[2].NodeID).Status}
	if states[0] != ConnUnknown || states[1] != ConnIdle || states[2] != ConnIdle {
		t.Errorf("states = %v, want the first (LRU) evicted", states)
	}
}

func TestMaxConnectionsWithEveryConnectionBusyRefusesInsteadOfExceeding(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxConnections = 1
	release := make(chan struct{})
	r := newRig(t, cfg, func(s *testServer) {
		s.handler = func(string, []byte) reply { return reply{wait: release} }
	})
	go func() { _, _ = r.run("busy") }()
	eventually(t, "first command running", func() bool { return r.server.inSessions.Load() == 1 })

	other := r.target()
	other.NodeID = domain.ID("00000000-0001-7000-8000-0000000000bb")
	_, err := r.pool.For(other).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
	requireCode(t, err, smerr.CodeNodeUnreachable)
	if n := r.server.connections.Load(); n != 1 {
		t.Errorf("%d connections, limit is 1", n)
	}
	close(release)
}

func TestClosingConnectionsAloneNeverRefuseADialWhileThePoolHasRoom(t *testing.T) { // CODE-16
	r := newRig(t, defaultConfig(), nil)
	r.pool.mu.Lock()
	r.pool.closesRunning = maxParallelCloses // a burst of idle carriers closing at once
	r.pool.mu.Unlock()

	if _, err := r.run("x"); err != nil {
		t.Fatalf("a dial to an empty pool was refused because of closes in flight: %v", err)
	}
}

func TestDialsAreRefusedWhileTooManyConnectionsAreStillClosing(t *testing.T) { // CODE-15
	cfg := defaultConfig()
	cfg.MaxConnections = 1
	r := newRig(t, cfg, nil)
	if _, err := r.run("x"); err != nil { // the pool is full
		t.Fatal(err)
	}
	r.pool.mu.Lock()
	r.pool.closesRunning = maxParallelCloses
	r.pool.mu.Unlock()

	other := r.target()
	other.NodeID = domain.ID("00000000-0001-7000-8000-0000000000cc")
	_, err := r.pool.For(other).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
	requireCode(t, err, smerr.CodeNodeUnreachable)
	if n := r.server.connections.Load(); n != 1 {
		t.Errorf("%d connections dialed while the closing bound was reached, want the first only", n)
	}

	r.pool.mu.Lock()
	r.pool.closesRunning = 0
	r.pool.mu.Unlock()
	if _, err := r.run("x"); err != nil {
		t.Fatalf("dial after the closes finished: %v", err)
	}
	target := r.target()
	r.pool.Invalidate(target.NodeID, target.User)
	r.pool.mu.Lock()
	running := r.pool.closesRunning
	r.pool.mu.Unlock()
	if running != 0 {
		t.Errorf("closesRunning = %d after the closes finished, want 0", running)
	}
}

func TestChangedTargetReplacesTheConnection(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	other := newSigner(t)
	r.server.setHostKey(other) // the node was rebuilt with a new key
	target := r.target()
	_, err := r.pool.For(target).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10})
	// target.HostKey is now the new key: the old connection must not be reused.
	if err != nil {
		t.Fatalf("new target: %v", err)
	}
	if n := r.server.connections.Load(); n != 2 {
		t.Errorf("%d connections, want 2", n)
	}
}

func TestSeparateLoginUsersGetSeparateConnections(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	admin := r.target()
	admin.User = "admin"
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.pool.For(admin).Run(context.Background(), templates.Command{Line: "x", MaxBytes: 10}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	if n := r.server.connections.Load(); n != 2 {
		t.Errorf("%d connections, want 2 (one per user)", n)
	}
}

func TestClosedPoolRefusesNewConnections(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	r.pool.Close()
	_, err := r.run("x")
	requireCode(t, err, smerr.CodeNodeUnreachable)
}

// TestRepinDiscardsTheOldConnectionAndTheOldPinNoLongerConnects: after the node
// presents a new key, dropping the pooled connection and re-pinning makes the
// new key the only one that connects; the old pin is a host-key mismatch.
func TestRepinDiscardsTheOldConnectionAndTheOldPinNoLongerConnects(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	oldPin := r.target()
	r.server.setHostKey(newSigner(t))
	r.pool.Invalidate(r.nodeID, oldPin.User)

	_, err := r.pool.For(oldPin).Run(context.Background(), templatesRead("x"))
	requireCode(t, err, smerr.CodeSSHHostKeyMismatch)

	repinned := r.target()
	if repinned.HostKey == oldPin.HostKey {
		t.Fatal("the rig did not move to the new key")
	}
	if _, err := r.pool.For(repinned).Run(context.Background(), templatesRead("x")); err != nil {
		t.Fatalf("new pin: %v", err)
	}
}
