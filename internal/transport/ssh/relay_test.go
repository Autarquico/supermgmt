package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const relayLine = `'/usr/bin/socat' STDIO TCP:127.0.0.1:8006`

var socat = templates.Relay{SocatPath: "/usr/bin/socat"}

// relayServer accepts one login key and hands every exec request to serve,
// which streams on the channel (the shared testServer buffers stdin to EOF).
type relayServer struct {
	listener net.Listener
	hostKey  cryptossh.Signer
	client   cryptossh.PublicKey
	serve    func(cmd string, ch cryptossh.Channel)
	execGate <-chan struct{} // when set, exec requests wait for it to close
	rejects  atomic.Int32    // channel opens still to refuse
	openGate chan struct{}   // when set, the first channel open waits for it to close
	gateOnce sync.Once

	mu       sync.Mutex
	commands []string
}

func startRelayServer(t *testing.T, client cryptossh.Signer, serve func(string, cryptossh.Channel)) *relayServer {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &relayServer{listener: l, hostKey: newSigner(t), client: client.PublicKey(), serve: serve}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *relayServer) handle(c net.Conn) {
	cfg := &cryptossh.ServerConfig{
		PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), s.client.Marshal()) {
				return nil, nil
			}
			return nil, io.ErrUnexpectedEOF
		},
	}
	cfg.AddHostKey(s.hostKey)
	conn, chans, reqs, err := cryptossh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer conn.Close()
	go cryptossh.DiscardRequests(reqs)
	for nc := range chans {
		if s.rejects.Add(-1) >= 0 {
			_ = nc.Reject(cryptossh.ResourceShortage, "refused")
			continue
		}
		s.rejects.Store(0)
		if s.openGate != nil {
			s.gateOnce.Do(func() { <-s.openGate })
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, requests)
	}
}

func (s *relayServer) session(ch cryptossh.Channel, requests <-chan *cryptossh.Request) {
	defer ch.Close()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var payload struct{ Command string }
		_ = cryptossh.Unmarshal(req.Payload, &payload)
		if s.execGate != nil {
			<-s.execGate
		}
		_ = req.Reply(true, nil)
		s.mu.Lock()
		s.commands = append(s.commands, payload.Command)
		s.mu.Unlock()
		s.serve(payload.Command, ch)
		return
	}
}

func (s *relayServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func echo(_ string, ch cryptossh.Channel) { _, _ = io.Copy(ch, ch) }

type relayRig struct {
	server *relayServer
	pool   *Pool
	nodeID domain.ID
}

func newRelayRig(t *testing.T, cfg PoolConfig, serve func(string, cryptossh.Channel)) relayRig {
	t.Helper()
	client := newSigner(t)
	pool := NewPool(cfg, &staticCreds{signer: client}, domaintest.NewFakeClock(epoch))
	t.Cleanup(pool.Close)
	return relayRig{
		server: startRelayServer(t, client, serve), pool: pool,
		nodeID: domaintest.NewSequentialIDs().NewID(),
	}
}

func (r relayRig) target() Target {
	return Target{
		NodeID: r.nodeID, Host: "127.0.0.1", Port: r.server.listener.Addr().(*net.TCPAddr).Port,
		User: "supermgmt", HostKey: string(bytes.TrimSpace(marshalAuthorized(r.server.hostKey))),
		CredentialRef: "secret://ssh/default",
	}
}

func (r relayRig) open(t *testing.T) net.Conn {
	t.Helper()
	conn, err := r.pool.OpenRelay(context.Background(), r.target(), socat)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestRelayCarriesBytesAndRunsTheFixedCommand(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), echo)
	conn := r.open(t)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
		t.Fatalf("read %q, %v", got, err)
	}
	if cmds := r.server.seen(); len(cmds) != 1 || cmds[0] != relayLine {
		t.Errorf("commands = %q, want [%q]", cmds, relayLine)
	}
}

func TestRelayRefusesASocatPathOutsideTheAllowlist(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), echo)
	for _, path := range []string{"", "socat", "/tmp/socat", "/usr/bin/socat; id", "/usr/bin/../bin/socat"} {
		_, err := r.pool.OpenRelay(context.Background(), r.target(), templates.Relay{SocatPath: path})
		if err == nil {
			t.Errorf("path %q was accepted", path)
		}
	}
	if len(r.server.seen()) != 0 {
		t.Errorf("a refused path reached the node: %q", r.server.seen())
	}
}

func TestRelayCountsAgainstTheSessionLimitUntilClosed(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxSessionsPerConnection = 1
	r := newRelayRig(t, cfg, echo)
	first := r.open(t)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := r.pool.OpenRelay(ctx, r.target(), socat)
	requireCode(t, err, smerr.CodeTimeout)

	_ = first.Close()
	r.open(t)
}

func TestRelayHoldsItsConnectionLeaseUntilClose(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), echo)
	conn := r.open(t)
	if st := r.pool.State(r.nodeID); st.Status != ConnConnected {
		t.Fatalf("state with a relay open = %v", st.Status)
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = conn.Close() }()
	}
	wg.Wait()
	_ = conn.Close()
	if st := r.pool.State(r.nodeID); st.Status != ConnIdle {
		t.Errorf("state after close = %v; the lease was not released exactly once", st.Status)
	}
}

func TestRelayReadDeadlineExpires(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), func(_ string, ch cryptossh.Channel) { _, _ = io.Copy(io.Discard, ch) })
	conn := r.open(t)
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:forbidigo // a deadline on a real connection
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("read error = %v, want a deadline error", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:forbidigo // a deadline on a real connection
	big := make([]byte, 1<<20)
	if _, err := conn.Write(big); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("write error = %v", err)
	}
}

func TestRelayEndsWithEOFWhenTheNodeEndsIt(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), func(string, cryptossh.Channel) {})
	conn := r.open(t)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("read error = %v, want EOF", err)
	}
}

func TestRelayDiagnosticsAreTheSanitizedStderr(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), func(_ string, ch cryptossh.Channel) {
		_, _ = io.WriteString(ch.Stderr(), "socat: connection refused\x1b[31m\n")
	})
	conn := r.open(t)
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()
	note := conn.(Diagnoser).Diagnostics()
	if !strings.Contains(note, "socat: connection refused") {
		t.Errorf("diagnostics = %q", note)
	}
	for _, c := range note {
		if c < ' ' {
			t.Errorf("control character in %q", note)
		}
	}
}

func TestRelayOpenCancelledLateIsCleanedUp(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxSessionsPerConnection = 1
	gate := make(chan struct{})
	r := newRelayRig(t, cfg, echo)
	r.server.execGate = gate

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := r.pool.OpenRelay(ctx, r.target(), socat)
	requireCode(t, err, smerr.CodeTimeout)

	close(gate)
	eventually(t, "the late session to give its slot back", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		conn, err := r.pool.OpenRelay(ctx, r.target(), socat)
		if err == nil {
			_ = conn.Close()
		}
		return err == nil
	})
}

func TestRelayCloseReturnsWithinTheBoundWhenTheNodeStopsAnswering(t *testing.T) {
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	r := newRelayRig(t, defaultConfig(), func(string, cryptossh.Channel) { <-stuck })
	conn := r.open(t)

	closed := make(chan struct{})
	go func() { _ = conn.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * diagnosticsWaitF):
		t.Fatal("Close hung on a node that never acknowledged it")
	}
	if st := r.pool.State(r.nodeID); st.Status == ConnConnected {
		t.Errorf("state after close = %v; the lease was kept", st.Status)
	}
}

func TestRelayRetriesOnceOnAFreshConnectionWhenTheSessionCannotOpen(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), echo)
	r.server.rejects.Store(1)
	conn := r.open(t)
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ok" {
		t.Fatalf("read %q, %v", got, err)
	}
}

func TestRelayDoesNotRetryASecondStaleOpen(t *testing.T) {
	r := newRelayRig(t, defaultConfig(), echo)
	r.server.rejects.Store(2)
	_, err := r.pool.OpenRelay(context.Background(), r.target(), socat)
	requireCode(t, err, smerr.CodeNodeUnreachable)
}

func TestRelayCancelledDuringNewSessionReleasesSlotAndLease(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxSessionsPerConnection = 1
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	r := newRelayRig(t, cfg, echo)
	r.server.openGate = gate

	var lc atomic.Pointer[liveConn]
	go func() {
		eventually(t, "the connection to be dialed", func() bool {
			r.pool.mu.Lock()
			defer r.pool.mu.Unlock()
			for _, pe := range r.pool.peers {
				if pe.conn != nil {
					lc.Store(pe.conn)
					return true
				}
			}
			return false
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := r.pool.OpenRelay(ctx, r.target(), socat)
	requireCode(t, err, smerr.CodeTimeout)
	got := lc.Load()
	if got == nil {
		t.Fatal("the connection was never observed")
	}
	if !got.isClosed() {
		t.Error("the connection with a hung NewSession was not closed")
	}
	eventually(t, "the slot and lease to come back", func() bool {
		r.pool.mu.Lock()
		defer r.pool.mu.Unlock()
		return got.active == 0 && len(got.sessions) == 0
	})
}
