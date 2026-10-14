//go:build stress

package stress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	sshpool "github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// poolServer is a scripted SSH server that answers every exec with "ok". While
// refusing is set it accepts TCP connections and drops them, like a node whose
// sshd is down.
type poolServer struct {
	listener       net.Listener
	hostKey        cryptossh.Signer
	client         cryptossh.PublicKey
	handshakeDelay time.Duration

	refusing     atomic.Bool
	accepted     atomic.Int32 // TCP connections, the number of dial attempts
	handshakes   atomic.Int32 // completed handshakes
	inHandshake  atomic.Int32
	maxHandshake atomic.Int32
}

type poolCreds struct{ signer cryptossh.Signer }

func (c poolCreds) Resolve(context.Context, string) (sshpool.Credential, error) {
	return sshpool.Credential{Auth: cryptossh.PublicKeys(c.signer)}, nil
}

func poolSigner(t *testing.T) cryptossh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func startPoolServer(t *testing.T, client cryptossh.Signer, handshakeDelay time.Duration) *poolServer {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &poolServer{listener: listener, hostKey: poolSigner(t), client: client.PublicKey(), handshakeDelay: handshakeDelay}
	t.Cleanup(func() { _ = listener.Close() })
	go s.acceptLoop()
	return s
}

func (s *poolServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		if s.refusing.Load() {
			_ = conn.Close()
			continue
		}
		go s.serve(conn)
	}
}

func (s *poolServer) serve(conn net.Conn) {
	// The handshake window ends when the key is accepted, before the client can
	// learn it succeeded, so it always lies inside the client's dial slot.
	leaveHandshake := sync.OnceFunc(func() { s.inHandshake.Add(-1) })
	cfg := &cryptossh.ServerConfig{
		PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			leaveHandshake()
			if bytes.Equal(key.Marshal(), s.client.Marshal()) {
				return nil, nil
			}
			return nil, io.ErrUnexpectedEOF
		},
	}
	cfg.AddHostKey(s.hostKey)
	concurrent := s.inHandshake.Add(1)
	for peak := s.maxHandshake.Load(); concurrent > peak && !s.maxHandshake.CompareAndSwap(peak, concurrent); peak = s.maxHandshake.Load() {
	}
	time.Sleep(s.handshakeDelay)
	sshConn, channels, requests, err := cryptossh.NewServerConn(conn, cfg)
	leaveHandshake()
	if err != nil {
		_ = conn.Close()
		return
	}
	s.handshakes.Add(1)
	go answerGlobalRequests(requests)
	for ch := range channels {
		session, sessionRequests, err := ch.Accept()
		if err != nil {
			continue
		}
		go answerExec(session, sessionRequests)
	}
	_ = sshConn.Close()
}

func answerGlobalRequests(requests <-chan *cryptossh.Request) {
	for req := range requests {
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	}
}

func answerExec(ch cryptossh.Channel, requests <-chan *cryptossh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		_ = req.Reply(true, nil)
		_, _ = io.WriteString(ch, "ok")
		_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

type poolRig struct {
	t      *testing.T
	server *poolServer
	pool   *sshpool.Pool
	clock  *domaintest.FakeClock
	ids    *domaintest.SequentialIDs
}

func newPoolRig(t *testing.T, cfg sshpool.PoolConfig, handshakeDelay time.Duration) *poolRig {
	t.Helper()
	client := poolSigner(t)
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	pool := sshpool.NewPool(cfg, poolCreds{signer: client}, clock)
	t.Cleanup(pool.Close)
	return &poolRig{
		t: t, server: startPoolServer(t, client, handshakeDelay), pool: pool, clock: clock, ids: domaintest.NewSequentialIDs(),
	}
}

func poolConfig() sshpool.PoolConfig {
	return sshpool.PoolConfig{
		ConnectTimeout: 10 * time.Second, CommandTimeout: 10 * time.Second,
		MaxDialsInFlight: 3, MaxConnections: 64, MaxSessionsPerConnection: 4,
	}
}

func (r *poolRig) target(node domain.ID) sshpool.Target {
	return sshpool.Target{
		NodeID: node, Host: "127.0.0.1", Port: r.server.listener.Addr().(*net.TCPAddr).Port, User: "supermgmt",
		HostKey: strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(r.server.hostKey.PublicKey()))), CredentialRef: "secret://ssh/default",
	}
}

func (r *poolRig) run(node domain.ID) error {
	res, err := r.pool.For(r.target(node)).Run(context.Background(), templates.Command{Line: "probe", MaxBytes: 1 << 10})
	if err == nil && string(res.Stdout) != "ok" {
		return errors.New("unexpected output " + string(res.Stdout))
	}
	return err
}

func TestManyCallersOnOneNodeShareASingleDial(t *testing.T) {
	const callers = 64
	rig := newPoolRig(t, poolConfig(), 20*time.Millisecond)
	node := rig.ids.NewID()

	jobsRunConcurrently(callers, func(int) {
		if err := rig.run(node); err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	if got := rig.server.handshakes.Load(); got != 1 {
		t.Errorf("%d handshakes for %d callers on one node, want 1", got, callers)
	}
}

func TestDialsInFlightNeverExceedTheConfiguredBound(t *testing.T) {
	const nodes, bound = 24, 3
	cfg := poolConfig()
	cfg.MaxDialsInFlight = bound
	rig := newPoolRig(t, cfg, 15*time.Millisecond)
	targets := make([]domain.ID, nodes)
	for i := range targets {
		targets[i] = rig.ids.NewID()
	}

	jobsRunConcurrently(nodes, func(i int) {
		if err := rig.run(targets[i]); err != nil {
			t.Errorf("Run node %d: %v", i, err)
		}
	})

	if got := rig.server.maxHandshake.Load(); got > bound {
		t.Errorf("peak concurrent handshakes = %d, want at most %d", got, bound)
	}
	if got := rig.server.handshakes.Load(); got != nodes {
		t.Errorf("%d handshakes, want one per node (%d)", got, nodes)
	}
}

func TestAnUnreachableNodeIsDialedOncePerBackoffWindowWhateverTheLoad(t *testing.T) {
	const callers = 64
	rig := newPoolRig(t, poolConfig(), 0)
	rig.server.refusing.Store(true)
	node := rig.ids.NewID()

	hammer := func() {
		jobsRunConcurrently(callers, func(int) {
			err := rig.run(node)
			if smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
				t.Errorf("Run = %v, want code %s", err, smerr.CodeNodeUnreachable)
			}
		})
	}

	hammer()
	if got := rig.server.accepted.Load(); got != 1 {
		t.Fatalf("%d dial attempts in the first wave, want 1 (single flight)", got)
	}
	hammer()
	if got := rig.server.accepted.Load(); got != 1 {
		t.Errorf("%d dial attempts, want none while the node is in backoff", got)
	}

	rig.clock.Advance(2 * time.Second)
	hammer()
	if got := rig.server.accepted.Load(); got != 2 {
		t.Errorf("%d dial attempts after the backoff elapsed, want 2", got)
	}

	rig.server.refusing.Store(false)
	rig.clock.Advance(10 * time.Minute)
	jobsRunConcurrently(callers, func(int) {
		if err := rig.run(node); err != nil {
			t.Errorf("Run after recovery: %v", err)
		}
	})
	if state := rig.pool.State(node); state.Status == sshpool.ConnBackoff {
		t.Errorf("node still in backoff after a successful dial: %+v", state)
	}
}

func TestInvalidatingANodeWhileCallersRunNeverLeavesThemWithoutAConnection(t *testing.T) {
	const callers, rounds = 16, 10
	rig := newPoolRig(t, poolConfig(), 2*time.Millisecond)
	node := rig.ids.NewID()
	// Invalidations are paced slower than a dial: an Invalidate arriving
	// during every handshake would (by design) supersede each dial forever.
	var invalidating sync.WaitGroup
	invalidating.Add(1)
	go func() {
		defer invalidating.Done()
		for range 15 {
			rig.pool.Invalidate(node, "supermgmt")
			time.Sleep(20 * time.Millisecond)
		}
	}()

	jobsRunConcurrently(callers, func(int) {
		for range rounds {
			if err := rig.run(node); err != nil {
				t.Errorf("Run during invalidation: %v", err)
				return
			}
		}
	})
	invalidating.Wait()
}
