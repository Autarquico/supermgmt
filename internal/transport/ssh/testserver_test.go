package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// reply is what the scripted server answers to one exec request.
type reply struct {
	stdout, stderr string
	status         int
	wait           <-chan struct{} // when set, the server answers only after it closes
}

type testServer struct {
	t          *testing.T
	listener   net.Listener
	hostKey    cryptossh.Signer
	authorized cryptossh.PublicKey

	handler          func(cmd string, stdin []byte) reply
	handshakeDelay   time.Duration
	ignoreKeepalives bool

	connections  atomic.Int32 // completed handshakes
	authAttempts atomic.Int32
	inHandshake  atomic.Int32
	maxHandshake atomic.Int32
	inSessions   atomic.Int32
	maxSessions  atomic.Int32

	mu    sync.Mutex
	conns []net.Conn
	keyMu sync.Mutex
}

func newSigner(t *testing.T) cryptossh.Signer {
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

// startServer listens on a loopback port and accepts the given client key.
func startServer(t *testing.T, client cryptossh.Signer, configure func(*testServer)) *testServer {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{
		t: t, listener: l, hostKey: newSigner(t), authorized: client.PublicKey(),
		handler: func(cmd string, _ []byte) reply { return reply{stdout: "ran: " + cmd} },
	}
	if configure != nil {
		configure(s)
	}
	t.Cleanup(s.close)
	go s.acceptLoop()
	return s
}

func (s *testServer) close() {
	_ = s.listener.Close()
	s.dropConnections()
}

func (s *testServer) dropConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

func (s *testServer) port() int { return s.listener.Addr().(*net.TCPAddr).Port }

func (s *testServer) currentHostKey() cryptossh.Signer {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return s.hostKey
}

func (s *testServer) setHostKey(k cryptossh.Signer) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	s.hostKey = k
}

func (s *testServer) pinned() string {
	return strings.TrimSpace(string(marshalAuthorized(s.currentHostKey())))
}

func marshalAuthorized(s cryptossh.Signer) []byte {
	return cryptossh.MarshalAuthorizedKey(s.PublicKey())
}

func rsaAuthorizedKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := cryptossh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(public)))
}

func (s *testServer) acceptLoop() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.serve(c)
	}
}

func bump(current, peak *atomic.Int32) {
	n := current.Add(1)
	for {
		old := peak.Load()
		if n <= old || peak.CompareAndSwap(old, n) {
			return
		}
	}
}

func (s *testServer) serve(c net.Conn) {
	cfg := &cryptossh.ServerConfig{
		PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			s.authAttempts.Add(1)
			if bytes.Equal(key.Marshal(), s.authorized.Marshal()) {
				return nil, nil
			}
			return nil, io.ErrUnexpectedEOF
		},
	}
	cfg.AddHostKey(s.currentHostKey())
	bump(&s.inHandshake, &s.maxHandshake)
	time.Sleep(s.handshakeDelay)
	conn, chans, reqs, err := cryptossh.NewServerConn(c, cfg)
	s.inHandshake.Add(-1)
	if err != nil {
		_ = c.Close()
		return
	}
	s.connections.Add(1)
	go s.serveRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(cryptossh.UnknownChannelType, "no")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.serveSession(channel, requests)
	}
	_ = conn.Close()
}

func (s *testServer) serveRequests(reqs <-chan *cryptossh.Request) {
	for req := range reqs {
		if s.ignoreKeepalives {
			continue
		}
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	}
}

func (s *testServer) serveSession(ch cryptossh.Channel, requests <-chan *cryptossh.Request) {
	defer ch.Close()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var payload struct{ Command string }
		if err := cryptossh.Unmarshal(req.Payload, &payload); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		stdin, _ := io.ReadAll(ch)
		bump(&s.inSessions, &s.maxSessions)
		r := s.handler(payload.Command, stdin)
		if r.wait != nil {
			<-r.wait
		}
		s.inSessions.Add(-1)
		_, _ = io.WriteString(ch, r.stdout)
		_, _ = io.WriteString(ch.Stderr(), r.stderr)
		_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{uint32(r.status)}))
		return
	}
}

// staticCreds authenticates with a fixed signer, standing in for the resolver.
type staticCreds struct {
	signer cryptossh.Signer
	calls  atomic.Int32
}

func (c *staticCreds) Resolve(context.Context, string) (Credential, error) {
	c.calls.Add(1)
	return Credential{Auth: cryptossh.PublicKeys(c.signer)}, nil
}

type rig struct {
	server *testServer
	pool   *Pool
	clock  *domaintest.FakeClock
	client cryptossh.Signer
	nodeID domain.ID
}

func (r rig) target() Target {
	return Target{
		NodeID: r.nodeID, Host: "127.0.0.1", Port: r.server.port(), User: "supermgmt",
		HostKey: r.server.pinned(), CredentialRef: "secret://ssh/default",
	}
}

func (r rig) run(cmd string) (string, error) {
	res, err := r.pool.For(r.target()).Run(context.Background(), templates.Command{Line: cmd, MaxBytes: 1 << 16})
	return string(res.Stdout), err
}

func defaultConfig() PoolConfig {
	return PoolConfig{
		ConnectTimeout: 5 * time.Second, CommandTimeout: 5 * time.Second,
		MaxDialsInFlight: 4, MaxConnections: 8, MaxSessionsPerConnection: 4,
	}
}

func newRig(t *testing.T, cfg PoolConfig, configure func(*testServer)) rig {
	t.Helper()
	client := newSigner(t)
	server := startServer(t, client, configure)
	clock := domaintest.NewFakeClock(epoch)
	pool := NewPool(cfg, &staticCreds{signer: client}, clock)
	t.Cleanup(pool.Close)
	return rig{server: server, pool: pool, clock: clock, client: client, nodeID: domaintest.NewSequentialIDs().NewID()}
}

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func templatesRead(line string) templates.Command {
	return templates.Command{Line: line, MaxBytes: 1 << 10}
}

// eventually polls cond for up to five seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for !cond() {
		if ctx.Err() != nil {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
