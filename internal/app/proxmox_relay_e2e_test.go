package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The relay scenarios end to end: a real ssh.Pool opens a real SSH session on
// an in-process server that only runs the one catalog command and pipes it to
// the TLS-serving PVE fake. The only route to PVE is the session.

const relayCommandLine = `'/usr/bin/socat' STDIO TCP:127.0.0.1:8006`

type signerOf struct{ s cryptossh.Signer }

func (s signerOf) Signer(context.Context, secrets.Ref) (cryptossh.Signer, error) { return s.s, nil }

// sshRelayServer accepts one key and refuses everything except session
// channels running relayCommandLine, which it connects to the PVE fake. It
// records what it was asked, as sshd with `restrict` would refuse the rest.
type sshRelayServer struct {
	listener net.Listener
	hostKey  cryptossh.Signer
	client   cryptossh.PublicKey
	fake     *pvefake.Fake

	mu       sync.Mutex
	commands []string
	channels []string
	globals  []string
}

func newSigner(t *testing.T) cryptossh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	mustf(t, err, "generate key")
	s, err := cryptossh.NewSignerFromKey(private)
	mustf(t, err, "signer")
	return s
}

func startSSHRelayServer(t *testing.T, client cryptossh.Signer, fake *pvefake.Fake) *sshRelayServer {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	mustf(t, err, "listen")
	s := &sshRelayServer{listener: l, hostKey: newSigner(t), client: client.PublicKey(), fake: fake}
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

func (s *sshRelayServer) handle(c net.Conn) {
	cfg := &cryptossh.ServerConfig{PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
		if bytes.Equal(key.Marshal(), s.client.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("unknown key")
	}}
	cfg.AddHostKey(s.hostKey)
	conn, chans, reqs, err := cryptossh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer conn.Close()
	go func() {
		for r := range reqs {
			s.mu.Lock()
			s.globals = append(s.globals, r.Type)
			s.mu.Unlock()
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for nc := range chans {
		s.mu.Lock()
		s.channels = append(s.channels, nc.ChannelType())
		s.mu.Unlock()
		if nc.ChannelType() != "session" {
			_ = nc.Reject(cryptossh.Prohibited, "forwarding is not allowed")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, requests)
	}
}

func (s *sshRelayServer) session(ch cryptossh.Channel, requests <-chan *cryptossh.Request) {
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
		_ = req.Reply(true, nil)
		s.mu.Lock()
		s.commands = append(s.commands, payload.Command)
		s.mu.Unlock()
		if payload.Command != relayCommandLine {
			_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{127}))
			return
		}
		upstream, err := s.fake.Dial("tcp", "")
		if err != nil {
			return
		}
		defer upstream.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, ch); done <- struct{}{} }()
		go func() { _, _ = io.Copy(ch, upstream); done <- struct{}{} }()
		<-done
		return
	}
}

func (s *sshRelayServer) seen() (commands, channels, globals []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...), append([]string(nil), s.channels...), append([]string(nil), s.globals...)
}

// sshViaNodeRig is a via_node provider whose relays are real SSH sessions.
type sshViaNodeRig struct {
	*viaNodeRig
	server *sshRelayServer
	pool   *ssh.Pool
	token  string
}

func newSSHViaNodeRig(t *testing.T, tweakMeta func(*runtimes.ProxmoxMeta)) *sshViaNodeRig {
	t.Helper()
	r := newViaNodeRig(t)
	r.fake.AddGuest(pvefake.Guest{Node: "pve1", Type: "qemu", VMID: 100, Name: "web", Status: "running"})
	r.fake.AddGuest(pvefake.Guest{Node: "pve1", Type: "lxc", VMID: 200, Name: "db", Status: "stopped"})
	r.fake.SetRole(pveRole, "VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit", "VM.PowerMgmt")
	secret, err := r.sync.opts.Token(context.Background(), nodeTokenRef)
	mustf(t, err, "token")

	client := newSigner(t)
	server := startSSHRelayServer(t, client, r.fake)
	pool := ssh.NewPool(ssh.PoolConfig{
		ConnectTimeout: 5 * time.Second, CommandTimeout: 5 * time.Second, KeepaliveInterval: 15 * time.Second,
		MaxDialsInFlight: 2, MaxConnections: 2, MaxSessionsPerConnection: 4, IdleConnectionTTL: time.Minute,
	}, ssh.NewCredentials(signerOf{client}), r.clock)
	t.Cleanup(pool.Close)

	hostKey := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(server.hostKey.PublicKey())))
	r.dialer.mu.Lock()
	r.dialer.relay = func(ctx context.Context, target ssh.Target, relay templates.Relay) (net.Conn, error) {
		target.Host, target.Port = "127.0.0.1", server.listener.Addr().(*net.TCPAddr).Port
		target.HostKey = hostKey
		return pool.OpenRelay(ctx, target, relay)
	}
	r.dialer.mu.Unlock()

	if tweakMeta != nil {
		px := r.px
		tweakMeta(&px)
		r.setMeta(r.meta, &px)
	}
	return &sshViaNodeRig{viaNodeRig: r, server: server, pool: pool, token: string(secret)}
}

func TestViaNodeSyncAndPowerRideTheSSHSessionAndNothingElse(t *testing.T) {
	r := newSSHViaNodeRig(t, nil)
	ctx := context.Background()
	p := r.provider()

	mustf(t, r.sync.Sync(ctx, p.ID), "Sync")

	discovered := map[string]bool{}
	for _, n := range mustNodes(t, r.fixture) {
		if n.ProviderID == p.ID {
			discovered[n.NativeID] = true
		}
	}
	if len(discovered) < 3 {
		t.Errorf("discovered %v, want the PVE node and both guests", discovered)
	}

	client, err := r.sync.clientFor(ctx, r.provider())
	mustf(t, err, "clientFor")
	_, outcome, err := client.Power(ctx, proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestLXC, VMID: 200}, "start")
	mustf(t, err, "Power")
	if outcome != proxmox.PowerAccepted || r.fake.GuestStatus(200) != "running" {
		t.Errorf("power outcome %v, guest status %q", outcome, r.fake.GuestStatus(200))
	}

	commands, channels, globals := r.server.seen()
	if len(commands) == 0 {
		t.Fatal("the node never saw a relay command")
	}
	for _, c := range commands {
		if c != relayCommandLine {
			t.Errorf("the node ran %q, want only the fixed relay command", c)
		}
	}
	for _, c := range channels {
		if c != "session" {
			t.Errorf("the connection asked for a %q channel; only sessions may be used", c)
		}
	}
	for _, g := range globals {
		if strings.Contains(g, "forward") {
			t.Errorf("the connection sent global request %q", g)
		}
	}
	if p.Endpoint != "" {
		t.Errorf("provider endpoint = %q; a via_node provider has no address to dial", p.Endpoint)
	}
}

func TestViaNodeSecretNeverReachesTheNodeTheAuditTrailOrTheRecordedState(t *testing.T) {
	r := newSSHViaNodeRig(t, nil)
	ctx := context.Background()
	p := r.provider()
	mustf(t, r.sync.Sync(ctx, p.ID), "Sync")

	commands, _, _ := r.server.seen()
	events, err := json.Marshal(r.events())
	mustf(t, err, "events")
	row, err := json.Marshal(r.provider())
	mustf(t, err, "provider row")
	nodes, err := json.Marshal(mustNodes(t, r.fixture))
	mustf(t, err, "nodes")
	places := map[string]string{
		"node commands": strings.Join(commands, "\n"), "audit events": string(events),
		"provider row": string(row), "discovered nodes": string(nodes),
	}
	for name, content := range places {
		if strings.Contains(content, r.token) {
			t.Errorf("the token is in the %s", name)
		}
	}
}

func TestViaNodeSyncFailsOnATLSMismatchAndSendsNoRequestWithTheToken(t *testing.T) {
	for name, tweak := range map[string]func(*runtimes.ProxmoxMeta){
		"a certificate that does not chain to the recorded CA": func(px *runtimes.ProxmoxMeta) {
			px.CAPEM = string(pvefake.New(t).CAPEM())
		},
		"a name the recorded server name does not match": func(px *runtimes.ProxmoxMeta) {
			px.TLSServerName = "pve.lan"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSSHViaNodeRig(t, tweak)
			ctx := context.Background()
			p := r.provider()

			err := r.sync.Sync(ctx, p.ID)

			var failure *SyncFailure
			if !errors.As(err, &failure) {
				t.Fatalf("Sync = %v, want a SyncFailure", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "tls") && !strings.Contains(err.Error(), "certificate") {
				t.Errorf("error %q does not say it is a TLS failure", err)
			}
			if got := r.fake.Requests(); len(got) != 0 {
				t.Errorf("PVE received %d requests over an unverified channel: %v", len(got), got)
			}
			if strings.Contains(err.Error(), r.token) {
				t.Error("the error quotes the token")
			}
		})
	}
}

func TestViaNodeClientIsReplacedWhenTheNodeIsRepinnedOrSwitchesTransport(t *testing.T) {
	changes := map[string]func(*domain.Node){
		"repin": func(n *domain.Node) { n.Endpoint.HostPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKey" },
		"transport switch": func(n *domain.Node) {
			n.Endpoint.Transport, n.Endpoint.TunnelHostname = domain.TransportCloudflare, "ssh-web-1.example.test"
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			r := newViaNodeRig(t)
			ctx := context.Background()
			p := r.provider()
			first, err := r.sync.clientFor(ctx, p)
			mustf(t, err, "first clientFor")
			_, err = first.Version(ctx)
			mustf(t, err, "version through the relay")

			r.inTx(func(ctx context.Context, tx *database.Tx) error {
				node, err := database.GetNode(ctx, tx, r.node.ID)
				if err != nil {
					return err
				}
				change(&node)
				_, err = database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
				return err
			})
			next, err := r.sync.clientFor(ctx, p)

			mustf(t, err, "clientFor after the change")
			if next == first {
				t.Fatal("the client survived the change of the node's connection")
			}
			eventually(t, "the old client's idle relay to close", func() bool { return r.conns[0].Load() })
		})
	}
}
