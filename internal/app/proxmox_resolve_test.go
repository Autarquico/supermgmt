package app

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const nodeTokenRef = "secret://proxmox/web-1"

// trackedConn reports when the relay it carries is closed.
type trackedConn struct {
	net.Conn
	closed *atomic.Bool
}

func (c trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// viaNodeRig is a fake PVE reachable only through the fixture's SSH node.
type viaNodeRig struct {
	*nodeFixture
	fake   *pvefake.Fake
	sync   *ProxmoxSync
	meta   runtimes.SetupMeta
	px     runtimes.ProxmoxMeta
	mu     sync.Mutex
	conns  []*atomic.Bool
	dialed []ssh.Target
	paths  []string
	refs   []string
}

func newViaNodeRig(t *testing.T, tweak ...func(*config.ProxmoxProvider)) *viaNodeRig {
	t.Helper()
	r := &viaNodeRig{nodeFixture: newNodeFixture(t), fake: pvefake.New(t)}
	r.fake.AddNode("pve1")
	r.fake.SetRole(pveRole, "VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit")
	token := r.fake.AddToken(pveTokenUser, "sm", false)
	r.fake.Grant(pveTokenUser, "/", pveRole, true)
	r.dialer.relay = func(_ context.Context, target ssh.Target, relay templates.Relay) (net.Conn, error) {
		conn, err := r.fake.Dial("tcp", "")
		if err != nil {
			return nil, err
		}
		closed := new(atomic.Bool)
		r.mu.Lock()
		r.conns = append(r.conns, closed)
		r.dialed = append(r.dialed, target)
		r.paths = append(r.paths, relay.SocatPath)
		r.mu.Unlock()
		return trackedConn{Conn: conn, closed: closed}, nil
	}
	r.meta = setupMetaFor()
	r.px = runtimes.ProxmoxMeta{
		CAPEM: string(r.fake.CAPEM()), TokenRef: nodeTokenRef, TokenID: pveTokenUser + "!sm",
		TLSServerName: pvefake.ServerIP, RelayPath: "/usr/bin/socat",
	}
	r.setMeta(r.meta, &r.px)

	provider := &config.ProxmoxProvider{
		Type: "proxmox", Name: "pve", ViaNode: "web-1", VerifyTLS: true, SyncInterval: 30 * time.Second,
	}
	for _, fn := range tweak {
		fn(provider)
	}
	mustf(t, r.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{{Proxmox: provider}}), "configure the provider")

	var err error
	r.sync, err = NewProxmoxSync(r.cfg, ProxmoxSyncOptions{
		Connector: r.conn,
		Token: func(_ context.Context, ref string) (audit.Secret, error) {
			r.mu.Lock()
			r.refs = append(r.refs, ref)
			r.mu.Unlock()
			return audit.Secret(token), nil
		},
	})
	mustf(t, err, "NewProxmoxSync")
	return r
}

func (r *viaNodeRig) setMeta(meta runtimes.SetupMeta, px *runtimes.ProxmoxMeta) {
	r.t.Helper()
	meta.SetupVersion = runtimes.SetupVersion
	meta.Proxmox = px
	capability, err := setupCapability(meta, r.clock.Now())
	mustf(r.t, err, "setupCapability")
	r.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, r.node.ID, capability)
	})
}

func (r *viaNodeRig) provider() domain.Provider {
	r.t.Helper()
	providers, err := database.ListProviders(context.Background(), r.db.Reader())
	mustf(r.t, err, "ListProviders")
	for _, p := range providers {
		if p.Name == "pve" {
			return p
		}
	}
	r.t.Fatal("no provider named pve")
	return domain.Provider{}
}

func (r *viaNodeRig) lastRef() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refs[len(r.refs)-1]
}

func TestViaNodeProviderSyncsThroughTheNodeRelay(t *testing.T) {
	r := newViaNodeRig(t)
	p := r.provider()
	if p.Endpoint != "" || p.Config[providerConfigViaNode] != "web-1" {
		t.Fatalf("provider row = endpoint %q config %v", p.Endpoint, p.Config)
	}

	mustf(t, r.sync.Sync(context.Background(), p.ID), "Sync")

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.dialed) == 0 {
		t.Fatal("the sync never opened a relay")
	}
	got := r.dialed[0]
	if got.NodeID != r.node.ID || got.User != "supermgmt" || got.CredentialRef != "secret://ssh/default@1" || r.paths[0] != "/usr/bin/socat" {
		t.Errorf("relay target = %+v socat %q", got, r.paths[0])
	}
	if r.refs[0] != nodeTokenRef {
		t.Errorf("token ref = %q, want the one setup recorded", r.refs[0])
	}
}

func TestViaNodeProviderIsUnavailableWhenItsNodeCannotCarryIt(t *testing.T) {
	for name, tc := range map[string]struct {
		arrange func(*viaNodeRig)
		code    smerr.Code
		want    string
	}{
		"no such node": {func(r *viaNodeRig) {
			r.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := tx.ExecContext(ctx, `UPDATE nodes SET name = 'other' WHERE id = ?`, r.node.ID)
				return err
			})
		}, smerr.CodeNotFound, "sm nodes add"},
		"not an ssh node": {func(r *viaNodeRig) {
			r.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := tx.ExecContext(ctx, `UPDATE nodes SET kind = 'local' WHERE id = ?`, r.node.ID)
				return err
			})
		}, smerr.CodeNotFound, "sm nodes add"},
		"never set up": {func(r *viaNodeRig) {
			r.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := tx.ExecContext(ctx, `DELETE FROM node_capabilities WHERE node_id = ? AND capability = 'node.setup'`, r.node.ID)
				return err
			})
		}, smerr.CodeCapabilityUnavailable, "sm nodes setup web-1 --proxmox"},
		"set up without proxmox": {func(r *viaNodeRig) { r.setMeta(r.meta, nil) }, smerr.CodeCapabilityUnavailable, "sm nodes setup web-1 --proxmox"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newViaNodeRig(t)
			tc.arrange(r)

			_, err := r.sync.clientFor(context.Background(), r.provider())

			wantError(t, err, tc.code, "")
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the fix %q", err, tc.want)
			}
			if _, err := r.sync.tokenUserOf(context.Background(), r.provider()); err == nil {
				t.Error("the power path resolved a provider the sync cannot")
			}
		})
	}
}

func TestViaNodeConfigurationOverridesWhatSetupRecorded(t *testing.T) {
	r := newViaNodeRig(t)
	target, err := r.sync.resolveTarget(context.Background(), r.provider())
	mustf(t, err, "resolve defaults")
	if target.tokenRef != nodeTokenRef || string(target.ca) != r.px.CAPEM || target.serverName != pvefake.ServerIP ||
		target.relay == nil || target.relay.path != "/usr/bin/socat" || target.endpoint != "" {
		t.Errorf("defaults = %+v", target)
	}

	caFile := t.TempDir() + "/ca.pem"
	override := newViaNodeRig(t, func(p *config.ProxmoxProvider) {
		p.CredentialRef, p.CAFile, p.TLSServerName = "secret://providers/pve/token", caFile, "pve.lan"
	})
	override.sync.opts.ReadFile = func(path string) ([]byte, error) {
		if path != caFile {
			return nil, errors.New("unexpected " + path)
		}
		return []byte("FILE CA"), nil
	}
	target, err = override.sync.resolveTarget(context.Background(), override.provider())
	mustf(t, err, "resolve overrides")
	if target.tokenRef != "secret://providers/pve/token" || string(target.ca) != "FILE CA" || target.serverName != "pve.lan" {
		t.Errorf("overrides = %+v", target)
	}
}

func TestPowerPathReadsTheSameCredentialAsTheSync(t *testing.T) {
	for name, configured := range map[string]string{"recorded by setup": "", "configured": "secret://providers/pve/token"} {
		t.Run(name, func(t *testing.T) {
			r := newViaNodeRig(t, func(p *config.ProxmoxProvider) { p.CredentialRef = configured })
			p := r.provider()
			want := nodeTokenRef
			if configured != "" {
				want = configured
			}

			_, err := r.sync.clientFor(context.Background(), p)
			mustf(t, err, "clientFor")
			synced := r.lastRef()
			user, err := r.sync.tokenUserOf(context.Background(), p)
			mustf(t, err, "tokenUserOf")

			if synced != want || r.lastRef() != want {
				t.Errorf("sync used %q, power used %q, want %q", synced, r.lastRef(), want)
			}
			if !strings.HasPrefix(user, pveTokenUser) {
				t.Errorf("token user = %q", user)
			}
		})
	}
}

func TestViaNodeClientIsReusedUntilSomethingItIsBuiltFromChanges(t *testing.T) {
	changes := map[string]func(*viaNodeRig){
		"node revision": func(r *viaNodeRig) { r.bumpNodeRevision() },
		"setup metadata": func(r *viaNodeRig) {
			px := r.px
			px.RelayPath = "/bin/socat"
			r.setMeta(r.meta, &px)
		},
		"pinned key": func(r *viaNodeRig) {
			meta := r.meta
			meta.KeyVersion = 2
			r.setMeta(meta, &r.px)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			r := newViaNodeRig(t)
			ctx := context.Background()
			p := r.provider()
			first, err := r.sync.clientFor(ctx, p)
			mustf(t, err, "first clientFor")
			again, err := r.sync.clientFor(ctx, p)
			mustf(t, err, "second clientFor")
			if first != again {
				t.Fatal("an unchanged provider rebuilt its client")
			}
			if _, err := first.Version(ctx); err != nil {
				t.Fatalf("version through the relay: %v", err)
			}
			if len(r.conns) != 1 || r.conns[0].Load() {
				t.Fatalf("expected one open idle relay, got %d (closed %v)", len(r.conns), r.conns[0].Load())
			}

			change(r)
			next, err := r.sync.clientFor(ctx, p)

			mustf(t, err, "clientFor after change")
			if next == first {
				t.Fatal("the client survived a change of its inputs")
			}
			eventually(t, "the old client's idle relay to close", func() bool { return r.conns[0].Load() })
		})
	}
}

func TestViaNodeClientIsClosedWhenTheNodeGoesAway(t *testing.T) {
	r := newViaNodeRig(t)
	ctx := context.Background()
	p := r.provider()
	client, err := r.sync.clientFor(ctx, p)
	mustf(t, err, "clientFor")
	_, err = client.Version(ctx)
	mustf(t, err, "version")

	r.setMeta(r.meta, nil)
	_, err = r.sync.clientFor(ctx, p)

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	eventually(t, "the dropped client's idle relay to close", func() bool { return r.conns[0].Load() })
	if len(r.sync.clients) != 0 {
		t.Errorf("clients cached = %d", len(r.sync.clients))
	}
}

func TestRelayIdentityFollowsTheNodeItsHostKeyAndItsProxmoxMetadata(t *testing.T) {
	node := domain.Node{ID: "n1", SpecRevision: 3, Endpoint: domain.NodeEndpoint{HostPublicKey: "ssh-ed25519 AAAA"}}
	base := nodeProxmox{setup: runtimes.SetupMeta{KeyRef: "secret://ssh/default", KeyVersion: 1}, px: runtimes.ProxmoxMeta{CAPEM: "ca", TLSServerName: "pve"}}
	want := relayIdentity(node, base)

	otherKey, otherRev, otherCA := node, node, base
	otherKey.Endpoint.HostPublicKey = "ssh-ed25519 BBBB"
	otherRev.SpecRevision++
	otherCA.px.CAPEM = "other"
	for name, got := range map[string]string{
		"host key": relayIdentity(otherKey, base), "revision": relayIdentity(otherRev, base), "metadata": relayIdentity(node, otherCA),
	} {
		if got == want {
			t.Errorf("identity ignores %s", name)
		}
	}
	if relayIdentity(node, base) != want {
		t.Error("identity is not stable")
	}
}
