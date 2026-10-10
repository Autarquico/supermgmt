package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// testHostKey is a valid OpenSSH host key for fixture nodes.
var testHostKey = newAuthorizedKey()

func newAuthorizedKey() string {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	key, err := cryptossh.NewPublicKey(public)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key)))
}

// linuxProbe is a probe output of a Debian node with systemd and Docker.
const linuxProbe = `@@probe 1
@@uname
Linux 6.12.43-amd64 x86_64
@@os
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
ID=debian
@@hostname
node-a
@@uptime
12345.67 9999.00
@@cpu
4
cpu  1000 0 500 8000 500 0 0 0 0 0
cpu  1100 0 600 8100 500 0 0 0 0 0
@@loadavg
0.52 0.40 0.30 1/200 999
@@memory
MemTotal:        8000000 kB
MemFree:         1000000 kB
MemAvailable:    5000000 kB
@@disk
Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/vda1         50000000 20000000  30000000      40% /
@@pkgmgr
apt-get
@@systemd
active
/usr/bin/systemctl
systemd 257 (257.9-1)
@@docker
path=/usr/bin/docker
server=26.1.5
compose=2.29.1
@@tools
btop
tmux
@@sudo
yes
@@setup
user=admin
home=absent
markers=absent
@@addresses
1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0
`

// fakeNode answers rendered templates by name, like a node would. Every call
// is recorded; a template without a handler fails the test.
type fakeNode struct {
	t        *testing.T
	mu       sync.Mutex
	handlers map[string]func(templates.Command) (transport.Result, error)
	calls    []templates.Command
	fallback func(templates.Command) (transport.Result, error) // for templates without a handler; nil fails the test
}

func newFakeNode(t *testing.T) *fakeNode {
	return &fakeNode{t: t, handlers: map[string]func(templates.Command) (transport.Result, error){}}
}

func (f *fakeNode) on(template string, h func(templates.Command) (transport.Result, error)) *fakeNode {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[template] = h
	return f
}

func (f *fakeNode) reply(template, stdout string) *fakeNode {
	return f.on(template, func(templates.Command) (transport.Result, error) {
		return transport.Result{Stdout: []byte(stdout)}, nil
	})
}

func (f *fakeNode) exit(template string, status int) *fakeNode {
	return f.on(template, func(templates.Command) (transport.Result, error) {
		return transport.Result{ExitStatus: status}, nil
	})
}

func (f *fakeNode) down(template string, err error) *fakeNode {
	return f.on(template, func(templates.Command) (transport.Result, error) { return transport.Result{}, err })
}

func (f *fakeNode) Run(_ context.Context, c templates.Command) (transport.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	h, ok := f.handlers[c.Template]
	fallback := f.fallback
	f.mu.Unlock()
	switch {
	case ok:
		return h(c)
	case fallback != nil:
		return fallback(c)
	}
	f.t.Errorf("unexpected template %s (line %q)", c.Template, c.Line)
	return transport.Result{ExitStatus: 127}, nil
}

func (f *fakeNode) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, len(f.calls))
	for i, c := range f.calls {
		names[i] = c.Template
	}
	return names
}

func (f *fakeNode) count(template string) int {
	n := 0
	for _, name := range f.ran() {
		if name == template {
			n++
		}
	}
	return n
}

// fakeDialer hands out one fakeNode per login user, and remembers the targets.
type fakeDialer struct {
	t      *testing.T
	mu     sync.Mutex
	nodes  map[string]*fakeNode
	routes map[domain.ID]*fakeNode // a node with its own behavior, whoever logs in
	states map[domain.ID]ssh.ConnState
	dialed []ssh.Target
}

func newFakeDialer(t *testing.T) *fakeDialer {
	return &fakeDialer{t: t, nodes: map[string]*fakeNode{}, routes: map[domain.ID]*fakeNode{}, states: map[domain.ID]ssh.ConnState{}}
}

// as returns the fake node reached as user.
func (d *fakeDialer) as(user string) *fakeNode {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nodes[user] == nil {
		d.nodes[user] = newFakeNode(d.t).reply("probe", linuxProbe)
	}
	return d.nodes[user]
}

// route gives one node its own fake, whatever user connects.
func (d *fakeDialer) route(id domain.ID, n *fakeNode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.routes[id] = n
}

func (d *fakeDialer) For(t ssh.Target) transport.Executor {
	d.mu.Lock()
	d.dialed = append(d.dialed, t)
	routed := d.routes[t.NodeID]
	d.mu.Unlock()
	if routed != nil {
		return routed
	}
	return d.as(t.User)
}

func (d *fakeDialer) State(node domain.ID) ssh.ConnState {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.states[node]; ok {
		return s
	}
	return ssh.ConnState{Status: ssh.ConnUnknown}
}

func (d *fakeDialer) targets() []ssh.Target {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]ssh.Target(nil), d.dialed...)
}

// nodeFixture is the fixture plus the node-facing services over a fake pool.
type nodeFixture struct {
	*fixture
	dialer *fakeDialer
	conn   Connector
	inv    *Inventory
	svcs   *Services
	probe  *Prober
}

func newNodeFixture(t *testing.T, tweak ...func(*Config)) *nodeFixture {
	t.Helper()
	f := newFixture(t, tweak...)
	n := &nodeFixture{fixture: f, dialer: newFakeDialer(t)}
	n.conn = Connector{Remote: n.dialer}
	var err error
	n.inv, err = NewInventory(f.cfg, InventoryOptions{Store: f.store, Connector: n.conn, Mode: config.ModeLocal})
	if err != nil {
		t.Fatalf("NewInventory: %v", err)
	}
	if n.svcs, err = NewServices(f.cfg, f.store); err != nil {
		t.Fatalf("NewServices: %v", err)
	}
	if n.probe, err = NewProber(f.cfg, n.conn, nil); err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	return n
}

// grantSetup records a completed node.setup on the fixture node.
func (f *fixture) grantSetup(units ...string) {
	f.t.Helper()
	meta := setupMetaFor(units...)
	capability, err := setupCapability(meta, f.clock.Now())
	if err != nil {
		f.t.Fatalf("setupCapability: %v", err)
	}
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.node.ID, capability)
	})
}

// setupMetaFor is the node.setup metadata of a node whose units each got every verb.
func setupMetaFor(units ...string) runtimes.SetupMeta {
	meta := runtimes.SetupMeta{
		SetupVersion: runtimes.SetupVersion, SystemctlPath: "/usr/bin/systemctl", LogsMode: runtimes.LogsJournalGroup,
		KeyRef: "secret://ssh/default", KeyVersion: 1, KeyFingerprint: "SHA256:test",
	}
	for _, unit := range units {
		meta.Units = append(meta.Units, runtimes.UnitGrant{Unit: unit, Verbs: domain.AllServiceVerbs()})
	}
	return meta
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second) //nolint:forbidigo // test polling against real goroutines
	for !cond() {
		if time.Now().After(deadline) { //nolint:forbidigo // see above
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func mustf(t *testing.T, err error, format string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", fmt.Sprintf(format, args...), err)
	}
}
