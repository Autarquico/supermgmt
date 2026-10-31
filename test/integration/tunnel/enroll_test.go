package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Scenarios "a node with no inbound port is added from the laptop", "Cloudflare objects come before any
// node and never leave an open route" and "the daemon dies mid-enrollment" (ADR-0039), on the real stack:
// the job engine, the scheduler, the SSH pool with the cloudflare dialler and the carrier stand-in
// (test/fixtures/cloudflared-fake), which bridges to an in-process SSH server. No Docker.

// enrolledNode is an SSH server that stands for the host after it ran the node line: it accepts the
// instance's key, answers the probe, and counts every TCP connection it accepts.
type enrolledNode struct {
	listener net.Listener
	hostKey  cryptossh.Signer
	client   cryptossh.PublicKey
	accepted atomic.Int32

	mu       sync.Mutex
	commands []string
}

func startEnrolledNode(t *testing.T, client string) *enrolledNode {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	signer, err := cryptossh.NewSignerFromKey(private)
	must(t, err)
	authorized, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(client))
	must(t, err)
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	must(t, err)
	n := &enrolledNode{listener: l, hostKey: signer, client: authorized}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.accepted.Add(1)
			go n.serve(c)
		}
	}()
	return n
}

func (n *enrolledNode) hostKeyLine() string {
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(n.hostKey.PublicKey())))
}

func (n *enrolledNode) serve(c net.Conn) {
	cfg := &cryptossh.ServerConfig{PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
		if bytes.Equal(key.Marshal(), n.client.Marshal()) {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	cfg.AddHostKey(n.hostKey)
	conn, chans, reqs, err := cryptossh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer conn.Close()
	go cryptossh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(cryptossh.Prohibited, "no forwarding")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go n.session(ch, requests)
	}
}

// probeOutput is the smallest output the discovery parser accepts: the header and every section, empty.
func probeOutput() string {
	var b strings.Builder
	b.WriteString("@@probe 1\n")
	for _, section := range templates.ProbeSections {
		b.WriteString("@@" + section + "\n")
	}
	return b.String()
}

func (n *enrolledNode) session(ch cryptossh.Channel, requests <-chan *cryptossh.Request) {
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
		n.mu.Lock()
		n.commands = append(n.commands, payload.Command)
		n.mu.Unlock()
		_, _ = ch.Write([]byte(probeOutput()))
		_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

// enrollRig is a stack with an enrollment service, a scheduler ticking in the background and a node that
// is reachable only through the carrier.
type enrollRig struct {
	*stack
	node *enrolledNode
}

func newEnrollRig(t *testing.T, o stackOptions) *enrollRig {
	t.Helper()
	s := newStack(t, o)
	identity, err := secrets.EnsureSSHIdentity(context.Background(), s.store)
	must(t, err)
	node := startEnrolledNode(t, identity.AuthorizedKey)
	must(t, os.WriteFile(filepath.Join(s.home, "forward"), []byte(node.listener.Addr().String()+"\n"), 0o600))

	var system domain.ID
	must(t, s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		system = s.ids.NewID()
		return database.CreateIdentity(ctx, tx, database.Identity{ID: system, ActorType: domain.ActorSystem, Subject: "system", CreatedAt: s.clock.Now()})
	}))
	scheduler := s.enroll.Scheduler(system)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if err := scheduler.Tick(ctx); err != nil && ctx.Err() == nil {
				s.logs.add("scheduler", err.Error())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &enrollRig{stack: s, node: node}
}

func (r *enrollRig) view(name string) app.TunnelEnrollmentView {
	r.t.Helper()
	v, err := r.enroll.Get(context.Background(), r.admin, name)
	must(r.t, err)
	return v
}

// until polls the enrollment until its phase is want.
func (r *enrollRig) until(name, want string) app.TunnelEnrollmentView {
	r.t.Helper()
	deadline := time.Now().Add(30 * time.Second) //nolint:forbidigo // wall-clock budget of a polling loop
	for time.Now().Before(deadline) {            //nolint:forbidigo // see above
		if v := r.view(name); v.Phase == want {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatalf("enrollment %s is %q (%s), want %q", name, r.view(name).Phase, r.view(name).Error, want)
	return app.TunnelEnrollmentView{}
}

func (r *enrollRig) nodeNamed(name string) (domain.Node, bool) {
	r.t.Helper()
	var found domain.Node
	var ok bool
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM nodes WHERE name = ?`, name)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			var id domain.ID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ok = true
			found, err = database.GetNode(ctx, tx, id)
			return err
		}
		return rows.Err()
	}))
	return found, ok
}

func (r *enrollRig) enrollToCommit(name string) (app.TunnelEnrollmentView, domain.Node) {
	r.t.Helper()
	res, err := r.enroll.Start(context.Background(), r.admin, app.StartTunnelEnrollment{Name: name})
	must(r.t, err)
	if res.Applied == nil {
		r.t.Fatalf("start parked for approval: %+v", res.Pending)
	}
	scanned := r.until(name, string(database.PhaseScanned))
	if scanned.HostPublicKey != r.node.hostKeyLine() {
		r.t.Fatalf("scanned %q, want the node's key %q", scanned.HostPublicKey, r.node.hostKeyLine())
	}
	if _, found := r.nodeNamed(name); found {
		r.t.Fatal("a node row exists before the confirmation")
	}
	_, err = r.enroll.Confirm(context.Background(), r.admin, name, scanned.ID, scanned.HostPublicKey)
	must(r.t, err)
	done := r.until(name, string(database.PhaseCommitted))
	node, found := r.nodeNamed(name)
	if !found {
		r.t.Fatal("no node row after the commit")
	}
	return done, node
}

func TestEnrollingANodeReachableOnlyThroughTheCarrierNeverDialsItsAddress(t *testing.T) {
	r := newEnrollRig(t, stackOptions{})
	view, node := r.enrollToCommit("vps1")

	if node.Endpoint.Transport != domain.TransportCloudflare || node.Endpoint.HostPublicKey != r.node.hostKeyLine() ||
		node.Endpoint.Host != view.Hostname || node.Endpoint.AdminUser != "" {
		t.Errorf("node endpoint = %+v, want cloudflare, the scanned key pinned and no admin user", node.Endpoint)
	}

	// every TCP connection the node accepted came from a carrier child: the instance never dialled it itself
	records := r.carrierRecords()
	if got := int(r.node.accepted.Load()); got == 0 || got != len(records) {
		t.Errorf("the node accepted %d connections and %d carriers ran, want equal and not zero", got, len(records))
	}
	for _, rec := range records {
		if !slices.Contains(rec.Argv, view.Hostname) {
			t.Errorf("carrier argv %v does not name the tunnel hostname", rec.Argv)
		}
	}

	// the order Cloudflare saw, and no moment with a route and no Access application
	var order []cffake.Op
	for _, m := range r.cf.Mutations() {
		order = append(order, m.Op)
	}
	at := func(op cffake.Op) int { return slices.Index(order, op) }
	if at(cffake.OpTunnelCreate) < 0 || at(cffake.OpTunnelCreate) >= at(cffake.OpTunnelConfigPut) ||
		at(cffake.OpTunnelConfigPut) >= at(cffake.OpAppCreate) || at(cffake.OpAppCreate) >= at(cffake.OpDNSCreate) {
		t.Errorf("Cloudflare mutations %v, want tunnel, ingress, Access application, DNS", order)
	}
	if routable := r.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		t.Errorf("routable without Access: %v", routable)
	}
}

func TestTheConnectorTokenLeavesNoTraceOnTheControlPlane(t *testing.T) {
	r := newEnrollRig(t, stackOptions{})
	res, err := r.enroll.Start(context.Background(), r.admin, app.StartTunnelEnrollment{Name: "vps1"})
	must(t, err)
	r.until("vps1", string(database.PhaseScanned))
	token, err := r.enroll.Token(context.Background(), r.admin, "vps1")
	must(t, err)
	secret := token.Reveal()
	if secret == "" {
		t.Fatal("no connector token while the enrollment is open")
	}
	scanned := r.view("vps1")
	_, err = r.enroll.Confirm(context.Background(), r.admin, "vps1", scanned.ID, scanned.HostPublicKey)
	must(t, err)
	r.until("vps1", string(database.PhaseCommitted))

	places := r.scanControlPlane()
	for _, rec := range r.carrierRecords() {
		places["carrier argv"] = append(places["carrier argv"], strings.Join(rec.Argv, "\x00")...)
		places["carrier env"] = append(places["carrier env"], strings.Join(rec.Env, "\x00")...)
	}
	places["join line"] = []byte(res.Applied.JoinLine)
	for name, data := range places {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("the connector token is in %s", name)
		}
	}
}

func TestACrashBetweenACloudflareCallAndItsRecordResumesWithoutDuplicates(t *testing.T) {
	r := newEnrollRig(t, stackOptions{})
	// the response of the 2nd and 5th mutations is lost: Cloudflare applied them, the job never saw it
	r.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Seq == 2 || m.Seq == 5 {
			return cffake.LostResponse
		}
		return cffake.NoFault
	})
	_, node := r.enrollToCommit("vps1")
	r.cf.ClearFaults()

	if node.Name != "vps1" {
		t.Fatalf("node = %+v", node)
	}
	snap := r.cf.Snapshot()
	hostname := r.view("vps1").Hostname
	tunnels, apps, records := 0, 0, 0
	for _, tun := range snap.Tunnels {
		if strings.Contains(tun.Name, node.ID.String()) {
			tunnels++
		}
	}
	for _, a := range snap.Apps {
		if a.Domain == hostname {
			apps++
		}
	}
	for _, d := range snap.DNSRecords {
		if d.Name == hostname {
			records++
		}
	}
	if tunnels != 1 || apps != 1 || records != 1 {
		t.Errorf("tunnels %d, Access applications %d, DNS records %d for the enrollment, want one of each", tunnels, apps, records)
	}
	if routable := r.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		t.Errorf("routable without Access: %v", routable)
	}
}
