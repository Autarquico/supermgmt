package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// enrollSetting is a tunnel fixture with the enrollment service over it: the Cloudflare fake, the scripted
// node that answers only through the tunnel, and a scanner that sees the node's host key once it is up.
type enrollSetting struct {
	*tunnelSetting
	svc    *TunnelEnrollments
	sched  *TunnelEnrollmentScheduler
	system domain.ID
	apply  applyHandler

	hostKey string       // what the node presents; "" while its connector is not up
	scanned []ssh.Target // every scan, which must all go through the tunnel
}

func newEnrollSetting(t *testing.T) *enrollSetting {
	t.Helper()
	ts := newTunnelSetting(t)
	es := &enrollSetting{tunnelSetting: ts}
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		es.system = ts.fixture.identity(ctx, tx, "system", domain.ActorSystem, "")
		return nil
	})
	es.svc = es.newService(ts.handler.tunnel)
	es.sched = es.svc.Scheduler(es.system)
	es.apply = applyHandler{inv: ts.inv, enrollments: es.svc}
	return es
}

// newService is a service over the fixture, as a restarted daemon builds one. engine nil: no cloudflare block.
func (es *enrollSetting) newService(engine *tunnelEngine) *TunnelEnrollments {
	es.t.Helper()
	svc, err := NewTunnelEnrollments(es.fixture.cfg, es.plans, es.store, TunnelEnrollmentOptions{
		Tunnel:    &TunnelOptions{Config: es.cfg, Secrets: es.secrets},
		Identity:  func(context.Context) (secrets.Identity, error) { return es.identity, nil },
		Connector: es.conn, Scan: es.scan, Prober: es.handler.prober,
	})
	mustf(es.t, err, "NewTunnelEnrollments")
	svc.engine = engine
	return svc
}

// restart replaces the service and the scheduler by new ones over the same database.
func (es *enrollSetting) restart() {
	es.svc = es.newService(es.handler.tunnel)
	es.sched = es.svc.Scheduler(es.system)
	es.apply = applyHandler{inv: es.inv, enrollments: es.svc}
}

func (es *enrollSetting) scan(_ context.Context, target ssh.Target) (ssh.HostKey, error) {
	es.scanned = append(es.scanned, target)
	if es.hostKey == "" {
		return ssh.HostKey{}, errors.New("the tunnel has no connector yet")
	}
	fingerprint, _ := sshnode.Fingerprint(es.hostKey)
	return ssh.HostKey{Authorized: es.hostKey, Type: "ssh-ed25519", FingerprintSHA256: fingerprint}, nil
}

func (es *enrollSetting) admin() Caller { return es.caller(es.fixture.admin) }

// start begins an enrollment of vps1 as the admin with no approval needed (no environment).
func (es *enrollSetting) start(mutate ...func(*StartTunnelEnrollment)) TunnelEnrollmentView {
	es.t.Helper()
	r := StartTunnelEnrollment{Name: "vps1"}
	for _, m := range mutate {
		m(&r)
	}
	res, err := es.svc.Start(context.Background(), es.admin(), r)
	mustf(es.t, err, "Start")
	if res.Applied == nil {
		es.t.Fatalf("Start parked for approval: %+v", res.Pending)
	}
	return *res.Applied
}

// runJob claims one job and runs it, leaving it running (a crash) when it fails.
func (es *enrollSetting) runJob() (jobs.Job, error, bool) {
	es.t.Helper()
	claimed, ok := es.claim()
	if !ok {
		return jobs.Job{}, nil, false
	}
	err := es.apply.Run(context.Background(), claimed.Lease)
	if err == nil {
		mustf(es.t, es.store.Succeed(context.Background(), claimed.Lease), "Succeed")
	}
	return claimed.Job, err, true
}

// work runs the queued jobs until none is claimable. A job that fails is failed the way the engine does
// (requeued with backoff while attempts are left).
func (es *enrollSetting) work() []error {
	es.t.Helper()
	var failures []error
	for {
		claimed, ok := es.claim()
		if !ok {
			return failures
		}
		err := es.apply.Run(context.Background(), claimed.Lease)
		if err == nil {
			mustf(es.t, es.store.Succeed(context.Background(), claimed.Lease), "Succeed")
			continue
		}
		failures = append(failures, err)
		mustf(es.t, es.store.Fail(context.Background(), claimed.Lease, err), "Fail")
	}
}

// tick lets the scheduler submit what is due and runs the jobs it submitted. The clock moves past the
// pauses of the work that waits, so it is due.
func (es *enrollSetting) tick() []error {
	es.t.Helper()
	es.clock.Advance(3 * time.Minute)
	mustf(es.t, es.sched.Tick(context.Background()), "Tick")
	return es.work()
}

// settle ticks until nothing changes the enrollment's phase, at most n times.
func (es *enrollSetting) settle(id domain.ID, n int) database.TunnelEnrollment {
	es.t.Helper()
	var row database.TunnelEnrollment
	for range n {
		before := es.enrollmentRow(id).Phase
		es.tick()
		row = es.enrollmentRow(id)
		if row.Phase == before {
			break
		}
	}
	return row
}

func (es *enrollSetting) enrollmentRow(id domain.ID) database.TunnelEnrollment {
	es.t.Helper()
	row, err := database.GetTunnelEnrollment(context.Background(), es.db.Reader(), id)
	mustf(es.t, err, "GetTunnelEnrollment")
	return row
}

func (es *enrollSetting) nodeNamed(name string) (domain.Node, bool) {
	es.t.Helper()
	nodes, err := database.ListNodes(context.Background(), es.db.Reader())
	mustf(es.t, err, "ListNodes")
	for _, n := range nodes {
		if n.Name == name {
			return n, true
		}
	}
	return domain.Node{}, false
}

func (es *enrollSetting) nodeCount() int {
	es.t.Helper()
	nodes, err := database.ListNodes(context.Background(), es.db.Reader())
	mustf(es.t, err, "ListNodes")
	return len(nodes)
}

// nodeComesUp makes the scanner see a new host key and returns it.
func (es *enrollSetting) nodeComesUp() string {
	es.hostKey = newAuthorizedKey()
	return es.hostKey
}

// scannedEnrollment drives a new enrollment to the point where the operator is shown the node's key.
func (es *enrollSetting) scannedEnrollment() (TunnelEnrollmentView, string) {
	es.t.Helper()
	view := es.start()
	es.work()
	key := es.nodeComesUp()
	row := es.settle(view.ID, 3)
	if row.Phase != database.PhaseScanned {
		es.t.Fatalf("phase = %s (%s), want scanned", row.Phase, row.LastError)
	}
	return view, key
}

// everything is every place the connector token could have been written: audit events, job payloads, plans,
// enrollment rows and the views.
func (es *enrollSetting) everything(id domain.ID) string {
	es.t.Helper()
	var b strings.Builder
	for _, e := range es.events() {
		raw, err := json.Marshal(e)
		mustf(es.t, err, "marshal event")
		b.Write(raw)
	}
	for _, query := range []string{`SELECT payload_json FROM jobs`, `SELECT plan_json FROM plans`, `SELECT error_json FROM jobs WHERE error_json IS NOT NULL`} {
		rows, err := es.db.Reader().QueryContext(context.Background(), query)
		mustf(es.t, err, "query %s", query)
		for rows.Next() {
			var text string
			mustf(es.t, rows.Scan(&text), "scan")
			b.WriteString(text)
		}
		mustf(es.t, rows.Err(), "rows")
		_ = rows.Close()
	}
	row := es.enrollmentRow(id)
	raw, err := json.Marshal(row)
	mustf(es.t, err, "marshal row")
	b.Write(raw)
	view, err := es.svc.view(context.Background(), es.db.Reader(), row)
	mustf(es.t, err, "view")
	raw, err = json.Marshal(view)
	mustf(es.t, err, "marshal view")
	b.Write(raw)
	return b.String()
}

// tokenOf reads the connector token the way the operator does.
func (es *enrollSetting) tokenOf(name string) audit.Secret {
	es.t.Helper()
	token, err := es.svc.Token(context.Background(), es.admin(), name)
	mustf(es.t, err, "Token")
	if token == "" {
		es.t.Fatal("empty connector token")
	}
	return token
}

func wantCode(t *testing.T, err error, code smerr.Code) {
	t.Helper()
	if err == nil || smerr.CodeOf(err) != code {
		t.Fatalf("error = %v (%s), want %s", err, smerr.CodeOf(err), code)
	}
}
