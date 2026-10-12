package proxmox_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
)

const testTimeout = 2 * time.Second

type env struct {
	fake   *pvefake.Fake
	client proxmox.Client
	token  string
}

func newEnv(t *testing.T, opts ...pvefake.Option) *env {
	t.Helper()
	f := pvefake.New(t, opts...)
	f.AddNode("pve1")
	f.AddNode("pve2")
	f.AddGuest(pvefake.Guest{Node: "pve1", Type: "qemu", VMID: 100, Name: "web", Status: "running", MaxCPU: 2, MaxMem: 1 << 30, MaxDisk: 8 << 30, Pool: "prod"})
	f.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "db", Template: true})
	f.AddStorage(pvefake.Storage{ID: "local", Node: "pve1", Plugin: "dir", Content: []string{"iso", "vztmpl"}, Total: 100, Used: 10})
	f.AddStorage(pvefake.Storage{ID: "ceph", Node: "pve2", Plugin: "rbd", Content: []string{"images"}, Total: 500, Used: 50, Shared: true})
	token := f.AddToken("root@pam", "admin", false)
	f.Grant("root@pam", "/", "Administrator", true)
	return &env{fake: f, token: token, client: newClient(t, f, token)}
}

func newClient(t *testing.T, f *pvefake.Fake, token string, opts ...proxmox.Option) proxmox.Client {
	t.Helper()
	opts = append([]proxmox.Option{
		proxmox.WithHTTPTimeout(testTimeout),
		proxmox.WithNetguardOptions(netguard.WithTestDialer(f.Dial)),
	}, opts...)
	c, err := proxmox.New(f.Endpoint(), f.CAPEM(), audit.Secret(token), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func secretOf(token string) string { _, s, _ := strings.Cut(token, "="); return s }

func TestVersionIsSupportedOnlyForPVE9(t *testing.T) {
	e := newEnv(t)
	v, err := e.client.Version(context.Background())
	if err != nil || v.Version != "9.0.3" || v.Release != "9.0" || !v.Supported() {
		t.Fatalf("Version = %+v, %v", v, err)
	}
	for version, want := range map[string]bool{"9.1.0": true, "8.4.1": false, "10.0": false, "": false, "x": false} {
		if got := (proxmox.Version{Version: version}).Supported(); got != want {
			t.Errorf("Supported(%q) = %v, want %v", version, got, want)
		}
	}
}

func TestResourcesMapNodesGuestsAndStorages(t *testing.T) {
	e := newEnv(t)
	inv, err := e.client.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Nodes) != 2 || inv.Nodes[0].Name != "pve1" || inv.Nodes[0].Status != "online" || inv.Nodes[0].MaxCPU != 8 {
		t.Errorf("nodes = %+v", inv.Nodes)
	}
	if len(inv.Guests) != 2 {
		t.Fatalf("guests = %+v", inv.Guests)
	}
	web, db := inv.Guests[0], inv.Guests[1]
	if web.Ref != (proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}) ||
		web.Name != "web" || web.Status != "running" || web.Pool != "prod" || web.Template || web.MaxCPU != 2 || web.MaxDisk != 8<<30 {
		t.Errorf("web = %+v", web)
	}
	if db.Ref.Type != proxmox.GuestLXC || !db.Template {
		t.Errorf("db = %+v", db)
	}
	if len(inv.Storages) != 2 {
		t.Fatalf("storages = %+v", inv.Storages)
	}
	local, ceph := inv.Storages[0], inv.Storages[1]
	if local.ID != "local" || local.Node != "pve1" || local.Plugin != "dir" || strings.Join(local.Content, ",") != "iso,vztmpl" ||
		local.Total != 100 || local.Used != 10 || local.Shared || !ceph.Shared {
		t.Errorf("storages = %+v", inv.Storages)
	}
}

func TestResourcesOnlyContainWhatTheTokenMayAudit(t *testing.T) {
	e := newEnv(t)
	e.fake.SetRole("Audit", "VM.Audit", "Sys.Audit")
	tok := e.fake.AddToken("ro@pve", "t", true)
	e.fake.Grant("ro@pve", "/", "Audit", true)
	e.fake.Grant("ro@pve!t", "/", "Audit", true)
	inv, err := newClient(t, e.fake, tok).Resources(context.Background())
	if err != nil || len(inv.Guests) != 2 || len(inv.Nodes) != 2 || len(inv.Storages) != 0 {
		t.Fatalf("inventory = %+v, %v", inv, err)
	}
	e.fake.Revoke("ro@pve!t", "/", "Audit")
	inv, err = newClient(t, e.fake, tok).Resources(context.Background())
	if err != nil || len(inv.Guests) != 0 {
		t.Fatalf("after the ACL shrank: %+v, %v", inv, err)
	}
}

func TestPermissions(t *testing.T) {
	e := newEnv(t)
	e.fake.SetRole("Audit", "VM.Audit")
	e.fake.SetRole("Power", "VM.PowerMgmt")
	tok := e.fake.AddToken("sm@pve", "t", true)
	for _, s := range []string{"sm@pve", "sm@pve!t"} {
		e.fake.Grant(s, "/", "Audit", true)
		e.fake.Grant(s, "/vms/100", "Power", true)
	}
	perms, err := newClient(t, e.fake, tok).Permissions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !perms["/vms/100"].Has("VM.PowerMgmt") || perms["/vms/200"].Has("VM.PowerMgmt") || !perms["/"].Has("VM.Audit") {
		t.Errorf("perms = %v", perms)
	}
}

// SEC-14: a grant that does not propagate is effective on its own path.
func TestNonPropagatingGrantIsKeptAsEffectiveOnItsOwnPath(t *testing.T) {
	e := newEnv(t)
	e.fake.SetRole("Power", "VM.PowerMgmt")
	tok := e.fake.AddToken("sm@pve", "t", false)
	e.fake.Grant("sm@pve", "/vms/100", "Power", false)
	c := newClient(t, e.fake, tok)

	perms, err := c.Permissions(context.Background())
	if err != nil || !perms["/vms/100"].Has("VM.PowerMgmt") || perms["/vms/100"]["VM.PowerMgmt"].Propagate {
		t.Errorf("Permissions = %v, %v; want VM.PowerMgmt on /vms/100 without propagation", perms, err)
	}
	privs, err := c.PathPermissions(context.Background(), "/vms/100")
	if err != nil || !privs.Has("VM.PowerMgmt") {
		t.Errorf("PathPermissions(/vms/100) = %v, %v", privs, err)
	}
}

// SEC-13: the exact path is asked, so a path the sparse list omits is neither
// guessed from a parent nor from an old pool.
func TestPathPermissionsAreEffectivePrivilegesOfTheExactPath(t *testing.T) {
	e := newEnv(t)
	e.fake.SetRole("Power", "VM.PowerMgmt")
	e.fake.SetRole("Audit", "VM.Audit")
	tok := e.fake.AddToken("sm@pve", "t", false)
	e.fake.Grant("sm@pve", "/vms", "Power", true)
	e.fake.Grant("sm@pve", "/vms/200", "NoAccess", true)
	e.fake.Grant("sm@pve", "/pool/prod", "Audit", true)
	c := newClient(t, e.fake, tok)

	tests := []struct {
		path, priv string
		want       bool
	}{
		{"/vms/100", "VM.Audit", true},      // the pool of guest 100 grants it
		{"/vms/100", "VM.PowerMgmt", false}, // the pool level replaces /vms
		{"/vms/200", "VM.PowerMgmt", false}, // NoAccess on the guest
		{"/vms/999", "VM.PowerMgmt", true},  // inherited from /vms
		{"/nodes/pve1", "Sys.Audit", false},
	}
	for _, tt := range tests {
		privs, err := c.PathPermissions(context.Background(), tt.path)
		if err != nil || privs.Has(tt.priv) != tt.want {
			t.Errorf("PathPermissions(%s).Has(%s) = %v (%v), want %v", tt.path, tt.priv, privs.Has(tt.priv), err, tt.want)
		}
	}
	last := e.fake.Requests()[len(e.fake.Requests())-1]
	if last.Query.Get("path") != "/nodes/pve1" {
		t.Errorf("last query = %v, want path=/nodes/pve1", last.Query)
	}
	if _, err := c.PathPermissions(context.Background(), "vms/100?x=1"); err == nil {
		t.Error("an invalid ACL path must be refused before any request")
	}
}

func TestPowerOutcomes(t *testing.T) {
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	tests := []struct {
		name    string
		prepare func(*env)
		ref     proxmox.GuestRef
		verb    string
		want    proxmox.PowerOutcome
	}{
		{"accepted", func(*env) {}, ref, "stop", proxmox.PowerAccepted},
		{"accepted with shutdown timeout", func(*env) {}, ref, "shutdown", proxmox.PowerAccepted},
		{"guest already in that state", func(*env) {}, ref, "start", proxmox.PowerRejected},
		{"guest moved to another node", func(e *env) { e.fake.MigrateGuest(100, "pve2") }, ref, "stop", proxmox.PowerRejected},
		{"guest locked", func(e *env) { e.fake.SetLock(100, "backup") }, ref, "stop", proxmox.PowerRejected},
		{"token lost VM.PowerMgmt", func(e *env) { e.fake.Revoke("root@pam", "/", "Administrator") }, ref, "stop", proxmox.PowerRejected},
		{"unknown verb never leaves the process", func(*env) {}, ref, "suspend", proxmox.PowerRejected},
		{"proxy error page", func(e *env) {
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(502, "<html>bad gateway</html>")})
		}, ref, "stop", proxmox.PowerUncertain},
		{"5xx without a PVE body", func(e *env) {
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(500, "")})
		}, ref, "stop", proxmox.PowerUncertain},
		{"5xx with a PVE body", func(e *env) {
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(500, `{"data":null,"message":"boom\n"}`)})
		}, ref, "stop", proxmox.PowerRejected},
		{"2xx with an unparsable body", func(e *env) {
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(200, "ok")})
		}, ref, "stop", proxmox.PowerUncertain},
		{"2xx with a data field that is no UPID", func(e *env) {
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(200, `{"data":"started"}`)})
		}, ref, "stop", proxmox.PowerUncertain},
		{"connection dropped before the request ran", func(e *env) {
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.DropBefore()})
		}, ref, "stop", proxmox.PowerUncertain},
		{"connection dropped after the request ran", func(e *env) {
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.DropAfter()})
		}, ref, "stop", proxmox.PowerUncertain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			tt.prepare(e)
			c := newClient(t, e.fake, e.token)
			upid, got, err := c.Power(context.Background(), tt.ref, tt.verb)
			if got != tt.want {
				t.Fatalf("outcome = %d (err %v), want %d", got, err, tt.want)
			}
			if got == proxmox.PowerAccepted && (err != nil || upid.Type != "qm"+tt.verb || upid.ID != "100" || upid.User != "root@pam!admin") {
				t.Errorf("accepted: upid %+v, err %v", upid, err)
			}
			if got != proxmox.PowerAccepted && (err == nil || upid.Raw != "") {
				t.Errorf("not accepted must carry an error and no UPID: %+v, %v", upid, err)
			}
			if n := e.fake.Count("POST", "/status/"+tt.verb); n > 1 {
				t.Errorf("%d POSTs sent, a power call must never retry", n)
			}
		})
	}
}

func TestPowerSendsExactlyOnePostWhenTheAnswerIsLost(t *testing.T) {
	e := newEnv(t)
	e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.DropAfter()})
	_, outcome, _ := e.client.Power(context.Background(), proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}, "stop")
	if outcome != proxmox.PowerUncertain || e.fake.Count("POST", "/status/stop") != 1 || e.fake.GuestStatus(100) != "stopped" {
		t.Fatalf("outcome %d, posts %d, guest %q", outcome, e.fake.Count("POST", "/status/stop"), e.fake.GuestStatus(100))
	}
}

func TestPowerTimeoutIsUncertain(t *testing.T) {
	e := newEnv(t)
	c := newClient(t, e.fake, e.token, proxmox.WithHTTPTimeout(200*time.Millisecond))
	e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Hang()})
	_, outcome, err := c.Power(context.Background(), proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}, "stop")
	if outcome != proxmox.PowerUncertain || err == nil {
		t.Fatalf("outcome %d, err %v", outcome, err)
	}
}

func TestPowerRefusedByNetguardIsRejected(t *testing.T) {
	// No test dialer: loopback is refused before any connection is made.
	c, err := proxmox.New("https://127.0.0.1:8006", nil, audit.Secret("u@pve!t=s"))
	if err != nil {
		t.Fatal(err)
	}
	_, outcome, err := c.Power(context.Background(), proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestLXC, VMID: 1}, "start")
	if outcome != proxmox.PowerRejected || !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("outcome %d, err %v", outcome, err)
	}
}

func TestPowerTaskLifecycle(t *testing.T) {
	e := newEnv(t, pvefake.WithManualTasks())
	upid, outcome, err := e.client.Power(context.Background(), proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}, "reboot")
	if outcome != proxmox.PowerAccepted || err != nil {
		t.Fatal(outcome, err)
	}
	st, err := e.client.Task(context.Background(), upid)
	if err != nil || st.Stopped() || st.Status != "running" {
		t.Fatalf("running task = %+v, %v", st, err)
	}
	e.fake.FinishTask(upid.Raw, "OK")
	st, err = e.client.Task(context.Background(), upid)
	if err != nil || !st.Stopped() || st.ExitStatus != "OK" || st.UPID.Raw != upid.Raw {
		t.Fatalf("stopped task = %+v, %v", st, err)
	}
}

func TestTaskRejectsMalformedAndForeignUPIDs(t *testing.T) {
	e := newEnv(t)
	if _, err := e.client.Task(context.Background(), proxmox.UPID{Raw: "UPID:pve1:../../x"}); err == nil {
		t.Error("a malformed UPID must be refused before any request")
	}
	if n := len(e.fake.Requests()); n != 0 {
		t.Errorf("%d requests sent for a malformed UPID", n)
	}
	upid := "UPID:pve1:000003E9:000003E9:6B49D200:qmstop:100:root@pam!admin:"
	if _, err := e.client.Task(context.Background(), mustParse(t, upid)); err == nil {
		t.Error("an unknown task must be an error")
	}
}

func mustParse(t *testing.T, s string) proxmox.UPID {
	t.Helper()
	u, err := proxmox.ParseUPID(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTasksReadsEveryPageAndFiltersServerSide(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	e := newEnv(t, pvefake.WithClock(func() time.Time { clock = clock.Add(time.Second); return clock }))
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	for range 130 {
		for _, verb := range []string{"stop", "start"} {
			if _, o, err := e.client.Power(context.Background(), ref, verb); o != proxmox.PowerAccepted {
				t.Fatal(o, err)
			}
		}
	}
	all, err := e.client.Tasks(context.Background(), "pve1", proxmox.TaskFilter{})
	if err != nil || len(all) != 260 {
		t.Fatalf("got %d tasks, %v; want 260 (more than one page)", len(all), err)
	}
	filtered, err := e.client.Tasks(context.Background(), "pve1", proxmox.TaskFilter{
		VMID: 100, TypeName: "qmstop", User: "root@pam!admin",
		Since: time.Unix(1_800_000_000, 0), Until: time.Unix(1_900_000_000, 0),
	})
	if err != nil || len(filtered) != 130 {
		t.Fatalf("filtered = %d, %v; want 130", len(filtered), err)
	}
	last := e.fake.Requests()[len(e.fake.Requests())-1].Query
	for key, want := range map[string]string{"vmid": "100", "typefilter": "qmstop", "userfilter": "root@pam", "source": "all", "since": "1800000000", "until": "1900000000"} {
		if last.Get(key) != want {
			t.Errorf("query %s = %q, want %q", key, last.Get(key), want)
		}
	}
	if _, err := e.client.Tasks(context.Background(), "pve1/../x", proxmox.TaskFilter{}); err == nil {
		t.Error("an invalid node name must be refused")
	}
}

func TestCorrelationFindsATaskThatOnlyAppearsOnPageTwo(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	e := newEnv(t, pvefake.WithClock(func() time.Time { return clock }))
	dispatchedAt := clock
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	if _, o, err := e.client.Power(context.Background(), ref, "stop"); o != proxmox.PowerAccepted {
		t.Fatal(o, err)
	}
	clock = clock.Add(time.Hour) // a burst of newer, unrelated tasks pushes it to page 2
	e.fake.AddGuest(pvefake.Guest{Node: "pve1", Type: "lxc", VMID: 300, Status: "stopped"})
	for range 60 {
		for _, verb := range []string{"start", "stop"} {
			if _, o, err := e.client.Power(context.Background(), proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestLXC, VMID: 300}, verb); o != proxmox.PowerAccepted {
				t.Fatal(o, err)
			}
		}
	}
	tasks, err := e.client.Tasks(context.Background(), "pve1", proxmox.TaskFilter{})
	if err != nil {
		t.Fatal(err)
	}
	from, until := proxmox.CorrelationWindow(dispatchedAt, testTimeout)
	got, result := proxmox.Correlate(tasks, proxmox.Want{Type: "qmstop", VMID: 100, User: "root@pam!admin", From: from, Until: until})
	if result != proxmox.CorrelatedOne || got.ID != "100" {
		t.Fatalf("Correlate = %+v, %d", got, result)
	}
}

func TestTLSTrust(t *testing.T) {
	e := newEnv(t)
	other := pvefake.New(t)
	dial := proxmox.WithNetguardOptions(netguard.WithTestDialer(e.fake.Dial))
	tests := []struct {
		name     string
		endpoint string
		ca       []byte
	}{
		{"CA that did not sign the server", e.fake.Endpoint(), other.CAPEM()},
		{"name not in the certificate", "https://10.77.0.2:8006", e.fake.CAPEM()},
		{"system roots do not know the appliance CA", e.fake.Endpoint(), nil},
	}
	for _, tt := range tests {
		c, err := proxmox.New(tt.endpoint, tt.ca, audit.Secret(e.token), dial, proxmox.WithHTTPTimeout(testTimeout))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Version(context.Background()); err == nil {
			t.Errorf("%s: the connection must be refused", tt.name)
		}
	}
	if n := len(e.fake.Requests()); n != 0 {
		t.Errorf("%d requests reached the server over an untrusted connection", n)
	}
	if _, err := newClient(t, e.fake, e.token).Version(context.Background()); err != nil {
		t.Errorf("the right CA and name must connect: %v", err)
	}
}

func TestNewValidatesItsInputs(t *testing.T) {
	good := audit.Secret("u@pve!t=s")
	tests := []struct {
		name     string
		endpoint string
		ca       []byte
		token    audit.Secret
	}{
		{"http endpoint", "http://pve:8006", nil, good},
		{"userinfo", "https://root:pw@pve:8006", nil, good},
		{"path", "https://pve:8006/api2/json", nil, good},
		{"query", "https://pve:8006?x=1", nil, good},
		{"no host", "https://", nil, good},
		{"CA that is not PEM", "https://pve:8006", []byte("garbage"), good},
		{"token without id", "https://pve:8006", nil, audit.Secret("secret")},
		{"empty token", "https://pve:8006", nil, ""},
	}
	for _, tt := range tests {
		if _, err := proxmox.New(tt.endpoint, tt.ca, tt.token); err == nil {
			t.Errorf("%s: want an error", tt.name)
		}
	}
	if _, err := proxmox.New("https://pve:8006/", nil, good); err != nil {
		t.Errorf("trailing slash: %v", err)
	}
}

// The token must not appear in any error, whatever the server or the network
// echoes back.
func TestTokenNeverAppearsInErrors(t *testing.T) {
	e := newEnv(t)
	secret := secretOf(e.token)
	ctx := context.Background()
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	echo := fmt.Sprintf(`{"data":null,"message":"token %s and secret %s are invalid"}`, e.token, secret)
	for _, path := range []string{"/version", "/cluster/resources", "/access/permissions", "/tasks"} {
		e.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: path, Fault: pvefake.Respond(500, echo)})
	}
	e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(500, echo)})

	var errs []error
	_, err := e.client.Version(ctx)
	errs = append(errs, err)
	_, err = e.client.Resources(ctx)
	errs = append(errs, err)
	_, err = e.client.Permissions(ctx)
	errs = append(errs, err)
	_, err = e.client.Tasks(ctx, "pve1", proxmox.TaskFilter{})
	errs = append(errs, err)
	_, _, err = e.client.Power(ctx, ref, "stop")
	errs = append(errs, err)

	// Wrong token (401) and unreachable server.
	bad := newClient(t, e.fake, "root@pam!admin=notthesecret0000")
	_, err = bad.Version(ctx)
	errs = append(errs, err)
	dead, _ := proxmox.New("https://10.77.0.1:8006", e.fake.CAPEM(), audit.Secret(e.token),
		proxmox.WithNetguardOptions(netguard.WithTestDialer(func(string, string) (net.Conn, error) {
			return nil, fmt.Errorf("dial failed for %s", e.token)
		})))
	_, err = dead.Version(ctx)
	errs = append(errs, err)

	for i, err := range errs {
		if err == nil {
			t.Fatalf("call %d: want an error", i)
		}
		for _, leak := range []string{secret, e.token, "notthesecret0000"} {
			if strings.Contains(err.Error(), leak) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), leak) {
				t.Errorf("call %d leaks %q: %v", i, leak, err)
			}
		}
	}
	var apiErr *proxmox.APIError
	if !errors.As(errs[0], &apiErr) || apiErr.Status != 500 {
		t.Errorf("want an *APIError with the status, got %v", errs[0])
	}
}

func TestEndpointURLIsNotLeakedWithQueryTokens(t *testing.T) {
	e := newEnv(t)
	if _, err := e.client.Tasks(context.Background(), "pve1", proxmox.TaskFilter{User: "x"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.fake.Requests() {
		if strings.Contains(r.Path, secretOf(e.token)) || strings.Contains(r.Query.Encode(), secretOf(e.token)) {
			t.Fatalf("the token travelled outside the Authorization header: %+v", r)
		}
	}
}
