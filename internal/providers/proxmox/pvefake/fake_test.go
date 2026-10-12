package pvefake

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type probe struct {
	f      *Fake
	token  string
	client *http.Client
}

func newProbe(t *testing.T, f *Fake, token string) *probe {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.CAPEM())
	return &probe{f: f, token: token, client: &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return f.Dial(network, addr)
			},
		},
	}}
}

type answer struct {
	status int
	body   map[string]any
}

func (p *probe) do(t *testing.T, method, path string, form url.Values) answer {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, p.f.Endpoint()+apiPrefix+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if p.token != "" {
		req.Header.Set("Authorization", "PVEAPIToken="+p.token)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return answer{status: resp.StatusCode, body: out}
}

// cluster builds two nodes, a stopped and a running guest, and an admin token.
func cluster(t *testing.T, opts ...Option) (*Fake, *probe) {
	t.Helper()
	f := New(t, opts...)
	f.AddNode("pve1")
	f.AddNode("pve2")
	f.AddGuest(Guest{Node: "pve1", Type: "qemu", VMID: 100, Name: "web", Status: "running"})
	f.AddGuest(Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "db"})
	f.AddStorage(Storage{ID: "local", Node: "pve1", Plugin: "dir", Content: []string{"iso", "vztmpl"}, Total: 100, Used: 10})
	admin := f.AddToken("root@pam", "admin", false)
	f.Grant("root@pam", "/", "Administrator", true)
	return f, newProbe(t, f, admin)
}

func TestUnknownEndpointsParametersAndMethodsAreRejected(t *testing.T) {
	_, p := cluster(t)
	tests := []struct {
		name, method, path string
		form               url.Values
		want               int
	}{
		{"unknown endpoint", "GET", "/cluster/status", nil, http.StatusNotImplemented},
		{"wrong method", "DELETE", "/version", nil, http.StatusNotImplemented},
		{"unknown query parameter", "GET", "/version?verbose=1", nil, http.StatusBadRequest},
		{"unknown form parameter", "POST", "/nodes/pve1/qemu/100/status/stop", url.Values{"force": {"1"}}, http.StatusBadRequest},
		{"lxc stop takes no timeout", "POST", "/nodes/pve2/lxc/200/status/stop", url.Values{"timeout": {"5"}}, http.StatusBadRequest},
		{"malformed value", "POST", "/nodes/pve1/qemu/100/status/shutdown", url.Values{"timeout": {"soon"}}, http.StatusBadRequest},
		{"unknown verb", "POST", "/nodes/pve1/qemu/100/status/suspend", nil, http.StatusNotImplemented},
		{"malformed upid", "GET", "/nodes/pve1/tasks/nope/status", nil, http.StatusBadRequest},
	}
	for _, tt := range tests {
		if got := p.do(t, tt.method, tt.path, tt.form); got.status != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.name, got.status, tt.want)
		}
	}
}

func TestAuthentication(t *testing.T) {
	f, _ := cluster(t)
	for _, token := range []string{"", "root@pam!admin=wrong", "ghost@pam!x=y"} {
		if got := newProbe(t, f, token).do(t, "GET", "/version", nil); got.status != http.StatusUnauthorized {
			t.Errorf("token %q: status = %d, want 401", token, got.status)
		}
	}
}

func TestPrivilegesAreEnforcedPerPath(t *testing.T) {
	f, _ := cluster(t)
	f.SetRole("SMAudit", "VM.Audit", "Sys.Audit", "Datastore.Audit")
	f.SetRole("SMPower", "VM.PowerMgmt")
	reader := f.AddToken("sm@pve", "ro", true)
	f.Grant("sm@pve", "/", "SMAudit", true)
	f.Grant("sm@pve!ro", "/", "SMAudit", true)
	p := newProbe(t, f, reader)

	if got := p.do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil); got.status != http.StatusForbidden {
		t.Errorf("power without VM.PowerMgmt: status = %d, want 403", got.status)
	}
	if got := f.GuestStatus(100); got != "running" {
		t.Errorf("a refused call changed the guest to %q", got)
	}
	if got := p.do(t, "GET", "/cluster/resources?type=vm", nil); len(got.body["data"].([]any)) != 2 {
		t.Errorf("auditor sees %v guests, want 2", got.body["data"])
	}
	blind := f.AddToken("blind@pve", "t", true)
	f.Grant("blind@pve", "/", "SMPower", true)
	f.Grant("blind@pve!t", "/", "SMPower", true)
	if got := newProbe(t, f, blind).do(t, "GET", "/cluster/resources", nil); len(got.body["data"].([]any)) != 0 {
		t.Errorf("a token without audit privileges sees %v", got.body["data"])
	}
}

func TestPrivilegeSeparationIsTheIntersectionOfUserAndToken(t *testing.T) {
	f, _ := cluster(t)
	f.SetRole("Power", "VM.PowerMgmt")
	userOnly := f.AddToken("u@pve", "a", true)
	f.Grant("u@pve", "/vms", "Power", true) // the token itself has no ACL
	if got := newProbe(t, f, userOnly).do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil); got.status != http.StatusForbidden {
		t.Errorf("privsep token without its own grant: status = %d, want 403", got.status)
	}
	f.Grant("u@pve!a", "/vms", "Power", true)
	if got := newProbe(t, f, userOnly).do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil); got.status != http.StatusOK {
		t.Errorf("privsep token granted on both: status = %d, want 200", got.status)
	}
}

// ADR-0023 grants SMAudit on / and SMPower on /vms to the same subject. PVE
// lets the deeper path replace what is inherited, so on a guest only the
// /vms role applies. This test pins the fake to that documented rule.
func TestDeeperPathReplacesInheritedRole(t *testing.T) {
	f, _ := cluster(t)
	f.SetRole("Audit", "VM.Audit", "Sys.Audit")
	f.SetRole("Power", "VM.PowerMgmt")
	tok := f.AddToken("sm@pve", "t", true)
	for _, subject := range []string{"sm@pve", "sm@pve!t"} {
		f.Grant(subject, "/", "Audit", true)
		f.Grant(subject, "/vms", "Power", true)
	}
	p := newProbe(t, f, tok)

	if got := p.do(t, "GET", "/cluster/resources?type=vm", nil); len(got.body["data"].([]any)) != 0 {
		t.Errorf("VM.Audit from / must be replaced by the /vms grant, saw %v", got.body["data"])
	}
	if got := p.do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil); got.status != http.StatusOK {
		t.Errorf("power via /vms: status = %d, want 200", got.status)
	}
	perms := p.do(t, "GET", "/access/permissions", nil).body["data"].(map[string]any)
	if _, ok := perms["/vms"].(map[string]any)["VM.PowerMgmt"]; !ok || perms["/"] == nil {
		t.Errorf("permissions = %v, want / and /vms entries", perms)
	}
}

func TestNonPropagatingGrantStopsAtItsPath(t *testing.T) {
	f, _ := cluster(t)
	f.SetRole("Power", "VM.PowerMgmt")
	tok := f.AddToken("u@pve", "t", false)
	f.Grant("u@pve", "/vms", "Power", false)
	if got := newProbe(t, f, tok).do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil); got.status != http.StatusForbidden {
		t.Errorf("status = %d, want 403: a non-propagating grant on /vms must not reach /vms/100", got.status)
	}
}

func TestPowerStateMachine(t *testing.T) {
	_, p := cluster(t, WithManualTasks())
	f := p.f
	post := func(path string) answer { return p.do(t, "POST", path, nil) }

	if got := post("/nodes/pve1/qemu/100/status/start"); got.status != http.StatusInternalServerError {
		t.Errorf("start of a running guest: status = %d, want 500", got.status)
	}
	if got := post("/nodes/pve2/lxc/200/status/stop"); got.status != http.StatusInternalServerError {
		t.Errorf("stop of a stopped guest: status = %d, want 500", got.status)
	}
	if got := post("/nodes/pve2/qemu/100/status/stop"); got.status != http.StatusInternalServerError ||
		!strings.Contains(got.body["message"].(string), "does not exist") {
		t.Errorf("wrong node: %v", got)
	}
	f.SetLock(100, "backup")
	if got := post("/nodes/pve1/qemu/100/status/stop"); got.status != http.StatusInternalServerError {
		t.Errorf("locked guest: status = %d, want 500", got.status)
	}
	f.SetLock(100, "")

	got := post("/nodes/pve1/qemu/100/status/stop")
	upid, _ := got.body["data"].(string)
	if got.status != http.StatusOK || !strings.HasPrefix(upid, "UPID:pve1:") {
		t.Fatalf("stop: %v", got)
	}
	if s := f.GuestStatus(100); s != "running" {
		t.Errorf("guest is %q while its task runs, want running", s)
	}
	status := p.do(t, "GET", "/nodes/pve1/tasks/"+upid+"/status", nil).body["data"].(map[string]any)
	if status["status"] != "running" {
		t.Errorf("task = %v, want running", status)
	}
	f.FinishTask(upid, "OK")
	if s := f.GuestStatus(100); s != "stopped" {
		t.Errorf("guest is %q after the task ended OK, want stopped", s)
	}
	status = p.do(t, "GET", "/nodes/pve1/tasks/"+upid+"/status", nil).body["data"].(map[string]any)
	if status["status"] != "stopped" || status["exitstatus"] != "OK" {
		t.Errorf("task = %v, want stopped OK", status)
	}

	failing := post("/nodes/pve1/qemu/100/status/start").body["data"].(string)
	f.FinishTask(failing, "start failed: timeout")
	if s := f.GuestStatus(100); s != "stopped" {
		t.Errorf("a failed start changed the guest to %q", s)
	}
}

func TestAutomaticTasksEndAtOnce(t *testing.T) {
	_, p := cluster(t)
	upid := p.do(t, "POST", "/nodes/pve1/qemu/100/status/shutdown", url.Values{"timeout": {"60"}}).body["data"].(string)
	if s := p.f.GuestStatus(100); s != "stopped" {
		t.Errorf("guest = %q, want stopped", s)
	}
	if tasks := p.f.Tasks(); len(tasks) != 1 || tasks[0].UPID != upid || tasks[0].Running || tasks[0].Exit != "OK" {
		t.Errorf("tasks = %+v", tasks)
	}
}

func TestMigratedGuestIsOnlyReachableOnItsNewNode(t *testing.T) {
	f, p := cluster(t)
	f.MigrateGuest(100, "pve2")
	if got := p.do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil); got.status != http.StatusInternalServerError {
		t.Errorf("old node: status = %d, want 500", got.status)
	}
	if got := p.do(t, "POST", "/nodes/pve2/qemu/100/status/stop", nil); got.status != http.StatusOK {
		t.Errorf("new node: status = %d, want 200", got.status)
	}
}

func TestTaskListIsNewestFirstPaginatedAndFiltered(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	f, p := cluster(t, WithClock(func() time.Time { clock = clock.Add(time.Second); return clock }))
	for range 30 {
		p.do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil)
		p.do(t, "POST", "/nodes/pve1/qemu/100/status/start", nil)
	}
	first := p.do(t, "GET", "/nodes/pve1/tasks", nil)
	rows := first.body["data"].([]any)
	if len(rows) != 50 || first.body["total"].(float64) != 60 {
		t.Fatalf("page 1 has %d rows of %v, want 50 of 60", len(rows), first.body["total"])
	}
	if rows[0].(map[string]any)["type"] != "qmstart" {
		t.Errorf("newest task = %v, want the last start", rows[0])
	}
	second := p.do(t, "GET", "/nodes/pve1/tasks?start=50&limit=50", nil).body["data"].([]any)
	if len(second) != 10 {
		t.Errorf("page 2 has %d rows, want 10", len(second))
	}
	stops := p.do(t, "GET", "/nodes/pve1/tasks?typefilter=qmstop&limit=100", nil).body["data"].([]any)
	if len(stops) != 30 {
		t.Errorf("typefilter returned %d, want 30", len(stops))
	}
	if other := p.do(t, "GET", "/nodes/pve2/tasks", nil).body["data"].([]any); len(other) != 0 {
		t.Errorf("tasks of another node leaked: %d", len(other))
	}
	if sub := p.do(t, "GET", "/nodes/pve1/tasks?userfilter=root@pam", nil).body["data"].([]any); len(sub) != 50 {
		t.Errorf("userfilter by user must match its token's tasks, got %d rows on page 1", len(sub))
	}
	for _, filter := range []string{"admin", "root@pam!admin", "root@pam!other"} {
		if sub := p.do(t, "GET", "/nodes/pve1/tasks?userfilter="+url.QueryEscape(filter), nil).body["data"].([]any); len(sub) != 0 {
			t.Errorf("userfilter %q matched %d rows: PVE compares the user, not a token id or a part of it", filter, len(sub))
		}
	}
	_ = f
}

func TestTaskListHoldsRunningTasksOnlyForSourceActiveOrAll(t *testing.T) {
	_, p := cluster(t, WithManualTasks())
	p.do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil)
	count := func(source string) int {
		path := "/nodes/pve1/tasks"
		if source != "" {
			path += "?source=" + source
		}
		return len(p.do(t, "GET", path, nil).body["data"].([]any))
	}
	for source, want := range map[string]int{"": 0, "archive": 0, "active": 1, "all": 1} {
		if got := count(source); got != want {
			t.Errorf("source %q lists %d running tasks, want %d", source, got, want)
		}
	}
	if got := p.do(t, "GET", "/nodes/pve1/tasks?source=other", nil); got.status != http.StatusBadRequest {
		t.Errorf("an unknown source: status = %d, want 400", got.status)
	}
}

func TestPathPermissionsIncludePoolAndKeepNonPropagatingGrants(t *testing.T) {
	f, _ := cluster(t)
	f.AddGuest(Guest{Node: "pve1", Type: "qemu", VMID: 300, Name: "pooled", Pool: "prod"})
	f.SetRole("Power", "VM.PowerMgmt")
	tok := f.AddToken("u@pve", "t", false)
	f.Grant("u@pve", "/pool/prod", "Power", true)
	f.Grant("u@pve", "/vms/100", "Power", false)
	p := newProbe(t, f, tok)

	at := func(path string) map[string]any {
		data := p.do(t, "GET", "/access/permissions?path="+path, nil).body["data"].(map[string]any)
		privs, _ := data[path].(map[string]any)
		return privs
	}
	if privs := at("/vms/300"); privs["VM.PowerMgmt"] != float64(1) {
		t.Errorf("a pool member holds the pool's grant, got %v", privs)
	}
	if privs := at("/vms/100"); privs["VM.PowerMgmt"] != float64(0) {
		t.Errorf("a non-propagating grant on the path is listed with flag 0, got %v", privs)
	}
	if privs := at("/vms/200"); len(privs) != 0 {
		t.Errorf("a path with no privileges lists none, got %v", privs)
	}
}

func TestTaskVisibilityWithoutSysAudit(t *testing.T) {
	f, admin := cluster(t)
	f.SetRole("Power", "VM.PowerMgmt")
	tok := f.AddToken("u@pve", "t", false)
	f.Grant("u@pve", "/vms", "Power", true)
	admin.do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil)
	mine := newProbe(t, f, tok)
	mine.do(t, "POST", "/nodes/pve1/qemu/100/status/start", nil)
	rows := mine.do(t, "GET", "/nodes/pve1/tasks", nil).body["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["user"] != "u@pve!t" {
		t.Errorf("a token without Sys.Audit must see only its own tasks, saw %v", rows)
	}
}

func TestInjectedFaults(t *testing.T) {
	f, p := cluster(t)
	f.Inject(Rule{Method: "POST", PathSuffix: "/status/stop", Fault: Respond(502, "bad gateway")})
	if got := p.do(t, "POST", "/nodes/pve1/qemu/100/status/stop", nil); got.status != 502 {
		t.Errorf("status = %d, want 502", got.status)
	}
	if f.GuestStatus(100) != "running" {
		t.Error("a Respond fault must not run the request")
	}

	f.Inject(Rule{Method: "POST", PathSuffix: "/status/stop", Fault: DropAfter()})
	req, _ := http.NewRequestWithContext(context.Background(), "POST", f.Endpoint()+apiPrefix+"/nodes/pve1/qemu/100/status/stop", nil)
	req.Header.Set("Authorization", "PVEAPIToken="+p.token)
	if resp, err := p.client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("DropAfter must not answer")
	}
	if f.GuestStatus(100) != "stopped" {
		t.Error("DropAfter must run the request")
	}
	if n := f.Count("POST", "/status/stop"); n != 2 {
		t.Errorf("Count = %d, want 2", n)
	}
}
