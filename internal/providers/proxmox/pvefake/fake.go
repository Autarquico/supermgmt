package pvefake

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Guest is a QEMU VM or an LXC container.
type Guest struct {
	Node     string
	Type     string // "qemu" | "lxc"
	VMID     int
	Name     string
	Status   string // "running" | "stopped" (default "stopped")
	Pool     string
	Lock     string // non-empty: the guest is locked by that operation
	Template bool
	MaxCPU   int
	MaxMem   int64
	MaxDisk  int64
	CPU      float64
	Mem      int64
	Disk     int64
	Uptime   int64
}

// Storage is one storage on one node.
type Storage struct {
	ID      string
	Node    string
	Plugin  string
	Content []string
	Total   int64
	Used    int64
	Shared  bool
}

// TaskInfo is a task as the fake holds it.
type TaskInfo struct {
	UPID    string
	Running bool
	Exit    string // "OK" or the failure text once stopped
}

// Request is one request the fake received.
type Request struct {
	Method string
	Path   string // without the /api2/json prefix
	Query  url.Values
	Form   url.Values
}

// Option adjusts a Fake.
type Option func(*Fake)

// WithManualTasks keeps power tasks running until FinishTask; by default a
// task ends "OK" the moment it is created.
func WithManualTasks() Option { return func(f *Fake) { f.manualTasks = true } }

// tickingClock is the default task clock: a fixed start that advances one
// second per reading, so task times are deterministic and strictly ordered.
func tickingClock() func() time.Time {
	var mu sync.Mutex
	at := time.Unix(1_800_000_000, 0)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		at = at.Add(time.Second)
		return at
	}
}

// WithClock sets the clock that stamps tasks.
func WithClock(now func() time.Time) Option { return func(f *Fake) { f.now = now } }

type tokenInfo struct {
	secret  string
	privsep bool
}

type nodeInfo struct {
	online bool
}

type task struct {
	upid    string
	node    string
	typ     string
	id      string
	user    string
	start   time.Time
	pid     int
	running bool
	exit    string
	effect  func()
}

// Fake is a Proxmox VE API server on a throwaway CA.
type Fake struct {
	t           testing.TB
	srv         *httptest.Server
	caPEM       []byte
	now         func() time.Time
	manualTasks bool

	mu       sync.Mutex
	nodes    map[string]*nodeInfo
	guests   map[int]*Guest
	storages []Storage
	roles    map[string]privSet
	acl      []aclEntry
	tokens   map[string]tokenInfo
	tasks    []*task
	rules    []*rule
	requests []Request
	nextPID  int
	done     chan struct{}
}

// privileges the fake knows; Administrator holds all of them.
var knownPrivileges = []string{
	"VM.Audit", "VM.PowerMgmt", "VM.Config.Options", "Sys.Audit", "Sys.Modify",
	"Datastore.Audit", "Datastore.AllocateSpace", "Pool.Audit", "Pool.Allocate",
}

// New starts the fake. It is stopped when the test ends.
func New(t testing.TB, opts ...Option) *Fake {
	t.Helper()
	f := &Fake{
		t: t, now: tickingClock(),
		nodes: map[string]*nodeInfo{}, guests: map[int]*Guest{},
		roles: map[string]privSet{}, tokens: map[string]tokenInfo{},
		nextPID: 1000, done: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(f)
	}
	f.roles["Administrator"] = privSet{}
	for _, p := range knownPrivileges {
		f.roles["Administrator"][p] = true
	}
	f.roles["PVEAuditor"] = privSet{"VM.Audit": true, "Sys.Audit": true, "Datastore.Audit": true, "Pool.Audit": true}

	cert, caPEM := newPKI(t)
	f.caPEM = caPEM
	f.srv = httptest.NewUnstartedServer(f.handler())
	f.srv.TLS = tlsConfig(cert)
	f.srv.StartTLS()
	t.Cleanup(f.close)
	return f
}

func (f *Fake) close() {
	close(f.done)
	f.srv.Close()
}

// Endpoint is the API base URL; its host is ServerIP.
func (f *Fake) Endpoint() string { return "https://" + ServerIP + ":8006" }

// CAPEM is the CA that signed the server certificate.
func (f *Fake) CAPEM() []byte { return f.caPEM }

// Dial connects to the fake whatever the address: pass it to
// netguard.WithTestDialer.
func (f *Fake) Dial(network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).Dial(network, f.srv.Listener.Addr().String())
}

// AddNode adds an online cluster member.
func (f *Fake) AddNode(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[name] = &nodeInfo{online: true}
}

// SetNodeOnline flips a node's reported status.
func (f *Fake) SetNodeOnline(name string, online bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[name].online = online
}

// AddGuest adds a guest to an existing node. A duplicate VMID fails the
// test: VMIDs are cluster-unique.
func (f *Fake) AddGuest(g Guest) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes[g.Node] == nil || (g.Type != "qemu" && g.Type != "lxc") || f.guests[g.VMID] != nil {
		f.t.Fatalf("pvefake: invalid or duplicate guest %+v", g)
	}
	if g.Status == "" {
		g.Status = "stopped"
	}
	f.guests[g.VMID] = &g
}

// AddStorage adds a storage.
func (f *Fake) AddStorage(s Storage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.storages = append(f.storages, s)
}

// MigrateGuest moves a guest to another node.
func (f *Fake) MigrateGuest(vmid int, node string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.guests[vmid] == nil || f.nodes[node] == nil {
		f.t.Fatalf("pvefake: cannot migrate %d to %s", vmid, node)
	}
	f.guests[vmid].Node = node
}

// SetPool moves a guest to a pool ("" takes it out of any pool).
func (f *Fake) SetPool(vmid int, pool string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.guests[vmid] == nil {
		f.t.Fatalf("pvefake: no guest %d", vmid)
	}
	f.guests[vmid].Pool = pool
}

// RemoveGuest deletes a guest.
func (f *Fake) RemoveGuest(vmid int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.guests, vmid)
}

// SetLock locks a guest with the given operation name ("" unlocks).
func (f *Fake) SetLock(vmid int, lock string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guests[vmid].Lock = lock
}

// GuestStatus is the guest's current power state, "" if it does not exist.
func (f *Fake) GuestStatus(vmid int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g := f.guests[vmid]; g != nil {
		return g.Status
	}
	return ""
}

// SetRole defines or replaces a role.
func (f *Fake) SetRole(name string, privs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roles[name] = privSet{}
	for _, p := range privs {
		f.roles[name][p] = true
	}
}

// AddToken creates user@realm!tokenid and returns the value a client sends:
// "user@realm!tokenid=<secret>".
func (f *Fake) AddToken(user, tokenID string, privsep bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	secret := hex.EncodeToString(raw)
	id := user + "!" + tokenID
	f.tokens[id] = tokenInfo{secret: secret, privsep: privsep}
	return id + "=" + secret
}

// Grant gives a role to a subject (a user or a "user!tokenid") on a path.
func (f *Fake) Grant(subject, path, role string, propagate bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acl = append(f.acl, aclEntry{path: path, subject: subject, role: role, propagate: propagate})
}

// Revoke removes every grant of role to subject on path.
func (f *Fake) Revoke(subject, path, role string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.acl[:0]
	for _, e := range f.acl {
		if e.subject != subject || e.path != path || e.role != role {
			kept = append(kept, e)
		}
	}
	f.acl = kept
}

// FinishTask ends a running task: "OK" applies its effect to the guest, any
// other text records a failure and leaves the guest alone. It fails the test
// when the task is unknown or already stopped (an impossible transition).
func (f *Fake) FinishTask(upid, exit string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, tk := range f.tasks {
		if tk.upid == upid {
			if !tk.running {
				f.t.Fatalf("pvefake: task %s already stopped", upid)
			}
			f.finish(tk, exit)
			return
		}
	}
	f.t.Fatalf("pvefake: unknown task %s", upid)
}

func (f *Fake) finish(tk *task, exit string) {
	tk.running, tk.exit = false, exit
	if exit == "OK" && tk.effect != nil {
		tk.effect()
	}
}

// Tasks lists every task, oldest first.
func (f *Fake) Tasks() []TaskInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]TaskInfo, len(f.tasks))
	for i, tk := range f.tasks {
		out[i] = TaskInfo{UPID: tk.upid, Running: tk.running, Exit: tk.exit}
	}
	return out
}

// Requests returns every request received, in order.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// Count is the number of requests with the method whose path ends in suffix.
func (f *Fake) Count(method, pathSuffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Method == method && strings.HasSuffix(r.Path, pathSuffix) {
			n++
		}
	}
	return n
}
