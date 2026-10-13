package installer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
)

// aw is an in-memory Proxmox host with one container inside. It implements
// the host seams of an appliance install, models the PVE state the installer
// must leave untouched, injects a failure at any single operation, and records
// every rule the installer must not break in violations.
type aw struct {
	t *testing.T

	// host file system
	files  map[string][]byte
	dirs   map[string]bool
	locked bool

	// entries overrides what Lstat reports for a path (owner, mode, symlink); by default the
	// installer's own files are root-owned and private.
	entries    map[string]EntryInfo
	unreadable map[string]bool // paths whose ReadFile fails with something other than not-exist

	// PVE
	version    string
	storages   []PVEStorage
	bridges    []string
	bridgeAddr netip.Addr
	tplLocal   []string
	tplAvail   []string
	guests     map[int]*fakeGuest
	users      map[string]string // name -> "foreign" | "ours"
	roles      map[string]string
	acls       map[ACL]bool
	tokens     map[string]string // user!id -> origin
	secret     string

	// container
	ct container

	// scenario switches
	collide        map[string]bool // user, auditrole, powerrole, token
	raceCreate     map[string]bool // user, role, token: another party creates it first and our create fails
	raceAtCreate   bool
	createShape    func(*fakeGuest) // makes the created guest differ from the plan
	lockDelay      int              // State polls a failed create keeps the guest locked
	pushIgnoresOwn bool
	pveTrusted     bool
	doctorOKAfter  int

	// fault injection and observation
	ops           int
	failAt        int
	applyOnInject bool
	opLog         []string
	violations    []string
	execs         []execRecord
	lastProbe     Probe
	confirmYes    bool
	asked         []string
	answers       []string
	onAsk         func() // runs after a question is asked and before it is answered
	recordReads   []bool // for every read of the appliance records: was the installer lock held
	out           bytes.Buffer
	rollbackStart int // the first operation of a rollback, 0 if none
}

type fakeGuest struct {
	desc      string
	status    string
	lock      string
	lockPolls int
	unpriv    bool
	features  map[string]string
	mounts    []string
	raw       []string
	tags      []string
	foreign   bool
}

type ctMeta struct{ owner, mode string }

type container struct {
	files      map[string][]byte
	meta       map[string]ctMeta
	dirs       map[string]ctMeta
	ip         netip.Addr
	unit       bool
	enabled    bool
	dbInit     bool
	imported   bool
	importedBy string
	provider   bool
	doctorN    int
}

type execRecord struct {
	user      string
	argv      []string
	sensitive bool
	stdin     string
}

var errInjected = errors.New("injected failure")

func newAW(t *testing.T) *aw {
	t.Helper()
	ca := testCAPEM(t)
	w := &aw{
		t: t, entries: map[string]EntryInfo{}, files: map[string][]byte{"/usr/local/src/sm": []byte("the sm binary"), defaultPVECAFile: ca},
		dirs: map[string]bool{"/": true, "/var/tmp": true, "/var/lib": true}, version: "9.0.3",
		storages: []PVEStorage{
			{ID: "local-lvm", Type: "lvmthin", Content: []string{"rootdir", "images"}, Active: true},
			{ID: "local", Type: "dir", Content: []string{"vztmpl", "iso"}, Active: true},
		},
		bridges: []string{"vmbr0"}, bridgeAddr: netip.MustParseAddr("192.168.1.10"),
		tplAvail: []string{"debian-12-standard_12.7-1_amd64.tar.zst", "debian-13-standard_13.1-1_amd64.tar.zst", "debian-13-standard_13.0-1_amd64.tar.zst"},
		guests:   map[int]*fakeGuest{}, users: map[string]string{}, roles: map[string]string{}, acls: map[ACL]bool{}, tokens: map[string]string{},
		secret: "SENTINEL-" + strings.Repeat("c0ffee", 4), collide: map[string]bool{}, pveTrusted: true, confirmYes: true,
		ct: container{files: map[string][]byte{}, meta: map[string]ctMeta{}, dirs: map[string]ctMeta{}, ip: netip.MustParseAddr("192.168.1.50")},
	}
	return w
}

func (w *aw) deps(interactive bool) Deps {
	d := Deps{
		Host:  Host{GOOS: "linux", GOARCH: "amd64", UID: 0, Home: "/root", Env: map[string]string{}, HasSystemd: true},
		Files: w, Runner: w, Health: w, PVE: w, Clock: fixedClock{}, Out: &w.out,
		Services: fakeServices{&world{}, ""},
	}
	if interactive {
		d.Prompter = w
	}
	return d
}

func (w *aw) opts() Options {
	return Options{Mode: ModeProxmoxLXC, Binary: "/usr/local/src/sm", Yes: true, Appliance: Appliance{Power: true}}
}

func fastHooks() provisionHooks {
	return provisionHooks{
		pause: func(context.Context, time.Duration) error { return nil },
		poll:  time.Second, guestWait: 5 * time.Second, lockWait: 5 * time.Second, readyWait: 5 * time.Second,
	}
}

func (w *aw) violate(format string, args ...any) {
	w.violations = append(w.violations, fmt.Sprintf(format, args...))
}

// ---- fault injection ----

func (w *aw) tick(op string) bool {
	w.checkBoot()
	w.ops++
	w.opLog = append(w.opLog, op)
	if w.rollbackStart == 0 && strings.Contains(w.out.String(), "rolling back") {
		w.rollbackStart = w.ops
	}
	return w.failAt != 0 && w.failAt == w.ops
}

func (w *aw) mutate(op string, apply func() error) error {
	injected := w.tick(op)
	if injected && !w.applyOnInject {
		return errInjected
	}
	err := apply()
	if injected {
		return errInjected
	}
	return err
}

func (w *aw) read(op string) error {
	if w.tick(op) {
		return errInjected
	}
	return nil
}

// checkBoot is the reboot-between-steps test: at every operation boundary a
// reboot would start an enabled unit, which must then have its credential.
func (w *aw) checkBoot() {
	if w.ct.enabled && (!w.ct.imported || !w.ct.provider) {
		w.violate("unit enabled before the credential was imported and the provider configured (op %d)", w.ops)
	}
}

// ---- host Files ----

func (w *aw) Exists(p string) bool {
	_, f := w.files[p]
	return f || w.dirs[p]
}

func (w *aw) Lstat(p string) (EntryInfo, error) {
	if info, ok := w.entries[p]; ok {
		return info, nil
	}
	switch _, isFile := w.files[p]; {
	case w.dirs[p]:
		return EntryInfo{Dir: true, Mode: 0o700}, nil
	case isFile:
		return EntryInfo{Regular: true, Mode: 0o600}, nil
	}
	return EntryInfo{}, fs.ErrNotExist
}

func (w *aw) ReadFile(p string) ([]byte, error) {
	if err := w.read("host.read " + p); err != nil {
		return nil, err
	}
	if strings.HasPrefix(p, appliancesDir) {
		w.recordReads = append(w.recordReads, w.locked)
	}
	if w.unreadable[p] {
		return nil, fs.ErrPermission
	}
	if b, ok := w.files[p]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, fs.ErrNotExist
}

func (w *aw) MkdirAll(p string, _ fs.FileMode, _ Owner) error {
	return w.mutate("host.mkdir "+p, func() error {
		for d := p; d != "/" && d != "."; d = path.Dir(d) {
			w.dirs[d] = true
		}
		return nil
	})
}

func (w *aw) WriteFile(p string, data []byte, _ fs.FileMode, _ Owner) error {
	return w.mutate("host.write "+p, func() error {
		if !w.dirs[path.Dir(p)] {
			return fs.ErrNotExist
		}
		w.files[p] = append([]byte(nil), data...)
		return nil
	})
}

func (w *aw) CopyFile(src, dst string, _ fs.FileMode, _ Owner) error {
	return w.mutate("host.copy "+dst, func() error { w.files[dst] = w.files[src]; return nil })
}

func (w *aw) RemoveAll(p string) error {
	return w.mutate("host.rm "+p, func() error {
		delete(w.files, p)
		delete(w.dirs, p)
		for k := range w.files {
			if strings.HasPrefix(k, p+"/") {
				delete(w.files, k)
			}
		}
		for k := range w.dirs {
			if strings.HasPrefix(k, p+"/") {
				delete(w.dirs, k)
			}
		}
		return nil
	})
}

func (w *aw) AppendSync(p string, line []byte) error {
	return w.mutate("host.append "+p, func() error {
		if !w.dirs[path.Dir(p)] {
			return fs.ErrNotExist
		}
		w.files[p] = append(append([]byte(nil), w.files[p]...), line...)
		return nil
	})
}

func (w *aw) SyncDir(dir string) error { return w.read("host.syncdir " + dir) }
func (w *aw) Rename(a, b string) error { return errors.New("not used") }
func (w *aw) Link(a, b string) error   { return errors.New("not used") }

func (w *aw) Hash(p string) (string, error) {
	if err := w.read("host.hash " + p); err != nil {
		return "", err
	}
	b, ok := w.files[p]
	if !ok {
		return "", fs.ErrNotExist
	}
	return sha256Hex(b), nil
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (w *aw) Lock(string) (func(), error) {
	if w.locked {
		return nil, errors.New("locked")
	}
	w.locked = true
	return func() { w.locked = false }, nil
}

func (w *aw) ListDir(dir string) ([]string, error) {
	if dir == appliancesDir {
		w.recordReads = append(w.recordReads, w.locked)
	}
	seen := map[string]bool{}
	for k := range w.dirs {
		if path.Dir(k) == dir {
			seen[path.Base(k)] = true
		}
	}
	for k := range w.files {
		if path.Dir(k) == dir {
			seen[path.Base(k)] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// ---- other seams ----

func (w *aw) Run(context.Context, Command) ([]byte, error) {
	return nil, errors.New("unexpected host command")
}

func (w *aw) WaitReady(_ context.Context, p Probe, _ time.Duration) error {
	if err := w.read("health"); err != nil {
		return err
	}
	w.lastProbe = p
	if !w.ct.enabled {
		return errors.New("not ready")
	}
	return nil
}

func (w *aw) Confirm(q string) (bool, error) { w.asked = append(w.asked, q); return w.confirmYes, nil }

func (w *aw) Ask(q string) (string, error) {
	w.asked = append(w.asked, q)
	if w.onAsk != nil {
		w.onAsk()
	}
	if len(w.answers) == 0 {
		return "", io.EOF
	}
	a := w.answers[0]
	w.answers = w.answers[1:]
	return a, nil
}

// ---- PVE ----

func (w *aw) Version(context.Context) (string, error) { return w.version, w.read("pve.version") }

func (w *aw) NextID(_ context.Context, from int) (int, error) {
	if err := w.read("pve.nextid"); err != nil {
		return 0, err
	}
	for id := from; ; id++ {
		if _, taken := w.guests[id]; !taken {
			return id, nil
		}
	}
}

func (w *aw) Storages(context.Context) ([]PVEStorage, error) {
	return w.storages, w.read("pve.storages")
}
func (w *aw) Bridges(context.Context) ([]string, error) { return w.bridges, w.read("pve.bridges") }
func (w *aw) BridgeAddress(context.Context, string) (netip.Addr, error) {
	return w.bridgeAddr, w.read("pve.bridgeaddr")
}

func (w *aw) Templates(context.Context, string) ([]string, error) {
	return append([]string(nil), w.tplLocal...), w.read("pve.templates")
}

func (w *aw) AvailableTemplates(context.Context) ([]string, error) {
	return w.tplAvail, w.read("pve.available")
}

func (w *aw) DownloadTemplate(_ context.Context, storage, name string) error {
	return w.mutate("pve.download "+name, func() error {
		w.tplLocal = append(w.tplLocal, storage+":vztmpl/"+name)
		return nil
	})
}

func (w *aw) Create(_ context.Context, s GuestSpec) error {
	if _, err := createArgs(s); err != nil { // the real argv builder validates the spec
		return err
	}
	return w.mutate("pve.create "+strconv.Itoa(s.VMID), func() error {
		if w.raceAtCreate {
			w.guests[s.VMID] = &fakeGuest{desc: "somebody else's", status: "stopped", foreign: true, tags: []string{"other"}}
		}
		if _, exists := w.guests[s.VMID]; exists {
			return errors.New("CT already exists")
		}
		g := &fakeGuest{
			desc: s.Description, status: "stopped", unpriv: true, features: map[string]string{"nesting": "0", "keyctl": "0"},
			tags: append([]string(nil), s.Tags...),
		}
		if w.createShape != nil {
			w.createShape(g)
		}
		if w.lockDelay > 0 && w.failAt == w.ops { // the CLI failed while the create task still runs
			g.lock, g.lockPolls = "create", w.lockDelay
		}
		w.guests[s.VMID] = g
		return nil
	})
}

func (w *aw) Config(_ context.Context, vmid int) (GuestConfig, error) {
	if err := w.read("pve.config"); err != nil {
		return GuestConfig{}, err
	}
	g, ok := w.guests[vmid]
	if !ok {
		return GuestConfig{}, errors.New("no such CT")
	}
	return GuestConfig{Unprivileged: g.unpriv, Features: g.features, Mounts: g.mounts, RawLXC: g.raw, Tags: g.tags, Description: g.desc, Lock: g.lock}, nil
}

func (w *aw) State(_ context.Context, vmid int) (GuestState, error) {
	if err := w.read("pve.state"); err != nil {
		return GuestState{}, err
	}
	g, ok := w.guests[vmid]
	if !ok {
		return GuestState{}, nil
	}
	if g.lockPolls > 0 {
		g.lockPolls--
		if g.lockPolls == 0 {
			g.lock = ""
		}
	}
	return GuestState{Exists: true, Status: g.status, Lock: g.lock}, nil
}

func (w *aw) Start(_ context.Context, vmid int) error {
	return w.mutate("pve.start", func() error {
		g, ok := w.guests[vmid]
		if !ok {
			return errors.New("no such CT")
		}
		g.status = "running"
		return nil
	})
}

func (w *aw) Stop(_ context.Context, vmid int) error {
	return w.mutate("pve.stop", func() error {
		g, ok := w.guests[vmid]
		if !ok {
			return errors.New("no such CT")
		}
		g.status = "stopped"
		for p := range w.ct.files { // /run is tmpfs: a stop clears it
			if strings.HasPrefix(p, "/run/") {
				delete(w.ct.files, p)
				delete(w.ct.meta, p)
			}
		}
		for p := range w.ct.dirs {
			if strings.HasPrefix(p, "/run/") {
				delete(w.ct.dirs, p)
			}
		}
		return nil
	})
}

func (w *aw) Destroy(_ context.Context, vmid int) error {
	return w.mutate("pve.destroy", func() error {
		g, ok := w.guests[vmid]
		if !ok {
			return errors.New("no such CT")
		}
		if g.foreign {
			w.violate("destroyed a guest this install did not create (%d)", vmid)
		}
		if g.status == "running" {
			return errors.New("CT is running")
		}
		delete(w.guests, vmid)
		w.ct = container{files: map[string][]byte{}, meta: map[string]ctMeta{}, dirs: map[string]ctMeta{}, ip: w.ct.ip}
		return nil
	})
}

func (w *aw) Push(_ context.Context, vmid int, src, dst string, owner Owner, mode fs.FileMode) error {
	if err := validPath(src); err != nil {
		return err
	}
	if err := validPath(dst); err != nil {
		return err
	}
	return w.mutate("pve.push "+dst, func() error {
		data, ok := w.files[src]
		if !ok {
			return fs.ErrNotExist
		}
		if g := w.guests[vmid]; g == nil || g.status != "running" {
			return errors.New("CT is not running")
		}
		if w.ct.dirs[path.Dir(dst)] == (ctMeta{}) {
			return errors.New("no such directory in the container")
		}
		w.ct.files[dst] = append([]byte(nil), data...)
		who := owner.User + ":" + owner.Group
		if w.pushIgnoresOwn {
			who = "root:root"
		}
		w.ct.meta[dst] = ctMeta{owner: who, mode: strconv.FormatUint(uint64(mode.Perm()), 8)}
		return nil
	})
}

func (w *aw) UserExists(_ context.Context, user string) (bool, error) {
	if err := w.read("pve.userexists"); err != nil {
		return false, err
	}
	if w.collide["user"] && strings.HasPrefix(user, "sm-") && w.users[user] == "" {
		w.users[user] = "foreign"
	}
	return w.users[user] != "", nil
}

func (w *aw) CreateUser(_ context.Context, user, _ string) error {
	return w.mutate("pve.createuser", func() error {
		if w.raceCreate["user"] {
			w.users[user] = "foreign"
		}
		if w.users[user] != "" {
			return errors.New("user exists")
		}
		w.users[user] = "ours"
		return nil
	})
}

func (w *aw) RemoveUser(_ context.Context, user string) error {
	return w.mutate("pve.removeuser", func() error {
		if w.users[user] == "foreign" {
			w.violate("removed a user this install did not create (%s)", user)
		}
		delete(w.users, user)
		return nil
	})
}

func (w *aw) RoleExists(_ context.Context, role string) (bool, error) {
	if err := w.read("pve.roleexists"); err != nil {
		return false, err
	}
	for kind, prefix := range map[string]string{"auditrole": "SMAudit-", "powerrole": "SMPower-"} {
		if w.collide[kind] && strings.HasPrefix(role, prefix) && w.roles[role] == "" {
			w.roles[role] = "foreign"
		}
	}
	return w.roles[role] != "", nil
}

func (w *aw) CreateRole(_ context.Context, role string, privs []string) error {
	return w.mutate("pve.createrole "+role+" "+strings.Join(privs, ","), func() error {
		if w.raceCreate["role"] && w.roles[role] == "" {
			w.roles[role] = "foreign"
		}
		if w.roles[role] != "" {
			return errors.New("role exists")
		}
		w.roles[role] = "ours"
		return nil
	})
}

func (w *aw) RemoveRole(_ context.Context, role string) error {
	return w.mutate("pve.removerole", func() error {
		if w.roles[role] == "foreign" {
			w.violate("removed a role this install did not create (%s)", role)
		}
		delete(w.roles, role)
		return nil
	})
}

func (w *aw) ACLs(context.Context) ([]ACL, error) {
	if err := w.read("pve.acls"); err != nil {
		return nil, err
	}
	var out []ACL
	for a := range w.acls {
		out = append(out, a)
	}
	return out, nil
}

func (w *aw) AddACL(_ context.Context, a ACL) error {
	if err := validACL(a); err != nil {
		return err
	}
	return w.mutate("pve.addacl "+aclName(a), func() error {
		if a.Token != "" && w.tokens[a.Token] == "" {
			return errors.New("no such token")
		}
		w.acls[a] = true
		return nil
	})
}

func (w *aw) RemoveACL(_ context.Context, a ACL) error {
	return w.mutate("pve.removeacl", func() error { delete(w.acls, a); return nil })
}

func (w *aw) TokenExists(_ context.Context, user, id string) (bool, error) {
	if err := w.read("pve.tokenexists"); err != nil {
		return false, err
	}
	key := user + "!" + id
	if w.collide["token"] && w.tokens[key] == "" {
		w.tokens[key] = "foreign"
	}
	return w.tokens[key] != "", nil
}

func (w *aw) AddToken(_ context.Context, user, id string) (audit.Secret, error) {
	var secret audit.Secret
	err := w.mutate("pve.addtoken", func() error {
		if w.users[user] == "" {
			return errors.New("no such user")
		}
		if w.raceCreate["token"] {
			w.tokens[user+"!"+id] = "foreign"
			return errors.New("token exists")
		}
		w.tokens[user+"!"+id] = "ours"
		secret = audit.Secret(w.secret)
		return nil
	})
	return secret, err
}

func (w *aw) RemoveToken(_ context.Context, user, id string) error {
	return w.mutate("pve.removetoken", func() error {
		if w.tokens[user+"!"+id] == "foreign" {
			w.violate("removed a token this install did not create")
		}
		delete(w.tokens, user+"!"+id)
		return nil
	})
}

// ---- inside the container ----

func (w *aw) Exec(_ context.Context, vmid int, user string, argv []string, stdin io.Reader, sensitive bool) ([]byte, error) {
	if err := validPath(argv[0]); err != nil {
		return nil, err
	}
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	w.execs = append(w.execs, execRecord{user: user, argv: append([]string(nil), argv...), sensitive: sensitive, stdin: string(in)})
	var out []byte
	err := w.mutate("ct.exec "+strings.Join(argv, " "), func() error {
		if g := w.guests[vmid]; g == nil || g.status != "running" {
			return errors.New("CT is not running")
		}
		var execErr error
		out, execErr = w.execInContainer(user, argv, in, sensitive)
		return execErr
	})
	return out, err
}

func exitStatus(code int) error { return &ExitStatus{Command: "ct", Code: code} }

func (w *aw) execInContainer(user string, argv []string, stdin []byte, sensitive bool) ([]byte, error) {
	c := &w.ct
	args := argv[1:]
	switch argv[0] {
	case "/usr/bin/hostname":
		return []byte(c.ip.String() + "\n"), nil
	case "/usr/bin/sha256sum":
		return []byte(sha256Hex(c.files[args[0]]) + "  " + args[0] + "\n"), nil
	case stagedBinary:
		return nil, w.installServer(user, args)
	case "/usr/local/bin/sm":
		return w.runSM(user, args, sensitive)
	case "/usr/bin/rm":
		w.ctRemove(args[len(args)-1])
		return nil, nil
	case "/usr/bin/cat":
		if b, ok := c.files[args[0]]; ok {
			return b, nil
		}
		return nil, exitStatus(1)
	case "/usr/bin/stat":
		return w.stat(args)
	case "/usr/bin/mkdir":
		if _, exists := w.ct.dirs[args[2]]; exists {
			return nil, exitStatus(1)
		}
		w.ct.dirs[args[2]] = ctMeta{owner: "root", mode: strings.TrimLeft(args[1], "0")}
		return nil, nil
	case "/usr/bin/id":
		return []byte("999\n"), nil
	case "/usr/bin/install":
		return nil, w.ctInstall(args)
	case "/usr/bin/tee":
		if _, ok := c.files[args[0]]; !ok {
			return nil, exitStatus(1)
		}
		c.files[args[0]] = append([]byte(nil), stdin...)
		c.provider = c.provider || bytes.Contains(stdin, []byte("providers:"))
		return stdin, nil
	case "/usr/bin/test":
		if _, ok := c.files[args[len(args)-1]]; ok {
			return nil, exitStatus(1)
		}
		return nil, nil
	case "/usr/bin/chown":
		m := c.meta[args[1]]
		m.owner = args[0]
		c.meta[args[1]] = m
		return nil, nil
	case "/usr/bin/chmod":
		m := c.meta[args[1]]
		m.mode = strings.TrimLeft(args[0], "0")
		c.meta[args[1]] = m
		return nil, nil
	case "/usr/bin/systemctl":
		return nil, w.systemctl(args)
	}
	return nil, fmt.Errorf("unexpected container command %v", argv)
}

func (w *aw) ctRemove(target string) {
	delete(w.ct.files, target)
	delete(w.ct.meta, target)
	delete(w.ct.dirs, target)
	for p := range w.ct.files {
		if strings.HasPrefix(p, target+"/") {
			delete(w.ct.files, p)
			delete(w.ct.meta, p)
		}
	}
}

func (w *aw) stat(args []string) ([]byte, error) {
	if args[0] == "-f" {
		return []byte("tmpfs\n"), nil
	}
	p := args[len(args)-1]
	if m, ok := w.ct.dirs[p]; ok {
		return []byte(m.owner + ":" + m.mode + "\n"), nil
	}
	if m, ok := w.ct.meta[p]; ok {
		return []byte(m.owner + ":" + m.mode + "\n"), nil
	}
	return nil, exitStatus(1)
}

// install handles `install -d -m M -o U -g G dir` and `install -m M -o U -g G /dev/null file`.
func (w *aw) ctInstall(args []string) error {
	var mode, owner, group string
	var dir bool
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			dir = true
		case "-m":
			i++
			mode = strings.TrimLeft(args[i], "0")
		case "-o":
			i++
			owner = args[i]
		case "-g":
			i++
			group = args[i]
		default:
			rest = append(rest, args[i])
		}
	}
	if dir {
		w.ct.dirs[rest[0]] = ctMeta{owner: owner + ":" + group, mode: mode}
		return nil
	}
	w.ct.files[rest[1]] = nil
	w.ct.meta[rest[1]] = ctMeta{owner: owner + ":" + group, mode: mode}
	return nil
}

func (w *aw) systemctl(args []string) error {
	if len(args) == 3 && args[0] == "enable" && args[1] == "--now" {
		if !w.ct.unit {
			return exitStatus(1)
		}
		w.ct.enabled = true
		return nil
	}
	return fmt.Errorf("unexpected systemctl %v", args)
}

func (w *aw) installServer(user string, args []string) error {
	if user != "" {
		w.violate("sm install server must run as root, ran as %q", user)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" install server ", " --no-start ", " --tls self-signed ", " --public-url https://" + w.ct.ip.String() + ":8443 "} {
		if !strings.Contains(joined, want) {
			return fmt.Errorf("sm install server: missing %q in %v", want, args)
		}
	}
	l := applianceLayout()
	cfg, err := renderServerConfig(l, serverSettings{
		Name: "supermgmt", Listen: "0.0.0.0:8443", PublicURL: "https://" + w.ct.ip.String() + ":8443", TLS: config.TLSDirect,
		CertFile: "/etc/supermgmt/tls/server.pem", KeyFile: "/etc/supermgmt/tls/server.key",
	})
	if err != nil {
		return err
	}
	w.ct.files[l.ConfigFile] = cfg
	w.ct.meta[l.ConfigFile] = ctMeta{owner: "root:supermgmt", mode: "640"}
	w.ct.files["/etc/supermgmt/tls/ca.pem"] = testCAPEM(w.t)
	w.ct.files["/etc/supermgmt/tls/server.pem"] = []byte("leaf")
	w.ct.files[l.Binary] = w.ct.files[stagedBinary]
	w.ct.unit = true // written, and deliberately not enabled
	return nil
}

func (w *aw) runSM(user string, args []string, sensitive bool) ([]byte, error) {
	c := &w.ct
	if user != ServiceUser {
		w.violate("sm %s ran as %q, want %s", args[0], user, ServiceUser)
	}
	own := ServiceUser + ":" + ServiceUser
	switch {
	case args[0] == "server" && args[1] == "init":
		if _, ok := c.files[applianceLayout().ConfigFile]; !ok {
			return nil, exitStatus(2)
		}
		c.dbInit = true
		c.files["/var/lib/supermgmt/supermgmt.db"] = []byte("db")
		c.meta["/var/lib/supermgmt/supermgmt.db"] = ctMeta{owner: own, mode: "600"}
		return nil, nil
	case args[0] == "providers" && contains(args, "--tls-only"):
		if _, ok := c.files[valueAfter(args, "--ca-file")]; !ok || !w.pveTrusted {
			return nil, exitStatus(ExitConnectivity)
		}
		return nil, nil
	case args[0] == "providers":
		if !c.imported || !c.provider || !w.pveTrusted {
			return nil, exitStatus(ExitConnectivity)
		}
		return nil, nil
	case args[0] == "secrets":
		return nil, w.importSecret(args, sensitive, own)
	case args[0] == "doctor":
		return w.doctor()
	case args[0] == "admin":
		return []byte("BOOT-1234\n"), nil
	}
	return nil, fmt.Errorf("unexpected sm command %v", args)
}

func valueAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (w *aw) importSecret(args []string, sensitive bool, own string) error {
	c := &w.ct
	if !sensitive {
		w.violate("secrets import ran without the Sensitive mode")
	}
	if !c.dbInit {
		return exitStatus(2)
	}
	from := valueAfter(args, "--from-file")
	data, ok := c.files[from]
	if !ok || c.meta[from].owner != own || c.meta[from].mode != "600" {
		return exitStatus(2)
	}
	if !strings.HasPrefix(string(data), "sm-") || !strings.Contains(string(data), "@pve!sm=") {
		return exitStatus(2)
	}
	c.imported, c.importedBy = true, sha256Hex(data)
	if contains(args, "--delete-source") {
		w.ctRemove(from)
	}
	return nil
}

func (w *aw) doctor() ([]byte, error) {
	c := &w.ct
	if !c.enabled {
		return nil, exitStatus(1)
	}
	c.doctorN++
	status := "warn"
	if c.doctorN > w.doctorOKAfter {
		status = "ok"
	}
	out, _ := json.Marshal(map[string]any{"ok": status == "ok", "checks": []map[string]string{{"name": "providers", "status": status, "detail": "first sync pending"}}})
	if status != "ok" {
		return out, exitStatus(1)
	}
	return out, nil
}

// ---- observation ----

// hostPaths lists what the host holds under prefix. The legacy journal prefix also covers
// journalRoot, so assertions about journal debris follow the journals to their new home.
func (w *aw) hostPaths(prefix string) []string {
	if prefix == journalTmpRoot+"/"+journalDirPrefix {
		return append(w.legacyHostPaths(journalRoot+"/"), w.legacyHostPaths(prefix)...)
	}
	return w.legacyHostPaths(prefix)
}

func (w *aw) legacyHostPaths(prefix string) []string {
	var found []string
	for p := range w.files {
		if strings.HasPrefix(p, prefix) {
			found = append(found, p)
		}
	}
	for p := range w.dirs {
		if strings.HasPrefix(p, prefix) {
			found = append(found, p)
		}
	}
	sort.Strings(found)
	return found
}

// leaks lists every place the token appears where it must not.
func (w *aw) leaks() []string {
	var found []string
	has := func(where, what string) {
		if strings.Contains(what, w.secret) {
			found = append(found, where)
		}
	}
	for _, e := range w.execs {
		has("argv "+strings.Join(e.argv, " "), strings.Join(e.argv, " "))
		has("stdin of "+e.argv[0], e.stdin)
	}
	for _, op := range w.opLog {
		has("op "+op, op)
	}
	has("output", w.out.String())
	for p, b := range w.files {
		has("host file "+p, string(b))
	}
	for p, b := range w.ct.files {
		has("container file "+p, string(b))
	}
	return found
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: testNow.Add(-time.Hour), NotAfter: realTLSValidity,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (w *aw) Canonical(p string) (string, error) { return p, nil }

func (w *aw) FreeBytes(string) (uint64, error) { return 1 << 40, nil }

func (w *aw) FileSize(p string) (int64, error) {
	b, ok := w.files[p]
	if !ok {
		return 0, fs.ErrNotExist
	}
	return int64(len(b)), nil
}
