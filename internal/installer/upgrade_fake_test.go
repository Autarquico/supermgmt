package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
)

// uhost is an in-memory server for upgrade and uninstall tests. Files are
// inodes, so a hard link is real: renaming over a name never touches the other
// names of the old file. The fake service runs whatever binary is at the live
// path and migrates the database the way the daemon does, and it records every
// breach of the rules the installer must keep in violations:
//   - the live sm is never missing,
//   - a sm.prev that holds the old binary is never replaced or removed,
//   - offline sm commands run as the service user and only on a stopped service.
type uhost struct {
	t *testing.T

	inodes map[string]*inode
	dirs   map[string]bool
	home   string
	uid    int

	// service and database
	unit      bool
	enabled   bool
	running   bool
	healthy   bool
	dbSchema  int
	archives  int
	startedAs string // content of the binary the service was last started from

	// knobs
	backupErr    error
	backupSchema int // reported by the backup; 0 = the real schema
	stopErr      error
	startErr     error
	freeBytes    uint64
	lockHeld     bool
	noDisk       bool

	// observation
	events     []string
	violations []string
	runs       []Command
	out        bytes.Buffer
	probes     []Probe
	asked      []string
	answers    []string
	yes        bool

	oldContent string // the binary whose sm.prev must survive
	prevOld    bool
}

type inode struct{ data []byte }

const (
	binV1 = "sm;version=1.0.0;schema=3"
	binV2 = "sm;version=1.1.0;schema=4"
)

func newUHost(t *testing.T) *uhost {
	t.Helper()
	l := applianceLayout()
	h := &uhost{
		t: t, inodes: map[string]*inode{}, dirs: map[string]bool{}, home: "/root", uid: 0, freeBytes: 1 << 40,
		unit: true, enabled: true, running: true, healthy: true, dbSchema: 3, oldContent: binV1, yes: true,
	}
	for _, d := range []string{"/", l.BinDir, l.ConfigDir, l.DataDir, l.BackupsDir, "/etc/systemd/system", "/usr/local/src", "/var/tmp"} {
		h.dirs[d] = true
	}
	h.put(l.Binary, binV1)
	h.put(l.UnitPath, "[Unit]")
	h.put(l.DataDir+"/supermgmt.db", "db")
	h.put(l.DataDir+"/supermgmt.db.lock", "")
	h.put("/usr/local/src/sm-new", binV2)
	h.put(l.ConfigFile, h.serverConfig())
	h.startedAs = binV1
	return h
}

func (h *uhost) serverConfig() string {
	cfg, err := renderServerConfig(applianceLayout(), serverSettings{
		Name: "supermgmt", Listen: "127.0.0.1:8787", PublicURL: "https://sm.example.com", TLS: config.TLSProxy,
		TrustedProxies: []string{"127.0.0.1/32"},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return string(cfg)
}

func (h *uhost) put(p, content string) { h.inodes[p] = &inode{data: []byte(content)} }

func (h *uhost) record(format string, args ...any) {
	h.events = append(h.events, fmt.Sprintf(format, args...))
}

func (h *uhost) violate(format string, args ...any) {
	h.violations = append(h.violations, fmt.Sprintf(format, args...))
}

func (h *uhost) content(p string) string {
	if n, ok := h.inodes[p]; ok {
		return string(n.data)
	}
	return ""
}

func (h *uhost) live() string { return h.content(applianceLayout().Binary) }

// check runs after every file-system mutation.
func (h *uhost) check() {
	l := applianceLayout()
	if _, ok := h.inodes[l.Binary]; !ok && h.oldContent != "" {
		h.violate("the live sm is missing")
	}
	prev := h.content(l.Binary + ".prev")
	switch {
	case prev == h.oldContent:
		h.prevOld = true
	case h.prevOld && prev != "":
		h.violate("sm.prev held the old binary and now holds %q", prev)
	case h.prevOld && prev == "":
		h.violate("sm.prev held the old binary and is gone")
	}
}

// ---- Files ----

func (h *uhost) Exists(p string) bool { _, ok := h.inodes[p]; return ok || h.dirs[p] }

func (h *uhost) ReadFile(p string) ([]byte, error) {
	if n, ok := h.inodes[p]; ok {
		return append([]byte(nil), n.data...), nil
	}
	return nil, fs.ErrNotExist
}

func (h *uhost) MkdirAll(p string, _ fs.FileMode, _ Owner) error { h.dirs[p] = true; return nil }

func (h *uhost) WriteFile(p string, data []byte, _ fs.FileMode, _ Owner) error {
	h.inodes[p] = &inode{data: append([]byte(nil), data...)}
	h.record("write %s", p)
	h.check()
	return nil
}

func (h *uhost) CopyFile(src, dst string, _ fs.FileMode, _ Owner) error {
	n, ok := h.inodes[src]
	if !ok {
		return fs.ErrNotExist
	}
	h.inodes[dst] = &inode{data: append([]byte(nil), n.data...)}
	h.record("copy %s %s", src, dst)
	h.check()
	return nil
}

func (h *uhost) RemoveAll(p string) error {
	delete(h.inodes, p)
	delete(h.dirs, p)
	for k := range h.inodes {
		if strings.HasPrefix(k, p+"/") {
			delete(h.inodes, k)
		}
	}
	for k := range h.dirs {
		if strings.HasPrefix(k, p+"/") {
			delete(h.dirs, k)
		}
	}
	h.record("remove %s", p)
	h.check()
	return nil
}

func (h *uhost) AppendSync(p string, line []byte) error {
	n := h.inodes[p]
	if n == nil {
		n = &inode{}
		h.inodes[p] = n
	}
	n.data = append(n.data, line...)
	return nil
}

func (h *uhost) SyncDir(string) error { return nil }

func (h *uhost) Rename(oldPath, newPath string) error {
	n, ok := h.inodes[oldPath]
	if !ok {
		return fs.ErrNotExist
	}
	h.inodes[newPath] = n
	delete(h.inodes, oldPath)
	h.record("rename %s %s", oldPath, newPath)
	h.check()
	return nil
}

func (h *uhost) Link(oldPath, newPath string) error {
	n, ok := h.inodes[oldPath]
	if !ok {
		return fs.ErrNotExist
	}
	if _, taken := h.inodes[newPath]; taken {
		return fs.ErrExist
	}
	h.inodes[newPath] = n
	h.record("link %s %s", oldPath, newPath)
	h.check()
	return nil
}

func (h *uhost) Hash(p string) (string, error) {
	n, ok := h.inodes[p]
	if !ok {
		return "", fs.ErrNotExist
	}
	return sha256Hex(n.data), nil
}

func (h *uhost) Lock(p string) (func(), error) {
	if p != installerLockPath && (h.running || h.lockHeld) {
		return nil, errors.New("held by another process")
	}
	h.record("lock %s", p)
	return func() {}, nil
}

func (h *uhost) ListDir(dir string) ([]string, error) {
	seen := map[string]bool{}
	for k := range h.inodes {
		if path.Dir(k) == dir {
			seen[path.Base(k)] = true
		}
	}
	var names []string
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

type diskHost struct{ *uhost }

func (d diskHost) FreeBytes(string) (uint64, error) { return d.freeBytes, nil }
func (d diskHost) FileSize(p string) (int64, error) { return int64(len(d.content(p))), nil }

// ---- services, health ----

type usvc struct{ h *uhost }

func (s usvc) Register(context.Context, Unit) error { return nil }
func (s usvc) Load(_ context.Context, u Unit) error { s.h.record("reload %s", u.Name); return nil }

func (s usvc) Start(_ context.Context, u Unit) error {
	h := s.h
	h.record("start %s", u.Name)
	if h.startErr != nil && h.live() != h.oldContent {
		return h.startErr
	}
	bin := h.live()
	h.running, h.startedAs, h.healthy = true, bin, true
	f := parseBin(bin)
	schema := atoiOr(f["schema"], 0)
	switch f["boot"] {
	case "fail":
		h.healthy = false
	case "fail-migrated":
		h.healthy, h.dbSchema = false, max(h.dbSchema, schema)
	default:
		h.dbSchema = max(h.dbSchema, schema)
	}
	return nil
}

func (s usvc) Stop(_ context.Context, u Unit) error {
	s.h.record("stop %s", u.Name)
	if s.h.stopErr != nil {
		return s.h.stopErr
	}
	s.h.running = false
	return nil
}

func (s usvc) Disable(_ context.Context, u Unit) error {
	s.h.record("disable %s", u.Name)
	s.h.enabled = false
	return nil
}

func (s usvc) WaitStopped(_ context.Context, u Unit, _ time.Duration) error {
	s.h.record("waitstopped %s", u.Name)
	if s.h.running {
		return errors.New("still running")
	}
	return nil
}

func (h *uhost) WaitReady(_ context.Context, p Probe, _ time.Duration) error {
	h.probes = append(h.probes, p)
	h.record("ready")
	if !h.running || !h.healthy {
		return errors.New("not ready")
	}
	return nil
}

// ---- Runner: the sm subcommands the installer runs ----

func parseBin(content string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(content, ";")[1:] {
		k, v, _ := strings.Cut(kv, "=")
		out[k] = v
	}
	return out
}

func atoiOr(s string, fallback int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return fallback
}

func (h *uhost) Run(_ context.Context, c Command) ([]byte, error) {
	h.runs = append(h.runs, c)
	h.record("run %s %s", c.Name, strings.Join(c.Args, " "))
	content, ok := h.inodes[c.Name]
	if !ok {
		return nil, fmt.Errorf("%s: not found", c.Name)
	}
	f := parseBin(string(content.data))
	switch c.Args[0] {
	case "version":
		return json.Marshal(map[string]string{"version": f["version"]})
	case "doctor":
		return h.doctor(c, f)
	case "backup":
		return h.backup(c, f)
	}
	return nil, fmt.Errorf("unexpected command %v", c.Args)
}

func (h *uhost) requireOffline(c Command) {
	if h.uid == 0 && c.User != ServiceUser {
		h.violate("sm %s ran as %q, want %s", c.Args[0], c.User, ServiceUser)
	}
}

func (h *uhost) doctor(c Command, f map[string]string) ([]byte, error) {
	h.requireOffline(c)
	if f["doctor"] == "broken" {
		return nil, &ExitStatus{Command: c.Name, Code: 2}
	}
	latest := atoiOr(f["schema"], 0)
	detail := fmt.Sprintf("version %d matches this binary", h.dbSchema)
	status := "ok"
	switch {
	case h.dbSchema < latest:
		detail, status = fmt.Sprintf("database schema version %d is behind this binary (%d); the daemon migrates on start", h.dbSchema, latest), "warn"
	case h.dbSchema > latest:
		detail, status = fmt.Sprintf("database schema version %d is newer than this binary (%d)", h.dbSchema, latest), "fail"
	}
	out, _ := json.Marshal(map[string]any{"ok": status != "fail", "checks": []map[string]string{{"name": "schema", "status": status, "detail": detail}}})
	if status == "fail" {
		return out, &ExitStatus{Command: c.Name, Code: 1}
	}
	return out, nil
}

func (h *uhost) backup(c Command, f map[string]string) ([]byte, error) {
	h.requireOffline(c)
	if h.running {
		h.violate("offline backup ran while the service was running")
	}
	if h.backupErr != nil {
		return nil, h.backupErr
	}
	h.archives++
	archive := fmt.Sprintf("%s/pre-%d.tar.zst", applianceLayout().BackupsDir, h.archives)
	h.put(archive, "archive")
	schema := h.dbSchema
	if h.backupSchema != 0 {
		schema = h.backupSchema
	}
	return json.Marshal(map[string]any{"path": archive, "schema_version": schema, "sm_version": f["version"]})
}

// ---- wiring ----

func (h *uhost) deps() Deps {
	var files Files = h
	if !h.noDisk {
		files = diskHost{h}
	}
	d := Deps{
		Host:  Host{GOOS: "linux", GOARCH: "amd64", UID: h.uid, Home: h.home, Env: map[string]string{}, HasSystemd: true},
		Files: files, Runner: h, Health: h, Clock: fixedClock{}, Out: &h.out,
		Services: usvc{h}, UserServices: usvc{h},
	}
	if len(h.answers) > 0 || !h.yes {
		d.Prompter = h
	}
	return d
}

func (h *uhost) Confirm(q string) (bool, error) { h.asked = append(h.asked, q); return true, nil }

func (h *uhost) Ask(q string) (string, error) {
	h.asked = append(h.asked, q)
	if len(h.answers) == 0 {
		return "", errors.New("no answer")
	}
	a := h.answers[0]
	h.answers = h.answers[1:]
	return a, nil
}

func (h *uhost) upgradeOpts() Options {
	return Options{Mode: ModeUpgrade, Binary: "/usr/local/src/sm-new", Yes: true}
}

func (h *uhost) upgrade(hooks provisionHooks) error {
	return New(h.deps()).upgrade(context.Background(), h.upgradeOpts(), hooks)
}

func (h *uhost) index(prefix string) int {
	for i, e := range h.events {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

func (h *uhost) has(event string) bool {
	for _, e := range h.events {
		if e == event {
			return true
		}
	}
	return false
}

func (h *uhost) count(prefix string) int {
	n := 0
	for _, e := range h.events {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

func (h *uhost) state() (upgradeState, bool) {
	raw, err := h.ReadFile(applianceLayout().DataDir + "/" + upgradeStateFile)
	if err != nil {
		return upgradeState{}, false
	}
	var st upgradeState
	if err := json.Unmarshal(raw, &st); err != nil {
		h.t.Fatalf("upgrade state is not JSON: %v", err)
	}
	return st, true
}

func (h *uhost) noViolations(t *testing.T) {
	t.Helper()
	if len(h.violations) > 0 {
		t.Errorf("violations: %v", h.violations)
	}
}
