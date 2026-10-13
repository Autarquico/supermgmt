package installer

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// downgradeSpy sees the downgrade record at the moment the binary is replaced.
// Root's own writes are recorded in rootWrites; the record is expected to
// arrive through the service account's shell instead.
type downgradeSpy struct {
	diskHost
	rootWrites   []string
	writtenBy    map[string]string
	synced       []string
	recordAtSwap []string
	syncedAtSwap []string
}

func newDowngradeSpy(h *uhost) *downgradeSpy {
	return &downgradeSpy{diskHost: diskHost{h}, writtenBy: map[string]string{}}
}

func (s *downgradeSpy) pending() []string {
	var found []string
	for p := range s.inodes {
		if strings.HasPrefix(p, applianceLayout().DataDir+"/"+pendingAuditDir+"/") {
			found = append(found, p)
		}
	}
	return found
}

func (s *downgradeSpy) WriteFile(p string, data []byte, mode fs.FileMode, o Owner) error {
	s.rootWrites = append(s.rootWrites, p)
	return s.diskHost.WriteFile(p, data, mode, o)
}

func (s *downgradeSpy) MkdirAll(p string, mode fs.FileMode, o Owner) error {
	s.rootWrites = append(s.rootWrites, p)
	return s.diskHost.MkdirAll(p, mode, o)
}

// Run stands in for the shell that stores the record as the command's user.
func (s *downgradeSpy) Run(ctx context.Context, c Command) ([]byte, error) {
	if c.Name != "/bin/sh" {
		return s.diskHost.Run(ctx, c)
	}
	dir, name := c.Args[len(c.Args)-2], c.Args[len(c.Args)-1]
	data, err := io.ReadAll(c.Stdin)
	if err != nil {
		return nil, err
	}
	s.dirs[dir] = true
	s.put(filepath.Join(dir, name), string(data))
	s.writtenBy[filepath.Join(dir, name)] = c.User
	return nil, nil
}

func (s *downgradeSpy) SyncDir(dir string) error {
	s.synced = append(s.synced, dir)
	return s.diskHost.SyncDir(dir)
}

func (s *downgradeSpy) Rename(from, to string) error {
	if to == applianceLayout().Binary && from == to+".new" {
		s.recordAtSwap = s.pending()
		s.syncedAtSwap = append([]string(nil), s.synced...)
	}
	return s.diskHost.Rename(from, to)
}

func downgradeHost(t *testing.T, allow bool) (*uhost, *downgradeSpy, error) {
	t.Helper()
	h := newUHost(t)
	h.oldContent = binV2
	h.put(applianceLayout().Binary, binV2)
	h.put("/usr/local/src/sm-new", binV1)
	spy := newDowngradeSpy(h)
	d := h.deps()
	d.Files = spy
	d.Runner = spy
	d.Host.UID = 0
	d.Host.Env = map[string]string{"USER": "root", "SUDO_USER": "alex"}
	o := h.upgradeOpts()
	o.AllowDowngrade = allow
	return h, spy, New(d).upgrade(context.Background(), o, defaultHooks())
}

func TestUpgrade_DowngradeRecordWrittenBeforeSwap(t *testing.T) {
	_, spy, err := downgradeHost(t, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.recordAtSwap) != 1 {
		t.Fatalf("records present when the binary was replaced = %v, want exactly 1", spy.recordAtSwap)
	}
	path := spy.recordAtSwap[0]
	if !slices.Contains(spy.syncedAtSwap, filepath.Dir(path)) {
		t.Errorf("record directory was not synced before the swap: %v", spy.syncedAtSwap)
	}
	if spy.writtenBy[path] != ServiceUser {
		t.Errorf("record written by %q, want the service account", spy.writtenBy[path])
	}
}

func TestUpgrade_RootNeverWritesUnderTheServiceOwnedAuditDir(t *testing.T) {
	_, spy, err := downgradeHost(t, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range spy.rootWrites {
		if strings.Contains(p, pendingAuditDir) {
			t.Errorf("root created or chowned %s", p)
		}
	}
}

func TestUpgrade_DowngradeRecordMatchesTheDaemonContract(t *testing.T) {
	_, spy, err := downgradeHost(t, true)
	if err != nil {
		t.Fatal(err)
	}
	path := spy.recordAtSwap[0]
	raw, readErr := spy.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	// The daemon decodes this exact file in internal/app (TestPendingAudit_DecodesTheInstallerContract);
	// the shared golden keeps both sides on one contract without the installer importing app.
	want, err := os.ReadFile(filepath.Join("testdata", "pending_audit.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Errorf("record =\n%s\nwant (testdata/pending_audit.golden.json)\n%s", raw, want)
	}
	if filepath.Base(path) != "126dd170-e3b1-74f1-bd51-82c86abd06b5.json" {
		t.Errorf("file name %q does not match the event_id", filepath.Base(path))
	}
}

// ---- SEC-1: a symlink planted by the service account ----

type pendingAuditExec struct{}

func (pendingAuditExec) Run(ctx context.Context, c Command) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Stdin = c.Stdin
	return cmd.Output()
}

// pendingAuditRootGuard fails the test when root-side file operations that follow symlinks are used.
type pendingAuditRootGuard struct {
	osFiles
	t *testing.T
}

func (g pendingAuditRootGuard) MkdirAll(p string, _ fs.FileMode, _ Owner) error {
	g.t.Errorf("root MkdirAll(%s) follows symlinks", p)
	return nil
}

func (g pendingAuditRootGuard) WriteFile(p string, _ []byte, _ fs.FileMode, _ Owner) error {
	g.t.Errorf("root WriteFile(%s) follows symlinks", p)
	return nil
}

func symlinkedDowngrade(t *testing.T) (u *upgrader, victim string) {
	t.Helper()
	dataDir := t.TempDir()
	victim = t.TempDir()
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dataDir, pendingAuditDir)); err != nil {
		t.Fatal(err)
	}
	l := applianceLayout()
	l.DataDir = dataDir
	d := Deps{Files: pendingAuditRootGuard{t: t}, Runner: pendingAuditExec{}, Clock: fixedClock{}, Host: Host{Env: map[string]string{}}}
	st := upgradeState{AllowDowngrade: true, OldSHA256: "a", NewSHA256: "b", StartedAt: testNow, FromVersion: "1.1.0", ToVersion: "1.0.0"}
	return &upgrader{d: d, t: upgradeTarget{l: l, runAs: ServiceUser}, st: st}, victim
}

func TestUpgrade_DowngradeRecordRefusesAPlantedSymlink(t *testing.T) {
	u, victim := symlinkedDowngrade(t)

	if err := u.recordDowngrade(t.Context()); err == nil {
		t.Fatal("recordDowngrade followed a symlink at audit-pending")
	}

	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("symlink target mode = %o, want 755 untouched", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Errorf("a file was written through the symlink: %v", entries)
	}
}

func TestUpgrade_DowngradeRecordScriptWritesARealDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), pendingAuditDir)
	u := &upgrader{d: Deps{Runner: pendingAuditExec{}}, t: upgradeTarget{runAs: ServiceUser}}

	if err := u.writePendingAudit(t.Context(), dir, "x.json", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "x.json"))
	if err != nil || string(got) != "{}\n" {
		t.Fatalf("record = %q, %v", got, err)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %o, want 700", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}
}

func TestUpgrade_NoDowngradeRecordForOtherUpgrades(t *testing.T) {
	t.Run("refused downgrade", func(t *testing.T) {
		_, spy, err := downgradeHost(t, false)
		if exitCodeOf(t, err) != ExitInvalid {
			t.Fatalf("err = %v", err)
		}
		if got := spy.pending(); len(got) != 0 {
			t.Errorf("records = %v", got)
		}
	})
	t.Run("plain upgrade", func(t *testing.T) {
		h := newUHost(t)
		spy := newDowngradeSpy(h)
		d := h.deps()
		d.Files = spy
		if err := New(d).upgrade(context.Background(), h.upgradeOpts(), defaultHooks()); err != nil {
			t.Fatal(err)
		}
		if got := spy.pending(); len(got) != 0 {
			t.Errorf("records = %v", got)
		}
	})
}

func TestDowngradeEventID_IsStablePerUpgradeAndValid(t *testing.T) {
	st := upgradeState{OldSHA256: "a", NewSHA256: "b", StartedAt: testNow}
	id := downgradeEventID(st)
	if _, err := domain.ParseID(id); err != nil {
		t.Fatalf("%q: %v", id, err)
	}
	if downgradeEventID(st) != id {
		t.Error("the same upgrade got two ids")
	}
	st.UpdatedAt = testNow.Add(time.Minute)
	if downgradeEventID(st) != id {
		t.Error("a resume changed the id")
	}
	st.NewSHA256 = "c"
	if downgradeEventID(st) == id {
		t.Error("another upgrade got the same id")
	}
}

func TestUpgradeState_StartedAtIsSetOnceAndSurvivesEveryLaterRecord(t *testing.T) {
	h := newUHost(t)
	clock := &steppingClock{now: testNow}
	d := h.deps()
	d.Clock = clock
	u := &upgrader{d: d, t: upgradeTarget{l: applianceLayout()}}
	h.dirs[u.t.l.DataDir] = true
	if err := u.record(upPrepared); err != nil {
		t.Fatal(err)
	}
	started := u.st.StartedAt
	id := downgradeEventID(u.st)

	clock.now = clock.now.Add(time.Hour)
	if err := u.record(upBackedUp); err != nil {
		t.Fatal(err)
	}

	if !u.st.StartedAt.Equal(started) || downgradeEventID(u.st) != id {
		t.Errorf("a later record changed the upgrade's identity: started %v -> %v", started, u.st.StartedAt)
	}
	if !u.st.UpdatedAt.After(started) {
		t.Error("UpdatedAt did not move")
	}
}

func TestLoadState_AStateWithoutStartedAtFallsBackToUpdatedAt(t *testing.T) {
	w := newAW(t)
	u := &upgrader{d: w.deps(false), t: upgradeTarget{l: applianceLayout()}}
	w.files[u.t.statePath()] = []byte(`{"phase":"backed_up","old_sha256":"a","new_sha256":"b","updated_at":"2026-01-02T03:04:05Z"}`)

	st, found, err := u.loadState()

	if err != nil || !found {
		t.Fatalf("loadState = %v, %v", found, err)
	}
	if want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC); !st.StartedAt.Equal(want) {
		t.Errorf("StartedAt = %v, want %v", st.StartedAt, want)
	}
}

type steppingClock struct{ now time.Time }

func (c *steppingClock) Now() time.Time { return c.now }
