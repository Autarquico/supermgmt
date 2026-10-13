package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// downgradeSpy sees the downgrade record at the moment the binary is replaced.
type downgradeSpy struct {
	diskHost
	modes        map[string]fs.FileMode
	owners       map[string]Owner
	synced       []string
	recordAtSwap []string
	syncedAtSwap []string
}

func newDowngradeSpy(h *uhost) *downgradeSpy {
	return &downgradeSpy{diskHost: diskHost{h}, modes: map[string]fs.FileMode{}, owners: map[string]Owner{}}
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
	s.modes[p], s.owners[p] = mode, o
	return s.diskHost.WriteFile(p, data, mode, o)
}

func (s *downgradeSpy) MkdirAll(p string, mode fs.FileMode, o Owner) error {
	s.modes[p], s.owners[p] = mode, o
	return s.diskHost.MkdirAll(p, mode, o)
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
	if spy.modes[path] != 0o600 {
		t.Errorf("record mode = %o, want 600", spy.modes[path])
	}
	if dir := filepath.Dir(path); spy.modes[dir] != 0o700 {
		t.Errorf("record directory mode = %o, want 700", spy.modes[dir])
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		if spy.owners[p] != (Owner{User: ServiceUser, Group: ServiceUser}) {
			t.Errorf("%s owner = %+v, want the service account", p, spy.owners[p])
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
	var rec downgradeRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("record is not strictly decodable: %v", err)
	}
	if _, err := domain.ParseID(rec.EventID); err != nil {
		t.Errorf("event_id %q: %v", rec.EventID, err)
	}
	if filepath.Base(path) != rec.EventID+".json" {
		t.Errorf("file name %q does not match event_id %q", filepath.Base(path), rec.EventID)
	}
	want := downgradeRecord{
		EventID: rec.EventID, Action: "instance.downgrade_authorized", OSUID: 0, OSUser: "root", SudoUser: "alex",
		From: "1.1.0", To: "1.0.0", At: testNow.UTC(),
	}
	if rec != want {
		t.Errorf("record = %+v, want %+v", rec, want)
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
