package app

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

type instanceAuditWorld struct {
	t     *testing.T
	audit InstanceAudit
	logs  *bytes.Buffer
}

func newInstanceAuditWorld(t *testing.T) *instanceAuditWorld {
	t.Helper()
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	db, err := database.Open(ctx, filepath.Join(dir, "sm.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ids := domaintest.NewSequentialIDs()
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.CreateInstance(ctx, tx, database.Instance{ID: ids.NewID(), Name: "t", CreatedAt: clock.Now()})
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	return &instanceAuditWorld{t: t, logs: logs, audit: InstanceAudit{
		DB: db, Clock: clock, IDs: ids, DataDir: dir, Log: slog.New(slog.NewTextHandler(logs, nil)),
	}}
}

func (w *instanceAuditWorld) start(version string) {
	w.t.Helper()
	if err := w.audit.Record(context.Background(), version, "c-"+version); err != nil {
		w.t.Fatal(err)
	}
}

func (w *instanceAuditWorld) events(action string) []domain.Event {
	w.t.Helper()
	all, err := database.ListEvents(context.Background(), w.audit.DB.Reader(), 0, 1000)
	if err != nil {
		w.t.Fatal(err)
	}
	var out []domain.Event
	for _, e := range all {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (w *instanceAuditWorld) pendingPath(id string) string {
	return filepath.Join(w.audit.DataDir, PendingAuditDir, id+".json")
}

func (w *instanceAuditWorld) leavePending(id, content string) string {
	w.t.Helper()
	path := w.pendingPath(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return path
}

const pendingAuditID = "01970000-0000-7000-8000-0000000000d1"

func pendingAuditJSON(id string) string {
	return `{"event_id":"` + id + `","action":"instance.downgrade_authorized","os_uid":1000,"os_user":"alex",` +
		`"sudo_user":"","from":"v0.6.0","to":"v0.5.0","at":"2026-04-30T10:00:00Z"}`
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestInstanceAudit_FirstStartRecordsOnlyTheSetting(t *testing.T) {
	w := newInstanceAuditWorld(t)
	w.start("v0.5.0")

	if _, err := database.GetSetting(context.Background(), w.audit.DB.Reader(), SettingBinaryVersion); err != nil {
		t.Fatalf("setting missing: %v", err)
	}
	if got := w.events(ActionVersionChanged); len(got) != 0 {
		t.Errorf("first start recorded %d events, want 0", len(got))
	}
}

func TestInstanceAudit_VersionTransitionDirections(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, commitFrom, commitTo, direction string
	}{
		{"upgrade", "v0.5.0", "v0.6.0", "a", "b", DirectionUpgrade},
		{"downgrade", "v0.6.0", "v0.5.0", "a", "b", DirectionDowngrade},
		{"same version, new commit", "v0.6.0", "v0.6.0", "a", "b", DirectionSame},
		{"numeric not lexical", "v0.9.0", "v0.10.0", "a", "b", DirectionUpgrade},
		{"release above its pre-release", "v1.0.0-rc.1", "v1.0.0", "a", "b", DirectionUpgrade},
		{"unparseable", "dev", "v0.6.0", "a", "b", DirectionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newInstanceAuditWorld(t)
			ctx := context.Background()
			if err := w.audit.Record(ctx, tc.from, tc.commitFrom); err != nil {
				t.Fatal(err)
			}
			if err := w.audit.Record(ctx, tc.to, tc.commitTo); err != nil {
				t.Fatal(err)
			}
			got := w.events(ActionVersionChanged)
			if len(got) != 1 {
				t.Fatalf("events = %d, want 1", len(got))
			}
			e := got[0]
			if e.Data["direction"] != tc.direction || e.Data["from"] != tc.from || e.Data["to"] != tc.to {
				t.Errorf("data = %v, want %s %s -> %s", e.Data, tc.direction, tc.from, tc.to)
			}
			if e.ActorType != domain.ActorSystem || e.ResourceType != domain.ResourceInstance || e.ResourceID == "" {
				t.Errorf("event = %+v, want a system event on the instance", e)
			}
		})
	}
}

func TestInstanceAudit_RestartOfTheSameBuildRecordsNothing(t *testing.T) {
	w := newInstanceAuditWorld(t)
	w.start("v0.5.0")
	w.start("v0.5.0")
	w.start("v0.5.0")
	if got := w.events(ActionVersionChanged); len(got) != 0 {
		t.Errorf("events = %d, want 0", len(got))
	}
}

func TestInstanceAudit_ImportsPendingOnce(t *testing.T) {
	w := newInstanceAuditWorld(t)
	path := w.leavePending(pendingAuditID, pendingAuditJSON(pendingAuditID))

	w.start("v0.5.0")
	w.start("v0.5.0")

	got := w.events(ActionDowngradeAuthorized)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	e := got[0]
	if string(e.EventID) != pendingAuditID || e.Data["from"] != "v0.6.0" || e.Data["os_user"] != "alex" {
		t.Errorf("event = %+v", e)
	}
	if !e.Timestamp.Equal(time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp = %v, want the authorization instant", e.Timestamp)
	}
	if exists(path) {
		t.Error("the record was not removed")
	}
}

func TestInstanceAudit_CrashBetweenInsertAndDeleteDoesNotDuplicate(t *testing.T) {
	w := newInstanceAuditWorld(t)
	path := w.leavePending(pendingAuditID, pendingAuditJSON(pendingAuditID))
	w.start("v0.5.0")
	w.leavePending(pendingAuditID, pendingAuditJSON(pendingAuditID)) // the delete never happened

	w.start("v0.5.0")

	if got := w.events(ActionDowngradeAuthorized); len(got) != 1 {
		t.Errorf("events = %d, want 1", len(got))
	}
	if exists(path) {
		t.Error("the stale record was not removed")
	}
}

func TestInstanceAudit_MalformedRecordIsKeptLoggedAndStartContinues(t *testing.T) {
	for name, content := range map[string]string{
		"not json":        "{",
		"wrong action":    strings.Replace(pendingAuditJSON(pendingAuditID), "downgrade_authorized", "something_else", 1),
		"unknown field":   strings.Replace(pendingAuditJSON(pendingAuditID), `"os_uid":1000`, `"os_uid":1000,"x":1`, 1),
		"missing to":      strings.Replace(pendingAuditJSON(pendingAuditID), `"to":"v0.5.0"`, `"to":""`, 1),
		"id not a uuid":   strings.Replace(pendingAuditJSON(pendingAuditID), pendingAuditID, "nope", 1),
		"id differs file": pendingAuditJSON("01970000-0000-7000-8000-0000000000d2"),
	} {
		t.Run(name, func(t *testing.T) {
			w := newInstanceAuditWorld(t)
			path := w.leavePending(pendingAuditID, content)

			w.start("v0.5.0")

			if !exists(path) {
				t.Error("a malformed record was removed")
			}
			if got := w.events(ActionDowngradeAuthorized); len(got) != 0 {
				t.Errorf("events = %d, want 0", len(got))
			}
			if !strings.Contains(w.logs.String(), "kept") {
				t.Errorf("nothing logged: %q", w.logs.String())
			}
		})
	}
}

func TestInstanceAudit_ASymlinkRecordIsNotFollowed(t *testing.T) {
	w := newInstanceAuditWorld(t)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(pendingAuditJSON(pendingAuditID)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := w.pendingPath(pendingAuditID)
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}

	w.start("v0.5.0")

	if got := w.events(ActionDowngradeAuthorized); len(got) != 0 {
		t.Errorf("a symlinked record was imported")
	}
}

func TestInstanceAudit_NoPendingDirectoryIsFine(t *testing.T) {
	w := newInstanceAuditWorld(t)
	w.start("v0.5.0")
}

func TestDecodePendingAudit_AcceptsTheInstallerRecord(t *testing.T) {
	p, err := DecodePendingAudit([]byte(pendingAuditJSON(pendingAuditID)))
	if err != nil {
		t.Fatal(err)
	}
	if p.OSUID != 1000 || p.From != "v0.6.0" || p.To != "v0.5.0" {
		t.Errorf("record = %+v", p)
	}
}

func FuzzDecodePendingAudit(f *testing.F) {
	f.Add([]byte(pendingAuditJSON(pendingAuditID)))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"event_id":"x"} trailing`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodePendingAudit(data)
		if err != nil {
			return
		}
		if p.Action != ActionDowngradeAuthorized || p.EventID == "" || p.From == "" || p.To == "" {
			t.Errorf("accepted an invalid record: %+v", p)
		}
	})
}
