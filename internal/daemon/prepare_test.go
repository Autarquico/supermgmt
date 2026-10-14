package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

func keyFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.key"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// prepare runs Prepare the way a caller must: holding the database lock, which
// is also what creates the data directory.
func prepare(t *testing.T, i *serverInstance) *Prepared {
	t.Helper()
	lock, err := database.AcquireDatabaseLock(i.cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	prepared, err := Prepare(context.Background(), Options{Config: i.cfg, ConfigFile: i.file})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestPrepareIsIdempotentAndNeverMakesASecondMasterKey(t *testing.T) {
	i := newServerInstance(t, "")

	first := prepare(t, i)
	firstKEK := first.ActiveKEK()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := prepare(t, i)
	defer func() { _ = second.Close() }()

	if firstKEK == "" || second.ActiveKEK() != firstKEK {
		t.Errorf("active key %q then %q, want the same one", firstKEK, second.ActiveKEK())
	}
	if files := keyFiles(t, i.cfg.Security.KeysDir); len(files) != 1 {
		t.Errorf("key files = %v, want exactly one", files)
	}
}

func TestPrepareCreatesOnlyWhatPrecedesConfiguration(t *testing.T) {
	ctx := context.Background()
	i := newServerInstance(t, "")
	prepared := prepare(t, i)
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}

	db := i.openDB()
	defer func() { _ = db.Close() }()
	if _, err := database.GetInstance(ctx, db.Reader()); err != nil {
		t.Errorf("the instance row is missing: %v", err)
	}
	if _, err := database.GetConfigSnapshot(ctx, db.Reader()); err == nil {
		t.Error("a configuration was activated: that is the daemon's job at start")
	}
}

func TestAServerStartsOnWhatPrepareLeft(t *testing.T) {
	i := newServerInstance(t, "")
	prepared := prepare(t, i)
	kek := prepared.ActiveKEK()
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}

	server := i.start()
	server.stop()
	if err := server.wait(); err != nil {
		t.Fatal(err)
	}

	files := keyFiles(t, i.cfg.Security.KeysDir)
	if len(files) != 1 || filepath.Base(files[0]) != kek.String()+".key" {
		t.Errorf("key files after the start = %v, want only %s.key", files, kek)
	}
	if info, err := os.Stat(i.cfg.Storage.SQLite.Path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("database: %v, %v", info, err)
	}
}

func prepareAsVersion(t *testing.T, i *serverInstance, version string) {
	t.Helper()
	lock, err := database.AcquireDatabaseLock(i.cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	prepared, err := Prepare(context.Background(), Options{Config: i.cfg, ConfigFile: i.file, SMVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
}

func eventsWithAction(t *testing.T, i *serverInstance, action string) []domain.Event {
	t.Helper()
	db := i.openDB()
	all, err := database.ListEvents(context.Background(), db.Reader(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []domain.Event
	for _, e := range all {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestPrepareRecordsAVersionChangeBeforeAnythingServes(t *testing.T) {
	i := newServerInstance(t, "")
	prepareAsVersion(t, i, "v0.5.0")
	if got := eventsWithAction(t, i, app.ActionVersionChanged); len(got) != 0 {
		t.Fatalf("first start recorded %d version events, want 0", len(got))
	}

	prepareAsVersion(t, i, "v0.6.0")

	got := eventsWithAction(t, i, app.ActionVersionChanged)
	if len(got) != 1 || got[0].Data["direction"] != app.DirectionUpgrade {
		t.Errorf("version events = %+v, want one upgrade", got)
	}
}

func TestPrepareImportsAPendingDowngradeOnce(t *testing.T) {
	i := newServerInstance(t, "")
	prepareAsVersion(t, i, "v0.6.0")
	const id = "01970000-0000-7000-8000-0000000000e1"
	dir := filepath.Join(i.dataDir(), app.PendingAuditDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := `{"event_id":"` + id + `","action":"instance.downgrade_authorized","os_uid":0,"os_user":"root",` +
		`"sudo_user":"alex","from":"v0.6.0","to":"v0.5.0","at":"2026-05-01T10:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}

	prepareAsVersion(t, i, "v0.5.0")
	prepareAsVersion(t, i, "v0.5.0")

	if got := eventsWithAction(t, i, app.ActionDowngradeAuthorized); len(got) != 1 {
		t.Errorf("downgrade events = %d, want 1", len(got))
	}
	if _, err := os.Stat(filepath.Join(dir, id+".json")); err == nil {
		t.Error("the record is still pending")
	}
}

func TestPrepareStartsDespiteAMalformedPendingRecord(t *testing.T) {
	i := newServerInstance(t, "")
	prepareAsVersion(t, i, "v0.6.0")
	dir := filepath.Join(i.dataDir(), app.PendingAuditDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	prepareAsVersion(t, i, "v0.6.0")

	if _, err := os.Stat(bad); err != nil {
		t.Errorf("the malformed record was not kept: %v", err)
	}
}
