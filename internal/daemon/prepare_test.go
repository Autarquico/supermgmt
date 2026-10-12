package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
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
