package cli

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
)

type initReport struct {
	Database string `json:"database"`
	KeysDir  string `json:"keys_dir"`
	KEKID    string `json:"kek_id"`
}

func runServerInit(t *testing.T, file string) (result, initReport) {
	t.Helper()
	r := runServerCmds([]string{"HOME=" + t.TempDir()}, "server", "init", "--config", file, "--json")
	var report initReport
	if r.code == 0 {
		if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
			t.Fatalf("report %q: %v", r.stdout, err)
		}
	}
	return r, report
}

func keyFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.key"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestServerInitIsIdempotentAndMakesOneMasterKey(t *testing.T) {
	file, _ := serverConfig(t)

	first, firstReport := runServerInit(t, file)
	second, secondReport := runServerInit(t, file)

	if first.code != 0 || second.code != 0 {
		t.Fatalf("exit %d %q / %d %q", first.code, first.stderr, second.code, second.stderr)
	}
	if firstReport.KEKID == "" || secondReport.KEKID != firstReport.KEKID {
		t.Errorf("master key %q then %q, want the same one", firstReport.KEKID, secondReport.KEKID)
	}
	if files := keyFilesIn(t, firstReport.KeysDir); len(files) != 1 {
		t.Errorf("key files = %v, want exactly one", files)
	}
	if _, err := os.Stat(firstReport.Database); err != nil {
		t.Errorf("no database after init: %v", err)
	}
}

func TestServerInitLeavesEverythingToTheInvokingUser(t *testing.T) {
	file, _ := serverConfig(t)

	r, report := runServerInit(t, file)

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	owner := os.Getuid()
	dataDir := filepath.Dir(report.Database)
	err := filepath.WalkDir(dataDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || strings.HasSuffix(path, ".lock") {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if uid := int(info.Sys().(*syscall.Stat_t).Uid); uid != owner {
			t.Errorf("%s is owned by uid %d, want the invoking user %d", path, uid, owner)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s has mode %04o: readable by others", path, mode)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServerInitRefusesWhileTheServiceHoldsTheDatabase(t *testing.T) {
	file, _ := serverConfig(t)
	result, err := config.Load(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := database.AcquireDatabaseLock(result.Config.Storage.SQLite.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()

	r, _ := runServerInit(t, file)

	if r.code != exitPrerequisite || !strings.Contains(r.stderr, "stop the service") {
		t.Errorf("exit %d, %q", r.code, r.stderr)
	}
	if keys := keyFilesIn(t, result.Config.Security.KeysDir); len(keys) != 0 {
		t.Errorf("a refused init created keys: %v", keys)
	}
}

func TestServerInitNeedsAServerConfiguration(t *testing.T) {
	local := filepath.Join(t.TempDir(), "local.yaml")
	if err := os.WriteFile(local, []byte("version: 1\ninstance:\n  mode: local\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, _ := runServerInit(t, local)

	if r.code != exitUsage {
		t.Errorf("exit %d, %q; want a usage error", r.code, r.stderr)
	}
}
