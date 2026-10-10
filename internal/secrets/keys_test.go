package secrets_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

func keysDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	return dir
}

func openKeys(t *testing.T, dir string, repo *secretstest.MemRepo, ids domain.IDGenerator) (*secrets.FileKeys, error) {
	t.Helper()
	return secrets.OpenFileKeys(context.Background(), dir, repo, ids)
}

func mustOpenKeys(t *testing.T, dir string, repo *secretstest.MemRepo, ids domain.IDGenerator) *secrets.FileKeys {
	t.Helper()
	keys, err := openKeys(t, dir, repo, ids)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func keyFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestFirstStartCreatesTheKEKFileAndSettings(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	keys := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs())

	id, key := keys.Active()
	if len(key) != 32 {
		t.Fatalf("active key is %d bytes, want 32", len(key))
	}
	path := filepath.Join(dir, id.String()+".key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", info.Mode().Perm())
	}
	if dirInfo, _ := os.Stat(dir); dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("keys dir mode = %04o, want 0700", dirInfo.Mode().Perm())
	}
	for _, setting := range []string{"active_kek_id", "kek_check." + id.String()} {
		if _, found, _ := repo.Setting(context.Background(), setting); !found {
			t.Errorf("settings.%s was not stored", setting)
		}
	}
}

func TestKeysDirIsMode0700EvenUnderARestrictiveUmask(t *testing.T) {
	dir := keysDir(t)
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	mustOpenKeys(t, dir, secretstest.NewMemRepo(), domaintest.NewSequentialIDs())
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("keys dir mode = %04o, want 0700", info.Mode().Perm())
	}
}

func TestRestartReusesTheSameKEK(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	first := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs())
	second := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs())

	firstID, firstKey := first.Active()
	secondID, secondKey := second.Active()
	if firstID != secondID || string(firstKey) != string(secondKey) {
		t.Error("a restart generated a different KEK")
	}
	if n := len(keyFiles(t, dir)); n != 1 {
		t.Errorf("%d files in the keys dir, want 1", n)
	}
}

func requireKeysUnavailable(t *testing.T, err error, wantIDs ...domain.ID) *secrets.KeysUnavailableError {
	t.Helper()
	var unavailable *secrets.KeysUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("got %v, want *KeysUnavailableError", err)
	}
	for _, id := range wantIDs {
		if !strings.Contains(err.Error(), id.String()) {
			t.Errorf("error does not name %s: %v", id, err)
		}
	}
	return unavailable
}

func TestMissingKEKFileFailsNamingTheID(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	id, _ := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs()).Active()
	if err := os.Remove(filepath.Join(dir, id.String()+".key")); err != nil {
		t.Fatal(err)
	}
	_, err := openKeys(t, dir, repo, domaintest.NewSequentialIDs())
	failure := requireKeysUnavailable(t, err, id)
	if len(failure.IDs) != 1 || failure.IDs[0] != id {
		t.Errorf("IDs = %v, want [%s]", failure.IDs, id)
	}
}

func TestWrongKEKContentFailsTheCheckRecord(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	id, _ := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs()).Active()
	if err := os.WriteFile(filepath.Join(dir, id.String()+".key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := openKeys(t, dir, repo, domaintest.NewSequentialIDs())
	_ = requireKeysUnavailable(t, err, id)
}

func TestKEKFileWithWrongSizeIsRefused(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	id, _ := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs()).Active()
	if err := os.WriteFile(filepath.Join(dir, id.String()+".key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := openKeys(t, dir, repo, domaintest.NewSequentialIDs())
	_ = requireKeysUnavailable(t, err, id)
}

func TestKEKFileWithGroupOrOtherBitsIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		t.Run(mode.String(), func(t *testing.T) {
			dir, repo := keysDir(t), secretstest.NewMemRepo()
			id, _ := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs()).Active()
			if err := os.Chmod(filepath.Join(dir, id.String()+".key"), mode); err != nil {
				t.Fatal(err)
			}
			_, err := openKeys(t, dir, repo, domaintest.NewSequentialIDs())
			_ = requireKeysUnavailable(t, err, id)
		})
	}
}

func TestKEKFileThatIsASymlinkIsRefused(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	id, key := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs()).Active()
	real := filepath.Join(t.TempDir(), "real.key")
	if err := os.WriteFile(real, key, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, id.String()+".key")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	_, err := openKeys(t, dir, repo, domaintest.NewSequentialIDs())
	_ = requireKeysUnavailable(t, err, id)
}

func TestKeysDirWithLooseModeIsRefused(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs())
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := openKeys(t, dir, repo, domaintest.NewSequentialIDs())
	_ = requireKeysUnavailable(t, err)
}

func TestKeysDirThatIsASymlinkIsRefused(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := openKeys(t, link, secretstest.NewMemRepo(), domaintest.NewSequentialIDs())
	_ = requireKeysUnavailable(t, err)
}

func TestPendingKeyFilesAreNeverLoaded(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	id, key := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs()).Active()
	live := filepath.Join(dir, id.String()+".key")
	if err := os.Rename(live, live+".pending"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live+".pending", key, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := openKeys(t, dir, repo, domaintest.NewSequentialIDs())
	_ = requireKeysUnavailable(t, err, id)
}

func TestEveryReferencedKEKMustBeAvailable(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	ids := domaintest.NewSequentialIDs()
	keys := mustOpenKeys(t, dir, repo, ids)
	store := secrets.NewStore(keys, repo, ids, domaintest.NewFakeClock(epoch))
	if _, err := store.Put(context.Background(), "demo/token", "value", nil); err != nil {
		t.Fatal(err)
	}
	ghost := ids.NewID()
	repo.Update("demo/token", 1, func(r *secrets.Record) { r.KEKID = ghost })

	_, err := openKeys(t, dir, repo, ids)
	_ = requireKeysUnavailable(t, err, ghost)
}

func TestMissingActivePointerWithExistingSecretsFailsFast(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	ids := domaintest.NewSequentialIDs()
	keys := mustOpenKeys(t, dir, repo, ids)
	store := secrets.NewStore(keys, repo, ids, domaintest.NewFakeClock(epoch))
	if _, err := store.Put(context.Background(), "demo/token", "value", nil); err != nil {
		t.Fatal(err)
	}
	empty := secretstest.NewMemRepo()
	for _, name := range []string{"demo/token"} {
		rec, _ := repo.Get(context.Background(), name, 1)
		_ = empty.Put(context.Background(), rec)
	}
	_, err := openKeys(t, dir, empty, ids)
	_ = requireKeysUnavailable(t, err)
}
