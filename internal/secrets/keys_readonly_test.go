package secrets_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

func TestReadOnlyLoaderOpensTheKeysAnInstanceAlreadyHas(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	created := mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs())

	loaded, err := secrets.OpenFileKeysReadOnly(context.Background(), dir, repo)
	if err != nil {
		t.Fatal(err)
	}

	wantID, wantKey := created.Active()
	gotID, gotKey := loaded.Active()
	if gotID != wantID || string(gotKey) != string(wantKey) {
		t.Errorf("loaded active key %s, want %s", gotID, wantID)
	}
}

func TestReadOnlyLoaderNeverCreatesTheKeysDirectory(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()

	_, err := secrets.OpenFileKeysReadOnly(context.Background(), dir, repo)

	_ = requireKeysUnavailable(t, err)
	if _, statErr := os.Lstat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the keys dir exists after a read-only open: %v", statErr)
	}
}

func TestReadOnlyLoaderNeverCreatesAFirstKey(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := secrets.OpenFileKeysReadOnly(context.Background(), dir, repo)

	_ = requireKeysUnavailable(t, err)
	if names := keyFiles(t, dir); len(names) != 0 {
		t.Errorf("key files created: %v", names)
	}
	if _, found, _ := repo.Setting(context.Background(), "active_kek_id"); found {
		t.Error("an active key was recorded")
	}
}

func TestReadOnlyLoaderRefusesALooseKeysDirectory(t *testing.T) {
	dir, repo := keysDir(t), secretstest.NewMemRepo()
	mustOpenKeys(t, dir, repo, domaintest.NewSequentialIDs())
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := secrets.OpenFileKeysReadOnly(context.Background(), dir, repo)

	_ = requireKeysUnavailable(t, err)
}
