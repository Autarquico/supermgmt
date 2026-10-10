package secrets_test

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

// TestCrashDuringFirstKEKCreationLeavesNoReferencedKEKBehind: the check record
// and the active pointer are stored together, so a failed first start leaves
// no setting at all and the next start succeeds.
func TestCrashDuringFirstKEKCreationLeavesNoReferencedKEKBehind(t *testing.T) {
	dir, repo, ids := keysDir(t), secretstest.NewMemRepo(), domaintest.NewSequentialIDs()
	repo.FailNextPutSettings()

	if _, err := openKeys(t, dir, repo, ids); err == nil {
		t.Fatal("first start succeeded although the settings write failed")
	}
	for _, key := range []string{"active_kek_id"} {
		if _, found, _ := repo.Setting(context.Background(), key); found {
			t.Errorf("settings.%s survived the failed start", key)
		}
	}
	if len(keyFiles(t, dir)) != 0 {
		t.Error("failed start left a key file behind")
	}
	if len(repo.Dump()) != 0 {
		t.Errorf("failed start left %d bytes in the repo", len(repo.Dump()))
	}

	keys, err := openKeys(t, dir, repo, ids)
	if err != nil {
		t.Fatalf("next start: %v", err)
	}
	if id, _ := keys.Active(); id == "" {
		t.Error("no active KEK after recovery")
	}
}
