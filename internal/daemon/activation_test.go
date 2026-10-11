package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/policy"
)

func TestStartupStoresTheExactConfigurationAndPolicyBytesAsTheSnapshot(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.yaml")
	policyBytes := append(policy.DefaultYAML(), []byte("\n# a comment the snapshot must keep byte for byte\n")...)
	if err := os.WriteFile(policyFile, policyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	i := newServerInstance(t, "  policy_file: "+policyFile+"\n")
	r := i.start()
	r.stop()
	_ = r.wait()

	db := i.openDB()
	snap, err := database.GetConfigSnapshot(context.Background(), db.Reader())
	want, _ := os.ReadFile(i.file)
	if err != nil || !bytes.Equal(snap.Config, want) || !bytes.Equal(snap.Policy, policyBytes) || snap.Generation != 1 {
		t.Errorf("snapshot = generation %d, %d config bytes (file has %d), %d policy bytes (file has %d); err %v",
			snap.Generation, len(snap.Config), len(want), len(snap.Policy), len(policyBytes), err)
	}

	_ = db.Close()
	again := i.start()
	again.stop()
	_ = again.wait()
	db = i.openDB()
	if snap, err := database.GetConfigSnapshot(context.Background(), db.Reader()); err != nil || snap.Generation != 2 {
		t.Errorf("after a second activation: generation %d, %v; every activation advances it", snap.Generation, err)
	}
}

func TestASecondServerOnTheSameDatabaseIsRefusedByTheLock(t *testing.T) {
	i := newServerInstance(t, "")
	i.start()

	second := i.start()

	var held *database.LockHeldError
	if err := second.wait(); !errors.As(err, &held) {
		t.Errorf("second server = %v, want the database lock error", err)
	}
}
