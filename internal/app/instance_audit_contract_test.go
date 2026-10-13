package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPendingAudit_DecodesTheInstallerContract decodes the record the
// installer writes (internal/installer pins the same golden byte for byte).
func TestPendingAudit_DecodesTheInstallerContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "installer", "testdata", "pending_audit.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := DecodePendingAudit(raw)
	if err != nil {
		t.Fatalf("the daemon rejects the installer's record: %v", err)
	}
	want := PendingAudit{
		EventID: rec.EventID, Action: ActionDowngradeAuthorized, OSUID: 0, OSUser: "root", SudoUser: "alex",
		From: "1.1.0", To: "1.0.0", At: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
	}
	if rec != want || string(rec.EventID) != "126dd170-e3b1-74f1-bd51-82c86abd06b5" {
		t.Errorf("record = %+v, want %+v", rec, want)
	}
}
