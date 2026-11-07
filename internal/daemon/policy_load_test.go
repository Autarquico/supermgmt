package daemon

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyLogsRetiredActionsOncePerAction(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.yaml")
	text := "version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['app_target.move', 'app_target.read']}\n  - {name: b, subjects: ['*'], deny: ['app_target.move']}\n"
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	pol, _, err := loadPolicy(file, slog.New(slog.NewTextHandler(&out, nil)))
	if err != nil || pol == nil {
		t.Fatalf("pol=%v err=%v", pol, err)
	}
	if got := strings.Count(out.String(), "retired action"); got != 1 || !strings.Contains(out.String(), "ADR-0043") {
		t.Errorf("log = %q, want one warning naming ADR-0043", out.String())
	}
}

func TestLoadPolicyRefusesATypo(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(file, []byte("version: 1\nrules:\n  - {name: r, subjects: ['*'], allow: ['app_target.moev']}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPolicy(file, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("typo accepted")
	}
}
