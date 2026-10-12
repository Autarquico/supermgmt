package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/secrets"
)

func TestOfflineSecretImportIsReadBackByTheDaemonsStoreAndAudited(t *testing.T) {
	const value = "oidc-client-secret-value"
	s, _ := keyedSandbox(t)

	r := s.runIn(value+"\n", "secrets", "import", "--offline", "--name", "oidc/client-secret")
	again := s.runIn(value+"-2\n", "secrets", "import", "--offline", "--name", "oidc/client-secret")

	if r.code != 0 || !strings.Contains(r.stdout, "version 1") || again.code != 0 || !strings.Contains(again.stdout, "version 2") {
		t.Fatalf("exit %d %q / %d %q", r.code, r.stderr, again.code, again.stderr)
	}
	assertNoSecret(t, value, r)
	ctx := context.Background()
	db, err := database.Open(ctx, s.dbPath, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	repo := offlineSecrets{ReadOnlySecrets: database.ReadOnlySecrets{Q: db.Reader()}, db: db}
	keys, err := secrets.OpenFileKeys(ctx, keysDirOf(t, s), repo, domain.UUIDv7Generator{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := secrets.NewStore(keys, repo, domain.UUIDv7Generator{}, domain.SystemClock{}).Get(ctx, secrets.Ref{Name: "oidc/client-secret"})
	if err != nil || got.Reveal() != value+"-2" {
		t.Fatalf("the store reads %q, %v; want the latest import", got.Reveal(), err)
	}
	events, err := database.ListEvents(ctx, db.Reader(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var imports int
	for _, e := range events {
		if e.Action == "secret.imported" && e.ActorType == domain.ActorSystem && e.Data["peer_uid"] != nil && e.Data["via"] == "offline" {
			imports++
		}
	}
	if imports != 2 {
		t.Errorf("audit events for the imports = %d, want 2 (system actor, peer uid)", imports)
	}
}

func TestOfflineSecretImportRefusesWhileADaemonHoldsTheDatabase(t *testing.T) {
	s, _ := keyedSandbox(t)
	lock, err := database.AcquireDatabaseLock(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()

	r := s.runIn("v\n", "secrets", "import", "--offline", "--name", "a/b")

	if r.code != exitPrerequisite || !strings.Contains(r.stderr, "stop the service") {
		t.Errorf("exit %d, %q", r.code, r.stderr)
	}
}

func TestOfflineSecretImportNeedsADatabaseAndRefusesTheReservedName(t *testing.T) {
	s := newSandbox(t)

	missing := s.runIn("v\n", "secrets", "import", "--offline", "--name", "a/b")
	reserved := s.runIn("v\n", "secrets", "import", "--offline", "--name", secrets.SSHIdentityName)

	for name, r := range map[string]result{"no database": missing, "reserved name": reserved} {
		if r.code != exitUsage {
			t.Errorf("%s: exit %d, %q; want a usage error", name, r.code, r.stderr)
		}
	}
}

func readStored(t *testing.T, s sandbox, name string) string {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, s.dbPath, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	repo := offlineSecrets{ReadOnlySecrets: database.ReadOnlySecrets{Q: db.Reader()}, db: db}
	keys, err := secrets.OpenFileKeys(ctx, keysDirOf(t, s), repo, domain.UUIDv7Generator{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := secrets.NewStore(keys, repo, domain.UUIDv7Generator{}, domain.SystemClock{}).Get(ctx, secrets.Ref{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return got.Reveal()
}

func sourceFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	writeFile(t, path, content)
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOfflineImportReadsAFileAndKeepsItUnlessAskedToDeleteIt(t *testing.T) {
	const value = "pve-api-token-value"
	s, _ := keyedSandbox(t)
	source := sourceFile(t, value+"\n", 0o600)

	r := s.runIn("", "secrets", "import", "--offline", "--name", "providers/pve/token", "--from-file", source)

	if r.code != 0 || !strings.Contains(r.stdout, "version 1") {
		t.Fatalf("exit %d %q", r.code, r.stderr)
	}
	assertNoSecret(t, value, r)
	if got := readStored(t, s, "providers/pve/token"); got != value {
		t.Errorf("stored %q, want the file's value without its final newline", got)
	}
	if _, err := os.Stat(source); err != nil {
		t.Errorf("the source was removed without --delete-source: %v", err)
	}
}

func TestOfflineImport_DeleteSourceOnlyOnSuccess(t *testing.T) {
	const value = "pve-api-token-value"
	args := func(source string, extra ...string) []string {
		return append([]string{"secrets", "import", "--offline", "--delete-source", "--from-file", source}, extra...)
	}
	holdLock := func(t *testing.T, s sandbox) {
		t.Helper()
		lock, err := database.AcquireDatabaseLock(s.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lock.Release() })
	}
	failures := []struct {
		name string
		mode os.FileMode
		prep func(*testing.T) sandbox
		args func(source string) []string
	}{
		{"no database", 0o600, newSandbox, func(f string) []string { return args(f, "--name", "a/b") }},
		{"reserved name", 0o600, func(t *testing.T) sandbox { s, _ := keyedSandbox(t); return s }, func(f string) []string { return args(f, "--name", secrets.SSHIdentityName) }},
		{"daemon holds the lock", 0o600, func(t *testing.T) sandbox { s, _ := keyedSandbox(t); holdLock(t, s); return s }, func(f string) []string { return args(f, "--name", "a/b") }},
		{"file readable by others", 0o644, func(t *testing.T) sandbox { s, _ := keyedSandbox(t); return s }, func(f string) []string { return args(f, "--name", "a/b") }},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			s := f.prep(t)
			source := sourceFile(t, value, f.mode)

			r := s.runIn("", f.args(source)...)

			if r.code == 0 {
				t.Fatalf("the import succeeded: %q", r.stdout)
			}
			if _, err := os.Stat(source); err != nil {
				t.Errorf("a failed import removed the source: %v", err)
			}
		})
	}

	t.Run("success", func(t *testing.T) {
		s, _ := keyedSandbox(t)
		source := sourceFile(t, value, 0o600)

		r := s.runIn("", args(source, "--name", "providers/pve/token")...)

		if r.code != 0 {
			t.Fatalf("exit %d: %s", r.code, r.stderr)
		}
		if got := readStored(t, s, "providers/pve/token"); got != value {
			t.Errorf("stored %q, want %q", got, value)
		}
		if _, err := os.Stat(source); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the source survived a committed import: %v", err)
		}
	})
}

func TestDeleteSourceNeedsOfflineAndAFile(t *testing.T) {
	s, _ := keyedSandbox(t)
	source := sourceFile(t, "v", 0o600)

	online := s.runIn("", "secrets", "import", "--name", "a/b", "--from-file", source, "--delete-source")
	noFile := s.runIn("v\n", "secrets", "import", "--offline", "--name", "a/b", "--delete-source")

	for name, r := range map[string]result{"online": online, "no file": noFile} {
		if r.code != exitUsage {
			t.Errorf("%s: exit %d, %q; want a usage error", name, r.code, r.stderr)
		}
	}
	if _, err := os.Stat(source); err != nil {
		t.Errorf("the source was touched: %v", err)
	}
}
