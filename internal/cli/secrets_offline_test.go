package cli

import (
	"context"
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

func TestOfflineSecretImportTakesNoFileAndNeedsADatabase(t *testing.T) {
	s := newSandbox(t)
	fromFile := filepath.Join(t.TempDir(), "v")
	writeFile(t, fromFile, "v")

	file := s.runIn("", "secrets", "import", "--offline", "--name", "a/b", "--from-file", fromFile)
	missing := s.runIn("v\n", "secrets", "import", "--offline", "--name", "a/b")
	reserved := s.runIn("v\n", "secrets", "import", "--offline", "--name", secrets.SSHIdentityName)

	for name, r := range map[string]result{"from-file": file, "no database": missing, "reserved name": reserved} {
		if r.code != exitUsage {
			t.Errorf("%s: exit %d, %q; want a usage error", name, r.code, r.stderr)
		}
	}
}
