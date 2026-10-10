package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

func record(name string, version int, kek domain.ID) secrets.Record {
	return secrets.Record{
		ID: domain.ID(fmt.Sprintf("00000000-0000-7000-8000-%012d", version)), Name: name, Version: version, EnvelopeVersion: 1,
		KEKID: kek, WrappedDEK: []byte("wrapped"), Ciphertext: []byte("sealed"), MetadataJSON: `{"public_key":"k"}`,
	}
}

func TestSecretsRepoStoresVersionsAndReturnsTheLatestForVersionZero(t *testing.T) {
	f := newFixture(t)
	repo := NewSecretsRepo(f.db, f.clock)
	ctx := context.Background()
	mustf(t, repo.Put(ctx, record("ssh/default", 1, "kek-1")), "Put v1")
	mustf(t, repo.Put(ctx, record("ssh/default", 2, "kek-1")), "Put v2")

	latest, err := repo.Get(ctx, "ssh/default", 0)
	first, errFirst := repo.Get(ctx, "ssh/default", 1)

	if err != nil || latest.Version != 2 || errFirst != nil || first.Version != 1 {
		t.Fatalf("latest %+v (%v), first %+v (%v)", latest, err, first, errFirst)
	}
	if string(latest.Ciphertext) != "sealed" || string(latest.WrappedDEK) != "wrapped" || latest.MetadataJSON != `{"public_key":"k"}` || latest.EnvelopeVersion != 1 {
		t.Errorf("record = %+v", latest)
	}
}

func TestSecretsRepoRefusesAVersionThatExistsOrSkipsAhead(t *testing.T) {
	f := newFixture(t)
	repo := NewSecretsRepo(f.db, f.clock)
	ctx := context.Background()
	mustf(t, repo.Put(ctx, record("ssh/default", 1, "kek-1")), "Put v1")

	again := repo.Put(ctx, record("ssh/default", 1, "kek-1"))
	skipped := repo.Put(ctx, record("ssh/default", 3, "kek-1"))

	if smerr.CodeOf(again) != smerr.CodeConflict || smerr.CodeOf(skipped) != smerr.CodeConflict {
		t.Errorf("existing version: %v, skipped version: %v; both must be CONFLICT", again, skipped)
	}
}

func TestSecretsRepoReportsAMissingSecretAsNotFound(t *testing.T) {
	f := newFixture(t)

	_, err := NewSecretsRepo(f.db, f.clock).Get(context.Background(), "nope", 0)

	if smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("error = %v, want NOT_FOUND", err)
	}
}

func TestSecretsRepoSettingsAndReferencedKEKs(t *testing.T) {
	f := newFixture(t)
	repo := NewSecretsRepo(f.db, f.clock)
	ctx := context.Background()

	if _, found, err := repo.Setting(ctx, "active_kek_id"); found || err != nil {
		t.Fatalf("absent setting: found %v, %v", found, err)
	}
	mustf(t, repo.PutSettings(ctx, map[string]string{"active_kek_id": `"kek-b"`}), "PutSetting")
	mustf(t, repo.PutSettings(ctx, map[string]string{"active_kek_id": `"kek-b"`}), "PutSetting again")
	mustf(t, repo.Put(ctx, record("ssh/default", 1, "kek-a")), "Put")

	value, found, err := repo.Setting(ctx, "active_kek_id")
	ids, idsErr := repo.ReferencedKEKs(ctx)

	if !found || err != nil || value != `"kek-b"` {
		t.Errorf("setting = %q found %v, %v", value, found, err)
	}
	if idsErr != nil || len(ids) != 2 || ids[0] != "kek-a" || ids[1] != "kek-b" {
		t.Errorf("referenced KEKs = %v, %v; both the secret row and the setting count", ids, idsErr)
	}
}

func TestSecretsRepoPutSettingsIsAllOrNothing(t *testing.T) {
	f := newFixture(t)
	repo := NewSecretsRepo(f.db, f.clock)
	ctx := context.Background()

	err := repo.PutSettings(ctx, map[string]string{"kek_check.a": `"ok"`, "active_kek_id": `not json`})
	if err == nil {
		t.Fatal("an invalid value was accepted")
	}
	if _, found, _ := repo.Setting(ctx, "kek_check.a"); found {
		t.Error("the valid half of a failed batch was committed")
	}
	mustf(t, repo.PutSettings(ctx, map[string]string{"kek_check.a": `"ok"`, "active_kek_id": `"a"`}), "valid batch")
	for _, key := range []string{"kek_check.a", "active_kek_id"} {
		if _, found, _ := repo.Setting(ctx, key); !found {
			t.Errorf("%s missing after a successful batch", key)
		}
	}
}

func TestTheSSHIdentityIsGeneratedOnceThroughTheDatabaseRepoAndNeverStoredInTheClear(t *testing.T) {
	f := newFixture(t)
	repo := NewSecretsRepo(f.db, f.clock)
	ctx := context.Background()
	keys, err := secrets.OpenFileKeys(ctx, filepath.Join(t.TempDir(), "keys"), repo, f.ids)
	mustf(t, err, "OpenFileKeys")
	store := secrets.NewStore(keys, repo, f.ids, f.clock)

	first, err := secrets.EnsureSSHIdentity(ctx, store)
	mustf(t, err, "EnsureSSHIdentity")
	second, err := secrets.EnsureSSHIdentity(ctx, store)
	mustf(t, err, "EnsureSSHIdentity again")

	if !first.Generated || second.Generated || first.Ref != second.Ref || first.Ref.Version != 1 || first.FingerprintSHA256 != second.FingerprintSHA256 {
		t.Errorf("first %+v, second %+v; the identity is generated once", first, second)
	}
	if _, err := store.Signer(ctx, first.Ref); err != nil {
		t.Errorf("Signer: %v", err)
	}
	private, err := store.Get(ctx, first.Ref)
	mustf(t, err, "Get")
	if private == "" || private.String() != audit.Redacted {
		t.Errorf("the private key must be redacted in every printed form, got %q", private.String())
	}
	assertAbsentFromDatabaseFiles(t, f, []byte("BEGIN OPENSSH PRIVATE KEY"), []byte(private.Reveal()))
}

// assertAbsentFromDatabaseFiles scans the SQLite file and its WAL for secrets.
func assertAbsentFromDatabaseFiles(t *testing.T, f *fixture, needles ...[]byte) {
	t.Helper()
	var path string
	err := f.db.Reader().QueryRowContext(context.Background(), `SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&path)
	mustf(t, err, "database path")
	for _, file := range []string{path, path + "-wal"} {
		data, err := os.ReadFile(file)
		if os.IsNotExist(err) {
			continue
		}
		mustf(t, err, "read %s", file)
		for _, needle := range needles {
			if len(needle) > 0 && bytes.Contains(data, needle) {
				t.Errorf("%s contains plaintext key material", filepath.Base(file))
			}
		}
	}
}

func TestGeneratingTheInstanceIdentityIsAuditedOnceWithTheFingerprintOnly(t *testing.T) {
	f := newFixture(t)
	repo := NewSecretsRepo(f.db, f.clock)
	ctx := context.Background()
	keys, err := secrets.OpenFileKeys(ctx, filepath.Join(t.TempDir(), "keys"), repo, f.ids)
	mustf(t, err, "OpenFileKeys")
	store := secrets.NewStore(keys, repo, f.ids, f.clock)

	first, err := EnsureInstanceIdentity(ctx, f.cfg, store)
	mustf(t, err, "first start")
	_, err = EnsureInstanceIdentity(ctx, f.cfg, store)
	mustf(t, err, "second start")

	events := f.events("ssh_identity.generated")
	if len(events) != 1 || events[0].ActorType != domain.ActorSystem || events[0].Data["fingerprint"] != first.FingerprintSHA256 {
		t.Fatalf("events = %+v", events)
	}
	for key, value := range events[0].Data {
		if s, ok := value.(string); ok && (key == "authorized_key" || s == first.AuthorizedKey) {
			t.Errorf("the event carries the public key under %q; the fingerprint is enough", key)
		}
	}
}
