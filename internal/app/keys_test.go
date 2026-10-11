package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

type noArchives struct{}

func (noArchives) ArchivedKEKIDs(context.Context) ([]domain.ID, error) { return nil, nil }

type keysFixture struct {
	*fixture
	dir   string
	repo  *SecretsKeyRepo
	keys  *secrets.FileKeys
	store *secrets.Store
	km    *KeyManager
}

func newKeysFixture(t *testing.T, mode config.Mode) *keysFixture {
	t.Helper()
	f := newFixture(t)
	repo := NewSecretsKeyRepo(f.db, f.clock)
	dir := filepath.Join(t.TempDir(), "keys")
	keys, err := secrets.OpenFileKeys(context.Background(), dir, repo, f.ids)
	mustf(t, err, "OpenFileKeys")
	store := secrets.NewStore(keys, repo, f.ids, f.clock)
	km, err := NewKeyManager(f.cfg, secrets.NewKeyAdmin(keys, repo, f.ids, noArchives{}), store, mode)
	mustf(t, err, "NewKeyManager")
	return &keysFixture{fixture: f, dir: dir, repo: repo, keys: keys, store: store, km: km}
}

func (k *keysFixture) local(id domain.ID) Caller {
	c := k.caller(id)
	c.Credential = domain.CredentialContext{Kind: domain.CredentialLocalSocket}
	return c
}

func TestRotateMasterKeyRewrapsThroughTheDatabaseAndIsAudited(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	ref, err := k.store.Put(ctx, "demo/token", audit.Secret("s3cret"), nil)
	mustf(t, err, "Put")
	oldID, _ := k.keys.Active()

	res, err := k.km.RotateMasterKey(ctx, k.caller(k.admin))

	mustf(t, err, "RotateMasterKey")
	newID, _ := k.keys.Active()
	if res.ActiveKEKID != newID || res.PreviousKEKID != oldID || res.Rewrapped != 1 {
		t.Errorf("result = %+v, active %s, old %s", res, newID, oldID)
	}
	if got, err := k.store.Get(ctx, ref); err != nil || got.Reveal() != "s3cret" {
		t.Errorf("secret after rotation = %q, %v", got.Reveal(), err)
	}
	// A restart reads the committed state through the same SQL.
	reopened, err := secrets.OpenFileKeys(ctx, k.dir, k.repo, k.ids)
	mustf(t, err, "reopen")
	if id, _ := reopened.Active(); id != newID {
		t.Errorf("active after reopen = %s, want %s", id, newID)
	}
	if events := k.events(eventMasterKeyRotated); len(events) != 1 || events[0].Result != domain.ResultSucceeded {
		t.Errorf("events = %+v", events)
	}
}

func TestRetireKeyNeedsTheExternalBackupAcknowledgementAndWorksAfterRotation(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	oldID, _ := k.keys.Active()
	_, err := k.km.RotateMasterKey(ctx, k.caller(k.admin))
	mustf(t, err, "rotate")

	err = k.km.RetireKey(ctx, k.caller(k.admin), wire.RetireKeyRequest{KEKID: oldID})
	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Fatalf("without acknowledgement: %v, want INVALID_ARGUMENT", err)
	}
	mustf(t, k.km.RetireKey(ctx, k.caller(k.admin), wire.RetireKeyRequest{KEKID: oldID, ExternalBackupsHandled: true}), "retire")

	events := k.events(eventMasterKeyRetired)
	if len(events) != 1 || events[0].Data["external_backups_handled"] != true {
		t.Errorf("events = %+v, want the acknowledgement recorded", events)
	}
	active, _ := k.keys.Active()
	err = k.km.RetireKey(ctx, k.caller(k.admin), wire.RetireKeyRequest{KEKID: active, ExternalBackupsHandled: true})
	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("retiring the active key: %v, want CONFLICT", err)
	}
	if failed := k.events(eventMasterKeyRetired); len(failed) != 2 || failed[1].Result != domain.ResultFailed {
		t.Errorf("the refused retirement was not audited as failed: %+v", failed)
	}
}

func TestExportKeyIsServedOnlyToLocalSocketCallersOfALocalInstance(t *testing.T) {
	ctx := context.Background()
	local := newKeysFixture(t, config.ModeLocal)
	id, _ := local.keys.Active()
	req := wire.ExportKeyRequest{KEKID: id, Passphrase: "correct horse battery"}

	for name, caller := range map[string]Caller{
		"api token": local.caller(local.admin),
		"session":   {ID: local.admin, Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: "s"}},
	} {
		if _, err := local.km.ExportKey(ctx, caller, req); smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s: error = %v, want POLICY_DENIED", name, err)
		}
	}
	server := newKeysFixture(t, config.ModeServer)
	sid, _ := server.keys.Active()
	if _, err := server.km.ExportKey(ctx, server.local(server.admin), wire.ExportKeyRequest{KEKID: sid, Passphrase: req.Passphrase}); smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Errorf("server mode over the local socket: %v, want POLICY_DENIED", err)
	}
	if got := local.events(eventMasterKeyExport); len(got) != 2 || got[0].Result != domain.ResultDenied {
		t.Errorf("refusals not audited as denied: %+v", got)
	}

	out, err := local.km.ExportKey(ctx, local.local(local.admin), req)
	mustf(t, err, "ExportKey")
	gotID, _, err := secrets.DecodeKeyExport(out.Export, req.Passphrase)
	if err != nil || gotID != id {
		t.Errorf("export decodes to %s, %v", gotID, err)
	}
	for _, e := range local.events(eventMasterKeyExport) {
		if strings.Contains(strings.ToLower(toText(e.Data)), "passphrase") || strings.Contains(toText(e.Data), req.Passphrase) {
			t.Errorf("event data leaks the passphrase: %v", e.Data)
		}
	}
}

func toText(m map[string]any) string { return fmt.Sprint(m) }

func TestKeyOperationsRequireSecretWrite(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	nobody := k.caller(k.dave)

	_, rotateErr := k.km.RotateMasterKey(ctx, nobody)
	_, importErr := k.km.ImportSecret(ctx, nobody, wire.ImportSecretRequest{Name: "demo/a", Value: "v"})
	_, sshErr := k.km.RotateSSHIdentity(ctx, nobody)

	for name, err := range map[string]error{"rotate": rotateErr, "import": importErr, "ssh-key rotate": sshErr} {
		if smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s: %v, want POLICY_DENIED", name, err)
		}
	}
	if _, err := k.store.Get(ctx, secrets.Ref{Name: "demo/a"}); err == nil {
		t.Error("a denied import stored a secret")
	}
}

func TestImportSecretStoresAVersionAndNeverAuditsTheValue(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()

	v1, err := k.km.ImportSecret(ctx, k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: "hunter2-value"})
	mustf(t, err, "import 1")
	v2, err := k.km.ImportSecret(ctx, k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: "second"})
	mustf(t, err, "import 2")

	if v1.Version != 1 || v2.Version != 2 {
		t.Errorf("versions = %d, %d", v1.Version, v2.Version)
	}
	if got, _ := k.store.Get(ctx, secrets.Ref{Name: "demo/token", Version: 1}); got.Reveal() != "hunter2-value" {
		t.Error("stored value differs")
	}
	for _, e := range k.events(eventSecretImported) {
		if strings.Contains(toText(e.Data), "hunter2") {
			t.Errorf("event leaks the value: %v", e.Data)
		}
	}
}

func TestImportSecretRefusals(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	cases := map[string]wire.ImportSecretRequest{
		"the instance identity": {Name: "ssh/default", Value: "x"},
		"an invalid name":       {Name: "Bad Name", Value: "x"},
		"an empty value":        {Name: "demo/a", Value: ""},
		"an oversized value":    {Name: "demo/a", Value: strings.Repeat("x", MaxImportedSecretBytes+1)},
	}
	for name, req := range cases {
		if _, err := k.km.ImportSecret(ctx, k.caller(k.admin), req); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestRotateSSHIdentityReturnsThePublicHalfOnlyAndAuditsTheFingerprint(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	first, err := secrets.EnsureSSHIdentity(ctx, k.store)
	mustf(t, err, "ensure")

	got, err := k.km.RotateSSHIdentity(ctx, k.caller(k.admin))

	mustf(t, err, "RotateSSHIdentity")
	if got.Version != first.Ref.Version+1 || got.Ref != "secret://ssh/default" || got.FingerprintSHA256 == first.FingerprintSHA256 || strings.Contains(got.AuthorizedKey, "PRIVATE") {
		t.Errorf("got %+v after %+v", got, first)
	}
	events := k.events(eventSSHKeyRotated)
	if len(events) != 1 || events[0].Data["fingerprint"] != got.FingerprintSHA256 {
		t.Errorf("events = %+v", events)
	}
}
