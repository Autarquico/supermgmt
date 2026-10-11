package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
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
	inv   *Inventory
}

func newKeysFixture(t *testing.T, mode config.Mode) *keysFixture {
	t.Helper()
	f := newFixture(t)
	repo := NewSecretsKeyRepo(f.db, f.clock)
	dir := filepath.Join(t.TempDir(), "keys")
	keys, err := secrets.OpenFileKeys(context.Background(), dir, repo, f.ids)
	mustf(t, err, "OpenFileKeys")
	store := secrets.NewStore(keys, repo, f.ids, f.clock)
	km, err := NewKeyManager(f.cfg, f.store, secrets.NewKeyAdmin(keys, repo, f.ids, noArchives{}), store, mode)
	mustf(t, err, "NewKeyManager")
	inv, err := NewInventory(f.cfg, InventoryOptions{Store: f.store, Connector: Connector{}, Mode: mode, Keys: km})
	mustf(t, err, "NewInventory")
	return &keysFixture{fixture: f, dir: dir, repo: repo, keys: keys, store: store, km: km, inv: inv}
}

func (k *keysFixture) local(id domain.ID) Caller {
	c := k.caller(id)
	c.Credential = domain.CredentialContext{Kind: domain.CredentialLocalSocket}
	return c
}

// approveAndRun has bob approve the pending job, then runs it the way the
// engine would and marks it finished.
func (k *keysFixture) approveAndRun(sub *Submission) error {
	k.t.Helper()
	if sub == nil {
		k.t.Fatal("the request was not parked for approval")
	}
	if _, err := k.approve(k.bob, sub.Job); err != nil {
		k.t.Fatalf("approve: %v", err)
	}
	claimed, ok := k.claim()
	if !ok {
		k.t.Fatal("the approved job was not claimable")
	}
	if err := (applyHandler{inv: k.inv}).Run(context.Background(), claimed.Lease); err != nil {
		return err
	}
	return k.fixture.store.Succeed(context.Background(), claimed.Lease)
}

func (k *keysFixture) mustRun(sub *Submission) {
	k.t.Helper()
	mustf(k.t, k.approveAndRun(sub), "run approved job")
}

func (k *keysFixture) secretRows() int { return k.count(`SELECT count(*) FROM secrets`) }

// stored is every byte the request path may have persisted besides the secrets table.
func (k *keysFixture) stored() string {
	k.t.Helper()
	var b strings.Builder
	for _, query := range []string{
		`SELECT plan_json FROM plans`, `SELECT payload_json FROM jobs`, `SELECT data_json FROM events`,
		`SELECT request_hash || response_json FROM idempotency_records`,
	} {
		rows, err := k.db.Reader().QueryContext(context.Background(), query)
		mustf(k.t, err, "%s", query)
		for rows.Next() {
			var text string
			mustf(k.t, rows.Scan(&text), "scan")
			b.WriteString(text)
		}
		mustf(k.t, rows.Err(), "rows")
		rows.Close()
	}
	return b.String()
}

func TestRotateMasterKeyWaitsForApprovalThenRewrapsThroughTheDatabase(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	ref, err := k.store.Put(ctx, "demo/token", audit.Secret("s3cret"), nil)
	mustf(t, err, "Put")
	oldID, _ := k.keys.Active()

	res, err := k.km.RotateMasterKey(ctx, k.caller(k.admin))

	mustf(t, err, "RotateMasterKey")
	if res.Applied != nil || res.Pending == nil || res.Pending.Job.State != domain.JobAwaitingApproval || res.Pending.Job.Type != JobControlPlaneApply {
		t.Fatalf("result = %+v, want a control_plane.apply job awaiting approval", res)
	}
	if active, _ := k.keys.Active(); active != oldID || len(k.events(eventMasterKeyRotated)) != 0 {
		t.Fatal("the key rotated before the approval")
	}

	k.mustRun(res.Pending)

	newID, _ := k.keys.Active()
	if newID == oldID {
		t.Fatal("the approved rotation did not make a new key active")
	}
	if got, err := k.store.Get(ctx, ref); err != nil || got.Reveal() != "s3cret" {
		t.Errorf("secret after rotation = %q, %v", got.Reveal(), err)
	}
	reopened, err := secrets.OpenFileKeys(ctx, k.dir, k.repo, k.ids)
	mustf(t, err, "reopen")
	if id, _ := reopened.Active(); id != newID {
		t.Errorf("active after reopen = %s, want %s", id, newID)
	}
	events := k.events(eventMasterKeyRotated)
	if len(events) != 1 || events[0].Result != domain.ResultSucceeded || fmt.Sprint(events[0].Data["previous_kek_id"]) != oldID.String() {
		t.Errorf("events = %+v", events)
	}
	if got := k.job(res.Pending.Job.ID); got.State != domain.JobSucceeded {
		t.Errorf("job state = %s", got.State)
	}
}

func TestRetireKeyNeedsTheExternalBackupAcknowledgementAndRunsAfterApproval(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	oldID, _ := k.keys.Active()
	rotation, err := k.km.RotateMasterKey(ctx, k.caller(k.admin))
	mustf(t, err, "rotate")
	k.mustRun(rotation.Pending)

	if _, err := k.km.RetireKey(ctx, k.caller(k.admin), wire.RetireKeyRequest{KEKID: oldID}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Fatalf("without acknowledgement: %v, want INVALID_ARGUMENT", err)
	}
	res, err := k.km.RetireKey(ctx, k.caller(k.admin), wire.RetireKeyRequest{KEKID: oldID, ExternalBackupsHandled: true})
	mustf(t, err, "retire request")
	if _, ok := k.keys.Key(oldID); !ok || len(k.events(eventMasterKeyRetired)) != 0 {
		t.Fatal("the key was retired before the approval")
	}

	k.mustRun(res.Pending)

	if _, ok := k.keys.Key(oldID); ok {
		t.Error("the approved retirement left the key loaded")
	}
	events := k.events(eventMasterKeyRetired)
	if len(events) != 1 || events[0].Data["external_backups_handled"] != true {
		t.Errorf("events = %+v, want the acknowledgement recorded", events)
	}
}

func TestRetiringTheActiveKeyFailsTheApprovedJobAndIsAudited(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	active, _ := k.keys.Active()
	res, err := k.km.RetireKey(context.Background(), k.caller(k.admin), wire.RetireKeyRequest{KEKID: active, ExternalBackupsHandled: true})
	mustf(t, err, "retire request")

	err = k.approveAndRun(res.Pending)

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("approved retirement of the active key: %v, want CONFLICT", err)
	}
	if failed := k.events(eventMasterKeyRetired); len(failed) != 1 || failed[0].Result != domain.ResultFailed {
		t.Errorf("the refused retirement was not audited as failed: %+v", failed)
	}
}

func TestKeyOperationsRequireSecretWrite(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	nobody := k.caller(k.dave)

	_, rotateErr := k.km.RotateMasterKey(ctx, nobody)
	_, importErr := k.km.ImportSecret(ctx, nobody, wire.ImportSecretRequest{Name: "demo/a", Value: "v"})
	_, sshErr := k.km.RotateSSHIdentity(ctx, nobody)
	_, retireErr := k.km.RetireKey(ctx, nobody, wire.RetireKeyRequest{KEKID: k.ids.NewID(), ExternalBackupsHandled: true})

	for name, err := range map[string]error{"rotate": rotateErr, "import": importErr, "ssh-key rotate": sshErr, "retire": retireErr} {
		if smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s: %v, want POLICY_DENIED", name, err)
		}
	}
	if k.secretRows() != 0 {
		t.Error("a denied import stored a secret, staged or not")
	}
	if n := k.count(`SELECT count(*) FROM jobs`); n != 0 {
		t.Errorf("denied requests created %d jobs", n)
	}
}

func TestImportSecretWaitsStagedAndNeverLeaksTheValue(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	const value = "hunter2-value"

	res, err := k.km.ImportSecret(ctx, k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: value})

	mustf(t, err, "ImportSecret")
	if res.Pending == nil || res.Applied != nil {
		t.Fatalf("result = %+v, want a pending job", res)
	}
	if _, err := k.store.Get(ctx, secrets.Ref{Name: "demo/token"}); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("a staged secret is readable as current: %v", err)
	}
	if _, err := k.store.Signer(ctx, secrets.Ref{Name: "demo/token", Version: -1}); err == nil {
		t.Error("a staged secret yields a signer")
	}
	if k.secretRows() != 1 {
		t.Fatalf("secret rows = %d, want the one staged version", k.secretRows())
	}
	referenced, err := k.repo.ReferencedKEKs(ctx)
	active, _ := k.keys.Active()
	if err != nil || len(referenced) != 1 || referenced[0] != active {
		t.Errorf("referenced KEKs = %v, %v; the staged ciphertext must count as a reference to %s", referenced, err, active)
	}

	k.mustRun(res.Pending)

	got, err := k.store.Get(ctx, secrets.Ref{Name: "demo/token", Version: 1})
	if err != nil || got.Reveal() != value {
		t.Errorf("activated value = %q, %v", got.Reveal(), err)
	}
	if latest, err := k.store.Get(ctx, secrets.Ref{Name: "demo/token"}); err != nil || latest.Reveal() != value {
		t.Errorf("latest = %q, %v", latest.Reveal(), err)
	}
	if events := k.events(eventSecretImported); len(events) != 1 || fmt.Sprint(events[0].Data["version"]) != "1" {
		t.Errorf("events = %+v", events)
	}
	if strings.Contains(k.stored(), value) {
		t.Error("the value reached a plan, job payload, event or idempotency record")
	}
	sum := sha256.Sum256([]byte(value))
	if strings.Contains(k.stored(), hex.EncodeToString(sum[:])) {
		t.Error("a plan, job payload or event carries an unkeyed hash of the value")
	}
}

func TestImportedVersionsKeepIncreasingWhileOthersWait(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	first, err := k.km.ImportSecret(ctx, k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: "one"})
	mustf(t, err, "import 1")
	second, err := k.km.ImportSecret(ctx, k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: "two"})
	mustf(t, err, "import 2")

	k.mustRun(second.Pending)
	k.mustRun(first.Pending)

	for version, want := range map[int]string{1: "two", 2: "one"} {
		if got, err := k.store.Get(ctx, secrets.Ref{Name: "demo/token", Version: version}); err != nil || got.Reveal() != want {
			t.Errorf("version %d = %q, %v; want %q", version, got.Reveal(), err, want)
		}
	}
}

func TestAStagedImportSurvivesARotationAndIsActivatedUnderTheNewKey(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	imported, err := k.km.ImportSecret(ctx, k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: "kept"})
	mustf(t, err, "import")
	rotation, err := k.km.RotateMasterKey(ctx, k.caller(k.admin))
	mustf(t, err, "rotate")
	k.mustRun(rotation.Pending)

	k.mustRun(imported.Pending)

	if got, err := k.store.Get(ctx, secrets.Ref{Name: "demo/token"}); err != nil || got.Reveal() != "kept" {
		t.Errorf("value = %q, %v", got.Reveal(), err)
	}
}

func TestRejectingOrCancellingAnImportDeletesTheStagedCiphertext(t *testing.T) {
	ending := map[string]func(k *keysFixture, job domain.ID){
		"rejection": func(k *keysFixture, job domain.ID) {
			j := k.job(job)
			_, err := k.appr.Reject(context.Background(), k.caller(k.bob), DecisionRequest{JobID: j.ID, PlanHash: j.PlanHash, Reason: "no"})
			mustf(k.t, err, "reject")
		},
		"cancellation": func(k *keysFixture, job domain.ID) {
			k.inTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := k.fixture.store.Cancel(ctx, tx, job, domain.Actor{Type: domain.ActorSystem})
				return err
			})
		},
		"expiry": func(k *keysFixture, job domain.ID) {
			k.clock.Advance(defaultPlanTTL + time.Minute)
			_, err := k.fixture.store.ExpirePlans(context.Background())
			mustf(k.t, err, "ExpirePlans")
		},
	}
	for name, end := range ending {
		t.Run(name, func(t *testing.T) {
			k := newKeysFixture(t, config.ModeLocal)
			res, err := k.km.ImportSecret(context.Background(), k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: "gone"})
			mustf(t, err, "import")
			if k.secretRows() != 1 {
				t.Fatalf("secret rows = %d before the job ended", k.secretRows())
			}

			end(k, res.Pending.Job.ID)

			if k.secretRows() != 0 {
				t.Errorf("secret rows = %d after %s, want the staged ciphertext gone", k.secretRows(), name)
			}
			if _, err := k.store.Get(context.Background(), secrets.Ref{Name: "demo/token"}); smerr.CodeOf(err) != smerr.CodeNotFound {
				t.Errorf("Get after %s: %v, want NOT_FOUND", name, err)
			}
		})
	}
}

func TestAnApprovedImportActivatesOnlyWhatWasApproved(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	res, err := k.km.ImportSecret(context.Background(), k.caller(k.admin), wire.ImportSecretRequest{Name: "demo/token", Value: "approved"})
	mustf(t, err, "import")
	k.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE secrets SET ciphertext = substr(ciphertext, 2) WHERE version < 0`)
		return err
	})

	err = k.approveAndRun(res.Pending)

	if err == nil {
		t.Fatal("a tampered staged ciphertext was activated")
	}
	if _, err := k.store.Get(context.Background(), secrets.Ref{Name: "demo/token"}); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("Get: %v, want NOT_FOUND", err)
	}
}

func TestAnIdempotentImportStoresNoValueAndLeavesNoStagedCopyOnReplay(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	const value = "idempotent-value"
	keyed := func() Caller {
		by := k.caller(k.admin)
		by.Source = "api"
		by.Idempotency = &Idempotency{
			Key: "key-1", Method: "POST", Path: "/api/v1/secrets", RequestHash: "hash",
			Respond: func(result any, _ error) (int, []byte) {
				res, _ := result.(Submission)
				return 202, fmt.Appendf(nil, `{"job":%q}`, res.Job.ID)
			},
		}
		return by
	}
	_, err := k.km.ImportSecret(context.Background(), keyed(), wire.ImportSecretRequest{Name: "demo/token", Value: value})
	mustf(t, err, "first")

	_, err = k.km.ImportSecret(context.Background(), keyed(), wire.ImportSecretRequest{Name: "demo/token", Value: value})

	if asReplay(t, err) == nil {
		t.Fatal("no replay")
	}
	if k.secretRows() != 1 {
		t.Errorf("secret rows = %d; a replay must not leave a second staged copy", k.secretRows())
	}
	if strings.Contains(k.stored(), value) {
		t.Error("the value reached an idempotency record, plan, job or event")
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
	if k.secretRows() != 0 {
		t.Errorf("refused imports left %d secret rows", k.secretRows())
	}
}

func TestRotateSSHIdentityWaitsForApprovalThenReturnsNothingSecret(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	first, err := secrets.EnsureSSHIdentity(ctx, k.store)
	mustf(t, err, "ensure")

	res, err := k.km.RotateSSHIdentity(ctx, k.caller(k.admin))
	mustf(t, err, "RotateSSHIdentity")
	if latest, _ := secrets.EnsureSSHIdentity(ctx, k.store); res.Pending == nil || latest.Ref.Version != first.Ref.Version {
		t.Fatalf("result %+v, version %d: the identity rotated before the approval", res, latest.Ref.Version)
	}

	k.mustRun(res.Pending)

	latest, err := secrets.EnsureSSHIdentity(ctx, k.store)
	mustf(t, err, "ensure after")
	if latest.Ref.Version != first.Ref.Version+1 || latest.FingerprintSHA256 == first.FingerprintSHA256 {
		t.Errorf("identity after rotation = %+v, before %+v", latest, first)
	}
	events := k.events(eventSSHKeyRotated)
	if len(events) != 1 || events[0].Data["fingerprint"] != latest.FingerprintSHA256 {
		t.Errorf("events = %+v", events)
	}
	if strings.Contains(k.stored(), "PRIVATE") {
		t.Error("private key material reached a plan, job or event")
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
		for step, passphrase := range map[string]string{"request": "", "execution": req.Passphrase} {
			if _, err := local.km.ExportKey(ctx, caller, wire.ExportKeyRequest{KEKID: id, Passphrase: passphrase}); smerr.CodeOf(err) != smerr.CodePolicyDenied {
				t.Errorf("%s %s: error = %v, want POLICY_DENIED", name, step, err)
			}
		}
	}
	server := newKeysFixture(t, config.ModeServer)
	sid, _ := server.keys.Active()
	if _, err := server.km.ExportKey(ctx, server.local(server.admin), wire.ExportKeyRequest{KEKID: sid}); smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Errorf("server mode over the local socket: %v, want POLICY_DENIED", err)
	}
	if got := local.events(eventMasterKeyExport); len(got) != 4 || got[0].Result != domain.ResultDenied {
		t.Errorf("refusals not audited as denied: %+v", got)
	}
	if n := local.count(`SELECT count(*) FROM jobs`); n != 0 {
		t.Errorf("refused export requests created %d jobs", n)
	}
}

// exportRequested makes an approved export request of the local admin.
func (k *keysFixture) exportRequested(kek domain.ID) *Submission {
	k.t.Helper()
	res, err := k.km.ExportKey(context.Background(), k.local(k.admin), wire.ExportKeyRequest{KEKID: kek})
	mustf(k.t, err, "request the export")
	if res.Pending == nil || res.Applied != nil {
		k.t.Fatalf("export request = %+v, want a pending job", res)
	}
	return res.Pending
}

func TestExportKeyIsRequestedThenExecutedOnceByTheSameIdentity(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	id, _ := k.keys.Active()
	req := wire.ExportKeyRequest{KEKID: id, Passphrase: "correct horse battery"}
	pending := k.exportRequested(id)

	_, early := k.km.ExportKey(ctx, k.local(k.admin), req)
	if smerr.CodeOf(early) != smerr.CodeApprovalRequired {
		t.Errorf("execution before approval: %v, want APPROVAL_REQUIRED", early)
	}
	k.mustRun(pending)

	out, err := k.km.ExportKey(ctx, k.local(k.admin), req)
	mustf(t, err, "execution")
	if out.Applied == nil {
		t.Fatalf("execution = %+v, want the export", out)
	}
	gotID, _, err := secrets.DecodeKeyExport(out.Applied.Export, req.Passphrase)
	if err != nil || gotID != id {
		t.Errorf("export decodes to %s, %v", gotID, err)
	}
	if _, again := k.km.ExportKey(ctx, k.local(k.admin), req); smerr.CodeOf(again) != smerr.CodeConflict {
		t.Errorf("second execution: %v, want CONFLICT", again)
	}
	if used := k.events(eventMasterKeyExport); len(used) != 3 || used[1].Result != domain.ResultSucceeded {
		t.Errorf("events = %+v, want the early refusal, one use and the conflict", used)
	}
	if text := k.stored(); strings.Contains(text, req.Passphrase) || strings.Contains(strings.ToLower(text), "passphrase") {
		t.Error("the passphrase reached a plan, job payload, event or idempotency record")
	}
}

func TestAnotherIdentityCannotExecuteSomeoneElsesApprovedExport(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	id, _ := k.keys.Active()
	k.mustRun(k.exportRequested(id))
	var other domain.ID
	k.inTx(func(ctx context.Context, tx *database.Tx) error {
		other = k.identity(ctx, tx, "root-2", domain.ActorHuman, k.role(ctx, tx, "admin"))
		return nil
	})

	_, err := k.km.ExportKey(context.Background(), k.local(other), wire.ExportKeyRequest{KEKID: id, Passphrase: "correct horse battery"})

	if smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Fatalf("another identity: %v, want POLICY_DENIED", err)
	}
	if _, err := k.km.ExportKey(context.Background(), k.local(k.admin), wire.ExportKeyRequest{KEKID: id, Passphrase: "correct horse battery"}); err != nil {
		t.Errorf("the owner lost the request to a stranger's attempt: %v", err)
	}
}

func TestAnApprovedExportExpiresAfterTwentyFourHours(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	id, _ := k.keys.Active()
	k.mustRun(k.exportRequested(id))

	k.clock.Advance(exportIntentTTL + time.Second)
	_, err := k.km.ExportKey(context.Background(), k.local(k.admin), wire.ExportKeyRequest{KEKID: id, Passphrase: "correct horse battery"})

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("late execution: %v, want CONFLICT", err)
	}
}

func TestAWeakPassphraseDoesNotSpendTheApprovedExport(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	id, _ := k.keys.Active()
	k.mustRun(k.exportRequested(id))

	_, weak := k.km.ExportKey(context.Background(), k.local(k.admin), wire.ExportKeyRequest{KEKID: id, Passphrase: "short"})
	_, strong := k.km.ExportKey(context.Background(), k.local(k.admin), wire.ExportKeyRequest{KEKID: id, Passphrase: "correct horse battery"})

	if weak == nil {
		t.Error("a 5-character passphrase exported a key")
	}
	if strong != nil {
		t.Errorf("the approved request was spent by the failed attempt: %v", strong)
	}
}

func TestAnExportNeedsAnExistingKey(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)

	_, err := k.km.ExportKey(context.Background(), k.local(k.admin), wire.ExportKeyRequest{KEKID: k.ids.NewID()})

	if smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("unknown key: %v, want NOT_FOUND", err)
	}
	if n := k.count(`SELECT count(*) FROM jobs`); n != 0 {
		t.Errorf("a request for an unknown key created %d jobs", n)
	}
}

func TestSecretWritePlansReplayTheirParametersStrictly(t *testing.T) {
	cases := map[string]secretWriteParams{
		"unknown operation":      {Operation: "format_disk"},
		"retire without ack":     {Operation: opRetireKey, KEKID: "01900000-0000-7000-8000-000000000001"},
		"retire without kek":     {Operation: opRetireKey, ExternalBackupsHandled: true},
		"import without staging": {Operation: opImportSecret, Name: "demo/a"},
	}
	for name, p := range cases {
		if err := p.validate(); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}
	raw, _ := json.Marshal(map[string]any{"operation": opRotateMasterKey, "smuggled": true})
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	if _, err := fromParams[secretWriteParams](decoded); err == nil {
		t.Error("an unknown parameter was accepted")
	}
}
