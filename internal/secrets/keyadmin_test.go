package secrets_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

const passphrase = "correct horse battery"

type fakeArchives struct {
	ids []domain.ID
	err error
}

func (f *fakeArchives) ArchivedKEKIDs(context.Context) ([]domain.ID, error) { return f.ids, f.err }

type adminFixture struct {
	fixture
	archives *fakeArchives
	admin    *secrets.KeyAdmin
}

func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	f := newFixture(t)
	archives := &fakeArchives{}
	return adminFixture{fixture: f, archives: archives, admin: secrets.NewKeyAdmin(f.keys, f.repo, f.ids, archives)}
}

func (f adminFixture) put(t *testing.T, name, value string) secrets.Ref {
	t.Helper()
	ref, err := f.store.Put(context.Background(), name, audit.Secret(value), nil)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func (f adminFixture) mustRotate(t *testing.T) secrets.Rotation {
	t.Helper()
	r, err := f.admin.Rotate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f adminFixture) requireReadable(t *testing.T, store *secrets.Store, ref secrets.Ref, want string) {
	t.Helper()
	got, err := store.Get(context.Background(), ref)
	if err != nil || got.Reveal() != want {
		t.Fatalf("secret %s = %q, %v; want %q", ref, got.Reveal(), err, want)
	}
}

func (f adminFixture) reopen(t *testing.T) (*secrets.FileKeys, *secrets.Store) {
	t.Helper()
	keys := mustOpenKeys(t, f.dir, f.repo, domaintest.NewSequentialIDs())
	return keys, secrets.NewStore(keys, f.repo, f.ids, f.clock)
}

func requireCode(t *testing.T, err error, want smerr.Code) {
	t.Helper()
	if smerr.CodeOf(err) != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func TestRotateRewrapsEverySecretUnderTheNewActiveKey(t *testing.T) {
	f := newAdminFixture(t)
	a, b := f.put(t, "demo/a", "alpha"), f.put(t, "demo/b", "beta")
	a2 := f.put(t, "demo/a", "alpha-2")
	oldID, _ := f.keys.Active()

	r := f.mustRotate(t)

	newID, _ := f.keys.Active()
	if r.Active != newID || r.Previous != oldID || r.Rewrapped != 3 || newID == oldID {
		t.Fatalf("rotation = %+v, active %s, old %s", r, newID, oldID)
	}
	for ref, want := range map[secrets.Ref]string{a: "alpha", b: "beta", a2: "alpha-2"} {
		f.requireReadable(t, f.store, ref, want)
	}
	referenced, _ := f.repo.ReferencedKEKs(context.Background())
	if !slices.Equal(referenced, []domain.ID{newID}) {
		t.Errorf("rows reference %v, want only %s", referenced, newID)
	}
	if !slices.Contains(keyFiles(t, f.dir), oldID.String()+".key") {
		t.Error("the old key file was removed by rotation")
	}
	if _, found, _ := f.repo.Setting(context.Background(), "kek_check."+newID.String()); !found {
		t.Error("no check record for the new key")
	}
	ref := f.put(t, "demo/c", "gamma")
	rec, _ := f.repo.Get(context.Background(), ref.Name, ref.Version)
	if rec.KEKID != newID {
		t.Errorf("a Put after rotation used kek %s, want %s", rec.KEKID, newID)
	}
}

func TestRestartAfterRotationLoadsTheNewActiveKeyAndReadsEverything(t *testing.T) {
	f := newAdminFixture(t)
	ref := f.put(t, "demo/a", "alpha")
	oldID, _ := f.keys.Active()
	f.mustRotate(t)
	newID, _ := f.keys.Active()

	keys, store := f.reopen(t)

	if id, _ := keys.Active(); id != newID {
		t.Errorf("active after restart = %s, want %s", id, newID)
	}
	if _, loaded := keys.Key(oldID); loaded {
		t.Error("the old key is loaded although no row references it")
	}
	f.requireReadable(t, store, ref, "alpha")
}

func TestCrashBeforeCommitLeavesTheOldStateAndAnIgnoredOrphanKeyFile(t *testing.T) {
	f := newAdminFixture(t)
	ref := f.put(t, "demo/a", "alpha")
	oldID, _ := f.keys.Active()
	f.repo.FailNextUpdateKeys()

	if _, err := f.admin.Rotate(context.Background()); err == nil {
		t.Fatal("rotation succeeded although the transaction failed")
	}

	if id, _ := f.keys.Active(); id != oldID {
		t.Errorf("active = %s after a failed rotation, want %s", id, oldID)
	}
	if n := len(keyFiles(t, f.dir)); n != 2 {
		t.Errorf("%d key files, want the old key plus one orphan", n)
	}
	f.requireReadable(t, f.store, ref, "alpha")
	f.put(t, "demo/b", "beta")
	keys, store := f.reopen(t)
	if id, _ := keys.Active(); id != oldID {
		t.Errorf("active after restart = %s, want the old %s: an orphan key must be ignored", id, oldID)
	}
	f.requireReadable(t, store, ref, "alpha")
}

func TestCrashAfterCommitLeavesTheNewStateAndKeepsTheOldKeyFile(t *testing.T) {
	f := newAdminFixture(t)
	ref := f.put(t, "demo/a", "alpha")
	oldID, _ := f.keys.Active()
	f.repo.FailAfterCommitNextUpdateKeys() // the process dies before it can publish

	if _, err := f.admin.Rotate(context.Background()); err == nil {
		t.Fatal("expected the injected failure")
	}

	keys, store := f.reopen(t)
	newID, _ := keys.Active()
	if newID == oldID {
		t.Fatal("the committed rotation was lost")
	}
	f.requireReadable(t, store, ref, "alpha")
	if !slices.Contains(keyFiles(t, f.dir), oldID.String()+".key") {
		t.Error("the old key file is gone")
	}
}

func TestRotateRacingPutsLeavesNoRowUnderASupersededKey(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	const writers, perWriter, rotations = 6, 25, 5

	var wg sync.WaitGroup
	errs := make(chan error, writers+1)
	refs := make(chan secrets.Ref, writers*perWriter)
	for w := range writers {
		wg.Go(func() {
			for i := range perWriter {
				ref, err := f.store.Put(ctx, fmt.Sprintf("race/w%d", w), audit.Secret(fmt.Sprintf("value-%d-%d", w, i)), nil)
				if err != nil {
					errs <- err
					return
				}
				refs <- ref
			}
		})
	}
	wg.Go(func() {
		for range rotations {
			if _, err := f.admin.Rotate(ctx); err != nil {
				errs <- err
				return
			}
		}
	})
	wg.Wait()
	close(errs)
	close(refs)
	for err := range errs {
		t.Fatal(err)
	}

	activeID, _ := f.keys.Active()
	referenced, _ := f.repo.ReferencedKEKs(ctx)
	if !slices.Equal(referenced, []domain.ID{activeID}) {
		t.Errorf("rows reference %v, want only the active %s: a Put sealed under a superseded key slipped past a rotation", referenced, activeID)
	}
	count := 0
	for ref := range refs {
		count++
		if _, err := f.store.Get(ctx, ref); err != nil {
			t.Fatalf("secret %s unreadable: %v", ref, err)
		}
	}
	if count != writers*perWriter {
		t.Errorf("%d puts recorded, want %d", count, writers*perWriter)
	}
}

// gatedRepo parks a Put inside the repository until released, so a rotation can
// be started in the window between sealing and committing.
type gatedRepo struct {
	*secretstest.MemRepo
	entered chan struct{}
	release chan struct{}
}

func (g gatedRepo) Put(ctx context.Context, r secrets.Record) error {
	close(g.entered)
	<-g.release
	return g.MemRepo.Put(ctx, r)
}

func TestARotationStartedMidPutWaitsForItAndRewrapsItsRow(t *testing.T) {
	ctx := context.Background()
	dir, mem, ids := keysDir(t), secretstest.NewMemRepo(), domaintest.NewSequentialIDs()
	keys := mustOpenKeys(t, dir, mem, ids)
	repo := gatedRepo{MemRepo: mem, entered: make(chan struct{}), release: make(chan struct{})}
	store := secrets.NewStore(keys, repo, ids, domaintest.NewFakeClock(epoch))
	admin := secrets.NewKeyAdmin(keys, repo, ids, &fakeArchives{})

	var wg sync.WaitGroup
	wg.Go(func() {
		if _, err := store.Put(ctx, "demo/a", audit.Secret("alpha"), nil); err != nil {
			t.Error(err)
		}
	})
	<-repo.entered // sealed under the old key, not yet committed
	rotated := make(chan error, 1)
	go func() { _, err := admin.Rotate(ctx); rotated <- err }()
	select {
	case err := <-rotated:
		t.Fatalf("the rotation finished while a Put was in flight: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(repo.release)
	wg.Wait()
	if err := <-rotated; err != nil {
		t.Fatal(err)
	}

	activeID, _ := keys.Active()
	if referenced, _ := mem.ReferencedKEKs(ctx); !slices.Equal(referenced, []domain.ID{activeID}) {
		t.Errorf("rows reference %v, want only the active %s", referenced, activeID)
	}
}

func TestRetireRemovesAnUnreferencedKeyAndRestartStillWorks(t *testing.T) {
	f := newAdminFixture(t)
	ref := f.put(t, "demo/a", "alpha")
	oldID, _ := f.keys.Active()
	f.mustRotate(t)

	if err := f.admin.Retire(context.Background(), oldID); err != nil {
		t.Fatal(err)
	}

	if slices.Contains(keyFiles(t, f.dir), oldID.String()+".key") {
		t.Error("the retired key file is still on disk")
	}
	if _, found, _ := f.repo.Setting(context.Background(), "kek_check."+oldID.String()); found {
		t.Error("the retired key's check record survived")
	}
	if _, loaded := f.keys.Key(oldID); loaded {
		t.Error("the retired key is still loaded")
	}
	_, store := f.reopen(t)
	f.requireReadable(t, store, ref, "alpha")
}

func TestRetireRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("active key", func(t *testing.T) {
		f := newAdminFixture(t)
		active, _ := f.keys.Active()
		requireCode(t, f.admin.Retire(ctx, active), smerr.CodeConflict)
	})
	t.Run("unknown key", func(t *testing.T) {
		f := newAdminFixture(t)
		requireCode(t, f.admin.Retire(ctx, f.ids.NewID()), smerr.CodeNotFound)
	})
	t.Run("a secret row still references it", func(t *testing.T) {
		f := newAdminFixture(t)
		f.put(t, "demo/a", "alpha")
		oldID, _ := f.keys.Active()
		f.mustRotate(t)
		f.repo.Update("demo/a", 1, func(r *secrets.Record) { r.KEKID = oldID })
		requireCode(t, f.admin.Retire(ctx, oldID), smerr.CodeConflict)
		if _, loaded := f.keys.Key(oldID); !loaded {
			t.Error("a refused retirement unloaded the key")
		}
	})
	t.Run("a committed backup lists it", func(t *testing.T) {
		f := newAdminFixture(t)
		oldID, _ := f.keys.Active()
		f.mustRotate(t)
		f.archives.ids = []domain.ID{oldID}
		requireCode(t, f.admin.Retire(ctx, oldID), smerr.CodeConflict)
		if !slices.Contains(keyFiles(t, f.dir), oldID.String()+".key") {
			t.Error("a refused retirement removed the key file")
		}
	})
	t.Run("a manifest cannot be read", func(t *testing.T) {
		f := newAdminFixture(t)
		oldID, _ := f.keys.Active()
		f.mustRotate(t)
		f.archives.err = errors.New("manifest.json: invalid character")
		requireCode(t, f.admin.Retire(ctx, oldID), smerr.CodeConflict)
		if _, loaded := f.keys.Key(oldID); !loaded {
			t.Error("an unreadable manifest let the key go")
		}
	})
}

func TestRetireRefusesWhileABackupHoldsAReservationAndAllowsItAfterRelease(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	oldID, _ := f.keys.Active()
	f.mustRotate(t)
	reservation := f.keys.Reserve()

	requireCode(t, f.admin.Retire(ctx, oldID), smerr.CodeConflict)
	if !slices.Contains(reservation.KEKIDs(), oldID) {
		t.Errorf("reservation %v does not cover the loaded key %s", reservation.KEKIDs(), oldID)
	}

	reservation.Release()
	reservation.Release() // idempotent
	if err := f.admin.Retire(ctx, oldID); err != nil {
		t.Fatalf("retire after release: %v", err)
	}
}

func TestAReservationCoversKeysARotationLoadsWhileItIsOpen(t *testing.T) {
	f := newAdminFixture(t)
	reservation := f.keys.Reserve()
	f.mustRotate(t)
	middle, _ := f.keys.Active() // may be in the backup's snapshot
	f.mustRotate(t)

	requireCode(t, f.admin.Retire(context.Background(), middle), smerr.CodeConflict)
	reservation.Release()
	if err := f.admin.Retire(context.Background(), middle); err != nil {
		t.Fatalf("retire after release: %v", err)
	}
}

func TestReserveWaitsForARunningPut(t *testing.T) {
	f := newAdminFixture(t)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() { f.put(t, fmt.Sprintf("demo/s%d", i), "v") })
		wg.Go(func() { f.keys.Reserve().Release() })
		wg.Go(func() { _, _ = f.admin.Rotate(context.Background()) })
	}
	wg.Wait()
}

func TestExportThenImportRestoresAKeyOnAFreshHost(t *testing.T) {
	ctx := context.Background()
	f := newAdminFixture(t)
	f.put(t, "demo/a", "alpha")
	oldID, oldKEK := f.keys.Active()
	f.mustRotate(t)

	export, err := f.admin.Export(ctx, oldID, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(export), string(oldKEK)) {
		t.Fatal("the export holds the key in the clear")
	}

	// A fresh host: empty keys dir, the same database (restored).
	fresh := keysDir(t)
	staged, err := secrets.ImportKey(ctx, fresh, nil, export, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if staged.KEKID != oldID || staged.Active {
		t.Errorf("without a database the key must wait pending: %+v", staged)
	}
	names := keyFiles(t, fresh)
	if len(names) != 1 || names[0] != oldID.String()+".key.pending" {
		t.Fatalf("files = %v, want one .pending", names)
	}
	if info, _ := os.Stat(filepath.Join(fresh, names[0])); info.Mode().Perm() != 0o600 {
		t.Errorf("pending mode = %04o, want 0600", info.Mode().Perm())
	}

	activated, err := secrets.ImportKey(ctx, fresh, f.repo, export, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Active || !slices.Equal(keyFiles(t, fresh), []string{oldID.String() + ".key"}) {
		t.Errorf("a key the database references must become .key: %+v, %v", activated, keyFiles(t, fresh))
	}
	got, err := os.ReadFile(filepath.Join(fresh, oldID.String()+".key"))
	if err != nil || string(got) != string(oldKEK) {
		t.Errorf("imported key differs: %v", err)
	}
}

func TestImportKeyRefusals(t *testing.T) {
	ctx := context.Background()
	f := newAdminFixture(t)
	id, _ := f.keys.Active()
	export, err := f.admin.Export(ctx, id, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong passphrase writes nothing", func(t *testing.T) {
		dir := keysDir(t)
		if _, err := secrets.ImportKey(ctx, dir, nil, export, "not the passphrase"); err == nil {
			t.Fatal("accepted")
		}
		if _, err := os.Stat(dir); err == nil && len(keyFiles(t, dir)) != 0 {
			t.Errorf("files left: %v", keyFiles(t, dir))
		}
	})
	t.Run("a key that fails the database check is deleted", func(t *testing.T) {
		wrongDB := secretstest.NewMemRepo()
		wrongKeys := mustOpenKeys(t, keysDir(t), wrongDB, f.ids)
		wrongID, _ := wrongKeys.Active()
		wrongExport, err := secrets.NewKeyAdmin(wrongKeys, wrongDB, f.ids, &fakeArchives{}).Export(ctx, wrongID, passphrase)
		if err != nil {
			t.Fatal(err)
		}
		// The database holds a check record sealed under another key for that id.
		if err := wrongDB.PutSettings(ctx, map[string]string{"kek_check." + wrongID.String(): f.checkRecord(t, id)}); err != nil {
			t.Fatal(err)
		}
		dir := keysDir(t)
		_, err = secrets.ImportKey(ctx, dir, wrongDB, wrongExport, passphrase)
		requireCode(t, err, smerr.CodeInvalidArgument)
		if names := keyFiles(t, dir); len(names) != 0 {
			t.Errorf("a key that does not match the database was kept: %v", names)
		}
	})
	t.Run("an installed key is not overwritten", func(t *testing.T) {
		_, err := secrets.ImportKey(ctx, f.dir, f.repo, export, passphrase)
		requireCode(t, err, smerr.CodeConflict)
	})
}

func (f adminFixture) checkRecord(t *testing.T, id domain.ID) string {
	t.Helper()
	raw, found, err := f.repo.Setting(context.Background(), "kek_check."+id.String())
	if err != nil || !found {
		t.Fatal("no check record", err)
	}
	return raw
}

func TestExportKeyOfflineReadsTheKeyFileAndMatchesTheOnlineExport(t *testing.T) {
	ctx := context.Background()
	f := newAdminFixture(t)
	id, kek := f.keys.Active()

	export, err := secrets.ExportKeyOffline(ctx, f.dir, f.repo, id, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	gotID, gotKEK, err := secrets.DecodeKeyExport(export, passphrase)
	if err != nil || gotID != id || string(gotKEK) != string(kek) {
		t.Errorf("offline export does not decode to the key: %v", err)
	}
	if _, err := secrets.ExportKeyOffline(ctx, f.dir, f.repo, f.ids.NewID(), passphrase); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("unknown key: %v, want NOT_FOUND", err)
	}
	if _, err := f.admin.Export(ctx, id, "short"); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("short passphrase: %v, want INVALID_ARGUMENT", err)
	}
	if _, err := f.admin.Export(ctx, f.ids.NewID(), passphrase); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("unknown key: %v, want NOT_FOUND", err)
	}
}

func TestRotateSSHIdentityAddsAVersionAndKeepsTheOldOne(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	first, err := secrets.EnsureSSHIdentity(ctx, f.store)
	if err != nil {
		t.Fatal(err)
	}

	second, err := secrets.RotateSSHIdentity(ctx, f.store)
	if err != nil {
		t.Fatal(err)
	}

	if second.Ref.Version != first.Ref.Version+1 || second.FingerprintSHA256 == first.FingerprintSHA256 {
		t.Errorf("first %+v, second %+v", first, second)
	}
	if again, _ := secrets.EnsureSSHIdentity(ctx, f.store); again.Ref != second.Ref {
		t.Errorf("the current identity is %v, want the rotated %v", again.Ref, second.Ref)
	}
	if _, err := f.store.Signer(ctx, first.Ref); err != nil {
		t.Errorf("the previous version is no longer usable: %v", err)
	}
}
