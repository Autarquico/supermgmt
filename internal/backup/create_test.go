package backup_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type fixture struct {
	t         *testing.T
	db        *database.DB
	clock     *domaintest.FakeClock
	ids       *domaintest.SequentialIDs
	keysDir   string
	keys      *secrets.FileKeys
	admin     *secrets.KeyAdmin
	archives  backup.Archives
	knownHost string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	f := &fixture{t: t, clock: domaintest.NewFakeClock(epoch), ids: domaintest.NewSequentialIDs(), keysDir: filepath.Join(root, "keys")}
	var err error
	if f.db, err = database.Open(ctx, filepath.Join(root, "sm.db"), database.Options{Clock: f.clock}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	if err := f.db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	repo := secretstest.NewMemRepo()
	if f.keys, err = secrets.OpenFileKeys(ctx, f.keysDir, repo, f.ids); err != nil {
		t.Fatal(err)
	}
	f.archives = backup.Archives{Dir: filepath.Join(root, "backups")}
	f.admin = secrets.NewKeyAdmin(f.keys, repo, f.ids, f.archives)
	f.knownHost = filepath.Join(root, "known_hosts")
	f.activate("listen: local\n", "policy: v1\n")
	return f
}

func (f *fixture) activate(config, policy string) {
	f.t.Helper()
	var p []byte
	if policy != "" {
		p = []byte(policy)
	}
	err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.PutConfigSnapshot(ctx, tx, []byte(config), p, f.clock.Now())
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) options() backup.CreateOptions {
	return backup.CreateOptions{
		Dir: f.archives.Dir, Instance: "lab", KnownHostsPath: f.knownHost, SMVersion: "9.9.9",
		Clock: f.clock, Source: f.db, Keys: f.keys,
	}
}

func (f *fixture) create() backup.Created {
	f.t.Helper()
	c, err := backup.Create(context.Background(), f.options())
	if err != nil {
		f.t.Fatalf("Create: %v", err)
	}
	return c
}

// member is one tar entry of an archive.
type member struct {
	name string
	data []byte
}

func readArchive(t *testing.T, path string) []member {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var out []member
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, member{h.Name, data})
	}
}

func openCopy(t *testing.T, path string) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), path, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func names(ms []member) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.name
	}
	return out
}

func TestArchiveHoldsExactlyTheDocumentedMembersWithTheirChecksums(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.knownHost, []byte("node ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	created := f.create()

	members := readArchive(t, created.Path)
	want := []string{backup.ManifestName, backup.DatabaseName, backup.ConfigName, backup.PolicyName, backup.KnownHostsName}
	if !slices.Equal(names(members), want) {
		t.Fatalf("members = %v, want %v", names(members), want)
	}
	manifest, err := backup.ParseManifest(members[0].data)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.SHA256) != len(want)-1 {
		t.Errorf("manifest checksums %d members, want %d", len(manifest.SHA256), len(want)-1)
	}
	for _, m := range members[1:] {
		sum := sha256.Sum256(m.data)
		if got := manifest.SHA256[m.name]; got != hex.EncodeToString(sum[:]) {
			t.Errorf("checksum of %s = %s, want %x", m.name, got, sum)
		}
	}
	if string(members[2].data) != "listen: local\n" || string(members[3].data) != "policy: v1\n" {
		t.Errorf("config members = %q, %q; want the activated snapshot bytes", members[2].data, members[3].data)
	}
	if manifest.FormatVersion != backup.FormatVersion || manifest.SMVersion != "9.9.9" || manifest.ConfigGeneration != 1 ||
		manifest.SchemaVersion < 1 || !manifest.CreatedAt.Equal(epoch) {
		t.Errorf("manifest = %+v", manifest)
	}
	if created.Manifest.SHA256[backup.DatabaseName] != manifest.SHA256[backup.DatabaseName] {
		t.Error("the returned manifest is not the archived one")
	}
}

func TestOptionalMembersAreOmittedWhenAbsent(t *testing.T) {
	f := newFixture(t)
	f.activate("listen: local\n", "") // no policy file in force; no known_hosts on disk

	members := readArchive(t, f.create().Path)

	want := []string{backup.ManifestName, backup.DatabaseName, backup.ConfigName}
	if !slices.Equal(names(members), want) {
		t.Fatalf("members = %v, want %v", names(members), want)
	}
}

func TestConfigMembersComeFromTheSnapshotNotFromDisk(t *testing.T) {
	f := newFixture(t)
	f.activate("generation: two\n", "policy: two\n")

	members := readArchive(t, f.create().Path)

	if string(members[2].data) != "generation: two\n" {
		t.Errorf("config member = %q", members[2].data)
	}
	manifest, _ := backup.ParseManifest(members[0].data)
	if manifest.ConfigGeneration != 2 {
		t.Errorf("config generation = %d, want 2", manifest.ConfigGeneration)
	}
}

func TestKEKFilesAreNeverArchived(t *testing.T) {
	f := newFixture(t)
	if _, err := f.admin.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	keyFiles, _ := filepath.Glob(filepath.Join(f.keysDir, "*.key"))
	if len(keyFiles) != 2 {
		t.Fatalf("key files = %v, want 2", keyFiles)
	}

	created := f.create()

	members := readArchive(t, created.Path)
	for _, m := range members {
		if strings.HasSuffix(m.name, ".key") || strings.HasSuffix(m.name, ".pending") {
			t.Errorf("archive holds key member %s", m.name)
		}
		for _, file := range keyFiles {
			secret, _ := os.ReadFile(file)
			if bytes.Contains(m.data, secret) {
				t.Errorf("member %s contains the bytes of %s", m.name, filepath.Base(file))
			}
		}
	}
	if len(created.Manifest.KEKIDs) != 2 {
		t.Errorf("manifest lists %d KEKs, want both loaded keys", len(created.Manifest.KEKIDs))
	}
}

func TestPublishedArchiveIsPrivateAndLeavesNothingElseBehind(t *testing.T) {
	f := newFixture(t)

	created := f.create()

	info, err := os.Stat(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("archive mode = %v, want 0600", info.Mode().Perm())
	}
	dir, _ := os.ReadDir(f.archives.Dir)
	if len(dir) != 1 || dir[0].Name() != created.Name {
		t.Errorf("backup directory = %v, want only %s", dir, created.Name)
	}
	if want := "supermgmt-lab-20261010T120000Z.tar.zst"; created.Name != want {
		t.Errorf("name = %s, want %s", created.Name, want)
	}
}

func TestArchivedDatabaseIsAUsableCopy(t *testing.T) {
	f := newFixture(t)
	members := readArchive(t, f.create().Path)

	path := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(path, members[1].data, 0o600); err != nil {
		t.Fatal(err)
	}
	copyDB := openCopy(t, path)
	var check string
	if err := copyDB.Reader().QueryRowContext(context.Background(), `PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check = %q, %v", check, err)
	}
	snap, err := database.GetConfigSnapshot(context.Background(), copyDB.Reader())
	if err != nil || string(snap.Config) != "listen: local\n" {
		t.Errorf("config snapshot in the copy = %+v, %v", snap, err)
	}
}

func TestArchiveIsConsistentWhileTheDaemonKeepsWriting(t *testing.T) {
	f := newFixture(t)
	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
				for _, side := range []string{"a", "b"} {
					key := fmt.Sprintf("pair.%s.%d", side, i)
					if err := database.PutSetting(ctx, tx, database.Setting{Key: key, Value: []byte(`1`), UpdatedAt: epoch}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Errorf("writer: %v", err)
				return
			}
		}
	}()
	defer writers.Wait()
	defer close(stop)

	for range 3 {
		f.clock.Advance(time.Second)
		members := readArchive(t, f.create().Path)
		path := filepath.Join(t.TempDir(), "copy.db")
		if err := os.WriteFile(path, members[1].data, 0o600); err != nil {
			t.Fatal(err)
		}
		reader := openCopy(t, path).Reader()
		var a, b int
		_ = reader.QueryRowContext(context.Background(), `SELECT count(*) FROM settings WHERE key LIKE 'pair.a.%'`).Scan(&a)
		_ = reader.QueryRowContext(context.Background(), `SELECT count(*) FROM settings WHERE key LIKE 'pair.b.%'`).Scan(&b)
		if a != b {
			t.Fatalf("archived database holds %d and %d paired rows: torn snapshot", a, b)
		}
	}
}

func TestCreateWithoutAnActivatedConfigurationIsRefused(t *testing.T) {
	f := newFixture(t)
	_ = f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, database.SettingConfigSnapshot)
		return err
	})

	_, err := backup.Create(context.Background(), f.options())

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("error = %v, want CONFLICT", err)
	}
	if entries, _ := os.ReadDir(f.archives.Dir); len(entries) != 0 {
		t.Errorf("a refused backup left %v behind", entries)
	}
}

func TestTwoBackupsInTheSameSecondDoNotOverwriteEachOther(t *testing.T) {
	f := newFixture(t)
	first := f.create()
	before, _ := os.ReadFile(first.Path)

	_, err := backup.Create(context.Background(), f.options())

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("error = %v, want CONFLICT", err)
	}
	if after, _ := os.ReadFile(first.Path); !bytes.Equal(before, after) {
		t.Error("the first archive changed")
	}
}

func TestInstanceNameCannotEscapeTheDirectory(t *testing.T) {
	f := newFixture(t)
	o := f.options()
	o.Instance = "../../etc/pass wd"

	created, err := backup.Create(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}

	if filepath.Dir(created.Path) != f.archives.Dir || strings.ContainsAny(created.Name, "/ ") {
		t.Errorf("archive %q escaped %s", created.Path, f.archives.Dir)
	}
}

// ---- reservations --------------------------------------------------------------

// retiringSource retires a key from inside the snapshot, the moment the
// reservation must already protect it.
type retiringSource struct {
	backup.Source
	retire func() error
	got    error
}

func (s *retiringSource) SnapshotTo(ctx context.Context, path string) (database.Snapshot, error) {
	s.got = s.retire()
	return s.Source.SnapshotTo(ctx, path)
}

func TestRetireIsRefusedWhileABackupIsInProgressAndAfterItsArchiveCommits(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old, _ := f.keys.Active()
	if _, err := f.admin.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	o := f.options()
	probe := &retiringSource{Source: f.db, retire: func() error { return f.admin.Retire(ctx, old) }}
	o.Source = probe

	if _, err := backup.Create(ctx, o); err != nil {
		t.Fatal(err)
	}

	if smerr.CodeOf(probe.got) != smerr.CodeConflict || !strings.Contains(probe.got.Error(), "backup in progress") {
		t.Errorf("retire during the backup = %v, want CONFLICT naming the backup in progress", probe.got)
	}
	err := f.admin.Retire(ctx, old)
	if smerr.CodeOf(err) != smerr.CodeConflict || !strings.Contains(err.Error(), "backup archive") {
		t.Errorf("retire after the commit = %v, want CONFLICT naming the archive", err)
	}
	entries, _ := f.archives.List()
	if err := os.Remove(filepath.Join(f.archives.Dir, entries[0].Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Retire(ctx, old); err != nil {
		t.Errorf("retire once no archive lists the key: %v", err)
	}
}

type failingSource struct{}

func (failingSource) SnapshotTo(context.Context, string) (database.Snapshot, error) {
	return database.Snapshot{}, errors.New("disk full")
}

func TestAnAbandonedBackupReleasesItsReservation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old, _ := f.keys.Active()
	if _, err := f.admin.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	o := f.options()
	o.Source = failingSource{}

	if _, err := backup.Create(ctx, o); err == nil {
		t.Fatal("Create succeeded with a failing source")
	}

	if err := f.admin.Retire(ctx, old); err != nil {
		t.Errorf("retire after an abandoned backup: %v", err)
	}
	if entries, _ := os.ReadDir(f.archives.Dir); len(entries) != 0 {
		t.Errorf("an abandoned backup left %v behind", entries)
	}
}

func TestReservationIsTakenBeforeTheDatabaseIsRead(t *testing.T) {
	f := newFixture(t)
	var order []string
	o := f.options()
	o.Keys = reserverFunc(func() *secrets.Reservation {
		order = append(order, "reserve")
		return f.keys.Reserve()
	})
	o.Source = sourceFunc(func(ctx context.Context, path string) (database.Snapshot, error) {
		order = append(order, "snapshot")
		return f.db.SnapshotTo(ctx, path)
	})

	if _, err := backup.Create(context.Background(), o); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(order, []string{"reserve", "snapshot"}) {
		t.Errorf("order = %v", order)
	}
}

type reserverFunc func() *secrets.Reservation

func (r reserverFunc) Reserve() *secrets.Reservation { return r() }

type sourceFunc func(ctx context.Context, path string) (database.Snapshot, error)

func (s sourceFunc) SnapshotTo(ctx context.Context, path string) (database.Snapshot, error) {
	return s(ctx, path)
}

func TestManifestListsTheKeyAThePrecedingRotationActivated(t *testing.T) {
	f := newFixture(t)
	rotation, err := f.admin.Rotate(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	created := f.create()

	if !slices.Contains(created.Manifest.KEKIDs, rotation.Active) || !slices.Contains(created.Manifest.KEKIDs, rotation.Previous) {
		t.Errorf("manifest KEKs = %v, want %s and %s", created.Manifest.KEKIDs, rotation.Active, rotation.Previous)
	}
}

func TestBackupsRunConcurrentlyWithRotationsAndListOnlyRealKeys(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	first, _ := f.keys.Active()
	existing := map[domain.ID]bool{first: true}
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 3 {
			r, err := f.admin.Rotate(ctx)
			if err != nil {
				t.Errorf("Rotate: %v", err)
				return
			}
			mu.Lock()
			existing[r.Active] = true
			mu.Unlock()
		}
	}()
	for range 3 {
		f.clock.Advance(time.Second)
		f.create()
	}
	wg.Wait()

	entries, err := f.archives.List()
	if err != nil || len(entries) != 3 {
		t.Fatalf("List = %d entries, %v", len(entries), err)
	}
	for _, e := range entries {
		if len(e.Manifest.KEKIDs) == 0 {
			t.Errorf("%s lists no KEK", e.Name)
		}
		for _, id := range e.Manifest.KEKIDs {
			mu.Lock()
			ok := existing[id]
			mu.Unlock()
			if !ok {
				t.Errorf("%s lists %s, which never existed", e.Name, id)
			}
		}
	}
}

// ---- catalog --------------------------------------------------------------------

func TestUnreadableManifestFailsTheCatalogAndRefusesRetirement(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old, _ := f.keys.Active()
	if _, err := f.admin.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.archives.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.archives.Dir, "supermgmt-lab-20200101T000000Z.tar.zst"), []byte("not zstd"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := f.archives.ArchivedKEKIDs(ctx); err == nil {
		t.Error("ArchivedKEKIDs ignored an unreadable manifest")
	}
	if err := f.admin.Retire(ctx, old); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("retire with an unreadable manifest = %v, want CONFLICT", err)
	}
}

func TestListIsOldestFirstAndMissingDirectoryIsEmpty(t *testing.T) {
	f := newFixture(t)
	if entries, err := f.archives.List(); err != nil || len(entries) != 0 {
		t.Fatalf("List on a missing directory = %v, %v", entries, err)
	}
	a := f.create()
	f.clock.Advance(time.Hour)
	b := f.create()

	entries, err := f.archives.List()

	if err != nil || len(entries) != 2 || entries[0].Name != a.Name || entries[1].Name != b.Name {
		t.Fatalf("List = %+v, %v", entries, err)
	}
	if entries[1].Size <= 0 || entries[1].Manifest.SMVersion != "9.9.9" {
		t.Errorf("entry = %+v", entries[1])
	}
}

func TestTemporaryFilesAreNotCommittedArchives(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(f.archives.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(f.archives.Dir, "supermgmt-lab-20200101T000000Z.tar.zst.partial")
	if err := os.WriteFile(partial, []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}

	ids, err := f.archives.ArchivedKEKIDs(context.Background())

	if err != nil || len(ids) != 0 {
		t.Errorf("ArchivedKEKIDs = %v, %v; a partial file is not an archive", ids, err)
	}
}

func TestCreateRemovesWorkDirectoriesACrashLeftBehind(t *testing.T) {
	f := newFixture(t)
	stale := filepath.Join(f.archives.Dir, ".work-crashed")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}

	f.create()

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale work directory still exists: %v", err)
	}
}

// ---- retention -------------------------------------------------------------------

func TestPruneKeepsTheNewestAndTouchesNothingElse(t *testing.T) {
	f := newFixture(t)
	var made []string
	for range 4 {
		f.clock.Advance(time.Hour)
		made = append(made, f.create().Name)
	}
	foreign := filepath.Join(f.archives.Dir, "hand-made.tar.zst")
	if err := os.WriteFile(foreign, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := backup.Prune(f.archives.Dir, 2)

	if err != nil || !slices.Equal(removed, made[:2]) {
		t.Fatalf("Prune = %v, %v; want %v", removed, err, made[:2])
	}
	left, _ := os.ReadDir(f.archives.Dir)
	var got []string
	for _, e := range left {
		got = append(got, e.Name())
	}
	slices.Sort(got)
	want := []string{"hand-made.tar.zst", made[2], made[3]}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("left = %v, want %v", got, want)
	}
}

func TestPruneNeverDeletesEverything(t *testing.T) {
	f := newFixture(t)
	created := f.create()

	for _, keep := range []int{0, -1} {
		if _, err := backup.Prune(f.archives.Dir, keep); err == nil {
			t.Errorf("Prune(keep=%d) succeeded", keep)
		}
	}
	if _, err := os.Stat(created.Path); err != nil {
		t.Errorf("archive gone: %v", err)
	}
}

func TestPruneWithFewerArchivesThanRetentionDoesNothing(t *testing.T) {
	f := newFixture(t)
	f.create()

	removed, err := backup.Prune(f.archives.Dir, 14)

	if err != nil || len(removed) != 0 {
		t.Errorf("Prune = %v, %v", removed, err)
	}
}

// ---- manifest --------------------------------------------------------------------

func TestReadManifestRejectsAnArchiveThatDoesNotStartWithOne(t *testing.T) {
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: backup.DatabaseName, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = zw.Close()

	if _, err := backup.ReadManifest(&buf); err == nil {
		t.Fatal("ReadManifest accepted an archive whose first member is not manifest.json")
	}
}

func TestParseManifestRejectsMalformedInput(t *testing.T) {
	valid := func(edit func(m *backup.Manifest)) []byte {
		m := backup.Manifest{
			FormatVersion: backup.FormatVersion, SMVersion: "1", SchemaVersion: 3, CreatedAt: epoch,
			KEKIDs: []domain.ID{}, ConfigGeneration: 1,
			SHA256: map[string]string{backup.DatabaseName: strings.Repeat("a", 64)},
		}
		edit(&m)
		out, err := backup.EncodeManifest(m)
		if err != nil {
			return []byte("{")
		}
		return out
	}
	tests := map[string][]byte{
		"not json":       []byte("{"),
		"unknown field":  []byte(`{"format_version":1,"surprise":true}`),
		"future format":  valid(func(m *backup.Manifest) { m.FormatVersion = 2 }),
		"no database":    valid(func(m *backup.Manifest) { m.SHA256 = map[string]string{} }),
		"short checksum": valid(func(m *backup.Manifest) { m.SHA256[backup.DatabaseName] = "abcd" }),
		"no generation":  valid(func(m *backup.Manifest) { m.ConfigGeneration = 0 }),
		"no timestamp":   valid(func(m *backup.Manifest) { m.CreatedAt = time.Time{} }),
	}
	for name, data := range tests {
		if _, err := backup.ParseManifest(data); err == nil {
			t.Errorf("%s: ParseManifest succeeded", name)
		}
	}
}
