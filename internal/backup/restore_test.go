package backup_test

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// newWorld is a source control plane with work in flight, its archive, and a
// target machine with a different live database.
func newWorld(t *testing.T) (*site, *target) {
	t.Helper()
	clock := domaintest.NewFakeClock(epoch)
	ids := domaintest.NewSequentialIDs()
	src := newSite(t, "source", clock, ids).withSecrets()
	src.seedWork()
	return src, newTarget(t, src, src.archive())
}

func scalar[T any](t *testing.T, db *database.DB, query string, args ...any) T {
	t.Helper()
	var v T
	if err := db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRestoreReplacesLiveStateKeepsLockAndWritesNoSecretsOutsideKeysDir(t *testing.T) {
	_, tg := newWorld(t)
	lockBefore, err := os.Stat(tg.dbPath + ".lock")
	if err != nil {
		t.Fatal(err)
	}

	if err := backup.Restore(context.Background(), tg.options()); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if _, err := os.Stat(tg.dbPath + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a -wal file sits next to the restored database: %v", err)
	}
	if info, err := os.Stat(tg.dbPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("restored database mode = %v, %v; want 0600", info.Mode(), err)
	}
	if got := marker(t, tg.dbPath); got != "from-archive" {
		t.Fatalf("live marker = %q, want the archive's", got)
	}
	pre := glob(t, filepath.Join(tg.dataDir, "pre-restore-*"))
	if len(pre) != 1 {
		t.Fatalf("pre-restore directories = %v, want one", pre)
	}
	if got := readFile(t, filepath.Join(pre[0], "supermgmt.db-wal")); got != "stray wal" {
		t.Errorf("previous -wal = %q", got)
	}
	if got := marker(t, filepath.Join(pre[0], "supermgmt.db")); got != liveMarker {
		t.Errorf("the previous database was not kept in pre-restore (marker %q)", got)
	}
	if got := readFile(t, filepath.Join(pre[0], "known_hosts")); got != "old host\n" {
		t.Errorf("previous known_hosts = %q", got)
	}
	if got := readFile(t, filepath.Join(tg.dataDir, "known_hosts")); got != "node ssh-ed25519 AAAA\n" {
		t.Errorf("known_hosts = %q, want the archived one", got)
	}
	configDir := filepath.Join(tg.dataDir, backup.RestoredConfigDir)
	if got := readFile(t, filepath.Join(configDir, "config.yaml")); got != "listen: local\n" {
		t.Errorf("restored config = %q", got)
	}
	if got := readFile(t, filepath.Join(configDir, "policies.yaml")); got != "policy: v1\n" {
		t.Errorf("restored policy = %q", got)
	}
	assertNoRestoreLeftovers(t, tg.dataDir)
	lockAfter, err := os.Stat(tg.dbPath + ".lock")
	if err != nil || !os.SameFile(lockBefore, lockAfter) || readFile(t, tg.dbPath+".lock") != "4242\n" {
		t.Errorf("the database lock file was touched: %v", err)
	}
}

func assertNoRestoreLeftovers(t *testing.T, dataDir string) {
	t.Helper()
	for _, pattern := range []string{backup.JournalName, backup.JournalName + ".tmp", "restore-*"} {
		if left := glob(t, filepath.Join(dataDir, pattern)); len(left) > 0 {
			t.Errorf("restore left %v behind", left)
		}
	}
}

func TestRestoreNeutralizesTheStagedDatabase(t *testing.T) {
	src, tg := newWorld(t)
	if err := backup.Restore(context.Background(), tg.options()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	db := openDB(t, tg.dbPath, tg.clock)
	restoredAt := src.clock.Now().UnixMilli()

	type jobRow struct {
		state, owner string
		generation   int64
		until        *int64
	}
	read := func(id string) jobRow {
		var r jobRow
		var owner *string
		if err := db.Reader().QueryRowContext(context.Background(),
			`SELECT state, lease_owner, lease_generation, lease_until FROM jobs WHERE id = ?`, id).Scan(&r.state, &owner, &r.generation, &r.until); err != nil {
			t.Fatal(err)
		}
		if owner != nil {
			r.owner = *owner
		}
		return r
	}
	// Fencing is past the job's own generation and its intents' (7, 4).
	for id, wantGeneration := range map[string]int64{"job-running": 8, "job-interrupted": 6, "job-nonretryable": 5} {
		got := read(id)
		if got.state != "interrupted" || got.generation != wantGeneration || got.owner != "" || got.until == nil || *got.until != restoredAt {
			t.Errorf("%s = %+v, want interrupted, generation %d, no owner, lease expired at restore time", id, got, wantGeneration)
		}
	}
	for _, id := range []string{"job-queued", "job-waiting"} {
		if got := read(id); got.state != "failed" {
			t.Errorf("%s state = %s, want failed", id, got.state)
		}
		if body := scalar[string](t, db, `SELECT error_json FROM jobs WHERE id = ?`, id); !strings.Contains(body, string(smerr.ReasonRestoredUndispatched)) {
			t.Errorf("%s error_json = %s, want RESTORED_UNDISPATCHED", id, body)
		}
	}
	if got := read("job-done"); got.state != "succeeded" || got.generation != 1 {
		t.Errorf("a terminal job changed: %+v", got)
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM resource_locks`); n != 1 {
		t.Errorf("lock rows = %d, want only the running job's", n)
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM resource_locks WHERE job_id = 'job-running'`); n != 1 {
		t.Error("the running job lost its lock")
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM job_approvals`); n != 0 {
		t.Errorf("approvals = %d, want none on non-terminal jobs", n)
	}
	for _, table := range []string{"sessions", "api_tokens"} {
		if n := scalar[int](t, db, `SELECT count(*) FROM `+table+` WHERE revoked_at IS NULL`); n != 0 {
			t.Errorf("%s still active: %d", table, n)
		}
	}
	for _, table := range []string{"bootstrap_codes", "join_tokens"} {
		if n := scalar[int](t, db, `SELECT count(*) FROM `+table+` WHERE invalidated_at IS NULL`); n != 0 {
			t.Errorf("%s still usable: %d", table, n)
		}
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM identities`); n != 1 {
		t.Errorf("identities = %d, want them kept", n)
	}
	if held, err := database.GetRestoreHold(context.Background(), db.Reader()); err != nil || !held {
		t.Errorf("restore hold = %v, %v; want true", held, err)
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM events WHERE action = 'backup.restore'`); n != 1 {
		t.Errorf("restore events = %d, want 1", n)
	}
}

type allowAll struct{}

func (allowAll) Revalidate(context.Context, database.Querier, jobs.Job) error { return nil }
func (allowAll) PlanLocks(context.Context, database.Querier, jobs.Job) ([]domain.LockSpec, error) {
	return nil, nil
}

func TestRestoredDispatchedJobReachesJobResolve(t *testing.T) {
	_, tg := newWorld(t)
	if err := backup.Restore(context.Background(), tg.options()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	db := openDB(t, tg.dbPath, tg.clock)
	store, err := jobs.NewStore(jobs.Config{DB: db, Clock: tg.clock, IDs: tg.ids, Revalidator: allowAll{}, LockPlanner: allowAll{}})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func() (jobs.Job, error) {
		var job jobs.Job
		err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
			var err error
			job, err = store.Resolve(ctx, tx, jobs.ResolveRequest{
				JobID: "job-running", Outcome: jobs.ResolveFailed, Note: "checked by hand", By: domain.Actor{Type: domain.ActorSystem},
			})
			return err
		})
		return job, err
	}

	if _, err := resolve(); err == nil {
		t.Fatal("a dispatched job is quiescent before its deadline and grace passed")
	}
	tg.clock.Advance(10 * time.Minute)
	job, err := resolve()
	if err != nil {
		t.Fatalf("job.resolve after the deadline: %v", err)
	}
	if job.State != domain.JobFailed {
		t.Errorf("resolved state = %s", job.State)
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM resource_locks WHERE job_id = 'job-running'`); n != 0 {
		t.Error("resolve left the job's lock")
	}
}

func TestPendingKeyIsPromotedAndDaemonLoadsIt(t *testing.T) {
	src, tg := newWorld(t)
	if err := os.RemoveAll(tg.keysDir); err != nil {
		t.Fatal(err)
	}
	tg.copyKeys(src, ".key.pending")

	if err := backup.Restore(context.Background(), tg.options()); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if left := glob(t, filepath.Join(tg.keysDir, "*.pending")); len(left) != 0 {
		t.Errorf("pending keys remain: %v", left)
	}
	db := openDB(t, tg.dbPath, tg.clock)
	if _, err := secrets.OpenFileKeys(context.Background(), tg.keysDir, app.NewSecretsRepo(db, tg.clock), tg.ids); err != nil {
		t.Fatalf("the daemon cannot load the promoted key: %v", err)
	}
}

func TestRestoreIntoAnEmptyDataDirectory(t *testing.T) {
	src, base := newWorld(t)
	tg := &target{site: newSite(t, "fresh", src.clock, src.ids), archive: base.archive}
	if err := tg.db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{tg.dbPath, tg.dbPath + "-wal", tg.dbPath + "-shm"} {
		_ = os.Remove(p)
	}
	tg.copyKeys(src, ".key")

	if err := backup.Restore(context.Background(), tg.options()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := marker(t, tg.dbPath); got != "from-archive" {
		t.Errorf("marker = %q", got)
	}
	if pre := glob(t, filepath.Join(tg.dataDir, "pre-restore-*")); len(pre) != 0 {
		t.Errorf("a fresh restore created %v", pre)
	}
}

func TestRestoreRejectionsLeaveLiveFilesByteIdentical(t *testing.T) {
	src, tg := newWorld(t)
	good := goodEntries(t, tg.archive)
	manifest := manifestOf(t, good)
	kekID := manifest.KEKIDs[0].String()
	index := func(name string) int {
		for i, e := range good {
			if e.name == name {
				return i
			}
		}
		t.Fatalf("no member %s", name)
		return -1
	}
	replace := func(name string, e rawEntry) []rawEntry {
		out := append([]rawEntry{}, good...)
		out[index(name)] = e
		return out
	}
	drop := func(name string) []rawEntry {
		i := index(name)
		return append(append([]rawEntry{}, good[:i]...), good[i+1:]...)
	}
	junkDB := []byte("this is not a database")
	badSum := func(entries []rawEntry) []rawEntry {
		return withManifest(t, entries, func(m *backup.Manifest) { m.SHA256[backup.DatabaseName] = digest(junkDB) })
	}
	zeros := make([]byte, 4<<20)

	cases := []struct {
		name    string
		entries []rawEntry
		env     backup.TestEnv
		trailer int
		prepare func(t *testing.T)
		wantErr string
	}{
		{name: "path traversal", entries: append(append([]rawEntry{}, good...), regular("../evil", []byte("x")))},
		{name: "absolute path", entries: append(append([]rawEntry{}, good...), regular("/tmp/evil", []byte("x")))},
		{name: "traversal inside a listed name", entries: append(withManifest(t, good, func(m *backup.Manifest) { m.SHA256["config/../evil"] = digest([]byte("x")) }), regular("config/../evil", []byte("x")))},
		{name: "duplicate member", entries: append(append([]rawEntry{}, good...), good[index(backup.KnownHostsName)])},
		{name: "symlink member", entries: replace(backup.KnownHostsName, rawEntry{name: backup.KnownHostsName, typeflag: tar.TypeSymlink, linkname: "/etc/passwd"})},
		{name: "hardlink member", entries: replace(backup.KnownHostsName, rawEntry{name: backup.KnownHostsName, typeflag: tar.TypeLink, linkname: backup.DatabaseName})},
		{name: "device member", entries: replace(backup.KnownHostsName, rawEntry{name: backup.KnownHostsName, typeflag: tar.TypeChar})},
		{name: "directory member", entries: replace(backup.KnownHostsName, rawEntry{name: backup.KnownHostsName, typeflag: tar.TypeDir})},
		{name: "member not in the manifest", entries: append(append([]rawEntry{}, good...), regular("extra.txt", []byte("x")))},
		{name: "listed member missing", entries: drop(backup.KnownHostsName)},
		{name: "checksum mismatch", entries: replace(backup.ConfigName, regular(backup.ConfigName, []byte("tampered: yes\n")))},
		{name: "unknown format version", entries: withManifest(t, good, func(m *backup.Manifest) { m.FormatVersion = 99 })},
		{name: "schema newer than the binary", entries: withManifest(t, good, func(m *backup.Manifest) { m.SchemaVersion = 999 })},
		{name: "schema invalid", entries: withManifest(t, good, func(m *backup.Manifest) { m.SchemaVersion = 0 })},
		{name: "schema disagrees with the database", entries: withManifest(t, good, func(m *backup.Manifest) { m.SchemaVersion = 1 })},
		{name: "manifest not json", entries: append([]rawEntry{regular(backup.ManifestName, []byte("{nope"))}, good[1:]...)},
		{name: "manifest not first", entries: append(append([]rawEntry{}, good[1:]...), good[0])},
		{name: "member over its cap", entries: good, env: backup.TestEnv{MemberLimit: 4}},
		{name: "database over its cap", entries: good, env: backup.TestEnv{DatabaseLimit: 1024}},
		{name: "total over its cap", entries: good, env: backup.TestEnv{TotalLimit: 50_000}},
		{name: "zero-filled trailer after the archive", entries: good, env: backup.TestEnv{TotalLimit: 4 << 20}, trailer: 32 << 20},
		{name: "zero-filled decompression bomb", entries: badSum(replace(backup.DatabaseName, regular(backup.DatabaseName, zeros))), env: backup.TestEnv{DatabaseLimit: 1 << 20}},
		{name: "database is not a database", entries: badSum(replace(backup.DatabaseName, regular(backup.DatabaseName, junkDB)))},
		{
			name: "KEK file missing", entries: good, wantErr: kekID,
			prepare: func(t *testing.T) { mustRemove(t, filepath.Join(tg.keysDir, kekID+".key")) },
		},
		{
			name: "KEK does not match the staged check record", entries: good, wantErr: kekID,
			prepare: func(t *testing.T) { mustWrite(t, filepath.Join(tg.keysDir, kekID+".key"), bytes.Repeat([]byte{7}, 32)) },
		},
		{
			name: "pending KEK does not match", entries: good, wantErr: kekID,
			prepare: func(t *testing.T) {
				mustRemove(t, filepath.Join(tg.keysDir, kekID+".key"))
				mustWrite(t, filepath.Join(tg.keysDir, kekID+".key.pending"), bytes.Repeat([]byte{7}, 32))
			},
		},
		{
			name: "KEK file readable by others", entries: good, wantErr: kekID,
			prepare: func(t *testing.T) {
				if err := os.Chmod(filepath.Join(tg.keysDir, kekID+".key"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "an earlier restore is unfinished", entries: good,
			prepare: func(t *testing.T) { mustWrite(t, filepath.Join(tg.dataDir, backup.JournalName), []byte("{}")) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() {
				mustRemoveAll(t, tg.keysDir)
				tg.copyKeys(src, ".key")
				_ = os.Remove(filepath.Join(tg.dataDir, backup.JournalName))
			})
			if tc.prepare != nil {
				tc.prepare(t)
			}
			opts := tg.options()
			opts.Archive = filepath.Join(t.TempDir(), "hostile.tar.zst")
			writeRawArchiveWithTrailer(t, opts.Archive, tc.entries, tc.trailer)
			before := tg.tree()

			err := backup.RestoreWith(context.Background(), opts, tc.env)

			if err == nil {
				t.Fatal("Restore accepted the archive")
			}
			t.Logf("rejected: %v", err)
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to name %s", err, tc.wantErr)
			}
			if after := tg.tree(); !sameTree(before, after) {
				t.Errorf("live files changed.\nbefore: %v\nafter:  %v", keysOf(before), keysOf(after))
			}
			if outside := glob(t, filepath.Join(tg.root, "..", "evil")); len(outside) != 0 {
				t.Errorf("a member escaped the staging directory: %v", outside)
			}
		})
	}
}

func mustRemoveAll(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreReportsUnusableInput(t *testing.T) {
	_, tg := newWorld(t)
	notArchive := filepath.Join(t.TempDir(), "junk.tar.zst")
	mustWrite(t, notArchive, bytes.Repeat([]byte("junk"), 100))

	cases := map[string]struct {
		archive string
		invalid bool
	}{
		"missing archive":      {archive: filepath.Join(t.TempDir(), "absent.tar.zst"), invalid: true},
		"directory as archive": {archive: t.TempDir(), invalid: true},
		"not a zstd stream":    {archive: notArchive},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			opts := tg.options()
			opts.Archive = tc.archive
			before := tg.tree()
			err := backup.Restore(context.Background(), opts)
			if err == nil {
				t.Fatal("Restore succeeded")
			}
			if invalid := smerr.CodeOf(err) == smerr.CodeInvalidArgument; invalid != tc.invalid {
				t.Errorf("invalid-argument = %v for %v, want %v", invalid, err, tc.invalid)
			}
			if !sameTree(before, tg.tree()) {
				t.Error("live files changed")
			}
		})
	}
}
