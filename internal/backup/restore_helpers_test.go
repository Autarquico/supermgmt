package backup_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const liveMarker = "live"

// site is one control plane: data directory, keys directory and database.
type site struct {
	t       *testing.T
	root    string
	dataDir string
	keysDir string
	dbPath  string
	db      *database.DB
	keys    *secrets.FileKeys
	clock   *domaintest.FakeClock
	ids     *domaintest.SequentialIDs
}

func newSite(t *testing.T, name string, clock *domaintest.FakeClock, ids *domaintest.SequentialIDs) *site {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	s := &site{t: t, root: root, dataDir: filepath.Join(root, "data"), keysDir: filepath.Join(root, "keys"), clock: clock, ids: ids}
	s.dbPath = filepath.Join(s.dataDir, "supermgmt.db")
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.db = openDB(t, s.dbPath, clock)
	return s
}

func openDB(t *testing.T, path string, clock domain.Clock) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), path, database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

// withSecrets creates the KEK and one secret, so the database references a key.
func (s *site) withSecrets() *site {
	s.t.Helper()
	ctx := context.Background()
	repo := app.NewSecretsRepo(s.db, s.clock)
	keys, err := secrets.OpenFileKeys(ctx, s.keysDir, repo, s.ids)
	if err != nil {
		s.t.Fatal(err)
	}
	s.keys = keys
	if _, err := secrets.NewStore(keys, repo, s.ids, s.clock).Put(ctx, "token", audit.Secret("hunter2"), nil); err != nil {
		s.t.Fatal(err)
	}
	return s
}

func (s *site) exec(query string, args ...any) {
	s.t.Helper()
	err := s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	})
	if err != nil {
		s.t.Fatalf("%s: %v", query, err)
	}
}

func (s *site) setMarker(value string) {
	s.t.Helper()
	err := s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.PutSetting(ctx, tx, database.Setting{Key: "marker", Value: json.RawMessage(`"` + value + `"`), UpdatedAt: s.clock.Now()})
	})
	if err != nil {
		s.t.Fatal(err)
	}
}

func marker(t *testing.T, dbPath string) string {
	t.Helper()
	db := openDB(t, dbPath, domain.SystemClock{})
	defer db.Close()
	setting, err := database.GetSetting(context.Background(), db.Reader(), "marker")
	if err != nil {
		t.Fatalf("read marker of %s: %v", dbPath, err)
	}
	var value string
	if err := json.Unmarshal(setting.Value, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

// seedWork fills the database with the states phase C must neutralize.
func (s *site) seedWork() {
	s.t.Helper()
	now := s.clock.Now().UnixMilli()
	s.exec(`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', ?)`, now)
	job := func(id, state, retry string, generation int64) {
		s.exec(`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class,
			lease_owner, lease_generation, lease_until, scheduled_at, created_at)
			VALUES (?, 'service.restart', 'node', 'n1', 'id-1', 'session', ?, 'operational', ?, 'worker-1', ?, ?, ?, ?)`,
			id, state, retry, generation, now+3_600_000, now, now)
	}
	job("job-running", "running", "resumable", 3)
	job("job-interrupted", "interrupted", "resumable", 5)
	job("job-queued", "queued", "idempotent", 0)
	job("job-waiting", "awaiting_approval", "idempotent", 0)
	job("job-nonretryable", "queued", "non_retryable", 2)
	job("job-done", "succeeded", "idempotent", 1)
	intent := func(id, jobID string, generation int64, dispatched bool) {
		var dispatchedAt any
		if dispatched {
			dispatchedAt = now
		}
		s.exec(`INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, dispatched_at)
			VALUES (?, ?, 'restart', ?, 'recorded', 'systemctl restart', 'node', 'n1', ?, ?, ?)`,
			id, jobID, generation, "marker-"+id, now+60_000, dispatchedAt)
	}
	intent("intent-running", "job-running", 7, true)
	intent("intent-nonretryable", "job-nonretryable", 4, true)
	for _, id := range []string{"job-running", "job-queued", "job-waiting"} {
		s.exec(`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES ('node', 'n-'||?, ?, 'exclusive', ?)`, id, id, now)
		s.exec(`INSERT INTO job_approvals (id, job_id, plan_hash, approver_id, decision, expires_at, created_at) VALUES ('appr-'||?, ?, 'h', 'id-1', 'approve', ?, ?)`, id, id, now+1000, now)
	}
	s.exec(`INSERT INTO sessions (id, identity_id, token_hash, origin, created_at, expires_at) VALUES ('sess-1', 'id-1', 'hash-s', 'oidc', ?, ?)`, now, now+3_600_000)
	s.exec(`INSERT INTO api_tokens (id, identity_id, name, token_hash, created_at, expires_at) VALUES ('tok-1', 'id-1', 'ci', 'hash-t', ?, ?)`, now, now+3_600_000)
	s.exec(`INSERT INTO bootstrap_codes (id, code_hash, created_at, expires_at) VALUES ('boot-1', 'hash-b', ?, ?)`, now, now+3_600_000)
	s.exec(`INSERT INTO join_tokens (id, token_hash, created_by, created_at, expires_at) VALUES ('join-1', 'hash-j', 'id-1', ?, ?)`, now, now+3_600_000)
	s.setMarker("from-archive")
}

func (s *site) activateConfig() {
	s.t.Helper()
	err := s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.PutConfigSnapshot(ctx, tx, []byte("listen: local\n"), []byte("policy: v1\n"), s.clock.Now())
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
}

// archive writes a real archive of this site and returns its path.
func (s *site) archive() string {
	s.t.Helper()
	s.activateConfig()
	known := filepath.Join(s.root, "known_hosts_source")
	if err := os.WriteFile(known, []byte("node ssh-ed25519 AAAA\n"), 0o600); err != nil {
		s.t.Fatal(err)
	}
	created, err := backup.Create(context.Background(), backup.CreateOptions{
		Dir: filepath.Join(s.root, "backups"), Instance: "lab", KnownHostsPath: known, SMVersion: "9.9.9",
		Clock: s.clock, Source: s.db, Keys: s.keys,
	})
	if err != nil {
		s.t.Fatalf("Create: %v", err)
	}
	return created.Path
}

// target is the machine a backup is restored onto.
type target struct {
	*site
	archive string
}

// newTarget builds a machine with a live database (marker "live"), stray WAL
// and lock files, an old known_hosts, and the KEKs of src as .key files.
func newTarget(t *testing.T, src *site, archive string) *target {
	t.Helper()
	tg := &target{site: newSite(t, "target", src.clock, src.ids), archive: archive}
	tg.setMarker(liveMarker)
	if err := tg.db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ name, content string }{{"supermgmt.db-wal", "stray wal"}, {"known_hosts", "old host\n"}} {
		if err := os.WriteFile(filepath.Join(tg.dataDir, f.name), []byte(f.content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(tg.dbPath+".lock", []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg.copyKeys(src, ".key")
	return tg
}

func (tg *target) copyKeys(src *site, suffix string) {
	tg.t.Helper()
	if err := os.MkdirAll(tg.keysDir, 0o700); err != nil {
		tg.t.Fatal(err)
	}
	entries, err := os.ReadDir(src.keysDir)
	if err != nil {
		tg.t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src.keysDir, e.Name()))
		if err != nil {
			tg.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tg.keysDir, e.Name()+suffix[len(".key"):]), data, 0o600); err != nil {
			tg.t.Fatal(err)
		}
	}
}

func (tg *target) options() backup.RestoreOptions {
	return backup.RestoreOptions{
		Archive: tg.archive, DataDir: tg.dataDir, KeysDir: tg.keysDir, DBPath: tg.dbPath, Clock: tg.clock, IDs: tg.ids,
	}
}

func (tg *target) tree() map[string]string { return treeOf(tg.t, tg.dataDir, tg.keysDir) }

// treeOf lists every entry below dirs with a digest of its content and mode.
func treeOf(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if d.IsDir() {
				out[path] = "dir"
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			out[path] = info.Mode().String() + " " + hex.EncodeToString(sum[:])
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	return out
}

func sameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- hand-made archives -----------------------------------------------------

// rawEntry is one tar entry written exactly as given.
type rawEntry struct {
	name     string
	typeflag byte
	linkname string
	data     []byte
	size     int64 // header size override when non-zero
}

func regular(name string, data []byte) rawEntry {
	return rawEntry{name: name, typeflag: tar.TypeReg, data: data}
}

// writeRawArchiveWithTrailer appends trailer zero bytes after the tar footer,
// still inside the zstd stream.
func writeRawArchiveWithTrailer(t *testing.T, path string, entries []rawEntry, trailer int) {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		size := int64(len(e.data))
		if e.size != 0 {
			size = e.size
		}
		if e.typeflag != tar.TypeReg {
			size = 0
		}
		h := &tar.Header{Typeflag: e.typeflag, Name: e.name, Linkname: e.linkname, Mode: 0o600, Size: size, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(make([]byte, trailer)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// goodEntries returns the members of a real archive, manifest first.
func goodEntries(t *testing.T, archive string) []rawEntry {
	t.Helper()
	var out []rawEntry
	for _, m := range readArchive(t, archive) {
		out = append(out, regular(m.name, m.data))
	}
	return out
}

func manifestOf(t *testing.T, entries []rawEntry) backup.Manifest {
	t.Helper()
	m, err := backup.ParseManifest(entries[0].data)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// withManifest re-encodes the manifest after mutate, keeping it first.
func withManifest(t *testing.T, entries []rawEntry, mutate func(*backup.Manifest)) []rawEntry {
	t.Helper()
	m := manifestOf(t, entries)
	mutate(&m)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]rawEntry{regular(backup.ManifestName, data)}, entries[1:]...)
	return out
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
