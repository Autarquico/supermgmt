//go:build migrationfixtures

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/cli"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// Databases and archives written by the real binary of each milestone (test/fixtures/migrations)
// must open, migrate and restore with the binary under test.

// migrationSite is one fixture installed the way a control plane lays its files out.
type migrationSite struct {
	root       string // short, so the daemon socket path stays under the sun_path limit
	dataDir    string
	keysDir    string
	dbPath     string
	configFile string
	socket     string
	fixture    string
	provenance provenanceSection
}

func installMigrationFixture(t *testing.T, name string) migrationSite {
	t.Helper()
	root, err := os.MkdirTemp("", "smf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	s := migrationSite{
		root: root, dataDir: filepath.Join(root, "data"), keysDir: filepath.Join(root, "keys"),
		socket: filepath.Join(root, "d.sock"), fixture: filepath.Join(migrationFixtureRoot, name),
		provenance: readProvenance(t)[name],
	}
	s.dbPath = filepath.Join(s.dataDir, "supermgmt.db")
	s.configFile = filepath.Join(root, "config.yaml")
	for _, dir := range []string{s.dataDir, s.keysDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	copyFixtureFile(t, filepath.Join(s.fixture, "sm.db"), s.dbPath)
	copyFixtureFile(t, filepath.Join(s.fixture, "master.key"), filepath.Join(s.keysDir, s.provenance.keyID+".key"))
	s.writeConfig(t)
	return s
}

func copyFixtureFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s migrationSite) writeConfig(t *testing.T) {
	t.Helper()
	yaml := "version: 1\n" +
		"instance:\n  name: migration-fixture\n  mode: local\n  data_dir: " + s.dataDir + "\n" +
		"daemon:\n  socket: " + s.socket + "\n  idle_exit: 1h\n" +
		"storage:\n  sqlite:\n    path: " + s.dbPath + "\n" +
		"security:\n  keys_dir: " + s.keysDir + "\n" +
		"backup:\n  directory: " + filepath.Join(s.root, "backups") + "\n" +
		"environments:\n  - name: staging\n    risk_level: staging\n  - name: production\n    risk_level: production\n"
	if err := os.WriteFile(s.configFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s migrationSite) loadConfig(t *testing.T) *config.Config {
	t.Helper()
	res, err := config.Load(s.configFile, []string{"HOME=" + s.root})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return res.Config
}

func openMigrationDatabase(t *testing.T, path string) *database.DB {
	t.Helper()
	db, err := database.Open(t.Context(), path, database.Options{})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func migrationScalar[T any](t *testing.T, db database.Querier, query string, args ...any) T {
	t.Helper()
	var v T
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

// rowCounts counts the rows of every table the database has, keyed by table name.
func rowCounts(t *testing.T, db database.Querier) map[string]int {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	counts := map[string]int{}
	for _, table := range tables {
		counts[table] = migrationScalar[int](t, db, `SELECT COUNT(*) FROM "`+table+`"`)
	}
	return counts
}

func jobsByState(t *testing.T, db database.Querier) map[string]int {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT state, COUNT(*) FROM jobs GROUP BY state`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	states := map[string]int{}
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			t.Fatal(err)
		}
		states[state] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return states
}

func assertHealthyDatabase(t *testing.T, db database.Querier) {
	t.Helper()
	if verdict := migrationScalar[string](t, db, `PRAGMA integrity_check`); verdict != "ok" {
		t.Errorf("integrity_check = %q, want ok", verdict)
	}
	rows, err := db.QueryContext(t.Context(), `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var table, rowid, parent, fk any
		if err := rows.Scan(&table, &rowid, &parent, &fk); err != nil {
			t.Fatal(err)
		}
		t.Errorf("foreign key violation: table %v row %v references %v", table, rowid, parent)
	}
}

func TestMigrationFixtures_MigrateToHeadKeepingEveryRow(t *testing.T) {
	latest, err := database.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range migrationFixtureNames {
		t.Run(name, func(t *testing.T) {
			site := installMigrationFixture(t, name)
			db := openMigrationDatabase(t, site.dbPath)
			before, statesBefore := rowCounts(t, db.Reader()), jobsByState(t, db.Reader())
			if v := migrationScalar[int](t, db.Reader(), `SELECT MAX(version) FROM schema_migrations`); v != site.provenance.schema {
				t.Fatalf("fixture schema = %d, PROVENANCE says %d", v, site.provenance.schema)
			}

			if err := db.Migrate(t.Context()); err != nil {
				t.Fatalf("Migrate: %v", err)
			}

			if v := migrationScalar[int](t, db.Reader(), `SELECT MAX(version) FROM schema_migrations`); v != latest {
				t.Errorf("schema after Migrate = %d, want %d", v, latest)
			}
			assertHealthyDatabase(t, db.Reader())
			after := rowCounts(t, db.Reader())
			for table, n := range before {
				if got, ok := after[table]; !ok || got < n {
					t.Errorf("table %s: %d rows before, %d after (present: %v)", table, n, got, ok)
				}
			}
			states := jobsByState(t, db.Reader())
			for state, n := range statesBefore {
				if states[state] != n {
					t.Errorf("jobs in state %s: %d before, %d after", state, n, states[state])
				}
			}
		})
	}
}

func TestMigrationFixtures_JobsReachEveryTerminalStateAndOneStaysAwaitingApproval(t *testing.T) {
	for _, name := range migrationFixtureNames {
		t.Run(name, func(t *testing.T) {
			site := installMigrationFixture(t, name)
			db := openMigrationDatabase(t, site.dbPath)

			states := jobsByState(t, db.Reader())

			for _, want := range []string{"succeeded", "failed", "cancelled"} {
				if states[want] == 0 {
					t.Errorf("no job is %s in the %s fixture: %v", want, name, states)
				}
			}
			if name != "m1" && states["awaiting_approval"] != 1 {
				t.Errorf("awaiting_approval jobs = %d, want the parked secret import: %v", states["awaiting_approval"], states)
			}
		})
	}
}

func TestMigrationFixtures_SecretsDecryptWithTheMasterKeyOfTheirMilestone(t *testing.T) {
	for _, name := range migrationFixtureNames {
		t.Run(name, func(t *testing.T) {
			site := installMigrationFixture(t, name)
			db := openMigrationDatabase(t, site.dbPath)
			if err := db.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			store := openFixtureStore(t, site, db)

			names := currentSecretNames(t, db)

			if len(names) == 0 {
				t.Fatal("the fixture has no current secret")
			}
			for _, secret := range names {
				got, err := store.Get(t.Context(), secrets.Ref{Name: secret})
				if err != nil || got.Reveal() == "" {
					t.Errorf("decrypt %s: %v", secret, err)
				}
			}
			if name == "m1" {
				return
			}
			for _, secret := range []string{"app/credential", "app/api-token"} {
				got, err := store.Get(t.Context(), secrets.Ref{Name: secret})
				if err != nil || strings.TrimSpace(got.Reveal()) != "fixture value of "+secret {
					t.Errorf("secret %s = %q, %v; want the value the world imported", secret, got.Reveal(), err)
				}
			}
		})
	}
}

func openFixtureStore(t *testing.T, site migrationSite, db *database.DB) *secrets.Store {
	t.Helper()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	ids := domaintest.NewSequentialIDs()
	repo := app.NewSecretsKeyRepo(db, clock)
	keys, err := secrets.OpenFileKeys(t.Context(), site.keysDir, repo, ids)
	if err != nil {
		t.Fatalf("open the fixture master key: %v", err)
	}
	return secrets.NewStore(keys, repo, ids, clock)
}

func currentSecretNames(t *testing.T, db *database.DB) []string {
	t.Helper()
	rows, err := db.Reader().QueryContext(t.Context(), `SELECT DISTINCT name FROM secrets WHERE version > 0 ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

// runMigrationDaemon starts the daemon of this build on the site, calls fn while it serves, and
// stops it.
func runMigrationDaemon(t *testing.T, site migrationSite, smVersion string, fn func(*client.Client)) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	listening, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			Config: site.loadConfig(t), ConfigFile: site.configFile, Socket: site.socket, SMVersion: smVersion,
			IdleCheck: 10 * time.Millisecond, OnListening: func(string) { close(listening) },
		})
	}()
	select {
	case <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("the daemon did not start on the fixture: %v", err)
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("the daemon did not start within 30s")
	}
	fn(client.New(client.Options{Socket: site.socket}))
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("daemon shutdown: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the daemon did not stop within 30s")
	}
}

func TestMigrationFixtures_TheDaemonStartsOnThemAndRecordsTheVersionTransition(t *testing.T) {
	latest, _ := database.LatestSchemaVersion()
	for _, name := range migrationFixtureNames {
		t.Run(name, func(t *testing.T) {
			site := installMigrationFixture(t, name)

			runMigrationDaemon(t, site, "v9.0.0", func(c *client.Client) {
				if me, err := c.Me(t.Context()); err != nil || len(me.Roles) != 1 || me.Roles[0] != "admin" {
					t.Errorf("Me = %+v, %v; want the local user as admin", me, err)
				}
			})
			runMigrationDaemon(t, site, "v9.1.0", func(*client.Client) {})

			db := openMigrationDatabase(t, site.dbPath)
			assertHealthyDatabase(t, db.Reader())
			if v := migrationScalar[int](t, db.Reader(), `SELECT MAX(version) FROM schema_migrations`); v != latest {
				t.Errorf("schema after the daemon started = %d, want %d", v, latest)
			}
			if n := migrationScalar[int](t, db.Reader(), `SELECT COUNT(*) FROM events WHERE action = 'instance.version_changed'`); n != 1 {
				t.Errorf("instance.version_changed events = %d, want 1 (the first start records only the setting)", n)
			}
			data := migrationScalar[string](t, db.Reader(), `SELECT data_json FROM events WHERE action = 'instance.version_changed'`)
			var transition struct{ From, To, Direction string }
			if err := json.Unmarshal([]byte(data), &transition); err != nil || transition.Direction != "upgrade" || transition.To != "v9.1.0" {
				t.Errorf("transition = %s (%v), want an upgrade to v9.1.0", data, err)
			}
		})
	}
}

// doctorReportOf runs `sm doctor --offline --json` against the site.
func doctorReportOf(t *testing.T, site migrationSite) (report struct {
	FormatVersion         int  `json:"format_version"`
	OK                    bool `json:"ok"`
	DatabaseSchemaVersion *int `json:"database_schema_version"`
	BinarySchemaVersion   int  `json:"binary_schema_version"`
	Checks                []struct{ Name, Status, Detail string }
}, exit int,
) {
	t.Helper()
	t.Setenv("HOME", site.root)
	t.Setenv("XDG_RUNTIME_DIR", site.root)
	var stdout, stderr bytes.Buffer
	exit = cli.Execute([]string{"--config", site.configFile, "--json", "doctor", "--offline"}, &stdout, &stderr)
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return report, exit
}

func TestMigrationFixtures_DoctorOfflineReportsTheirSchemaBeforeAndAfterTheMigration(t *testing.T) {
	latest, _ := database.LatestSchemaVersion()
	for _, name := range migrationFixtureNames {
		t.Run(name, func(t *testing.T) {
			site := installMigrationFixture(t, name)

			before, exit := doctorReportOf(t, site)

			if exit != 0 || before.FormatVersion != 1 || before.BinarySchemaVersion != latest {
				t.Errorf("doctor before: exit %d, %+v; want exit 0, format 1, binary schema %d", exit, before, latest)
			}
			if before.DatabaseSchemaVersion == nil || *before.DatabaseSchemaVersion != site.provenance.schema {
				t.Errorf("database_schema_version = %v, want %d", before.DatabaseSchemaVersion, site.provenance.schema)
			}
			for _, c := range before.Checks {
				if c.Status == "fail" {
					t.Errorf("check %s fails on a fixture: %s", c.Name, c.Detail)
				}
			}

			db := openMigrationDatabase(t, site.dbPath)
			if err := db.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			after, exit := doctorReportOf(t, site)
			if exit != 0 || after.DatabaseSchemaVersion == nil || *after.DatabaseSchemaVersion != latest {
				t.Errorf("doctor after: exit %d, database schema %v; want exit 0 and %d", exit, after.DatabaseSchemaVersion, latest)
			}
		})
	}
}

// ---- archives --------------------------------------------------------------------------------

var migrationArchiveNames = []string{"m2", "m3", "m4", "m5"}

// fixtureArchive is the absolute path of the one archive a fixture directory holds.
func fixtureArchive(t *testing.T, site migrationSite) string {
	t.Helper()
	archives, err := filepath.Glob(filepath.Join(site.fixture, "*"+backup.Extension))
	if err != nil || len(archives) != 1 {
		t.Fatalf("archives of %s = %v, %v; want exactly one", site.fixture, archives, err)
	}
	abs, err := filepath.Abs(archives[0])
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func restoreMigrationArchive(t *testing.T, name string) migrationSite {
	t.Helper()
	site := installMigrationFixture(t, name)
	if err := os.Remove(site.dbPath); err != nil { // the target of a restore has no database yet
		t.Fatal(err)
	}
	archive := fixtureArchive(t, site)
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	err := backup.Restore(t.Context(), backup.RestoreOptions{
		Archive: archive, DataDir: site.dataDir, KeysDir: site.keysDir, DBPath: site.dbPath,
		Clock: clock, IDs: domaintest.NewSequentialIDs(),
	})
	if err != nil {
		t.Fatalf("Restore %s: %v", archive, err)
	}
	return site
}

func TestMigrationFixtures_EveryArchiveRestoresWithTheCurrentBinaryAtTheLatestSchema(t *testing.T) {
	latest, _ := database.LatestSchemaVersion()
	for _, name := range migrationArchiveNames {
		t.Run(name, func(t *testing.T) {
			site := restoreMigrationArchive(t, name)
			db := openMigrationDatabase(t, site.dbPath)

			if v := migrationScalar[int](t, db.Reader(), `SELECT MAX(version) FROM schema_migrations`); v != latest {
				t.Errorf("restored schema = %d, want %d: the restore migrates the staged database", v, latest)
			}
			if err := db.Migrate(t.Context()); err != nil {
				t.Fatalf("Migrate the restored database again: %v", err)
			}

			assertHealthyDatabase(t, db.Reader())
			if v := migrationScalar[int](t, db.Reader(), `SELECT MAX(version) FROM schema_migrations`); v != latest {
				t.Errorf("schema after Migrate = %d, want %d", v, latest)
			}
			if n := migrationScalar[int](t, db.Reader(), `SELECT COUNT(*) FROM events WHERE action = 'backup.restore'`); n != 1 {
				t.Errorf("restore events = %d, want 1", n)
			}
			states := jobsByState(t, db.Reader())
			for _, live := range []string{"awaiting_approval", "queued", "running"} {
				if states[live] != 0 {
					t.Errorf("%d jobs are still %s after the restore neutralized the database: %v", states[live], live, states)
				}
			}
			store := openFixtureStore(t, site, db)
			if got, err := store.Get(t.Context(), secrets.Ref{Name: "app/credential"}); err != nil || strings.TrimSpace(got.Reveal()) != "fixture value of app/credential" {
				t.Errorf("secret app/credential after the restore = %q, %v", got.Reveal(), err)
			}
		})
	}
}

func TestMigrationFixtures_RestoringAnArchiveRevokesEveryCredential(t *testing.T) {
	for _, name := range migrationArchiveNames {
		t.Run(name, func(t *testing.T) {
			site := restoreMigrationArchive(t, name)
			db := openMigrationDatabase(t, site.dbPath)

			if n := migrationScalar[int](t, db.Reader(), `SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL`); n != 0 {
				t.Errorf("%d API tokens stay valid after the restore", n)
			}
			if name != "m5" {
				return
			}
			if n := migrationScalar[int](t, db.Reader(), `SELECT COUNT(*) FROM mcp_clients`); n == 0 {
				t.Fatal("the m5 archive has no MCP client; the fixture is not the m5 world")
			}
			if n := migrationScalar[int](t, db.Reader(), `SELECT COUNT(*) FROM mcp_clients WHERE revoked_at IS NULL AND state <> 'deleted'`); n != 0 {
				t.Errorf("%d MCP client tokens stay valid after the restore (§29.2)", n)
			}
		})
	}
}

func TestMigrationFixtures_AnArchiveWithoutItsMasterKeyIsRefused(t *testing.T) {
	site := installMigrationFixture(t, "m2")
	if err := os.Remove(filepath.Join(site.keysDir, site.provenance.keyID+".key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(site.dbPath); err != nil {
		t.Fatal(err)
	}

	err := backup.Restore(t.Context(), backup.RestoreOptions{
		Archive: fixtureArchive(t, site), DataDir: site.dataDir, KeysDir: site.keysDir, DBPath: site.dbPath,
		Clock: domaintest.NewFakeClock(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)), IDs: domaintest.NewSequentialIDs(),
	})

	if err == nil || !strings.Contains(err.Error(), site.provenance.keyID) {
		t.Errorf("Restore without the master key: %v; want an error naming %s", err, site.provenance.keyID)
	}
	if _, statErr := os.Stat(site.dbPath); statErr == nil {
		t.Error("a database was installed although the restore failed")
	}
}
