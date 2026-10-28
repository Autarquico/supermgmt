//go:build e2e

package e2e_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Spec docs/specs/m6-hardening.md (upgrade chain), ADR-0035 and PLAN row T24.
//
// The oldest supported release (the M2 merge commit, schema 3) runs the data of its migration
// fixture (test/fixtures/migrations/m2, made by the real M2 binary) and is upgraded to the tree under
// test in one jump, over every schema step in between (4, 5 and 6).

const (
	chainFixtureDir  = "test/fixtures/migrations/m2"
	chainDatabase    = harness.ServerData + "/supermgmt.db"
	chainKeysDir     = harness.ServerData + "/secrets/keys"
	chainOldestSchem = 3
)

// TestM6_UpgradeChainOldestToLatestInOneJump
//
// Given the M2 release serving the data of its fixture. When it is upgraded to the latest release.
// Then: the doctor reports the latest schema (6), every row the old release serves survives, and the
// doctor finds the service sound under the master key of the fixture.
func TestM6_UpgradeChainOldestToLatestInOneJump(t *testing.T) {
	h := newPreviousServer(t)
	h.stageNext()
	fixture := chainFixtureDatabase(t)
	h.loadFixtureWorld(fixture)

	if got := h.schema(prevBinary); got != chainOldestSchem {
		t.Fatalf("%s serves schema %d, want %d", prevVersion, got, chainOldestSchem)
	}
	// The baseline is what the old release serves, not the fixture file: on start it retires rows
	// by wall-clock age (idempotency records, observations, expired secrets), so a fixture older
	// than those TTLs loses them before any upgrade runs. The upgrade must keep everything else.
	seeded := h.databaseRows()
	t.Logf("%s retired %d of the fixture's rows by age before the upgrade", prevVersion, chainCount(chainRows(t, fixture))-chainCount(seeded))

	res := h.upgrade(nextBinary)
	if res.Code != 0 {
		t.Fatalf("sm install upgrade exited %d\n%s", res.Code, res.Output())
	}
	h.srv.WaitReady(h.ctx())

	t.Run("the doctor reports the latest schema", func(t *testing.T) {
		want := milestones[len(milestones)-1].schema
		if pendingSchema != 0 {
			want = pendingSchema
		}
		if want != latestSchema(t) {
			t.Fatalf("the milestone table says schema %d, the build says %d", want, latestSchema(t))
		}
		if got := h.schema(harness.ServerBinary); got != want {
			t.Errorf("schema %d after the upgrade, want %d", got, want)
		}
	})

	t.Run("every row the old release served survives", func(t *testing.T) {
		chainAssertRows(t, "after the upgrade", seeded, h.databaseRows())
	})

	t.Run("the doctor finds the service sound", func(t *testing.T) {
		for _, check := range h.doctorChecks(harness.ServerBinary) {
			if check.Status == "fail" {
				t.Errorf("doctor check %s fails: %s", check.Name, check.Detail)
			}
			if check.Name == "orphan_keys" && check.Status != "ok" {
				t.Errorf("the master key of the fixture is not the one the database references: %s", check.Detail)
			}
		}
	})
}

// loadFixtureWorld replaces the data of the running previous release with the fixture: database,
// master key under the id the database names; the service starts on it.
func (h *upgradeHost) loadFixtureWorld(fixture string) {
	h.t.Helper()
	c := h.srv.C
	c.MustExec(h.ctx(), "systemctl", "stop", "supermgmt")
	c.MustExec(h.ctx(), "sh", "-c", "rm -f "+chainDatabase+"* "+chainKeysDir+"/*.key")
	kek := chainActiveKEK(h.t, fixture)
	c.Copy(fixture, chainDatabase)
	c.Copy(filepath.Join(harness.RepoRoot(), chainFixtureDir, "master.key"), chainKeysDir+"/"+kek+".key")
	c.MustExec(h.ctx(), "chown", "supermgmt:supermgmt", chainDatabase, chainKeysDir+"/"+kek+".key")
	c.MustExec(h.ctx(), "chmod", "0600", chainDatabase, chainKeysDir+"/"+kek+".key")
	c.MustExec(h.ctx(), "systemctl", "start", "supermgmt")
	h.srv.WaitReady(h.ctx())
}

// databaseRows reads the rows of the service's database. The service is stopped for the copy so
// that nothing is left in the write-ahead log, and started again afterwards.
func (h *upgradeHost) databaseRows() map[string][]string {
	h.t.Helper()
	h.srv.C.MustExec(h.ctx(), "systemctl", "stop", "supermgmt")
	defer func() {
		h.srv.C.MustExec(h.ctx(), "systemctl", "start", "supermgmt")
		h.srv.WaitReady(h.ctx())
	}()
	path := filepath.Join(h.t.TempDir(), "supermgmt.db")
	harness.MustDocker(h.t, "cp", h.srv.C.Name+":"+chainDatabase, path)
	return chainRows(h.t, path)
}

// chainFixtureDatabase is a private copy of the M2 fixture, so reading it never touches the repo file.
func chainFixtureDatabase(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(harness.RepoRoot(), chainFixtureDir, "sm.db"))
	if err != nil {
		t.Fatalf("read the M2 fixture (make migration-fixtures): %v", err)
	}
	path := filepath.Join(t.TempDir(), "fixture.db")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func chainActiveKEK(t *testing.T, path string) string {
	t.Helper()
	db := chainOpen(t, path)
	var raw string
	if err := db.QueryRowContext(t.Context(), `SELECT value_json FROM settings WHERE key = 'active_kek_id'`).Scan(&raw); err != nil {
		t.Fatalf("the fixture names no active master key: %v", err)
	}
	var id string
	if err := json.Unmarshal([]byte(raw), &id); err != nil {
		t.Fatalf("active_kek_id %q: %v", raw, err)
	}
	return id
}

func chainOpen(t *testing.T, path string) database.Querier {
	t.Helper()
	db, err := database.OpenReadOnly(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db.Querier()
}

// chainRows maps every table of the database at path (but the migration ledger) to the primary keys of its rows.
func chainRows(t *testing.T, path string) map[string][]string {
	t.Helper()
	db := chainOpen(t, path)
	tables := chainColumn(t, db, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations' ORDER BY name`)
	rows := make(map[string][]string, len(tables))
	for _, table := range tables {
		keys := chainColumn(t, db, fmt.Sprintf(`SELECT name FROM pragma_table_info('%s') WHERE pk > 0 ORDER BY pk`, table))
		if len(keys) == 0 {
			t.Fatalf("table %s has no primary key to identify its rows by", table)
		}
		rows[table] = chainColumn(t, db, fmt.Sprintf(`SELECT %s FROM %s`, strings.Join(chainConcat(keys), " || '|' || "), table))
	}
	return rows
}

func chainCount(rows map[string][]string) int {
	n := 0
	for _, keys := range rows {
		n += len(keys)
	}
	return n
}

func chainConcat(columns []string) []string {
	quoted := make([]string, len(columns))
	for i, c := range columns {
		quoted[i] = fmt.Sprintf(`CAST("%s" AS TEXT)`, c)
	}
	return quoted
}

func chainColumn(t *testing.T, db database.Querier, query string) []string {
	t.Helper()
	cursor, err := db.QueryContext(t.Context(), query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer cursor.Close()
	var out []string
	for cursor.Next() {
		var v string
		if err := cursor.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := cursor.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// chainAssertRows fails for every seeded row that got is missing.
func chainAssertRows(t *testing.T, when string, seeded, got map[string][]string) {
	t.Helper()
	total := 0
	for table, keys := range seeded {
		present := map[string]bool{}
		for _, k := range got[table] {
			present[k] = true
		}
		for _, k := range keys {
			total++
			if !present[k] {
				t.Errorf("%s: row %s of %s is missing", when, k, table)
			}
		}
	}
	if total == 0 {
		t.Fatalf("%s: the fixture seeded no rows", when)
	}
}

type chainCheck struct{ Name, Status, Detail string }

// doctorChecks is the offline doctor report of bin; a running service is stopped for the reading
// and started again, because the offline doctor needs the database lock.
func (h *upgradeHost) doctorChecks(bin string) []chainCheck {
	h.t.Helper()
	h.srv.C.MustExec(h.ctx(), "systemctl", "stop", "supermgmt")
	defer func() {
		h.srv.C.MustExec(h.ctx(), "systemctl", "start", "supermgmt")
		h.srv.WaitReady(h.ctx())
	}()
	res := h.srv.C.Exec(h.ctx(), "", "runuser", "-u", "supermgmt", "--", bin, "doctor", "--offline", "--json", "--config", harness.ServerConfig)
	var report struct{ Checks []chainCheck }
	if err := json.Unmarshal([]byte(res.Stdout), &report); err != nil {
		h.t.Fatalf("%s doctor --offline gave no report: %v\n%s", bin, err, res.Output())
	}
	return report.Checks
}
