package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/migrations"
)

var update = flag.Bool("update", false, "rewrite testdata golden files")

const (
	schemaGolden     = "testdata/schema.golden"
	migrationsLedger = "testdata/migrations.sha256"
)

func TestSchemaMatchesGolden(t *testing.T) {
	db := migratedTest(t)
	rows, err := db.Reader().QueryContext(context.Background(),
		`SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var typ, name, ddl string
		if err := rows.Scan(&typ, &name, &ddl); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "-- %s %s\n%s;\n\n", typ, name, ddl)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	assertGolden(t, schemaGolden, b.String())
}

func assertGolden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (run with -update to create): %v", path, err)
	}
	if string(want) != got {
		t.Fatalf("%s is out of date (run with -update after reviewing the schema change)\n--- got ---\n%s", path, got)
	}
}

// Released migrations are immutable: schema changes ship as a new file, whose
// hash is then added to the ledger.
func TestReleasedMigrationsAreNeverEdited(t *testing.T) {
	var current []string
	err := fs.WalkDir(migrations.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		body, err := fs.ReadFile(migrations.FS, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		current = append(current, hex.EncodeToString(sum[:])+"  "+path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(current)
	got := strings.Join(current, "\n") + "\n"

	if *update {
		assertGolden(t, migrationsLedger, got)
		return
	}
	released, err := os.ReadFile(migrationsLedger)
	if err != nil {
		t.Fatalf("read %s: %v", migrationsLedger, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(released)), "\n") {
		if !slices.Contains(current, line) {
			t.Errorf("released migration changed or removed: %s", line)
		}
	}
	for _, line := range current {
		if !strings.Contains(string(released), line) {
			t.Errorf("new migration not in %s (add its hash once released): %s", migrationsLedger, line)
		}
	}
}

func values[T ~string](vs []T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}

// enumColumns maps table.column to the domain values its CHECK must allow.
func enumColumns() map[string][]string {
	return map[string][]string{
		"identities.actor_type":       values(domain.AllActorTypes()),
		"environments.risk_level":     values(domain.AllEnvironmentRiskLevels()),
		"providers.origin":            values(domain.AllProviderOrigins()),
		"nodes.management_state":      values(domain.AllManagementStates()),
		"nodes.reachability":          values(domain.AllReachabilities()),
		"observations.resource_type":  values(domain.AllResourceTypes()),
		"plans.credential_kind":       values(domain.AllCredentialKinds()),
		"jobs.resource_type":          values(domain.AllResourceTypes()),
		"jobs.credential_kind":        values(domain.AllCredentialKinds()),
		"jobs.state":                  values(domain.AllJobStates()),
		"jobs.risk":                   values(domain.AllRiskClasses()),
		"jobs.retry_class":            values(domain.AllRetryClasses()),
		"job_approvals.decision":      values(domain.AllApprovalDecisions()),
		"operation_intents.state":     values(domain.AllIntentStates()),
		"resource_locks.mode":         values(domain.AllLockModes()),
		"events.actor_type":           values(domain.AllActorTypes()),
		"events.resource_type":        append([]string{""}, values(domain.AllResourceTypes())...),
		"events.severity":             values(domain.AllSeverities()),
		"events.result":               values(domain.AllResults()),
		"node_capabilities.available": {"0", "1"},
	}
}

var checkInList = regexp.MustCompile(`(?s)(\w+)\s+TEXT[^,]*?CHECK\s*\(\s*(\w+)\s+IN\s*\(([^)]*)\)`)

// The CHECK lists written in SQL must equal the domain enums exactly.
func TestEnumChecksMatchDomain(t *testing.T) {
	db := migratedTest(t)
	for key, want := range enumColumns() {
		table, column, _ := strings.Cut(key, ".")
		if table == "node_capabilities" {
			continue // integer flag, covered by TestEnumChecksRejectUnknownValues
		}
		ddl := scalar[string](t, db.Reader(), `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table)
		var got []string
		for _, m := range checkInList.FindAllStringSubmatch(ddl, -1) {
			if m[2] != column {
				continue
			}
			for _, item := range strings.Split(m[3], ",") {
				got = append(got, strings.Trim(strings.TrimSpace(item), "'"))
			}
		}
		slices.Sort(got)
		wantSorted := slices.Sorted(slices.Values(want))
		if !slices.Equal(got, wantSorted) {
			t.Errorf("%s CHECK = %v, want %v", key, got, wantSorted)
		}
	}
}

const (
	idA = "01970000-0000-7000-8000-00000000a001"
	idB = "01970000-0000-7000-8000-00000000a002"
)

// baselines are valid rows; each enum test mutates exactly one column.
func baselines() map[string]map[string]any {
	return map[string]map[string]any{
		"identities":   {"id": idA, "actor_type": "human", "created_at": 1},
		"environments": {"id": idA, "name": "n", "risk_level": "production"},
		"providers": {
			"id": idA, "type": "ssh", "name": "n", "origin": "static",
			"created_at": 1, "updated_at": 1,
		},
		"nodes": {
			"id": idA, "provider_id": idA, "native_id": "x", "name": "n", "kind": "host",
			"management_state": "managed", "reachability": "unknown", "created_at": 1, "updated_at": 1,
		},
		"node_capabilities": {"node_id": idA, "capability": "node.ssh", "available": 1, "checked_at": 1},
		"observations": {
			"id": idA, "resource_type": "node", "resource_id": idA, "kind": "k",
			"value_json": "{}", "observed_at": 1,
		},
		"plans": {
			"id": idA, "action": "a", "actor_id": idA, "credential_kind": "session",
			"plan_json": "{}", "plan_hash": "sha256:00", "finalized_at": 1, "created_at": 1, "expires_at": 2,
		},
		"jobs": {
			"id": idA, "type": "t", "resource_type": "node", "resource_id": idA, "actor_id": idA,
			"credential_kind": "session", "state": "queued", "risk": "read", "retry_class": "idempotent",
			"scheduled_at": 1, "created_at": 1,
		},
		"job_approvals": {
			"id": idA, "job_id": idA, "plan_hash": "h", "approver_id": idA,
			"decision": "approve", "expires_at": 2, "created_at": 1,
		},
		"operation_intents": {
			"id": idA, "job_id": idA, "step": "s", "lease_generation": 1, "state": "recorded",
			"operation": "o", "target_type": "node", "target_id": idA, "marker": "m", "deadline_at": 2,
		},
		"resource_locks": {
			"resource_type": "node", "resource_id": idA, "job_id": idA,
			"mode": "exclusive", "acquired_at": 1,
		},
		"events": {
			"event_id": idA, "timestamp": 1, "actor_type": "system", "actor_id": idA, "source": "s",
			"action": "a", "severity": "info", "result": "succeeded",
		},
	}
}

func insertRow(ctx context.Context, tx *Tx, table string, row map[string]any) error {
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	args := make([]any, len(cols))
	for i, c := range cols {
		args[i] = row[c]
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (?%s)", table, strings.Join(cols, ", "),
		strings.Repeat(", ?", len(cols)-1))
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

// tryInsert inserts row with foreign keys deferred and always rolls back.
func tryInsert(t *testing.T, db *DB, table string, row map[string]any) error {
	t.Helper()
	var insertErr error
	_ = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
			t.Fatal(err)
		}
		insertErr = insertRow(ctx, tx, table, row)
		return fmt.Errorf("rollback")
	})
	return insertErr
}

func TestEnumChecksRejectUnknownValues(t *testing.T) {
	db := migratedTest(t)
	for key, valid := range enumColumns() {
		table, column, _ := strings.Cut(key, ".")
		t.Run(key, func(t *testing.T) {
			base := baselines()[table]
			if base == nil {
				t.Fatalf("no baseline row for %s", table)
			}
			for _, v := range valid {
				row := cloneRow(base)
				row[column] = enumValue(table, column, v)
				if err := tryInsert(t, db, table, row); err != nil {
					t.Errorf("valid %s=%q rejected: %v", key, v, err)
				}
			}
			row := cloneRow(base)
			row[column] = enumValue(table, column, "bogus")
			err := tryInsert(t, db, table, row)
			if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
				t.Errorf("%s=bogus: err = %v, want CHECK constraint failure", key, err)
			}
		})
	}
}

func enumValue(table, column, v string) any {
	if table == "node_capabilities" && column == "available" {
		if v == "bogus" {
			return 2
		}
		return map[string]int{"0": 0, "1": 1}[v]
	}
	return v
}

func cloneRow(row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		out[k] = v
	}
	return out
}

func TestEventsAreAppendOnly(t *testing.T) {
	db := migratedTest(t)
	ctx := context.Background()
	if err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		return insertRow(ctx, tx, "events", baselines()["events"])
	}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE events SET action = 'tampered'`,
		`DELETE FROM events`,
	} {
		err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
			_, err := tx.ExecContext(ctx, stmt)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%q: err = %v, want append-only abort", stmt, err)
		}
	}
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM events WHERE action = 'a'`); n != 1 {
		t.Fatalf("event rows = %d, want 1 untouched", n)
	}
}

func TestSemanticConstraints(t *testing.T) {
	db := migratedTest(t)
	cases := []struct {
		name  string
		table string
		first map[string]any
		dup   map[string]any
	}{
		{
			"identities unique tuple", "identities",
			baselines()["identities"],
			override(baselines()["identities"], "id", idB),
		},
		{
			"providers unique name", "providers",
			baselines()["providers"],
			override(baselines()["providers"], "id", idB),
		},
		{
			"nodes unique provider+native", "nodes",
			baselines()["nodes"],
			override(baselines()["nodes"], "id", idB),
		},
		{
			"operation_intents unique marker", "operation_intents",
			baselines()["operation_intents"],
			override(baselines()["operation_intents"], "id", idB),
		},
		{
			"events unique event_id", "events",
			baselines()["events"],
			baselines()["events"],
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dupErr error
			_ = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
				if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
					t.Fatal(err)
				}
				if err := insertRow(ctx, tx, tc.table, tc.first); err != nil {
					t.Fatalf("first insert: %v", err)
				}
				dupErr = insertRow(ctx, tx, tc.table, tc.dup)
				return fmt.Errorf("rollback")
			})
			if dupErr == nil || !strings.Contains(dupErr.Error(), "UNIQUE constraint failed") {
				t.Fatalf("duplicate err = %v, want UNIQUE failure", dupErr)
			}
		})
	}
}

func override(row map[string]any, key string, value any) map[string]any {
	out := cloneRow(row)
	out[key] = value
	return out
}

func TestForeignKeysAreEnforced(t *testing.T) {
	db := migratedTest(t)
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		return insertRow(ctx, tx, "nodes", baselines()["nodes"]) // provider does not exist
	})
	if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Fatalf("err = %v, want FOREIGN KEY failure", err)
	}
}
