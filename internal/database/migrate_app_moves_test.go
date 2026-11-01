package database

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/migrations"
)

// dumpTable returns every row of the table, ordered by id, as text.
func dumpTable(ctx context.Context, t *testing.T, q Querier, table, orderBy string) []string {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT * FROM "+table+" ORDER BY "+orderBy)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%#v", vals))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// schemaOf lists the DDL of the objects the query selects from sqlite_master.
func schemaOf(t *testing.T, q Querier, where string) []string {
	t.Helper()
	rows, err := q.QueryContext(context.Background(),
		"SELECT type || ' ' || name || ': ' || coalesce(sql, '') FROM sqlite_master WHERE "+where+" ORDER BY type, name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A database at schema 9 keeps every deployment, its steps, indexes and references when 000010 rebuilds the
// deployments table to allow the kind 'move'.
func TestMigration000010RebuildsDeploymentsKeepingEverything(t *testing.T) {
	ctx := context.Background()
	all, err := loadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sm.db"), Options{Clock: domaintest.NewFakeClock(testEpoch)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, m := range all {
		if m.version <= 9 {
			if err := db.apply(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	seed := []string{
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`,
		`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', 1, 1)`,
		`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
			VALUES ('node-1', 'prov-1', 'n', 'n', 'host', 'managed', 'unknown', 1, 1)`,
		`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`,
		`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
			VALUES ('app-1', 'web', 'web', '{}', 'control-plane', 1, 1)`,
		`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
			VALUES ('target-1', 'app-1', 'env-1', 'node-1', 'web-prod', '{}', 1, 1)`,
	}
	for i, d := range []struct{ id, kind, state, previous, rollbackOf, recoveryTarget, knownGood string }{
		{"dep-1", "deploy", "succeeded", "NULL", "NULL", "NULL", "1"},
		{"dep-2", "deploy", "failed", "'dep-1'", "NULL", "NULL", "0"},
		{"dep-3", "rollback", "rolled_back", "'dep-2'", "'dep-1'", "'dep-1'", "0"},
	} {
		recoveryMode := "NULL"
		if d.recoveryTarget != "NULL" {
			recoveryMode = "'safety_recovery'"
		}
		seed = append(seed,
			fmt.Sprintf(`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by,
				previous_deployment_id, rollback_of_deployment_id, recovery_mode, recovery_target_deployment_id, known_good,
				commit_sha, requested_json, credential_kind, scopes_json, created_at, updated_at, finished_at)
				VALUES ('%s', '%s', 'app-1', 'target-1', 'env-1', 'node-1', '%s', 'id-1', %s, %s, %s, %s, %s,
				'abc', '{"n":%d}', 'session', '["x"]', %d, %d, %d)`,
				d.id, d.kind, d.state, d.previous, d.rollbackOf, recoveryMode, d.recoveryTarget, d.knownGood, i, 10+i, 20+i, 30+i),
			fmt.Sprintf(`INSERT INTO deployment_steps (id, deployment_id, ordinal, name, state, attempt)
				VALUES ('%s-step-a', '%s', 1, 'pull', 'succeeded', 1), ('%s-step-b', '%s', 2, 'start', 'failed', 2)`,
				d.id, d.id, d.id, d.id))
	}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		for _, stmt := range seed {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	rowsBefore := dumpTable(ctx, t, db.Reader(), "deployments", "id")
	stepsBefore := dumpTable(ctx, t, db.Reader(), "deployment_steps", "id")
	indexesBefore := schemaOf(t, db.Reader(), "tbl_name = 'deployments' AND type IN ('index', 'trigger') AND sql IS NOT NULL")
	triggersBefore := schemaOf(t, db.Reader(), "type = 'trigger' AND name <> 'app_routes_ids_once'")
	fkBefore := scalar[string](t, db.Reader(), `SELECT group_concat("table" || '.' || "from" || '>' || "to" || ':' || on_delete, ' ')
		FROM pragma_foreign_key_list('deployments')`)
	stepFKBefore := scalar[string](t, db.Reader(), `SELECT group_concat("table" || '.' || "from" || '>' || "to", ' ') FROM pragma_foreign_key_list('deployment_steps')`)
	if len(rowsBefore) != 3 || len(stepsBefore) != 6 || len(indexesBefore) != 4 {
		t.Fatalf("seed: %d deployments, %d steps, %d indexes", len(rowsBefore), len(stepsBefore), len(indexesBefore))
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate from version 9: %v", err)
	}

	if got := dumpTable(ctx, t, db.Reader(), "deployments", "id"); !reflect.DeepEqual(got, rowsBefore) {
		t.Errorf("deployments changed\nbefore %v\nafter  %v", rowsBefore, got)
	}
	if got := dumpTable(ctx, t, db.Reader(), "deployment_steps", "id"); !reflect.DeepEqual(got, stepsBefore) {
		t.Errorf("deployment_steps changed\nbefore %v\nafter  %v", stepsBefore, got)
	}
	if got := schemaOf(t, db.Reader(), "tbl_name = 'deployments' AND type IN ('index', 'trigger') AND sql IS NOT NULL"); !reflect.DeepEqual(got, indexesBefore) {
		t.Errorf("indexes changed\nbefore %v\nafter  %v", indexesBefore, got)
	}
	// the triggers of every table survive, and the move tables add their own; 000011 replaces app_routes_ids_once
	var surviving []string
	for _, s := range schemaOf(t, db.Reader(), "type = 'trigger'") {
		if !strings.Contains(s, "app_move") && !strings.HasPrefix(s, "trigger app_routes_ids_once") {
			surviving = append(surviving, s)
		}
	}
	if !reflect.DeepEqual(surviving, triggersBefore) {
		t.Errorf("triggers changed\nbefore %v\nafter  %v", triggersBefore, surviving)
	}
	if got := scalar[string](t, db.Reader(), `SELECT group_concat("table" || '.' || "from" || '>' || "to" || ':' || on_delete, ' ')
		FROM pragma_foreign_key_list('deployments')`); got != fkBefore {
		t.Errorf("deployments references = %q, want %q", got, fkBefore)
	}
	if got := scalar[string](t, db.Reader(), `SELECT group_concat("table" || '.' || "from" || '>' || "to", ' ') FROM pragma_foreign_key_list('deployment_steps')`); got != stepFKBefore {
		t.Errorf("deployment_steps references = %q, want %q", got, stepFKBefore)
	}
	for query, want := range map[string]int{
		`SELECT count(*) FROM pragma_foreign_key_check`:                                                         0,
		`SELECT count(*) FROM pragma_table_list WHERE name = 'deployments' AND strict = 1`:                      1,
		`SELECT count(*) FROM sqlite_master WHERE name = 'deployments_rebuild'`:                                 0,
		`SELECT count(*) FROM schema_migrations WHERE version = 10`:                                             1,
		`SELECT count(*) FROM pragma_table_list WHERE name IN ('app_moves', 'app_move_volumes') AND strict = 1`: 2,
	} {
		if got := scalar[int](t, db.Reader(), query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}

	// the references are live: a step needs its deployment, a deployment its parents, and the kind move is allowed
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO deployment_steps (id, deployment_id, ordinal, name, state) VALUES ('s', 'nope', 1, 'x', 'pending')`); err == nil {
			t.Error("a step of a missing deployment was accepted")
		}
		insert := func(id, kind, node string) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by,
				commit_sha, requested_json, credential_kind, created_at, updated_at)
				VALUES (?, ?, 'app-1', 'target-1', 'env-1', ?, 'created', 'id-1', 'abc', '{}', 'session', 1, 1)`, id, kind, node)
			return err
		}
		if err := insert("dep-move", "move", "node-1"); err != nil {
			t.Errorf("kind move: %v", err)
		}
		if err := insert("dep-bad", "bogus", "node-1"); err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("kind bogus: err = %v", err)
		}
		if err := insert("dep-orphan", "deploy", "missing"); err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
			t.Errorf("missing node: err = %v", err)
		}
		return fmt.Errorf("rollback")
	})
	if err == nil || err.Error() != "rollback" {
		t.Fatal(err)
	}
}
