package database

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

const (
	moveJobTypes     = `'app_target.move', 'app_target.cleanup_source', 'app_target.abandon_move'`
	retireGuidance   = "finish the app move (or abandon it where it halted) with the previous SuperMgmt version before upgrading"
	retiredTableList = `'app_moves', 'app_move_volumes', 'app_move_routes'`
)

// migratedTo opens a database and applies the migrations up to version.
func migratedTo(t *testing.T, version int) *DB {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sm.db"), Options{Clock: domaintest.NewFakeClock(testEpoch)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := MigrateUpTo(ctx, db, version); err != nil {
		t.Fatal(err)
	}
	return db
}

func execAll(t *testing.T, db *DB, stmts ...string) {
	t.Helper()
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		for _, stmt := range stmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// movesWorld seeds a database at schema 11: two targets with a routed one, three move plans and jobs (job-1..3, all
// succeeded), five deployments and the move rows given by moves.
func movesWorld(t *testing.T, moves ...string) *DB {
	t.Helper()
	db := migratedTo(t, 11)
	seed := []string{
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`,
		`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', 1, 1)`,
		`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
			VALUES ('node-1', 'prov-1', 'n1', 'n1', 'host', 'managed', 'unknown', 1, 1),
			       ('node-2', 'prov-1', 'n2', 'n2', 'host', 'managed', 'unknown', 1, 1)`,
		`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`,
		`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
			VALUES ('app-1', 'web', 'web', '{}', 'control-plane', 1, 1), ('app-2', 'api', 'api', '{}', 'control-plane', 1, 1)`,
		`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
			VALUES ('target-1', 'app-1', 'env-1', 'node-2', 'web-prod', '{}', 1, 1),
			       ('target-2', 'app-2', 'env-1', 'node-1', 'api-prod', '{}', 1, 1)`,
		`INSERT INTO app_routes (id, app_target_id, node_id, hostname, service, port, access, phase, phase_started_at, account_id, zone,
				instance_id, tunnel_id, tunnel_generation, dns_record_id, created_by, created_at, updated_at)
			VALUES ('route-1', 'target-1', 'node-2', 'shop.example.com', 'web', 8080, 'public', 'active', 1, 'acct', 'example.com',
				'inst', 'tun-b', 1, 'dns-1', 'id-1', 1, 1)`,
	}
	for _, n := range []string{"1", "2", "3"} {
		seed = append(seed,
			fmt.Sprintf(`INSERT INTO plans (id, action, actor_id, credential_kind, plan_json, plan_hash, finalized_at, created_at, expires_at)
				VALUES ('plan-%s', 'app_target.move', 'id-1', 'session', '{}', 'sha256:%s', 1, 1, 2)`, n, n),
			fmt.Sprintf(`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
				VALUES ('job-%s', 'app_target.move', 'app_target', 'target-1', 'id-1', 'session', 'succeeded', 'operational', 'resumable', 1, 1)`, n),
			fmt.Sprintf(`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by, known_good,
				commit_sha, requested_json, credential_kind, created_at, updated_at)
				VALUES ('dep-%s', 'deploy', 'app-1', 'target-1', 'env-1', 'node-1', 'succeeded', 'id-1', 1, 'abc', '{"n":%s}', 'session', 1, 1)`, n, n))
	}
	seed = append(seed,
		`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by, known_good,
			commit_sha, requested_json, credential_kind, created_at, updated_at)
			VALUES ('dep-b', 'move', 'app-1', 'target-1', 'env-1', 'node-2', 'succeeded', 'id-1', 1, 'abc', '{"n":9}', 'session', 1, 1)`,
		`INSERT INTO events (event_id, timestamp, actor_type, actor_id, source, action, resource_type, resource_id, severity, result, data_json)
			VALUES ('ev-1', 5, 'human', 'id-1', 'api', 'app_target.move', 'app_target', 'target-1', 'info', 'succeeded', '{"to":"node-2"}')`)
	execAll(t, db, append(seed, moves...)...)
	return db
}

const (
	doneMove = `INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id,
			dest_deployment_id, stateful, phase, phase_started_at, created_by, created_at, updated_at, committed_revision)
		VALUES ('move-1', 'target-1', 'node-1', 'node-2', 'plan-1', 'job-1', 'dep-1', 'dep-b', 1, 'done', 5, 'id-1', 4, 9, 2)`
	rolledBackMove = `INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id,
			stateful, phase, phase_started_at, created_by, created_at, updated_at)
		VALUES ('move-2', 'target-2', 'node-1', 'node-2', 'plan-2', 'job-2', 'dep-2', 0, 'rolled_back', 5, 'id-1', 10, 11)`
	moveLockOf = `INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES ('app_target', 'target-1', '%s', 'exclusive', 1)`
)

// stateOf is everything a refused migration must leave alone: schema version, every schema object and every row of
// the tables that hold the move, its jobs, locks and intents.
func stateOf(t *testing.T, db *DB) string {
	t.Helper()
	r := db.Reader()
	var b strings.Builder
	fmt.Fprintf(&b, "version=%d\n", scalar[int](t, r, `SELECT max(version) FROM schema_migrations`))
	b.WriteString(dump(t, r, `SELECT type, name, sql FROM sqlite_master ORDER BY type, name`))
	for _, table := range []string{"app_moves", "app_move_volumes", "app_move_routes", "app_routes", "jobs", "resource_locks", "operation_intents", "deployments", "events"} {
		fmt.Fprintf(&b, "-- %s\n%s", table, dump(t, r, `SELECT * FROM `+table))
	}
	return b.String()
}

func dump(t *testing.T, q Querier, query string) string {
	t.Helper()
	rows, err := q.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var b strings.Builder
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			b.WriteString(v.String + "|")
		}
		b.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestMigration000012OnAnEmptyDatabase(t *testing.T) {
	db := migratedTest(t)
	r := db.Reader()
	for query, want := range map[string]int{
		`SELECT max(version) FROM schema_migrations`:                                              12,
		`SELECT count(*) FROM sqlite_master WHERE name IN (` + retiredTableList + `)`:             0,
		`SELECT count(*) FROM sqlite_master WHERE name LIKE 'retire_app_moves%'`:                  0,
		`SELECT count(*) FROM sqlite_master WHERE name = 'app_routes_ids_once'`:                   1,
		`SELECT count(*) FROM sqlite_master WHERE sql LIKE '%app_move%'`:                          0,
		`SELECT count(*) FROM pragma_foreign_key_check`:                                           0,
		`SELECT count(*) FROM pragma_table_list WHERE name = 'deployments' AND strict = 1`:        1,
		`SELECT count(*) FROM sqlite_master WHERE name = 'deployments' AND sql LIKE '%''move''%'`: 1,
	} {
		if got := scalar[int](t, r, query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}
}

func TestMigration000012RefusesUnfinishedMovesAndChangesNothing(t *testing.T) {
	openMove := func(phase, halted string) string {
		halt := "NULL"
		if halted != "" {
			halt = "'" + halted + "'"
		}
		return fmt.Sprintf(`INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id,
				stateful, phase, halted_phase, phase_started_at, created_by, created_at, updated_at)
			VALUES ('move-3', 'target-2', 'node-1', 'node-2', 'plan-3', 'job-3', 'dep-3', 0, '%s', %s, 5, 'id-1', 6, 9)`, phase, halt)
	}
	cases := []struct {
		name  string
		setup []string
	}{
		{"a move in flight", []string{openMove("started", ""), fmt.Sprintf(moveLockOf, "job-3")}},
		{"a halted move", []string{openMove("failed", "verified")}},
		{"a conflicting move", []string{openMove("conflict", "committed")}},
		{"a terminal move with a running cleanup job", []string{
			doneMove,
			`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
				VALUES ('job-c', 'app_target.cleanup_source', 'app_target', 'target-1', 'id-1', 'session', 'running', 'destructive', 'resumable', 1, 1)`,
			fmt.Sprintf(moveLockOf, "job-c"),
		}},
		{"a terminal move with an interrupted cleanup job", []string{
			rolledBackMove,
			`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
				VALUES ('job-c', 'app_target.cleanup_source', 'app_target', 'target-2', 'id-1', 'session', 'interrupted', 'destructive', 'resumable', 1, 1)`,
		}},
		{"a queued move job without a move row", []string{
			`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
				VALUES ('job-q', 'app_target.move', 'app_target', 'target-2', 'id-1', 'session', 'queued', 'operational', 'resumable', 1, 1)`,
		}},
		{"a terminal move with an abandon job awaiting approval", []string{
			rolledBackMove,
			`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
				VALUES ('job-a', 'app_target.abandon_move', 'app_target', 'target-2', 'id-1', 'session', 'awaiting_approval', 'destructive', 'resumable', 1, 1)`,
		}},
		{"a terminal move job with an intent not completed", []string{
			doneMove,
			`INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, dispatched_at)
				VALUES ('intent-1', 'job-1', 'cleanup', 1, 'recorded', 'compose.down', 'app_target', 'target-1', 'marker-1', 9, 8)`,
			fmt.Sprintf(moveLockOf, "job-1"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := movesWorld(t, tc.setup...)
			before := stateOf(t, db)
			err := db.Migrate(context.Background())
			if err == nil || !strings.Contains(err.Error(), retireGuidance) {
				t.Fatalf("Migrate: err = %v, want the guidance %q", err, retireGuidance)
			}
			if after := stateOf(t, db); after != before {
				t.Errorf("a refused migration changed the database\nbefore:\n%s\nafter:\n%s", before, after)
			}
			// the refusal repeats until the previous version has finished the move
			if err := db.Migrate(context.Background()); err == nil {
				t.Error("second Migrate succeeded")
			}
		})
	}
}

func TestMigration000012RetiresTerminalMoves(t *testing.T) {
	ctx := context.Background()
	db := movesWorld(t, doneMove, rolledBackMove,
		fmt.Sprintf(moveLockOf, "job-1"),
		`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES ('app_target', 'target-2', 'job-2', 'exclusive', 1)`,
		`INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, completed_at, outcome)
			VALUES ('intent-1', 'job-1', 'cleanup', 1, 'completed', 'compose.down', 'app_target', 'target-1', 'marker-1', 9, 9, 'succeeded')`,
		// an ordinary deployment job and its lock are not the migration's to touch
		`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
			VALUES ('job-d', 'deployment.create', 'app_target', 'target-2', 'id-1', 'session', 'running', 'operational', 'resumable', 1, 1)`,
		`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES ('app_target', 'target-2', 'job-d', 'exclusive', 1)`,
		`INSERT INTO app_move_volumes (move_id, volume_name, service, mount_target, created_at, updated_at) VALUES ('move-1', 'web_db', 'db', '/var/lib/db', 4, 4)`,
		`INSERT INTO app_move_routes (move_id, route_id, frozen_phase, from_node_id, from_tunnel_id, from_generation, to_node_id, to_tunnel_id, to_generation,
				dns_record_id, state, created_at, updated_at)
			VALUES ('move-1', 'route-1', 'active', 'node-1', 'tun-a', 1, 'node-2', 'tun-b', 1, 'dns-1', 'source_cleaned', 4, 9)`,
	)
	r := db.Reader()
	routesBefore := dump(t, r, `SELECT * FROM app_routes ORDER BY id`)
	eventsBefore := dump(t, r, `SELECT * FROM events ORDER BY seq`)
	jobsBefore := dump(t, r, `SELECT * FROM jobs ORDER BY id`)
	intentsBefore := dump(t, r, `SELECT * FROM operation_intents ORDER BY id`)
	deploymentsBefore := dump(t, r, `SELECT * FROM deployments ORDER BY id`)

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	for query, want := range map[string]int{
		`SELECT max(version) FROM schema_migrations`: 12,
		`SELECT count(*) FROM sqlite_master WHERE name IN (` + retiredTableList + `) OR name LIKE 'retire_app_moves%'`:   0,
		`SELECT count(*) FROM sqlite_master WHERE sql LIKE '%app_move%'`:                                                 0,
		`SELECT count(*) FROM resource_locks WHERE job_id IN (SELECT id FROM jobs WHERE type IN (` + moveJobTypes + `))`: 0,
		`SELECT count(*) FROM resource_locks WHERE job_id = 'job-d'`:                                                     1,
		`SELECT count(*) FROM resource_locks`:                                                                            1,
		`SELECT count(*) FROM pragma_foreign_key_check`:                                                                  0,
		`SELECT count(*) FROM deployments WHERE kind = 'move'`:                                                           1,
		`SELECT count(*) FROM jobs WHERE type IN (` + moveJobTypes + `)`:                                                 3,
	} {
		if got := scalar[int](t, r, query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}
	for name, pair := range map[string][2]string{
		"app_routes":        {routesBefore, dump(t, r, `SELECT * FROM app_routes ORDER BY id`)},
		"events":            {eventsBefore, dump(t, r, `SELECT * FROM events ORDER BY seq`)},
		"jobs":              {jobsBefore, dump(t, r, `SELECT * FROM jobs ORDER BY id`)},
		"operation_intents": {intentsBefore, dump(t, r, `SELECT * FROM operation_intents ORDER BY id`)},
		"deployments":       {deploymentsBefore, dump(t, r, `SELECT * FROM deployments ORDER BY id`)},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s changed\nbefore:\n%s\nafter:\n%s", name, pair[0], pair[1])
		}
	}
	if got := scalar[string](t, r, `SELECT data_json FROM events WHERE event_id = 'ev-1'`); got != `{"to":"node-2"}` {
		t.Errorf("event payload = %s", got)
	}

	// app_routes_ids_once is the 000009 trigger again: the identity and the tunnel tuple are fixed, phase and object IDs are not
	err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		exec := func(stmt string) error { _, err := tx.ExecContext(ctx, stmt); return err }
		for _, set := range []string{"hostname = 'x.example.com'", "tunnel_id = 'x'", "node_id = 'node-1'", "tunnel_generation = 2"} {
			if err := exec(`UPDATE app_routes SET ` + set + ` WHERE id = 'route-1'`); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
				t.Errorf("UPDATE %s: err = %v", set, err)
			}
		}
		for _, set := range []string{"phase = 'removing'", "access_app_id = 'acc-1'", "last_error = 'x'", "updated_at = 7"} {
			if err := exec(`UPDATE app_routes SET ` + set + ` WHERE id = 'route-1'`); err != nil {
				t.Errorf("UPDATE %s: %v", set, err)
			}
		}
		if err := exec(`UPDATE app_routes SET dns_record_id = 'dns-2' WHERE id = 'route-1'`); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
			t.Errorf("a recorded DNS record ID changed: err = %v", err)
		}
		return fmt.Errorf("rollback")
	})
	if err == nil || err.Error() != "rollback" {
		t.Fatal(err)
	}
}
