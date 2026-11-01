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

// A database at schema 10 keeps every move, its volumes, indexes, triggers and references when 000011 rebuilds
// app_moves to allow the routes phases, and the routes trigger is replaced.
func TestMigration000011RebuildsAppMovesKeepingEverything(t *testing.T) {
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
		if m.version <= 10 {
			if err := db.apply(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
	}
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
			VALUES ('target-1', 'app-1', 'env-1', 'node-1', 'web-prod', '{}', 1, 1),
			       ('target-2', 'app-2', 'env-1', 'node-1', 'api-prod', '{}', 1, 1)`,
		`INSERT INTO app_routes (id, app_target_id, node_id, hostname, service, port, access, phase, phase_started_at, account_id, zone,
				instance_id, tunnel_id, tunnel_generation, dns_record_id, created_by, created_at, updated_at)
			VALUES ('route-1', 'target-1', 'node-1', 'shop.example.com', 'web', 8080, 'public', 'active', 1, 'acct', 'example.com',
				'inst', 'tun-a', 1, 'dns-1', 'id-1', 1, 1)`,
	}
	for i, id := range []string{"1", "2", "3"} {
		seed = append(seed,
			fmt.Sprintf(`INSERT INTO plans (id, action, actor_id, credential_kind, plan_json, plan_hash, finalized_at, created_at, expires_at)
				VALUES ('plan-%s', 'app_target.move', 'id-1', 'session', '{}', 'sha256:%s', 1, 1, 2)`, id, id),
			fmt.Sprintf(`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
				VALUES ('job-%s', 'app_target.move', 'app_target', 'target-1', 'id-1', 'session', 'succeeded', 'operational', 'resumable', 1, 1)`, id),
			fmt.Sprintf(`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by, known_good,
				commit_sha, requested_json, credential_kind, created_at, updated_at)
				VALUES ('dep-%s', 'deploy', 'app-1', 'target-1', 'env-1', 'node-1', 'succeeded', 'id-1', 1, 'abc', '{"n":%d}', 'session', 1, 1)`, id, i))
	}
	seed = append(seed,
		// a finished move, a halted open one on another target, and a stateful one mid-copy on a third state of the same target set
		`INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id, stateful,
				phase, phase_started_at, created_by, created_at, updated_at, committed_revision)
			VALUES ('move-1', 'target-1', 'node-1', 'node-2', 'plan-1', 'job-1', 'dep-1', 0, 'done', 5, 'id-1', 4, 9, 2)`,
		`INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id, stateful,
				phase, halted_phase, last_error, phase_started_at, created_by, created_at, updated_at)
			VALUES ('move-2', 'target-1', 'node-2', 'node-1', 'plan-2', 'job-2', 'dep-2', 0, 'failed', 'verified', 'boom', 5, 'id-1', 10, 11)`,
		`INSERT INTO app_moves (id, app_target_id, source_node_id, dest_node_id, plan_id, job_id, known_good_deployment_id, stateful,
				b_started_at, phase, phase_started_at, created_by, created_at, updated_at)
			VALUES ('move-3', 'target-2', 'node-1', 'node-2', 'plan-3', 'job-3', 'dep-3', 1, 7, 'data_copied', 8, 'id-1', 6, 9)`,
		`INSERT INTO app_move_volumes (move_id, volume_name, service, mount_target, other_services_json, state, source_bytes, dest_bytes,
				source_digest, dest_digest, created_by_move, created_at, updated_at)
			VALUES ('move-3', 'web_db', 'db', '/var/lib/db', '["worker"]', 'verified', 10, 10, 'sha256:x', 'sha256:x', 1, 6, 9),
			       ('move-3', 'web_cache', 'web', '/cache', '[]', 'pending', 5, 0, '', '', 0, 6, 6)`)
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

	r := db.Reader()
	const moveObjects = "tbl_name = 'app_moves' AND type IN ('index', 'trigger') AND sql IS NOT NULL"
	const volumeObjects = "tbl_name = 'app_move_volumes' AND type IN ('index', 'trigger') AND sql IS NOT NULL"
	fkOf := func(table string) string {
		return scalar[string](t, r, fmt.Sprintf(`SELECT group_concat("table" || '.' || "from" || '>' || "to" || ':' || on_delete, ' ')
			FROM pragma_foreign_key_list('%s')`, table))
	}
	movesBefore := dumpTable(ctx, t, r, "app_moves", "id")
	volumesBefore := dumpTable(ctx, t, r, "app_move_volumes", "volume_name")
	routesBefore := dumpTable(ctx, t, r, "app_routes", "id")
	moveObjectsBefore := schemaOf(t, r, moveObjects)
	volumeObjectsBefore := schemaOf(t, r, volumeObjects)
	movesFKBefore, volumesFKBefore := fkOf("app_moves"), fkOf("app_move_volumes")
	if len(movesBefore) != 3 || len(volumesBefore) != 2 || len(moveObjectsBefore) != 6 || len(volumeObjectsBefore) != 1 {
		t.Fatalf("seed: %d moves, %d volumes, %d move objects, %d volume objects",
			len(movesBefore), len(volumesBefore), len(moveObjectsBefore), len(volumeObjectsBefore))
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate from version 10: %v", err)
	}

	for table, order := range map[string]string{"app_moves": "id", "app_move_volumes": "volume_name", "app_routes": "id"} {
		before := map[string][]string{"app_moves": movesBefore, "app_move_volumes": volumesBefore, "app_routes": routesBefore}[table]
		if got := dumpTable(ctx, t, r, table, order); !reflect.DeepEqual(got, before) {
			t.Errorf("%s changed\nbefore %v\nafter  %v", table, before, got)
		}
	}
	if got := schemaOf(t, r, moveObjects); !reflect.DeepEqual(got, moveObjectsBefore) {
		t.Errorf("app_moves indexes and triggers changed\nbefore %v\nafter  %v", moveObjectsBefore, got)
	}
	if got := schemaOf(t, r, volumeObjects); !reflect.DeepEqual(got, volumeObjectsBefore) {
		t.Errorf("app_move_volumes indexes and triggers changed\nbefore %v\nafter  %v", volumeObjectsBefore, got)
	}
	if got := fkOf("app_moves"); got != movesFKBefore {
		t.Errorf("app_moves references = %q, want %q", got, movesFKBefore)
	}
	if got := fkOf("app_move_volumes"); got != volumesFKBefore {
		t.Errorf("app_move_volumes references = %q, want %q", got, volumesFKBefore)
	}
	for query, want := range map[string]int{
		`SELECT count(*) FROM pragma_foreign_key_check`:                                                                               0,
		`SELECT count(*) FROM sqlite_master WHERE name = 'app_moves_rebuild'`:                                                         0,
		`SELECT count(*) FROM schema_migrations WHERE version = 11`:                                                                   1,
		`SELECT count(*) FROM pragma_table_list WHERE name IN ('app_moves', 'app_move_routes') AND strict = 1`:                        2,
		`SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'app_routes_ids_once' AND sql LIKE '%app_move_routes%'`: 1,
	} {
		if got := scalar[int](t, r, query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}

	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		exec := func(stmt string) error { _, err := tx.ExecContext(ctx, stmt); return err }
		// the volumes still resolve their move, and a missing move is refused
		if err := exec(`INSERT INTO app_move_volumes (move_id, volume_name, service, mount_target, created_at, updated_at)
			VALUES ('nope', 'v', 's', '/m', 1, 1)`); err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
			t.Errorf("volume of a missing move: err = %v", err)
		}
		// the new phases are allowed in both columns, others are not
		for _, phase := range []string{
			"routes_dest_included", "routes_switched", "routes_source_cleaned",
			"compensating_routes_restored", "compensating_routes_withdrawn",
		} {
			if err := exec(`UPDATE app_moves SET phase = '` + phase + `', halted_phase = NULL WHERE id = 'move-3'`); err != nil {
				t.Errorf("phase %s: %v", phase, err)
			}
			if err := exec(`UPDATE app_moves SET phase = 'conflict', halted_phase = '` + phase + `' WHERE id = 'move-3'`); err != nil {
				t.Errorf("halted_phase %s: %v", phase, err)
			}
		}
		if err := exec(`UPDATE app_moves SET phase = 'bogus' WHERE id = 'move-3'`); err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("phase bogus: err = %v", err)
		}
		// the triggers of app_moves live: a finished move stays finished, the identity stays fixed, one open move per target
		if err := exec(`UPDATE app_moves SET phase = 'staged' WHERE id = 'move-1'`); err == nil || !strings.Contains(err.Error(), "does not change phase") {
			t.Errorf("finished move changed phase: err = %v", err)
		}
		if err := exec(`UPDATE app_moves SET stateful = 0 WHERE id = 'move-3'`); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
			t.Errorf("identity of a move changed: err = %v", err)
		}
		if err := exec(`UPDATE app_moves SET phase = 'preflight', halted_phase = NULL WHERE id = 'move-1'`); err == nil {
			t.Error("a finished move reopened")
		}
		// the routes trigger keeps the old rules and refuses a move of the route without move evidence
		for _, set := range []string{"hostname = 'x.example.com'", "tunnel_id = 'x'", "node_id = 'node-2'", "tunnel_generation = 2"} {
			if err := exec(`UPDATE app_routes SET ` + set + ` WHERE id = 'route-1'`); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
				t.Errorf("UPDATE %s: err = %v", set, err)
			}
		}
		return fmt.Errorf("rollback")
	})
	if err == nil || err.Error() != "rollback" {
		t.Fatal(err)
	}
}
