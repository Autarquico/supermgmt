package database

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const waitedNote = "waited for a deployment; routes no longer wait for one"

// nodeRoutesWorld seeds a database at schema 12 with one route per phase of interest.
func nodeRoutesWorld(t *testing.T, routes ...string) *DB {
	t.Helper()
	db := migratedTo(t, 12)
	execAll(t, db, append([]string{
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`,
		`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', 1, 1)`,
		`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
			VALUES ('node-1', 'prov-1', 'n1', 'n1', 'host', 'managed', 'unknown', 1, 1)`,
		`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`,
		`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
			VALUES ('app-1', 'web', 'web', '{}', 'control-plane', 1, 1)`,
		`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
			VALUES ('target-1', 'app-1', 'env-1', 'node-1', 'web-prod', '{}', 1, 1)`,
	}, routes...)...)
	return db
}

// routeAt12 inserts an app route; halted is the halted_phase column ('NULL' for none).
func routeAt12(id string, port int, phase, halted, dnsID, lastError string) string {
	if halted != "NULL" {
		halted = "'" + halted + "'"
	}
	accessID := "acc-" + id
	if dnsID == "" { // a route that created nothing in Cloudflare has no object IDs at all
		accessID = ""
	}
	return fmt.Sprintf(`INSERT INTO app_routes (id, app_target_id, node_id, hostname, service, port, access, phase, halted_phase,
			phase_started_at, account_id, zone, instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id, last_error,
			created_by, created_at, updated_at)
		VALUES ('%[1]s', 'target-1', 'node-1', '%[1]s.example.com', 'web', %[2]d, 'owners', '%[3]s', %[4]s,
			2, 'acct', 'example.com', 'inst', 'tun-1', 3, '%[5]s', '%[7]s', '%[6]s', 'id-1', 1, 5)`,
		id, port, phase, halted, dnsID, lastError, accessID)
}

func TestMigration000013RebuildsAppRoutesAsNodeRoutes(t *testing.T) {
	ctx := context.Background()
	db := nodeRoutesWorld(t,
		routeAt12("active", 8001, "active", "NULL", "dns-a", ""),
		routeAt12("halted", 8002, "conflict", "provisioning", "dns-h", "record owned by another"),
		routeAt12("removed", 8003, "removed", "NULL", "dns-r", ""),
		routeAt12("waiting", 8004, "waiting", "NULL", "", ""),
		routeAt12("stuck", 8005, "failed", "waiting", "", "boom"),
		routeAt12("dup", 8001, "removed", "NULL", "dns-d", ""), // a removed route does not hold its port
	)

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	r := db.Reader()

	got := dump(t, r, `SELECT id, node_id, hostname, port, access, phase, halted_phase, phase_started_at, tunnel_id, tunnel_generation,
		dns_record_id, access_app_id, last_error FROM node_routes ORDER BY id`)
	want := strings.Join([]string{
		"active|node-1|active.example.com|8001|owners|active||2|tun-1|3|dns-a|acc-active||",
		"dup|node-1|dup.example.com|8001|owners|removed||2|tun-1|3|dns-d|acc-dup||",
		"halted|node-1|halted.example.com|8002|owners|conflict|provisioning|2|tun-1|3|dns-h|acc-halted|record owned by another|",
		"removed|node-1|removed.example.com|8003|owners|removed||2|tun-1|3|dns-r|acc-removed||",
		"stuck|node-1|stuck.example.com|8005|owners|removed||2|tun-1|3|||boom; " + waitedNote + "|",
		"waiting|node-1|waiting.example.com|8004|owners|removed||2|tun-1|3|||" + waitedNote + "|",
	}, "\n")
	if strings.TrimSpace(got) != want {
		t.Errorf("node_routes\ngot:\n%s\nwant:\n%s", got, want)
	}
	for query, wantN := range map[string]int{
		`SELECT max(version) FROM schema_migrations`:                                                       13,
		`SELECT count(*) FROM sqlite_master WHERE name LIKE 'app_routes%'`:                                 0,
		`SELECT count(*) FROM sqlite_master WHERE name LIKE 'node_routes_port_%'`:                          0,
		`SELECT count(*) FROM sqlite_master WHERE sql LIKE '%app_routes%'`:                                 0,
		`SELECT count(*) FROM pragma_foreign_key_check`:                                                    0,
		`SELECT count(*) FROM sqlite_master WHERE name = 'node_routes_ids_once'`:                           1,
		`SELECT count(*) FROM pragma_table_info('node_routes') WHERE name IN ('service', 'app_target_id')`: 0,
	} {
		if n := scalar[int](t, r, query); n != wantN {
			t.Errorf("%s = %d, want %d", query, n, wantN)
		}
	}
}

func TestMigration000013RefusesTwoLiveRoutesOnOnePort(t *testing.T) {
	ctx := context.Background()
	for name, second := range map[string]string{
		"active and active": routeAt12("two", 8001, "active", "NULL", "dns-2", ""),
		"active and halted": routeAt12("two", 8001, "failed", "ingress_ready", "", "boom"),
	} {
		t.Run(name, func(t *testing.T) {
			db := nodeRoutesWorld(t, routeAt12("one", 8001, "active", "NULL", "dns-1", ""), second)
			before := dump(t, db.Reader(), `SELECT type, name, sql FROM sqlite_master ORDER BY type, name`) + dump(t, db.Reader(), `SELECT * FROM app_routes ORDER BY id`)
			err := db.Migrate(ctx)
			if err == nil || !strings.Contains(err.Error(), "unexpose one of them with the previous SuperMgmt version") {
				t.Fatalf("Migrate: err = %v, want the guidance", err)
			}
			if after := dump(t, db.Reader(), `SELECT type, name, sql FROM sqlite_master ORDER BY type, name`) + dump(t, db.Reader(), `SELECT * FROM app_routes ORDER BY id`); after != before {
				t.Errorf("a refused migration changed the database")
			}
		})
	}
}

// routesStateOf is what a refused migration must leave alone: schema objects (triggers included) and the rows of the tables it reads.
func routesStateOf(t *testing.T, db *DB) string {
	t.Helper()
	r := db.Reader()
	return dump(t, r, `SELECT max(version) FROM schema_migrations`) + dump(t, r, `SELECT type, name, sql FROM sqlite_master ORDER BY type, name`) +
		dump(t, r, `SELECT * FROM app_routes ORDER BY id`) + dump(t, r, `SELECT * FROM jobs ORDER BY id`) + dump(t, r, `SELECT * FROM operation_intents ORDER BY id`)
}

const routeJobGuidance = "finish or cancel the route job with the previous SuperMgmt version before upgrading"

// routeJobAt12 seeds a plan of the given action and a control_plane.apply job linked to it, as the app code stores a route job.
func routeJobAt12(id, action, state string) []string {
	return []string{
		fmt.Sprintf(`INSERT INTO plans (id, action, actor_id, credential_kind, plan_json, plan_hash, finalized_at, created_at, expires_at)
			VALUES ('plan-%s', '%s', 'id-1', 'session', '{}', 'hash', 1, 1, 9)`, id, action),
		fmt.Sprintf(`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, plan_id, scheduled_at, created_at)
			VALUES ('%s', 'control_plane.apply', 'app_target', 'target-1', 'id-1', 'session', '%s', 'operational', 'resumable', 'plan-%s', 1, 1)`, id, state, id),
	}
}

func TestMigration000013RefusesOpenRouteJobs(t *testing.T) {
	ctx := context.Background()
	intent := `INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, dispatched_at)
		VALUES ('intent-1', 'job-1', 'dns', 1, 'recorded', 'dns.create', 'app_target', 'target-1', 'marker-1', 9, 8)`
	for name, setup := range map[string][]string{
		"queued expose":                  routeJobAt12("job-1", "app_route.expose", "queued"),
		"running unexpose":               routeJobAt12("job-1", "app_route.unexpose", "running"),
		"interrupted expose":             routeJobAt12("job-1", "app_route.expose", "interrupted"),
		"succeeded job with open intent": append(routeJobAt12("job-1", "app_route.expose", "succeeded"), intent),
	} {
		t.Run(name, func(t *testing.T) {
			db := nodeRoutesWorld(t, append([]string{routeAt12("one", 8001, "active", "NULL", "dns-1", "")}, setup...)...)
			before := routesStateOf(t, db)
			err := db.Migrate(ctx)
			if err == nil || !strings.Contains(err.Error(), routeJobGuidance) {
				t.Fatalf("Migrate: err = %v, want the guidance", err)
			}
			if after := routesStateOf(t, db); after != before {
				t.Errorf("a refused migration changed the database (schema version, rows or triggers)")
			}
			if n := scalar[int](t, db.Reader(), `SELECT max(version) FROM schema_migrations`); n != 12 {
				t.Errorf("schema version = %d, want 12", n)
			}
		})
	}
}

func TestMigration000013TerminalRouteJobsMigrate(t *testing.T) {
	var setup []string
	for i, state := range []string{"succeeded", "failed", "cancelled"} {
		setup = append(setup, routeJobAt12(fmt.Sprintf("job-%d", i), "app_route.expose", state)...)
	}
	setup = append(setup, routeJobAt12("job-q", "app_target.deploy", "queued")...) // an open job of another plan action is not this guard's business
	db := nodeRoutesWorld(t, setup...)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if n := scalar[int](t, db.Reader(), `SELECT max(version) FROM schema_migrations`); n != 13 {
		t.Errorf("schema version = %d, want 13", n)
	}
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM sqlite_master WHERE name LIKE 'node_routes_jobs_%'`); n != 0 {
		t.Errorf("guard objects left behind: %d", n)
	}
}

func TestMigration000013WaitingRoutesDoNotBlockOnPort(t *testing.T) {
	db := nodeRoutesWorld(t,
		routeAt12("one", 8001, "active", "NULL", "dns-1", ""),
		routeAt12("two", 8001, "waiting", "NULL", "", ""),
	)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
}

func TestNodeRoutesTriggersAndIndexes(t *testing.T) {
	ctx := context.Background()
	db := nodeRoutesWorld(t, routeAt12("route-1", 8001, "active", "NULL", "dns-1", ""))
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		exec := func(stmt string) error { _, err := tx.ExecContext(ctx, stmt); return err }
		for _, set := range []string{"hostname = 'x.example.com'", "port = 9", "node_id = 'node-2'", "access = 'public'", "tunnel_generation = 4"} {
			if err := exec(`UPDATE node_routes SET ` + set + ` WHERE id = 'route-1'`); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
				t.Errorf("UPDATE %s: err = %v", set, err)
			}
		}
		if err := exec(`UPDATE node_routes SET dns_record_id = 'dns-2' WHERE id = 'route-1'`); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
			t.Errorf("a recorded DNS record ID changed: err = %v", err)
		}
		for _, set := range []string{"phase = 'removing'", "last_error = 'x'", "updated_at = 7"} {
			if err := exec(`UPDATE node_routes SET ` + set + ` WHERE id = 'route-1'`); err != nil {
				t.Errorf("UPDATE %s: %v", set, err)
			}
		}

		insert := func(id string, port int, host string) error {
			return exec(fmt.Sprintf(`INSERT INTO node_routes (id, node_id, hostname, port, access, phase, phase_started_at, account_id, zone,
				instance_id, tunnel_id, tunnel_generation, created_by, created_at, updated_at)
				VALUES ('%s', 'node-1', '%s', %d, 'public', 'provisioning', 1, 'acct', 'example.com', 'inst', 'tun-1', 1, 'id-1', 1, 1)`, id, host, port))
		}
		if err := insert("route-2", 8001, "other.example.com"); err == nil || !strings.Contains(err.Error(), "UNIQUE") {
			t.Errorf("a second live route on the node port: err = %v", err)
		}
		if err := insert("route-2", 8002, "other.example.com"); err != nil {
			t.Errorf("another port: %v", err)
		}
		for _, p := range [][2]string{{"removing", "dns_removed"}, {"dns_removed", "ingress_removed"}, {"ingress_removed", "removed"}} {
			if err := exec(fmt.Sprintf(`UPDATE node_routes SET phase = '%s' WHERE id = 'route-1' AND phase = '%s'`, p[1], p[0])); err != nil {
				t.Fatal(err)
			}
		}
		if err := exec(`UPDATE node_routes SET phase = 'active' WHERE id = 'route-1'`); err == nil || !strings.Contains(err.Error(), "does not change phase") {
			t.Errorf("a removed route changed phase: err = %v", err)
		}
		if err := insert("route-3", 8001, "third.example.com"); err != nil {
			t.Errorf("a removed route must release its port: %v", err)
		}
		return fmt.Errorf("rollback")
	})
	if err == nil || err.Error() != "rollback" {
		t.Fatal(err)
	}
}
