package database

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/migrations"
)

const (
	deploymentsGuidance = "let it finish (or cancel it) with the previous SuperMgmt version before upgrading"
	deployerRoleID      = "01970000-0000-7000-8000-000000000003"
	operatorRoleID      = "01970000-0000-7000-8000-000000000002"
	githubActionsIssuer = "https://token.actions.githubusercontent.com"
	deploymentTables    = `'deployments', 'deployment_steps', 'health_checks', 'apps', 'app_targets', 'repositories', 'artifacts', 'artifact_checks',
		'github_oidc_credentials', 'webhook_deliveries', 'execution_snapshots'`
)

func jobRow(id, jobType, resource, resourceID, state string) string {
	return fmt.Sprintf(`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, payload_json, plan_id, scheduled_at, created_at)
		VALUES ('%s', '%s', '%s', '%s', 'id-1', 'session', '%s', 'operational', 'resumable', '{}', 'plan-%s', 1, 1)`, id, jobType, resource, resourceID, state, id)
}

func planRow(id, action string) string {
	return fmt.Sprintf(`INSERT INTO plans (id, action, actor_id, credential_kind, plan_json, plan_hash, finalized_at, created_at, expires_at)
		VALUES ('plan-%s', '%s', 'id-1', 'session', '{}', 'sha256:%s', 1, 1, 2)`, id, action, id)
}

func lockRow(job string) string {
	return fmt.Sprintf(`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES ('app_target', 'lock-%s', '%s', 'exclusive', 1)`, job, job)
}

func deploymentRow(id, state string) string {
	return fmt.Sprintf(`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, state, requested_by, commit_sha, requested_json, credential_kind, created_at, updated_at)
		VALUES ('%s', 'deploy', 'app-1', 'target-1', 'env-1', 'node-1', '%s', 'id-1', 'abc', '{}', 'session', 1, 1)`, id, state)
}

// deploymentsWorld seeds a database at schema 13 the way a finished M4 instance looks: an app with an automation
// identity that holds role bindings, a GitHub OIDC credential of a second automation identity, a deployer binding,
// a GitHub and an SSH provider, terminal deployments with their jobs and locks, and the events they left.
func deploymentsWorld(t *testing.T, extra ...string) *DB {
	t.Helper()
	db := migratedTo(t, 13)
	seed := []string{
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`,
		`INSERT INTO identities (id, actor_type, issuer, subject, created_at) VALUES ('id-auto', 'automation', '` + githubActionsIssuer + `', 'repo:acme/web', 1)`,
		`INSERT INTO identities (id, actor_type, issuer, subject, created_at) VALUES ('id-oidc', 'automation', '` + githubActionsIssuer + `', 'repo:acme/api', 1)`,
		// the app was unlinked and the identity never exchanged a token
		`INSERT INTO identities (id, actor_type, issuer, subject, created_at) VALUES ('id-ci', 'automation', '` + githubActionsIssuer + `', 'repo:acme/old', 1)`,
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-bot', 'automation', 'unrelated-bot', 1)`,
		fmt.Sprintf(`INSERT INTO role_bindings (id, identity_id, role_id, created_at) VALUES
			('rb-1', 'id-1', '%[1]s', 1), ('rb-2', 'id-1', '%[2]s', 1), ('rb-3', 'id-auto', '%[1]s', 1),
			('rb-4', 'id-oidc', '%[1]s', 1), ('rb-5', 'id-auto', '%[2]s', 1), ('rb-6', 'id-bot', '%[2]s', 1), ('rb-7', 'id-ci', '%[2]s', 1)`, deployerRoleID, operatorRoleID),
		`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', 1, 1)`,
		`INSERT INTO providers (id, type, name, origin, credential_ref, created_at, updated_at)
			VALUES ('prov-gh', 'github', 'gh', 'api', 'secret://providers/gh/token', 1, 1)`,
		`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
			VALUES ('node-1', 'prov-1', 'n1', 'n1', 'host', 'managed', 'unknown', 1, 1)`,
		`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`,
		`INSERT INTO repositories (id, provider_id, github_repository_id, github_owner_id, owner, name, url, default_branch, created_at, updated_at)
			VALUES ('repo-1', 'prov-gh', 42, 7, 'acme', 'web', 'https://github.com/acme/web', 'main', 1, 1)`,
		`INSERT INTO apps (id, name, repository_id, deployed_service, image_policy_json, compose_source, automation_identity_id, created_at, updated_at)
			VALUES ('app-1', 'web', 'repo-1', 'web', '{}', 'control-plane', 'id-auto', 1, 1)`,
		`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
			VALUES ('target-1', 'app-1', 'env-1', 'node-1', 'web-prod', '{}', 1, 1)`,
		`INSERT INTO github_oidc_credentials (id, identity_id, repository_id, claims_json, issued_at, expires_at, created_at)
			VALUES ('cred-1', 'id-oidc', 42, '{}', 1, 2, 1)`,
		`INSERT INTO node_capabilities (node_id, capability, available, checked_at)
			VALUES ('node-1', 'docker.compose.deploy', 1, 1), ('node-1', 'health.http', 1, 1), ('node-1', 'health.tcp', 1, 1),
			       ('node-1', 'docker.inventory', 1, 1)`,
		deploymentRow("dep-1", "succeeded"), deploymentRow("dep-2", "rolled_back"), deploymentRow("dep-3", "cancelled"),
		planRow("job-d", "deployment.create"), jobRow("job-d", "deployment.create", "app_target", "target-1", "succeeded"), lockRow("job-d"),
		planRow("job-r", "deployment.rollback"), jobRow("job-r", "deployment.rollback", "app_target", "target-1", "failed"), lockRow("job-r"),
		planRow("job-a", "app.write"), jobRow("job-a", "control_plane.apply", "app", "app-1", "succeeded"), lockRow("job-a"),
		// an unrelated job keeps its lock
		planRow("job-n", "node.probe"), jobRow("job-n", "node.probe", "node", "node-1", "running"),
		`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES ('node', 'node-1', 'job-n', 'shared', 1)`,
		`INSERT INTO events (event_id, timestamp, actor_type, actor_id, source, action, resource_type, resource_id, severity, result, data_json)
			VALUES ('ev-1', 5, 'human', 'id-1', 'api', 'deployment.created', 'deployment', 'dep-1', 'info', 'succeeded', '{"commit":"abc"}'),
			       ('ev-2', 6, 'automation', 'id-auto', 'webhook', 'webhook.received', 'app', 'app-1', 'info', 'succeeded', '{}'),
			       ('ev-3', 7, 'human', 'id-1', 'api', 'app.write', 'app', 'app-1', 'info', 'succeeded', '{}'),
			       ('ev-4', 8, 'human', 'id-1', 'api', 'app_target.write', 'app_target', 'target-1', 'info', 'succeeded', '{}')`,
	}
	execAll(t, db, append(seed, extra...)...)
	return db
}

// deploymentsStateOf is everything a refused migration must leave alone.
func deploymentsStateOf(t *testing.T, db *DB) string {
	t.Helper()
	r := db.Reader()
	var b strings.Builder
	fmt.Fprintf(&b, "version=%d\n", scalar[int](t, r, `SELECT max(version) FROM schema_migrations`))
	b.WriteString(dump(t, r, `SELECT type, name, sql FROM sqlite_master ORDER BY type, name`))
	for _, table := range []string{
		"deployments", "apps", "app_targets", "github_oidc_credentials", "jobs", "plans", "resource_locks",
		"operation_intents", "identities", "role_bindings", "roles", "providers", "events",
	} {
		fmt.Fprintf(&b, "-- %s\n%s", table, dump(t, r, `SELECT * FROM `+table))
	}
	return b.String()
}

func TestMigration000014OnAnEmptyDatabase(t *testing.T) {
	db := migratedTo(t, 14)
	r := db.Reader()
	for query, want := range map[string]int{
		`SELECT max(version) FROM schema_migrations`:                                  14,
		`SELECT count(*) FROM sqlite_master WHERE name IN (` + deploymentTables + `)`: 0,
		`SELECT count(*) FROM sqlite_master WHERE name LIKE 'retire_deployments%'`:    0,
		`SELECT count(*) FROM roles WHERE name = 'deployer'`:                          0,
		`SELECT count(*) FROM roles`:                                                  3,
		`SELECT count(*) FROM pragma_foreign_key_check`:                               0,
	} {
		if got := scalar[int](t, r, query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}
}

func TestMigration000014RefusesOpenWorkAndChangesNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup []string
	}{
		{"a deployment created", []string{deploymentRow("dep-x", "created")}},
		{"a deployment waiting for CI", []string{deploymentRow("dep-x", "waiting_ci")}},
		{"a deployment awaiting approval", []string{deploymentRow("dep-x", "awaiting_approval")}},
		{"a deployment queued", []string{deploymentRow("dep-x", "queued")}},
		{"a deployment deploying", []string{deploymentRow("dep-x", "deploying")}},
		{"a deployment interrupted", []string{deploymentRow("dep-x", "interrupted")}},
		{"a deployment rolling back", []string{deploymentRow("dep-x", "rolling_back")}},
		{"a running deployment.create job", []string{planRow("x", "deployment.create"), jobRow("x", "deployment.create", "app_target", "target-1", "running"), lockRow("x")}},
		{"a queued deployment.rollback job", []string{planRow("x", "deployment.rollback"), jobRow("x", "deployment.rollback", "app_target", "target-1", "queued")}},
		{"an interrupted deployment job", []string{planRow("x", "deployment.create"), jobRow("x", "deployment.create", "app_target", "target-1", "interrupted")}},
		{"an app.write awaiting approval", []string{planRow("x", "app.write"), jobRow("x", "control_plane.apply", "app", "app-1", "awaiting_approval")}},
		{"an app_target.write queued", []string{planRow("x", "app_target.write"), jobRow("x", "control_plane.apply", "app_target", "target-1", "queued")}},
		{"a GitHub provider.write running", []string{
			planRow("x", "provider.write"),
			`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, payload_json, plan_id, scheduled_at, created_at)
				VALUES ('x', 'control_plane.apply', 'provider', 'prov-gh', 'id-1', 'session', 'running', 'operational', 'idempotent', '{"api_url":"https://api.github.com"}', 'plan-x', 1, 1)`,
		}},
		{"a terminal deployment job with an intent not completed", []string{
			`INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, dispatched_at)
				VALUES ('intent-1', 'job-d', 'deploy', 1, 'recorded', 'compose up', 'deployment', 'dep-1', 'marker-1', 9, 8)`,
		}},
		{"a terminal app.write job with an intent not completed", []string{
			`INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, dispatched_at)
				VALUES ('intent-1', 'job-a', 'apply', 1, 'recorded', 'app.write', 'app', 'app-1', 'marker-1', 9, 8)`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := deploymentsWorld(t, tc.setup...)
			before := deploymentsStateOf(t, db)
			err := db.Migrate(context.Background())
			if err == nil || !strings.Contains(err.Error(), deploymentsGuidance) {
				t.Fatalf("Migrate: err = %v, want the guidance %q", err, deploymentsGuidance)
			}
			if after := deploymentsStateOf(t, db); after != before {
				t.Errorf("a refused migration changed the database\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if err := db.Migrate(context.Background()); err == nil {
				t.Error("second Migrate succeeded")
			}
		})
	}
}

func TestMigration000014IgnoresOpenWorkOfOtherActions(t *testing.T) {
	db := deploymentsWorld(t,
		planRow("local", "provider.write"),
		`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, payload_json, plan_id, scheduled_at, created_at)
			VALUES ('local', 'control_plane.apply', 'provider', 'prov-1', 'id-1', 'session', 'queued', 'operational', 'idempotent', '{"node_id":"n"}', 'plan-local', 1, 1)`,
		planRow("probe", "node.probe"), jobRow("probe", "node.probe", "node", "node-1", "queued"),
	)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
}

func TestMigration000014RetiresAFinishedInstanceAndKeepsItsAudit(t *testing.T) {
	db := deploymentsWorld(t)
	r := db.Reader()
	jobsBefore := dump(t, r, `SELECT * FROM jobs ORDER BY id`)
	plansBefore := dump(t, r, `SELECT * FROM plans ORDER BY id`)
	eventsBefore := dump(t, r, `SELECT * FROM events ORDER BY seq`)
	bindingsOfOthers := dump(t, r, `SELECT * FROM role_bindings WHERE identity_id IN ('id-1', 'id-bot') AND role_id <> '`+deployerRoleID+`' ORDER BY id`)

	if err := MigrateUpTo(context.Background(), db, 14); err != nil {
		t.Fatalf("MigrateUpTo 14: %v", err)
	}

	for query, want := range map[string]int{
		`SELECT max(version) FROM schema_migrations`:                                                                              14,
		`SELECT count(*) FROM sqlite_master WHERE name IN (` + deploymentTables + `)`:                                             0,
		`SELECT count(*) FROM sqlite_master WHERE name LIKE 'retire_deployments%'`:                                                0,
		`SELECT count(*) FROM resource_locks WHERE job_id IN ('job-d', 'job-r', 'job-a')`:                                         0,
		`SELECT count(*) FROM resource_locks WHERE job_id = 'job-n'`:                                                              1,
		`SELECT count(*) FROM providers WHERE type = 'github'`:                                                                    0,
		`SELECT count(*) FROM providers WHERE type = 'ssh'`:                                                                       1,
		`SELECT count(*) FROM roles WHERE name = 'deployer'`:                                                                      0,
		`SELECT count(*) FROM role_bindings WHERE role_id = '` + deployerRoleID + `'`:                                             0,
		`SELECT count(*) FROM role_bindings WHERE identity_id IN ('id-auto', 'id-oidc', 'id-ci')`:                                 0,
		`SELECT count(*) FROM identities WHERE id IN ('id-auto', 'id-oidc', 'id-ci') AND disabled_at IS NOT NULL`:                 3,
		`SELECT count(*) FROM identities`:                                                                                         5,
		`SELECT count(*) FROM node_capabilities WHERE capability IN ('docker.compose.deploy', 'health.http', 'health.tcp')`:       0,
		`SELECT count(*) FROM node_capabilities WHERE capability = 'docker.inventory'`:                                            1,
		`SELECT count(*) FROM identities WHERE id IN ('id-1', 'id-bot') AND disabled_at IS NULL`:                                  2,
		`SELECT count(*) FROM pragma_foreign_key_check`:                                                                           0,
		`SELECT count(*) FROM events WHERE action IN ('deployment.created', 'webhook.received', 'app.write', 'app_target.write')`: 4,
	} {
		if got := scalar[int](t, r, query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}
	for name, pair := range map[string][2]string{
		"jobs":   {jobsBefore, dump(t, r, `SELECT * FROM jobs ORDER BY id`)},
		"plans":  {plansBefore, dump(t, r, `SELECT * FROM plans ORDER BY id`)},
		"events": {eventsBefore, dump(t, r, `SELECT * FROM events ORDER BY seq`)},
		"the bindings of other identities": {
			bindingsOfOthers,
			dump(t, r, `SELECT * FROM role_bindings WHERE identity_id IN ('id-1', 'id-bot') ORDER BY id`),
		},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s changed\nbefore:\n%s\nafter:\n%s", name, pair[0], pair[1])
		}
	}
}

func TestMigration000014RefusalTextIsWhatRestoreMatches(t *testing.T) {
	sql, err := fs.ReadFile(migrations.FS, "000014_retire_deployments.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sql), "'"+UnfinishedDeploymentRefusal) {
		t.Errorf("migration 000014 does not abort with a message starting %q", UnfinishedDeploymentRefusal)
	}
}

func TestMigration000014KeepsTheSecretsOfAGitHubProvider(t *testing.T) {
	db := deploymentsWorld(t)
	var secrets int
	if err := db.Reader().QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_master WHERE name = 'secrets'`).Scan(&secrets); err != nil || secrets != 1 {
		t.Fatalf("secrets table: %d, %v", secrets, err)
	}
	execAll(t, db, `INSERT INTO secrets (id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext, created_at)
		VALUES ('sec-1', 'providers/gh/token', 1, 1, 'kek', x'00', x'00', 1)`)

	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if n := scalar[int](t, db.Reader(), `SELECT count(*) FROM secrets WHERE name = 'providers/gh/token'`); n != 1 {
		t.Errorf("the GitHub token secret was removed (%d rows)", n)
	}
}

// The databases written by the real M4 and M5 binaries (test/fixtures/migrations) hold the app.write and
// app_target.write events of a fixture app and no deployment: they migrate and the audit stays readable.
func TestMigration000014MigratesTheShippedFixtures(t *testing.T) {
	for _, milestone := range []string{"m4", "m5"} {
		t.Run(milestone, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"sm.db", "sm.db-wal", "sm.db-shm"} {
				data, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "migrations", milestone, name))
				if errors.Is(err, fs.ErrNotExist) && name != "sm.db" {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			db, err := Open(context.Background(), filepath.Join(dir, "sm.db"), Options{Clock: domaintest.NewFakeClock(testEpoch)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			events := scalar[int](t, db.Reader(), `SELECT count(*) FROM events WHERE action IN ('app.write', 'app_target.write')`)

			if err := db.Migrate(context.Background()); err != nil {
				t.Fatalf("Migrate: %v", err)
			}

			r := db.Reader()
			for query, want := range map[string]int{
				`SELECT count(*) FROM sqlite_master WHERE name IN (` + deploymentTables + `)`:   0,
				`SELECT count(*) FROM events WHERE action IN ('app.write', 'app_target.write')`: events,
				`SELECT count(*) FROM pragma_foreign_key_check`:                                 0,
				`SELECT count(*) FROM roles WHERE name = 'deployer'`:                            0,
			} {
				if got := scalar[int](t, r, query); got != want {
					t.Errorf("%s = %d, want %d", query, got, want)
				}
			}
			if events == 0 {
				t.Error("the fixture holds no app.write or app_target.write event")
			}
		})
	}
}
