package database

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// m4Baselines are valid rows for the M4 tables (foreign keys are deferred by the helpers).
func m4Baselines() map[string]map[string]any {
	return map[string]map[string]any{
		"repositories": {
			"id": idA, "provider_id": idA, "github_repository_id": 1, "github_owner_id": 2, "owner": "o",
			"name": "r", "url": "https://github.com/o/r", "default_branch": "main", "created_at": 1, "updated_at": 1,
		},
		"apps": {
			"id": idA, "name": "web", "deployed_service": "web", "image_policy_json": "{}",
			"compose_source": "control-plane", "created_at": 1, "updated_at": 1,
		},
		"app_targets": {
			"id": idA, "app_id": idA, "environment_id": idA, "node_id": idA, "compose_project": "web-prod",
			"deployment_policy_json": "{}", "created_at": 1, "updated_at": 1,
		},
		"artifacts": {
			"id": idA, "app_id": idA, "type": "oci_image", "immutable_ref": "ghcr.io/o/r@sha256:aa",
			"digest": "sha256:aa", "commit_sha": "c", "provenance_json": "{}", "provenance_method": "attestation",
			"created_at": 1,
		},
		"artifact_checks": {"artifact_id": idA, "check_name": "ci", "app_id": 15368, "conclusion": "success"},
		"github_oidc_credentials": {
			"id": idA, "identity_id": idA, "repository_id": 1, "claims_json": "{}", "issued_at": 1,
			"expires_at": 2, "created_at": 1,
		},
		"deployments": {
			"id": idA, "kind": "deploy", "app_id": idA, "app_target_id": idA, "environment_id": idA,
			"node_id": idA, "state": "created", "requested_by": idA, "commit_sha": "c", "requested_json": "{}",
			"credential_kind": "session", "created_at": 1, "updated_at": 1,
		},
		"deployment_steps": {"id": idA, "deployment_id": idA, "ordinal": 1, "name": "pull", "state": "pending"},
		"health_checks": {
			"id": idA, "resource_type": "app_target", "resource_id": idA, "type": "http", "scope": "node",
			"config_json": "{}", "created_at": 1,
		},
		"webhook_deliveries": {
			"id": idA, "provider": "github", "delivery_id": "d1", "received_at": 1, "signature_valid": 1,
		},
		"execution_snapshots": {"hash": "sha256:aa", "kind": "manifest", "content": "x", "created_at": 1},
	}
}

func TestM4BaselineRowsAreValid(t *testing.T) {
	db := migratedTest(t)
	for table, row := range m4Baselines() {
		if err := tryInsert(t, db, table, row); err != nil {
			t.Errorf("%s baseline rejected: %v", table, err)
		}
	}
}

func TestM4ChecksRejectInvalidValues(t *testing.T) {
	db := migratedTest(t)
	cases := []struct {
		table, column string
		value         any
	}{
		{"apps", "compose_source", "git"},
		{"artifacts", "type", "tarball"},
		{"artifacts", "digest", "md5:aa"},
		{"artifacts", "provenance_method", "trust_me"},
		{"deployments", "kind", "upgrade"},
		{"deployments", "state", "paused"},
		{"deployments", "credential_kind", "cookie"},
		{"deployments", "known_good", 2},
		{"deployments", "mutation_started", 2},
		{"deployments", "recovery_mode", "backward"},
		{"deployment_steps", "state", "waiting"},
		{"health_checks", "resource_type", "node"},
		{"health_checks", "type", "command-template"},
		{"health_checks", "scope", "cluster"},
		{"health_checks", "enabled", 2},
		{"webhook_deliveries", "signature_valid", 2},
		{"execution_snapshots", "kind", "secrets"},
	}
	for _, tc := range cases {
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			err := tryInsert(t, db, tc.table, override(m4Baselines()[tc.table], tc.column, tc.value))
			if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
				t.Fatalf("err = %v, want CHECK failure", err)
			}
		})
	}
}

func TestM4DeploymentStatesMatchTheStateMachine(t *testing.T) {
	db := migratedTest(t)
	for _, state := range []string{
		"created", "waiting_ci", "awaiting_approval", "queued", "preparing", "staging", "deploying",
		"verifying", "rolling_back", "interrupted", "succeeded", "failed", "rolled_back",
		"rollback_failed", "cancelled",
	} {
		if err := tryInsert(t, db, "deployments", override(m4Baselines()["deployments"], "state", state)); err != nil {
			t.Errorf("state %q rejected: %v", state, err)
		}
	}
}

func TestM4UniquenessRules(t *testing.T) {
	db := migratedTest(t)
	b := m4Baselines()
	cases := []struct {
		name  string
		table string
		dup   map[string]any
	}{
		{"repository per provider", "repositories", override(b["repositories"], "id", idB)},
		{"app name", "apps", override(b["apps"], "id", idB)},
		{"project per node", "app_targets", override(override(b["app_targets"], "id", idB), "app_id", idB)},
		{"one target per app and environment", "app_targets", override(override(b["app_targets"], "id", idB), "compose_project", "other")},
		{"check name per artifact", "artifact_checks", b["artifact_checks"]},
		{"one deployment per job", "deployments", override(b["deployments"], "id", idB)},
		{"step attempt", "deployment_steps", override(b["deployment_steps"], "id", idB)},
		{"webhook delivery", "webhook_deliveries", override(b["webhook_deliveries"], "id", idB)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := b[tc.table]
			if tc.table == "deployments" {
				first = override(first, "job_id", idA)
				tc.dup = override(tc.dup, "job_id", idA)
			}
			err := inRolledBackTx(t, db, func(ctx context.Context, tx *Tx) error {
				if err := insertRow(ctx, tx, tc.table, first); err != nil {
					t.Fatalf("first insert: %v", err)
				}
				return insertRow(ctx, tx, tc.table, tc.dup)
			})
			if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
				t.Fatalf("err = %v, want UNIQUE failure", err)
			}
		})
	}
}

func TestM4DeploymentsMayShareNoJobButManyMayHaveNone(t *testing.T) {
	db := migratedTest(t)
	err := inRolledBackTx(t, db, func(ctx context.Context, tx *Tx) error {
		if err := insertRow(ctx, tx, "deployments", m4Baselines()["deployments"]); err != nil {
			return err
		}
		return insertRow(ctx, tx, "deployments", override(m4Baselines()["deployments"], "id", idB))
	})
	if err != nil {
		t.Fatalf("two provisional deployments without a job: %v", err)
	}
}

func TestM4RecoveryRecordCheck(t *testing.T) {
	db := migratedTest(t)
	base := m4Baselines()["deployments"]
	with := func(kv ...any) map[string]any {
		row := cloneRow(base)
		for i := 0; i < len(kv); i += 2 {
			row[kv[i].(string)] = kv[i+1]
		}
		return row
	}
	cases := []struct {
		name string
		row  map[string]any
		ok   bool
	}{
		{"no recovery record", with(), true},
		{"forward without target", with("recovery_mode", "forward"), true},
		{"safety recovery with target", with("recovery_mode", "safety_recovery", "recovery_target_deployment_id", idB), true},
		{"safety recovery without target", with("recovery_mode", "safety_recovery"), false},
		{"forward with target", with("recovery_mode", "forward", "recovery_target_deployment_id", idB), false},
		{"target without mode", with("recovery_target_deployment_id", idB), false},
		{"cause with reason", with("state_reason", "DEPLOYMENT_FAILED", "state_cause", "STATEFUL"), true},
		{"cause without reason", with("state_cause", "STATEFUL"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tryInsert(t, db, "deployments", tc.row)
			if tc.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "CHECK constraint failed")) {
				t.Fatalf("err = %v, want CHECK failure", err)
			}
		})
	}
}

func TestM4ForeignKeysAreEnforced(t *testing.T) {
	db := migratedTest(t)
	for _, table := range []string{"repositories", "apps", "app_targets", "deployments", "deployment_steps", "artifact_checks"} {
		row := cloneRow(m4Baselines()[table])
		if table == "apps" {
			row["repository_id"] = idB
		}
		err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
			return insertRow(ctx, tx, table, row)
		})
		if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
			t.Errorf("%s: err = %v, want FOREIGN KEY failure", table, err)
		}
	}
}

func TestM4ImmutabilityTriggers(t *testing.T) {
	db := migratedTest(t)
	b := m4Baselines()
	cases := []struct {
		name, table, mutation string
		wantErr               string
	}{
		{"project rename", "app_targets", `UPDATE app_targets SET compose_project = 'renamed'`, "compose_project is immutable"},
		{"artifact update", "artifacts", `UPDATE artifacts SET commit_sha = 'x'`, "artifacts are immutable"},
		{"artifact delete", "artifacts", `DELETE FROM artifacts`, "artifacts are immutable"},
		{"snapshot update", "execution_snapshots", `UPDATE execution_snapshots SET content = 'y'`, "snapshots are immutable"},
		{"snapshot delete", "execution_snapshots", `DELETE FROM execution_snapshots`, "snapshots are immutable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inRolledBackTx(t, db, func(ctx context.Context, tx *Tx) error {
				if err := insertRow(ctx, tx, tc.table, b[tc.table]); err != nil {
					t.Fatalf("insert: %v", err)
				}
				_, err := tx.ExecContext(ctx, tc.mutation)
				return err
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestM4AppTargetOtherColumnsStayMutable(t *testing.T) {
	db := migratedTest(t)
	err := inRolledBackTx(t, db, func(ctx context.Context, tx *Tx) error {
		if err := insertRow(ctx, tx, "app_targets", m4Baselines()["app_targets"]); err != nil {
			t.Fatalf("insert: %v", err)
		}
		_, err := tx.ExecContext(ctx, `UPDATE app_targets SET spec_revision = 2, compose_project = compose_project`)
		return err
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
}

// inRolledBackTx runs fn with foreign keys deferred, rolls back, and returns fn's error.
func inRolledBackTx(t *testing.T, db *DB, fn func(context.Context, *Tx) error) error {
	t.Helper()
	var fnErr error
	_ = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
			t.Fatal(err)
		}
		fnErr = fn(ctx, tx)
		return fmt.Errorf("rollback")
	})
	return fnErr
}
