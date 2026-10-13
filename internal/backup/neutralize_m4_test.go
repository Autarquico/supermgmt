package backup_test

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// seedDeployments adds one deployment per interesting state, each next to the
// job that executes it, and returns nothing: the test reads them back by id.
func (s *site) seedDeployments() {
	s.t.Helper()
	now := s.clock.Now().UnixMilli()
	s.exec(`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', ?)`, now)
	s.exec(`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', ?, ?)`, now, now)
	s.exec(`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
		VALUES ('node-1', 'prov-1', 'n', 'n', 'host', 'managed', 'unknown', ?, ?)`, now, now)
	s.exec(`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`)
	s.exec(`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
		VALUES ('app-1', 'web', 'web', '{}', 'control-plane', ?, ?)`, now, now)
	s.exec(`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
		VALUES ('target-1', 'app-1', 'env-1', 'node-1', 'web-prod', '{}', ?, ?)`, now, now)

	deployment := func(id, state, jobID string, mutated int) {
		var job any
		if jobID != "" {
			job = jobID
			s.exec(`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class,
				lease_owner, lease_generation, lease_until, scheduled_at, created_at)
				VALUES (?, 'deployment.create', 'deployment', ?, 'id-1', 'session', ?, 'high', 'resumable',
				'worker-1', 1, ?, ?, ?)`, jobID, id, jobState(state), now+3_600_000, now, now)
			s.exec(`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at)
				VALUES ('app_target', 'lock-'||?, ?, 'exclusive', ?)`, id, jobID, now)
		}
		s.exec(`INSERT INTO deployments (id, kind, app_id, app_target_id, environment_id, node_id, job_id, state, requested_by,
			commit_sha, requested_json, credential_kind, mutation_started, created_at, updated_at)
			VALUES (?, 'deploy', 'app-1', 'target-1', 'env-1', 'node-1', ?, ?, 'id-1', 'c', '{}', 'session', ?, ?, ?)`,
			id, job, state, mutated, now, now)
	}
	deployment("dep-created", "created", "", 0)
	deployment("dep-waiting-ci", "waiting_ci", "", 0)
	deployment("dep-awaiting-approval", "awaiting_approval", "job-awaiting", 0)
	deployment("dep-queued", "queued", "job-queued", 0)
	deployment("dep-deploying", "deploying", "job-deploying", 1)
	deployment("dep-succeeded", "succeeded", "job-succeeded", 1)
	s.exec(`UPDATE deployments SET known_good = 1, finished_at = ? WHERE id = 'dep-succeeded'`, now)
	s.exec(`UPDATE deployments SET recovery_mode = 'forward', resume_step = 'deploy' WHERE id = 'dep-deploying'`)
	s.exec(`INSERT INTO operation_intents (id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, deadline_at, dispatched_at)
		VALUES ('intent-deploying', 'job-deploying', 'deploy', 1, 'recorded', 'compose up', 'node', 'node-1', 'marker', ?, ?)`, now+60_000, now)
}

func jobState(deploymentState string) string {
	switch deploymentState {
	case "awaiting_approval":
		return "awaiting_approval"
	case "queued":
		return "queued"
	case "succeeded":
		return "succeeded"
	}
	return "running"
}

func TestRestoreNeutralizesDeployments(t *testing.T) {
	clock := domaintest.NewFakeClock(epoch)
	ids := domaintest.NewSequentialIDs()
	src := newSite(t, "source", clock, ids).withSecrets()
	src.seedDeployments()
	tg := newTarget(t, src, src.archive())
	if err := backup.Restore(context.Background(), tg.options()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	db := openDB(t, tg.dbPath, tg.clock)
	restoredAt := src.clock.Now().UnixMilli()

	type row struct {
		state, reason string
		mutated       int
		finishedAt    *int64
		recovery      *string
	}
	read := func(id string) row {
		var r row
		var reason *string
		if err := db.Reader().QueryRowContext(context.Background(),
			`SELECT state, state_reason, mutation_started, finished_at, recovery_mode FROM deployments WHERE id = ?`, id).
			Scan(&r.state, &reason, &r.mutated, &r.finishedAt, &r.recovery); err != nil {
			t.Fatal(err)
		}
		if reason != nil {
			r.reason = *reason
		}
		return r
	}

	for _, id := range []string{"dep-created", "dep-waiting-ci", "dep-awaiting-approval", "dep-queued"} {
		got := read(id)
		if got.state != "failed" || got.reason != string(smerr.ReasonRestoredUndispatched) ||
			got.finishedAt == nil || *got.finishedAt != restoredAt {
			t.Errorf("%s = %+v, want failed RESTORED_UNDISPATCHED finished at restore time", id, got)
		}
	}

	held := read("dep-deploying")
	if held.state != "interrupted" || held.mutated != 1 || held.recovery == nil || *held.recovery != "forward" || held.finishedAt != nil {
		t.Errorf("dep-deploying = %+v, want interrupted, mutation recorded, recovery record kept, not finished", held)
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM resource_locks WHERE job_id = 'job-deploying'`); n != 1 {
		t.Error("the dispatched deployment lost its lock")
	}

	done := read("dep-succeeded")
	if done.state != "succeeded" || done.finishedAt == nil {
		t.Errorf("a terminal deployment changed: %+v", done)
	}
	if n := scalar[int](t, db, `SELECT known_good FROM deployments WHERE id = 'dep-succeeded'`); n != 1 {
		t.Error("restore dropped the known-good flag")
	}
	if n := scalar[int](t, db, `SELECT count(*) FROM events WHERE action = 'backup.restore' AND data_json LIKE '%"deployments_failed":4%'`); n != 1 {
		t.Error("the restore event does not count the failed deployments")
	}
}
