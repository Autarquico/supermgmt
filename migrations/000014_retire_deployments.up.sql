-- Retire deployments, apps and the GitHub connector (ADR-0043). SuperMgmt no longer deploys or tracks apps, so the
-- M4 tables go, the deployer role goes, and the automation identities that CI used lose their access.
--
-- A deployment that is not finished leaves work this version can no longer finish: a rollout may hold a stack half
-- applied and a job may have dispatched commands that were never confirmed. The migration refuses to run then, changes
-- nothing, and tells the operator to let it finish with the previous version. Only succeeded, failed, rolled_back,
-- rollback_failed and cancelled are terminal deployment states; every other state (created, waiting_ci,
-- awaiting_approval, queued, preparing, staging, deploying, verifying, rolling_back, interrupted) is open. The jobs are selected by their type (deployment.create, deployment.rollback) or by the
-- plan of a control_plane.apply job (app.write, app_target.write and the registration of a GitHub provider).

CREATE TABLE retire_deployments_jobs (id TEXT PRIMARY KEY) STRICT;
INSERT INTO retire_deployments_jobs
SELECT id FROM jobs WHERE type IN ('deployment.create', 'deployment.rollback');
INSERT OR IGNORE INTO retire_deployments_jobs
SELECT j.id FROM jobs j JOIN plans p ON p.id = j.plan_id
WHERE j.type = 'control_plane.apply'
  AND (p.action IN ('app.write', 'app_target.write')
       OR (p.action = 'provider.write' AND json_extract(j.payload_json, '$.api_url') IS NOT NULL));

-- The guard: a row inserted into this table aborts the transaction with a fixed message, and the migration rolls back.
CREATE TABLE retire_deployments_guard (open_work INTEGER NOT NULL) STRICT;
CREATE TRIGGER retire_deployments_refuse BEFORE INSERT ON retire_deployments_guard
BEGIN SELECT RAISE(ABORT, 'a deployment is unfinished: let it finish (or cancel it) with the previous SuperMgmt version before upgrading'); END;
INSERT INTO retire_deployments_guard
SELECT 1 WHERE EXISTS (SELECT 1 FROM deployments
                       WHERE state NOT IN ('succeeded', 'failed', 'rolled_back', 'rollback_failed', 'cancelled'))
    OR EXISTS (SELECT 1 FROM jobs
               WHERE id IN (SELECT id FROM retire_deployments_jobs)
                 AND state NOT IN ('succeeded', 'failed', 'cancelled'))
    OR EXISTS (SELECT 1 FROM operation_intents
               WHERE state <> 'completed'
                 AND job_id IN (SELECT id FROM retire_deployments_jobs));
DROP TABLE retire_deployments_guard;

-- Every job left is terminal and settled: its locks are leftovers nothing will release. Jobs, plans, intents and
-- events stay as history.
DELETE FROM resource_locks WHERE job_id IN (SELECT id FROM retire_deployments_jobs);
DROP TABLE retire_deployments_jobs;

-- The automation identities CI used are disabled and lose their bindings, never deleted: jobs, plans, approvals and
-- events reference them.
CREATE TABLE retire_deployments_identities (id TEXT PRIMARY KEY) STRICT;
INSERT OR IGNORE INTO retire_deployments_identities
SELECT automation_identity_id FROM apps WHERE automation_identity_id IS NOT NULL;
INSERT OR IGNORE INTO retire_deployments_identities
SELECT identity_id FROM github_oidc_credentials;
-- An identity whose app was unlinked or re-pointed, and that never exchanged a token, is in neither table.
INSERT OR IGNORE INTO retire_deployments_identities
SELECT id FROM identities WHERE actor_type = 'automation' AND issuer = 'https://token.actions.githubusercontent.com';
UPDATE identities
SET disabled_at = COALESCE(disabled_at, CAST(strftime('%s', 'now') AS INTEGER) * 1000)
WHERE actor_type = 'automation' AND id IN (SELECT id FROM retire_deployments_identities);
DELETE FROM role_bindings
WHERE identity_id IN (SELECT id FROM identities WHERE actor_type = 'automation')
  AND identity_id IN (SELECT id FROM retire_deployments_identities);
DROP TABLE retire_deployments_identities;

-- Discovery no longer reports what deployments needed; the rows would claim a capability nothing provides.
DELETE FROM node_capabilities WHERE capability IN ('docker.compose.deploy', 'health.http', 'health.tcp');

-- The deployer role (seeded by 000001) only granted deployment actions.
DELETE FROM role_bindings WHERE role_id = '01970000-0000-7000-8000-000000000003';
DELETE FROM roles WHERE id = '01970000-0000-7000-8000-000000000003' AND name = 'deployer';

-- Children first: DROP TABLE deletes the rows under foreign key enforcement. The secrets a GitHub provider referenced
-- are not touched: they have no foreign key to it and the upgrade guide lists them for removal.
DROP TABLE deployment_steps;
DROP TABLE health_checks;
DROP TABLE deployments;
DROP TABLE artifact_checks;
DROP TABLE artifacts;
DROP TABLE app_targets;
DROP TABLE apps;
DROP TABLE repositories;
DROP TABLE github_oidc_credentials;
DROP TABLE webhook_deliveries;
DROP TABLE execution_snapshots;
DELETE FROM providers WHERE type = 'github';
