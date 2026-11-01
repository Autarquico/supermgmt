-- Move an app target to another node (ADR-0041). Conventions as in 000001 and 000007: STRICT tables, timestamps in
-- Unix milliseconds, enumerations as CHECKs. Besides the two new tables, deployments gains the kind 'move'.
-- Nothing here holds a secret: IDs, volume names, byte counts, digests and sanitized error text only.

-- deployments.kind allows 'move'. SQLite cannot alter a CHECK, so the table is rebuilt in place: its rows go to a
-- scratch table, the table is dropped and created again under the same name (deployment_steps and the self
-- references keep pointing at it by name), and the rows come back. Foreign keys are deferred for the transaction,
-- so the drop does not trip over deployment_steps; the rows put back resolve every reference before the commit.
PRAGMA defer_foreign_keys = ON;
CREATE TABLE deployments_rebuild AS SELECT * FROM deployments;
DROP TABLE deployments;
CREATE TABLE deployments (
    id                            TEXT PRIMARY KEY,
    kind                          TEXT NOT NULL CHECK (kind IN ('deploy', 'rollback', 'move')),
    app_id                        TEXT NOT NULL REFERENCES apps (id),
    app_target_id                 TEXT NOT NULL REFERENCES app_targets (id),
    environment_id                TEXT NOT NULL REFERENCES environments (id),
    node_id                       TEXT NOT NULL REFERENCES nodes (id),
    artifact_id                   TEXT REFERENCES artifacts (id),
    job_id                        TEXT REFERENCES jobs (id),
    plan_id                       TEXT REFERENCES plans (id),
    strategy                      TEXT NOT NULL DEFAULT 'docker-compose',
    state                         TEXT NOT NULL CHECK (state IN (
        'created', 'waiting_ci', 'awaiting_approval', 'queued', 'preparing', 'staging', 'deploying',
        'verifying', 'rolling_back', 'interrupted', 'succeeded', 'failed', 'rolled_back',
        'rollback_failed', 'cancelled')),
    state_code                    TEXT,
    state_reason                  TEXT,
    state_cause                   TEXT,
    requested_by                  TEXT NOT NULL REFERENCES identities (id),
    previous_deployment_id        TEXT REFERENCES deployments (id),
    rollback_of_deployment_id     TEXT REFERENCES deployments (id),
    known_good                    INTEGER NOT NULL DEFAULT 0 CHECK (known_good IN (0, 1)),
    compose_hash                  TEXT,
    plan_hash                     TEXT,
    commit_sha                    TEXT NOT NULL,
    requested_json                TEXT NOT NULL,
    credential_kind               TEXT NOT NULL CHECK (credential_kind IN (
        'local_socket', 'session', 'api_token', 'mcp_token', 'oauth_access_token', 'github_oidc')),
    credential_id                 TEXT NOT NULL DEFAULT '',
    scopes_json                   TEXT NOT NULL DEFAULT '[]',
    credential_expires_at         INTEGER,
    ci_deadline_at                INTEGER,
    next_ci_check_at              INTEGER,
    mutation_started              INTEGER NOT NULL DEFAULT 0 CHECK (mutation_started IN (0, 1)),
    recovery_mode                 TEXT CHECK (recovery_mode IN ('forward', 'safety_recovery')),
    resume_step                   TEXT,
    recovery_reason               TEXT,
    recovery_target_deployment_id TEXT REFERENCES deployments (id),
    created_at                    INTEGER NOT NULL,
    updated_at                    INTEGER NOT NULL,
    finished_at                   INTEGER,
    CHECK (state_cause IS NULL OR state_reason IS NOT NULL),
    CHECK ((recovery_target_deployment_id IS NOT NULL) = (recovery_mode IS 'safety_recovery'))
) STRICT;
CREATE INDEX deployments_by_app_env ON deployments (app_id, environment_id, created_at DESC);
CREATE INDEX deployments_waiting_ci ON deployments (state, next_ci_check_at) WHERE state = 'waiting_ci';
CREATE INDEX deployments_known_good ON deployments (app_target_id, known_good, finished_at DESC);
CREATE UNIQUE INDEX deployments_by_job ON deployments (job_id) WHERE job_id IS NOT NULL;
INSERT INTO deployments SELECT * FROM deployments_rebuild;
DROP TABLE deployments_rebuild;

-- One row per move of an app target from its node (source, "A") to another (destination, "B"). The row survives a
-- crash so a takeover resumes from the recorded phase, and it outlives the move as the record of what happened.
CREATE TABLE app_moves (
    id                      TEXT PRIMARY KEY,
    app_target_id           TEXT NOT NULL REFERENCES app_targets (id),
    source_node_id          TEXT NOT NULL REFERENCES nodes (id),
    dest_node_id            TEXT NOT NULL REFERENCES nodes (id),
    plan_id                 TEXT NOT NULL REFERENCES plans (id),    -- the plan of the job that runs the move; a resume rebinds it
    job_id                  TEXT NOT NULL REFERENCES jobs (id),
    known_good_deployment_id TEXT NOT NULL REFERENCES deployments (id), -- the content that moves
    dest_deployment_id      TEXT REFERENCES deployments (id),       -- B's deployment (kind move); NULL until staged; set once
    stateful                INTEGER NOT NULL CHECK (stateful IN (0, 1)),
    b_started_at            INTEGER,                                -- NULL until B starts for the first time; set once. From then on B may hold newer data
    phase                   TEXT NOT NULL CHECK (phase IN (
                                'preflight', 'staged', 'source_stopped', 'data_copied',         -- forward, in order (source_stopped and data_copied: stateful only)
                                'started', 'verified', 'committed', 'source_parked', 'done',
                                'compensating_b_stopped', 'compensating_source_started',        -- before committed only, in order
                                'compensating_source_verified', 'compensating_b_removed', 'rolled_back',
                                'failed', 'conflict')),             -- halted: see halted_phase
    halted_phase            TEXT CHECK (halted_phase IS NULL OR halted_phase IN (
                                'preflight', 'staged', 'source_stopped', 'data_copied',
                                'started', 'verified', 'committed', 'source_parked', 'done',
                                'compensating_b_stopped', 'compensating_source_started',
                                'compensating_source_verified', 'compensating_b_removed', 'rolled_back')), -- phase held when the move halted; NULL otherwise
    phase_started_at        INTEGER NOT NULL,
    last_error              TEXT NOT NULL DEFAULT '',               -- sanitized; never a token, header or command output
    committed_revision      INTEGER CHECK (committed_revision IS NULL OR committed_revision >= 1), -- the target revision the commit wrote; set once
    created_by              TEXT NOT NULL REFERENCES identities (id),
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    CHECK (source_node_id <> dest_node_id),
    CHECK ((phase IN ('failed', 'conflict')) = (halted_phase IS NOT NULL)),
    CHECK (stateful = 1 OR (phase NOT IN ('source_stopped', 'data_copied')
                            AND COALESCE(halted_phase, 'preflight') NOT IN ('source_stopped', 'data_copied'))),
    CHECK (phase_started_at <= updated_at)
) STRICT;
-- At most one open move per target. A halted move stays open: B or its volumes may hold data until an operator
-- resumes or abandons it.
CREATE UNIQUE INDEX app_moves_one_open ON app_moves (app_target_id) WHERE phase NOT IN ('done', 'rolled_back');
CREATE INDEX app_moves_by_target ON app_moves (app_target_id, created_at DESC);
CREATE INDEX app_moves_open_dest ON app_moves (dest_node_id) WHERE phase NOT IN ('done', 'rolled_back');
CREATE INDEX app_moves_by_job ON app_moves (job_id);
-- the identity of a move never changes; B's deployment, B's first start and the committed revision are recorded once
CREATE TRIGGER app_moves_ids_once BEFORE UPDATE OF id, app_target_id, source_node_id, dest_node_id,
        known_good_deployment_id, dest_deployment_id, stateful, b_started_at, committed_revision, created_by, created_at ON app_moves
WHEN NEW.id <> OLD.id OR NEW.app_target_id <> OLD.app_target_id OR NEW.source_node_id <> OLD.source_node_id
  OR NEW.dest_node_id <> OLD.dest_node_id OR NEW.known_good_deployment_id <> OLD.known_good_deployment_id
  OR NEW.stateful <> OLD.stateful OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at
  OR (OLD.dest_deployment_id IS NOT NULL AND NEW.dest_deployment_id IS NOT OLD.dest_deployment_id)
  OR (OLD.b_started_at IS NOT NULL AND NEW.b_started_at IS NOT OLD.b_started_at)
  OR (OLD.committed_revision IS NOT NULL AND NEW.committed_revision IS NOT OLD.committed_revision)
BEGIN SELECT RAISE(ABORT, 'an app move keeps its identity and recorded IDs'); END;
-- a finished move never changes phase again
CREATE TRIGGER app_moves_final BEFORE UPDATE OF phase ON app_moves
WHEN OLD.phase IN ('done', 'rolled_back') AND NEW.phase <> OLD.phase
BEGIN SELECT RAISE(ABORT, 'a finished app move does not change phase'); END;

-- One row per entry of the move's volume map: a distinct named volume (<project>_<volume>), copied once through
-- one service's container.
CREATE TABLE app_move_volumes (
    move_id             TEXT NOT NULL REFERENCES app_moves (id),
    volume_name         TEXT NOT NULL CHECK (volume_name <> ''),
    service             TEXT NOT NULL CHECK (service <> ''),     -- first service, in name order, that mounts the volume read-write
    mount_target        TEXT NOT NULL CHECK (mount_target <> ''),
    other_services_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(other_services_json)), -- every other service that mounts it
    attempt             INTEGER NOT NULL DEFAULT 1 CHECK (attempt >= 1), -- a retry replaces the volume and takes the next attempt
    state               TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'importing', 'imported', 'verified')),
    source_bytes        INTEGER NOT NULL DEFAULT 0 CHECK (source_bytes >= 0),
    dest_bytes          INTEGER NOT NULL DEFAULT 0 CHECK (dest_bytes >= 0),
    source_digest       TEXT NOT NULL DEFAULT '',                -- manifest digest of what A exported; '' until measured
    dest_digest         TEXT NOT NULL DEFAULT '',                -- manifest digest of what B exported back; '' until verified
    created_by_move     INTEGER NOT NULL DEFAULT 0 CHECK (created_by_move IN (0, 1)), -- the ownership evidence for removing it on B
    import_deadline_at  INTEGER,                                 -- while importing: when the import is proven stopped
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    PRIMARY KEY (move_id, volume_name),
    CHECK ((state = 'importing') = (import_deadline_at IS NOT NULL)),
    CHECK (state <> 'verified' OR (source_digest <> '' AND source_digest = dest_digest))
) STRICT;
-- the volume's identity never changes and the evidence of ownership is never withdrawn
CREATE TRIGGER app_move_volumes_ids_once BEFORE UPDATE OF move_id, volume_name, service, mount_target, other_services_json,
        created_by_move, created_at ON app_move_volumes
WHEN NEW.move_id <> OLD.move_id OR NEW.volume_name <> OLD.volume_name OR NEW.service <> OLD.service
  OR NEW.mount_target <> OLD.mount_target OR NEW.other_services_json <> OLD.other_services_json
  OR NEW.created_at <> OLD.created_at OR (OLD.created_by_move = 1 AND NEW.created_by_move = 0)
BEGIN SELECT RAISE(ABORT, 'an app move volume keeps its identity and its ownership evidence'); END;
