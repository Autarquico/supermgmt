-- M4 schema additions (spec §9; ADR-0007, ADR-0011, ADR-0028, ADR-0029). Conventions as in 000001:
-- every table is STRICT, timestamps are Unix milliseconds, enumerations are CHECKs.
-- The events/observations resource_type CHECKs are unchanged: repository and webhook events use
-- resource_type 'provider' (ADR-0029).

CREATE TABLE repositories (
    id                   TEXT PRIMARY KEY,
    provider_id          TEXT NOT NULL REFERENCES providers (id),
    github_repository_id INTEGER NOT NULL,
    github_owner_id      INTEGER NOT NULL,
    owner                TEXT NOT NULL,
    name                 TEXT NOT NULL,
    url                  TEXT NOT NULL,
    default_branch       TEXT NOT NULL,
    metadata_json        TEXT NOT NULL DEFAULT '{}',
    spec_revision        INTEGER NOT NULL DEFAULT 1,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    UNIQUE (provider_id, github_repository_id)
) STRICT;

-- compose_source_hash is the SHA-256 of compose_content and is target-independent (ADR-0007).
CREATE TABLE apps (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    repository_id           TEXT REFERENCES repositories (id),
    manifest_path           TEXT NOT NULL DEFAULT '.supermgmt.yaml',
    deployed_service        TEXT NOT NULL,
    image_policy_json       TEXT NOT NULL,
    compose_source          TEXT NOT NULL CHECK (compose_source IN ('control-plane', 'repository')),
    compose_content         TEXT,
    compose_source_hash     TEXT,
    compose_exceptions_json TEXT NOT NULL DEFAULT '{}',
    variables_json          TEXT NOT NULL DEFAULT '{}',
    secret_refs_json        TEXT NOT NULL DEFAULT '{}',
    ci_policy_json          TEXT,
    automation_identity_id  TEXT REFERENCES identities (id),
    spec_revision           INTEGER NOT NULL DEFAULT 1,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL
) STRICT;

CREATE TABLE app_targets (
    id                     TEXT PRIMARY KEY,
    app_id                 TEXT NOT NULL REFERENCES apps (id),
    environment_id         TEXT NOT NULL REFERENCES environments (id),
    node_id                TEXT NOT NULL REFERENCES nodes (id),
    compose_project        TEXT NOT NULL,
    deployment_policy_json TEXT NOT NULL,
    spec_revision          INTEGER NOT NULL DEFAULT 1,
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    UNIQUE (node_id, compose_project),
    UNIQUE (app_id, environment_id)
) STRICT;

CREATE TRIGGER app_targets_project_immutable BEFORE UPDATE OF compose_project ON app_targets
WHEN NEW.compose_project <> OLD.compose_project
BEGIN
    SELECT RAISE(ABORT, 'app_targets.compose_project is immutable');
END;

CREATE TABLE artifacts (
    id                 TEXT PRIMARY KEY,
    app_id             TEXT NOT NULL REFERENCES apps (id),
    type               TEXT NOT NULL CHECK (type IN ('oci_image')),
    immutable_ref      TEXT NOT NULL,
    digest             TEXT NOT NULL CHECK (digest GLOB 'sha256:*'),
    commit_sha         TEXT NOT NULL,
    source_run_id      INTEGER,
    source_run_attempt INTEGER,
    provenance_json    TEXT NOT NULL,
    provenance_method  TEXT NOT NULL CHECK (provenance_method IN ('attestation', 'oidc_claims')),
    created_at         INTEGER NOT NULL
) STRICT;

CREATE INDEX artifacts_by_app_digest ON artifacts (app_id, digest);

CREATE TRIGGER artifacts_no_update BEFORE UPDATE ON artifacts
BEGIN
    SELECT RAISE(ABORT, 'artifacts are immutable');
END;

CREATE TRIGGER artifacts_no_delete BEFORE DELETE ON artifacts
BEGIN
    SELECT RAISE(ABORT, 'artifacts are immutable');
END;

-- app_id is the GitHub App id that produced the check run (§9, §18), not an apps row.
CREATE TABLE artifact_checks (
    artifact_id   TEXT NOT NULL REFERENCES artifacts (id),
    check_name    TEXT NOT NULL,
    app_id        INTEGER NOT NULL,
    workflow_path TEXT NOT NULL DEFAULT '',
    run_id        INTEGER,
    run_attempt   INTEGER,
    conclusion    TEXT NOT NULL,
    completed_at  INTEGER,
    PRIMARY KEY (artifact_id, check_name)
) STRICT;

-- id is sha256(issuer|jti). claims_json holds the §18 non-secret claims; the token is never stored.
CREATE TABLE github_oidc_credentials (
    id            TEXT PRIMARY KEY,
    identity_id   TEXT NOT NULL REFERENCES identities (id),
    repository_id INTEGER NOT NULL,
    claims_json   TEXT NOT NULL,
    issued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    revoked_at    INTEGER,
    created_at    INTEGER NOT NULL
) STRICT;

CREATE INDEX github_oidc_credentials_by_identity ON github_oidc_credentials (identity_id)
    WHERE revoked_at IS NULL;

CREATE TABLE deployments (
    id                            TEXT PRIMARY KEY,
    kind                          TEXT NOT NULL CHECK (kind IN ('deploy', 'rollback')),
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

CREATE TABLE deployment_steps (
    id            TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments (id),
    ordinal       INTEGER NOT NULL,
    name          TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'skipped')),
    attempt       INTEGER NOT NULL DEFAULT 1,
    started_at    INTEGER,
    finished_at   INTEGER,
    output_ref    TEXT,
    error_json    TEXT,
    UNIQUE (deployment_id, name, attempt)
) STRICT;

CREATE TABLE health_checks (
    id            TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('app_target')),
    resource_id   TEXT NOT NULL,
    type          TEXT NOT NULL CHECK (type IN ('http', 'https', 'tcp', 'docker-health')),
    scope         TEXT NOT NULL CHECK (scope IN ('node', 'control_plane')),
    config_json   TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    spec_revision INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
) STRICT;

CREATE INDEX health_checks_by_resource ON health_checks (resource_type, resource_id);

CREATE TABLE webhook_deliveries (
    id              TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    delivery_id     TEXT NOT NULL,
    received_at     INTEGER NOT NULL,
    signature_valid INTEGER NOT NULL CHECK (signature_valid IN (0, 1)),
    event_type      TEXT NOT NULL DEFAULT '',
    processed_at    INTEGER,
    result          TEXT,
    UNIQUE (provider, delivery_id)
) STRICT;

-- Content-addressed and immutable: hash is the sha256: value the plan binds (ADR-0007).
CREATE TABLE execution_snapshots (
    hash       TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN (
        'compose_model', 'health', 'deployment_policy', 'exceptions', 'manifest')),
    content    TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER execution_snapshots_no_update BEFORE UPDATE ON execution_snapshots
BEGIN
    SELECT RAISE(ABORT, 'execution snapshots are immutable');
END;

CREATE TRIGGER execution_snapshots_no_delete BEFORE DELETE ON execution_snapshots
BEGIN
    SELECT RAISE(ABORT, 'execution snapshots are immutable');
END;
