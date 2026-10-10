-- SuperMgmt initial schema (spec §9, ADR-0001, ADR-0002, ADR-0013).
--
-- Conventions
--   * Every table is STRICT.
--   * Identifiers are lowercase UUIDv7 text.
--   * Timestamps are integer Unix milliseconds supplied by an injected clock.
--   * Every enumeration from §9 and internal/domain is a CHECK constraint.
--   * resource_locks stores domain.LockSpec.Key, which has the form "<kind>:<key>"
--     (for example "node:<id>", "compose_project:<node>:<project>"), split at the
--     FIRST colon: resource_type = <kind>, resource_id = <key>.

CREATE TABLE schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE identities (
    id           TEXT PRIMARY KEY,
    actor_type   TEXT NOT NULL CHECK (actor_type IN ('human', 'automation', 'mcp', 'system')),
    issuer       TEXT NOT NULL DEFAULT '',
    subject      TEXT NOT NULL DEFAULT '',
    client_id    TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER,
    disabled_at  INTEGER,
    UNIQUE (actor_type, issuer, subject, client_id)
) STRICT;

CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
) STRICT;

INSERT INTO roles (id, name, description) VALUES
    ('01970000-0000-7000-8000-000000000001', 'viewer',   'Read-only access'),
    ('01970000-0000-7000-8000-000000000002', 'operator', 'Operational actions'),
    ('01970000-0000-7000-8000-000000000003', 'deployer', 'Deployments and rollbacks'),
    ('01970000-0000-7000-8000-000000000004', 'admin',    'Full administration');

CREATE TABLE role_bindings (
    id          TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities (id),
    role_id     TEXT NOT NULL REFERENCES roles (id),
    created_at  INTEGER NOT NULL,
    UNIQUE (identity_id, role_id)
) STRICT;

CREATE TABLE environments (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    risk_level    TEXT NOT NULL CHECK (risk_level IN ('development', 'staging', 'production')),
    config_json   TEXT NOT NULL DEFAULT '{}',
    spec_revision INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE TABLE providers (
    id             TEXT PRIMARY KEY,
    type           TEXT NOT NULL,
    name           TEXT NOT NULL UNIQUE,
    origin         TEXT NOT NULL CHECK (origin IN ('static', 'api')),
    endpoint       TEXT NOT NULL DEFAULT '',
    credential_ref TEXT NOT NULL DEFAULT '',
    config_json    TEXT NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL DEFAULT '',
    spec_revision  INTEGER NOT NULL DEFAULT 1,
    last_sync_at   INTEGER,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE nodes (
    id               TEXT PRIMARY KEY,
    provider_id      TEXT NOT NULL REFERENCES providers (id),
    native_id        TEXT NOT NULL,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,
    environment_id   TEXT REFERENCES environments (id),
    management_state TEXT NOT NULL CHECK (management_state IN ('discovered', 'managed', 'retired')),
    reachability     TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (reachability IN ('reachable', 'unreachable', 'unknown')),
    endpoint_json    TEXT NOT NULL DEFAULT '{}',
    credential_ref   TEXT NOT NULL DEFAULT '',
    os               TEXT NOT NULL DEFAULT '',
    arch             TEXT NOT NULL DEFAULT '',
    metadata_json    TEXT NOT NULL DEFAULT '{}',
    spec_revision    INTEGER NOT NULL DEFAULT 1,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    last_seen_at     INTEGER,
    UNIQUE (provider_id, native_id)
) STRICT;

CREATE INDEX nodes_by_environment ON nodes (environment_id);
CREATE INDEX nodes_by_name ON nodes (name);

CREATE TABLE node_tags (
    node_id TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    tag     TEXT NOT NULL,
    PRIMARY KEY (node_id, tag)
) STRICT;

CREATE INDEX node_tags_by_tag ON node_tags (tag);

CREATE TABLE node_capabilities (
    node_id       TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    capability    TEXT NOT NULL,
    available     INTEGER NOT NULL CHECK (available IN (0, 1)),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    checked_at    INTEGER NOT NULL,
    PRIMARY KEY (node_id, capability)
) STRICT;

CREATE TABLE runtimes (
    id            TEXT PRIMARY KEY,
    node_id       TEXT NOT NULL REFERENCES nodes (id),
    type          TEXT NOT NULL,
    native_id     TEXT NOT NULL,
    version       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    last_seen_at  INTEGER,
    UNIQUE (node_id, type, native_id)
) STRICT;

CREATE TABLE services (
    id            TEXT PRIMARY KEY,
    runtime_id    TEXT NOT NULL REFERENCES runtimes (id),
    node_id       TEXT NOT NULL REFERENCES nodes (id),
    native_id     TEXT NOT NULL,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT '',
    health        TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    spec_revision INTEGER NOT NULL DEFAULT 1,
    last_seen_at  INTEGER,
    UNIQUE (runtime_id, native_id)
) STRICT;

CREATE INDEX services_by_node_name ON services (node_id, name);

CREATE TABLE observations (
    id            TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK (resource_type IN (
        'node', 'service', 'app', 'app_target', 'deployment', 'environment', 'provider',
        'job', 'plan', 'event', 'instance', 'identity', 'secret')),
    resource_id   TEXT NOT NULL,
    kind          TEXT NOT NULL,
    value_json    TEXT NOT NULL,
    observed_at   INTEGER NOT NULL,
    expires_at    INTEGER
) STRICT;

CREATE INDEX observations_by_resource
    ON observations (resource_type, resource_id, kind, observed_at DESC);

-- plans.submitted_job_id and jobs.plan_id reference each other; both foreign
-- keys are deferred so either row may be written first inside a transaction.
CREATE TABLE plans (
    id               TEXT PRIMARY KEY,
    action           TEXT NOT NULL,
    actor_id         TEXT NOT NULL REFERENCES identities (id),
    credential_kind  TEXT NOT NULL CHECK (credential_kind IN (
        'local_socket', 'session', 'api_token', 'mcp_token', 'oauth_access_token', 'github_oidc')),
    credential_id    TEXT NOT NULL DEFAULT '',
    scopes_json      TEXT NOT NULL DEFAULT '[]',
    plan_json        TEXT NOT NULL,
    plan_hash        TEXT NOT NULL,
    finalized_at     INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    submitted_job_id TEXT REFERENCES jobs (id) DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (submitted_job_id)
) STRICT;

CREATE INDEX plans_by_hash ON plans (plan_hash);

CREATE TABLE jobs (
    id               TEXT PRIMARY KEY,
    type             TEXT NOT NULL,
    resource_type    TEXT NOT NULL CHECK (resource_type IN (
        'node', 'service', 'app', 'app_target', 'deployment', 'environment', 'provider',
        'job', 'plan', 'event', 'instance', 'identity', 'secret')),
    resource_id      TEXT NOT NULL,
    actor_id         TEXT NOT NULL REFERENCES identities (id),
    credential_kind  TEXT NOT NULL CHECK (credential_kind IN (
        'local_socket', 'session', 'api_token', 'mcp_token', 'oauth_access_token', 'github_oidc')),
    credential_id    TEXT NOT NULL DEFAULT '',
    scopes_json      TEXT NOT NULL DEFAULT '[]',
    state            TEXT NOT NULL CHECK (state IN (
        'awaiting_approval', 'queued', 'running', 'interrupted',
        'succeeded', 'failed', 'cancelled')),
    risk             TEXT NOT NULL CHECK (risk IN (
        'read', 'operational', 'high', 'destructive', 'governance')),
    retry_class      TEXT NOT NULL CHECK (retry_class IN (
        'idempotent', 'resumable', 'non_retryable')),
    idempotency_key  TEXT,
    payload_json     TEXT NOT NULL DEFAULT '{}',
    plan_id          TEXT REFERENCES plans (id) DEFERRABLE INITIALLY DEFERRED,
    plan_hash        TEXT,
    lease_owner      TEXT,
    lease_generation INTEGER NOT NULL DEFAULT 0,
    lease_until      INTEGER,
    heartbeat_at     INTEGER,
    attempts         INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL DEFAULT 1,
    scheduled_at     INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    started_at       INTEGER,
    finished_at      INTEGER,
    error_json       TEXT
) STRICT;

CREATE INDEX jobs_queue ON jobs (state, scheduled_at);
CREATE INDEX jobs_by_resource ON jobs (resource_type, resource_id);

CREATE TABLE job_approvals (
    id          TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL REFERENCES jobs (id),
    plan_hash   TEXT NOT NULL,
    approver_id TEXT NOT NULL REFERENCES identities (id),
    decision    TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    reason      TEXT NOT NULL DEFAULT '',
    expires_at  INTEGER NOT NULL,
    renewed_at  INTEGER,
    created_at  INTEGER NOT NULL,
    UNIQUE (job_id, plan_hash, approver_id)
) STRICT;

CREATE TABLE operation_intents (
    id               TEXT PRIMARY KEY,
    job_id           TEXT NOT NULL REFERENCES jobs (id),
    step             TEXT NOT NULL,
    lease_generation INTEGER NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('recorded', 'completed')),
    operation        TEXT NOT NULL,
    target_type      TEXT NOT NULL,
    target_id        TEXT NOT NULL,
    marker           TEXT NOT NULL,
    pre_state_json   TEXT,
    deadline_at      INTEGER NOT NULL,
    dispatched_at    INTEGER,
    completed_at     INTEGER,
    outcome          TEXT,
    evidence_json    TEXT,
    UNIQUE (marker)
) STRICT;

CREATE INDEX operation_intents_by_job ON operation_intents (job_id, state);

CREATE TABLE resource_locks (
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    job_id        TEXT NOT NULL REFERENCES jobs (id),
    mode          TEXT NOT NULL CHECK (mode IN ('exclusive', 'shared')),
    acquired_at   INTEGER NOT NULL,
    PRIMARY KEY (resource_type, resource_id, job_id)
) STRICT;

CREATE INDEX resource_locks_by_job ON resource_locks (job_id);

CREATE TABLE events (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       TEXT NOT NULL UNIQUE,
    timestamp      INTEGER NOT NULL,
    actor_type     TEXT NOT NULL CHECK (actor_type IN ('human', 'automation', 'mcp', 'system')),
    actor_id       TEXT NOT NULL,
    source         TEXT NOT NULL,
    action         TEXT NOT NULL,
    resource_type  TEXT NOT NULL DEFAULT '' CHECK (resource_type IN (
        '', 'node', 'service', 'app', 'app_target', 'deployment', 'environment', 'provider',
        'job', 'plan', 'event', 'instance', 'identity', 'secret')),
    resource_id    TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error')),
    result         TEXT NOT NULL CHECK (result IN ('succeeded', 'failed', 'denied', 'pending')),
    data_json      TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX events_by_timestamp ON events (timestamp);
CREATE INDEX events_by_resource ON events (resource_type, resource_id, seq);
CREATE INDEX events_by_correlation ON events (correlation_id) WHERE correlation_id <> '';

CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;
