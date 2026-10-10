-- M1 schema additions (spec §9, ADR-0014, ADR-0016). Conventions as in 000001:
-- every table is STRICT, timestamps are Unix milliseconds, enumerations are CHECKs.

-- One row, written by the first daemon start.
CREATE TABLE instances (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE node_addresses (
    id           TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL REFERENCES nodes (id),
    address      TEXT NOT NULL,
    family       TEXT NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
    scope        TEXT NOT NULL CHECK (scope IN ('global', 'private', 'link', 'loopback')),
    source       TEXT NOT NULL CHECK (source IN ('probe', 'provider')),
    preferred    INTEGER NOT NULL DEFAULT 0 CHECK (preferred IN (0, 1)),
    last_seen_at INTEGER NOT NULL,
    UNIQUE (node_id, address)
) STRICT;

CREATE INDEX node_addresses_by_node ON node_addresses (node_id);

-- response_json holds the exact wire envelope bytes of the committed response (ADR-0014).
CREATE TABLE idempotency_records (
    identity_id   TEXT NOT NULL REFERENCES identities (id),
    key           TEXT NOT NULL,
    method        TEXT NOT NULL,
    path          TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    status_code   INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    job_id        TEXT REFERENCES jobs (id),
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    PRIMARY KEY (identity_id, key)
) STRICT;

CREATE INDEX idempotency_records_by_expiry ON idempotency_records (expires_at);

-- Encrypted secrets (§9, §10), pulled forward from M2 for the instance SSH identity (ADR-0016).
CREATE TABLE secrets (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    version          INTEGER NOT NULL,
    envelope_version INTEGER NOT NULL CHECK (envelope_version = 1),
    kek_id           TEXT NOT NULL,
    wrapped_dek      BLOB NOT NULL,
    ciphertext       BLOB NOT NULL,
    metadata_json    TEXT NOT NULL DEFAULT '{}',
    created_at       INTEGER NOT NULL,
    rotated_at       INTEGER,
    UNIQUE (name, version)
) STRICT;

CREATE TABLE interactive_sessions (
    id          TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities (id),
    node_id     TEXT NOT NULL REFERENCES nodes (id),
    tool        TEXT NOT NULL CHECK (tool IN ('shell', 'lazydocker', 'btop', 'tmux')),
    state       TEXT NOT NULL CHECK (state IN ('issued', 'ended', 'abandoned')),
    exit_code   INTEGER,
    end_reason  TEXT CHECK (end_reason IN ('exited', 'launch_failed', 'abandoned')),
    created_at  INTEGER NOT NULL,
    ended_at    INTEGER
) STRICT;

-- services(runtime_id) needs no index of its own: UNIQUE (runtime_id, native_id) covers it.
CREATE INDEX jobs_by_state_finished ON jobs (state, finished_at);
