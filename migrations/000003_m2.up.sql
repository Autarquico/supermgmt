-- M2 schema additions (spec §9, §11, §13; ADR-0017, ADR-0018, ADR-0022). Conventions as in 000001:
-- every table is STRICT, timestamps are Unix milliseconds, enumerations are CHECKs.
-- Credentials are stored only as SHA-256 hashes; plaintext never reaches the database.

CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    identity_id  TEXT NOT NULL REFERENCES identities (id),
    token_hash   TEXT NOT NULL UNIQUE,
    client       TEXT NOT NULL DEFAULT '',
    origin       TEXT NOT NULL CHECK (origin IN ('oidc', 'bootstrap')),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    last_used_at INTEGER
) STRICT;

CREATE INDEX sessions_by_identity ON sessions (identity_id);
CREATE INDEX sessions_by_expiry ON sessions (expires_at);

-- Expiry is mandatory and at most 365 days after creation (§11.3).
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    identity_id  TEXT NOT NULL REFERENCES identities (id),
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes_json  TEXT NOT NULL DEFAULT '[]',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL CHECK (expires_at <= created_at + 31536000000),
    revoked_at   INTEGER,
    last_used_at INTEGER,
    UNIQUE (identity_id, name)
) STRICT;

CREATE INDEX api_tokens_by_identity ON api_tokens (identity_id);

CREATE TABLE bootstrap_codes (
    id             TEXT PRIMARY KEY,
    code_hash      TEXT NOT NULL UNIQUE,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    consumed_at    INTEGER,
    consumed_by    TEXT REFERENCES identities (id),
    invalidated_at INTEGER
) STRICT;

CREATE TABLE oidc_replay (
    issuer     TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (issuer, jti)
) STRICT;

CREATE INDEX oidc_replay_by_expiry ON oidc_replay (expires_at);

-- The request digest and token id of an enrollment live in the enrolled node's
-- metadata_json (ADR-0022), so a token with max_nodes > 1 replays per node.
CREATE TABLE join_tokens (
    id               TEXT PRIMARY KEY,
    token_hash       TEXT NOT NULL UNIQUE,
    created_by       TEXT NOT NULL REFERENCES identities (id),
    constraints_json TEXT NOT NULL DEFAULT '{}',
    uses             INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    consumed_at      INTEGER,
    invalidated_at   INTEGER
) STRICT;

CREATE INDEX join_tokens_by_expiry ON join_tokens (expires_at);
