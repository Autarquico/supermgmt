-- M5 schema additions (spec §11.1, §11.2, §24; ADR-0032, ADR-0033). Conventions as in 000001:
-- every table is STRICT, timestamps are Unix milliseconds, enumerations are CHECKs.
-- No existing table changes: credential_kind and actor_type already admit the MCP values.

CREATE TABLE mcp_clients (
    id                  TEXT PRIMARY KEY,                         -- credential_id of its mcp_token
    identity_id         TEXT NOT NULL REFERENCES identities (id), -- not UNIQUE: history survives re-registration
    name                TEXT NOT NULL,
    origin              TEXT NOT NULL CHECK (origin IN ('local', 'remote')),
    state               TEXT NOT NULL CHECK (state IN ('pending_token', 'active', 'deleted')),
    requested_by        TEXT NOT NULL REFERENCES identities (id),
    registration_job_id TEXT REFERENCES jobs (id),                -- NULL when policy needed no approval
    approved_at         INTEGER NOT NULL,                         -- start of the 24h issuance window
    token_hash          TEXT UNIQUE,                              -- local only; NULL until issued
    token_issued_at     INTEGER,
    token_expires_at    INTEGER,
    revoked_at          INTEGER,
    last_used_at        INTEGER,
    created_at          INTEGER NOT NULL,                         -- lower bound for accepted OAuth iat
    updated_at          INTEGER NOT NULL,
    deleted_at          INTEGER,
    CHECK (origin = 'local' OR token_hash IS NULL),
    CHECK ((token_hash IS NULL) = (token_issued_at IS NULL) AND (token_hash IS NULL) = (token_expires_at IS NULL)),
    CHECK (token_expires_at IS NULL OR token_expires_at <= token_issued_at + 31536000000),
    CHECK (state <> 'active' OR origin = 'remote' OR token_hash IS NOT NULL),
    CHECK ((state = 'deleted') = (deleted_at IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX mcp_clients_live_identity ON mcp_clients (identity_id) WHERE state <> 'deleted';
CREATE UNIQUE INDEX mcp_clients_live_name ON mcp_clients (name) WHERE state <> 'deleted';
CREATE INDEX mcp_clients_by_requester ON mcp_clients (requested_by);
-- identity must be actor_type 'mcp'; state moves only pending_token->active, *->deleted; token set once
CREATE TRIGGER mcp_clients_identity_is_mcp BEFORE INSERT ON mcp_clients
WHEN (SELECT actor_type FROM identities WHERE id = NEW.identity_id) IS NOT 'mcp'
BEGIN SELECT RAISE(ABORT, 'mcp_clients.identity_id must be an mcp identity'); END;
CREATE TRIGGER mcp_clients_state_forward BEFORE UPDATE OF state ON mcp_clients
WHEN NOT ((OLD.state = 'pending_token' AND NEW.state IN ('active', 'deleted'))
       OR (OLD.state = 'active' AND NEW.state = 'deleted') OR OLD.state = NEW.state)
BEGIN SELECT RAISE(ABORT, 'invalid mcp client state transition'); END;
CREATE TRIGGER mcp_clients_token_once BEFORE UPDATE OF token_hash ON mcp_clients
WHEN OLD.token_hash IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an mcp client token is issued once'); END;

CREATE TABLE oauth_access_tokens (
    id            TEXT PRIMARY KEY,                               -- credential_id
    mcp_client_id TEXT NOT NULL REFERENCES mcp_clients (id),
    token_hash    TEXT NOT NULL UNIQUE,                           -- SHA-256 of the presented token
    issuer        TEXT NOT NULL,
    jti           TEXT NOT NULL DEFAULT '',
    issued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    revoked_at    INTEGER,
    first_seen_at INTEGER NOT NULL,
    last_used_at  INTEGER
) STRICT;
CREATE INDEX oauth_access_tokens_by_client ON oauth_access_tokens (mcp_client_id);
CREATE INDEX oauth_access_tokens_by_expiry ON oauth_access_tokens (expires_at);
CREATE TRIGGER oauth_access_tokens_stay_revoked BEFORE UPDATE OF revoked_at, mcp_client_id ON oauth_access_tokens
WHEN OLD.revoked_at IS NOT NULL OR NEW.mcp_client_id IS NOT OLD.mcp_client_id
BEGIN SELECT RAISE(ABORT, 'an oauth access token row never changes client or un-revokes'); END;
