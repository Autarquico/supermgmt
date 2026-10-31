-- Node enrollment through Cloudflare Tunnel (ADR-0039). Conventions as in 000001 and 000007: STRICT tables,
-- timestamps in Unix milliseconds, enumerations as CHECKs. No existing table changes. Nothing here holds a
-- secret: Cloudflare object IDs, public keys, secret-store references and sanitized error text only.

-- The record of a node that does not exist yet. The node ID is allocated when the enrollment starts (every
-- Cloudflare object name embeds it) but no node row is written until the commit, so there is no foreign key
-- to nodes. The enable phases mirror tunnel_operations; provisionCloudflare walks both tables through one
-- interface.
CREATE TABLE tunnel_enrollments (
    id                      TEXT PRIMARY KEY,                    -- the node ID allocated for the enrollment
    name                    TEXT NOT NULL CHECK (name <> ''),
    environment_id          TEXT REFERENCES environments (id),
    tags_json               TEXT NOT NULL DEFAULT '[]',
    phase                   TEXT NOT NULL CHECK (phase IN (
                                'started', 'token_ready', 'tunnel_created', 'ingress_set', 'access_ready',
                                'dns_created',                    -- enable, in order; dns_created = waiting for the node
                                'scanned', 'confirmed', 'committed',  -- host key scanned over the tunnel, confirmed by the operator, node written
                                'removing', 'route_closed', 'access_removed', 'tunnel_deleted',  -- cleanup, in order
                                'expired', 'cancelled',           -- cleanup done: the terminal outcomes without a node
                                'mismatch',                       -- the host key was refused; goes on to removing
                                'failed', 'conflict')),           -- halted: see halted_phase
    halted_phase            TEXT CHECK (halted_phase IS NULL OR halted_phase IN (
                                'started', 'token_ready', 'tunnel_created', 'ingress_set', 'access_ready',
                                'dns_created', 'scanned', 'confirmed', 'committed',
                                'removing', 'route_closed', 'access_removed', 'tunnel_deleted',
                                'expired', 'cancelled', 'mismatch')),  -- phase held when the enrollment halted; NULL otherwise
    phase_started_at        INTEGER NOT NULL,                    -- adoption of an object requires created_at >= this
    account_id              TEXT NOT NULL,                       -- Cloudflare account the objects live in
    zone                    TEXT NOT NULL,                       -- DNS zone name
    instance_id             TEXT NOT NULL,                       -- SuperMgmt instance ID baked into object names
    hostname                TEXT NOT NULL,                       -- ssh-<name>.<zone>
    tunnel_id               TEXT NOT NULL DEFAULT '',            -- '' until created; set once
    dns_record_id           TEXT NOT NULL DEFAULT '',            -- '' until created; set once
    access_app_id           TEXT NOT NULL DEFAULT '',            -- '' until created; set once
    expires_at              INTEGER NOT NULL,
    started_by              TEXT NOT NULL,                       -- identity that started the enrollment; the only one that reads the token and confirms or refuses the key
    identity_public_key     TEXT NOT NULL,                       -- SSH identity snapshot taken at start; used by the line, the proof and the commit
    identity_fingerprint    TEXT NOT NULL,
    identity_credential_ref TEXT NOT NULL,                       -- versioned secret reference of the snapshot's private key
    scanned_host_key        TEXT NOT NULL DEFAULT '',            -- authorized_keys form, as scanned over the tunnel
    confirmed_host_key      TEXT NOT NULL DEFAULT '',            -- '' until confirmed; set once, and equal to the scanned key
    token_ref               TEXT NOT NULL DEFAULT '',            -- secret-store reference of the connector token; never the token
    terminal_reason         TEXT NOT NULL DEFAULT '',            -- why the enrollment is being removed or ended
    last_error              TEXT NOT NULL DEFAULT '',            -- sanitized; never a token, header or response body
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    CHECK ((phase IN ('failed', 'conflict')) = (halted_phase IS NOT NULL)),
    CHECK (phase_started_at <= updated_at),
    CHECK (expires_at > created_at),
    CHECK (confirmed_host_key = '' OR confirmed_host_key = scanned_host_key),
    CHECK (phase <> 'scanned' OR scanned_host_key <> ''),
    CHECK (phase <> 'confirmed' OR confirmed_host_key <> '')
) STRICT;
-- One open enrollment per name. Halted ones stay open: their Cloudflare objects may exist, so the name is held
-- until cleanup finishes.
CREATE UNIQUE INDEX tunnel_enrollments_one_open ON tunnel_enrollments (name)
    WHERE phase NOT IN ('committed', 'expired', 'cancelled');
-- object IDs, the identity snapshot and the confirmed key are recorded once; a different value is a bug or a
-- hostile write
CREATE TRIGGER tunnel_enrollments_ids_once BEFORE UPDATE OF id, name, environment_id, tags_json, account_id, zone,
        instance_id, hostname, tunnel_id, dns_record_id, access_app_id, expires_at, started_by, identity_public_key,
        identity_fingerprint, identity_credential_ref, confirmed_host_key, token_ref, created_at ON tunnel_enrollments
WHEN (OLD.tunnel_id <> '' AND NEW.tunnel_id <> OLD.tunnel_id)
  OR (OLD.dns_record_id <> '' AND NEW.dns_record_id <> OLD.dns_record_id)
  OR (OLD.access_app_id <> '' AND NEW.access_app_id <> OLD.access_app_id)
  OR (OLD.confirmed_host_key <> '' AND NEW.confirmed_host_key <> OLD.confirmed_host_key)
  OR (OLD.token_ref <> '' AND NEW.token_ref <> OLD.token_ref)
  OR NEW.id <> OLD.id OR NEW.name <> OLD.name OR NEW.environment_id IS NOT OLD.environment_id
  OR NEW.tags_json <> OLD.tags_json OR NEW.account_id <> OLD.account_id OR NEW.zone <> OLD.zone
  OR NEW.instance_id <> OLD.instance_id OR NEW.hostname <> OLD.hostname OR NEW.expires_at <> OLD.expires_at
  OR NEW.started_by <> OLD.started_by
  OR NEW.identity_public_key <> OLD.identity_public_key OR NEW.identity_fingerprint <> OLD.identity_fingerprint
  OR NEW.identity_credential_ref <> OLD.identity_credential_ref OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'a tunnel enrollment keeps its identity snapshot and recorded object IDs'); END;
-- a finished enrollment never changes phase again
CREATE TRIGGER tunnel_enrollments_final BEFORE UPDATE OF phase ON tunnel_enrollments
WHEN OLD.phase IN ('committed', 'expired', 'cancelled') AND NEW.phase <> OLD.phase
BEGIN SELECT RAISE(ABORT, 'a finished tunnel enrollment does not change phase'); END;
