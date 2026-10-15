-- Cloudflare tunnel transport (ADR-0037). Conventions as in 000001: every table is STRICT, timestamps are
-- Unix milliseconds, enumerations are CHECKs. No existing table changes. Nothing here ever holds a secret:
-- only Cloudflare object IDs, names and sanitized error text.

-- The per-node operation record. One row per enable or disable attempt; the row survives a crash so a
-- takeover can reconcile it against Cloudflare before mutating anything.
CREATE TABLE tunnel_operations (
    id               TEXT PRIMARY KEY,
    node_id          TEXT NOT NULL REFERENCES nodes (id),
    generation       INTEGER NOT NULL CHECK (generation >= 1),   -- per node, 1, 2, 3...; stale writers carry an old one
    operation        TEXT NOT NULL CHECK (operation IN ('enable', 'disable')),
    phase            TEXT NOT NULL CHECK (phase IN (
                         'started',                                -- both: record written, nothing created yet
                         'token_ready', 'tunnel_created', 'ingress_set', 'access_ready',
                         'dns_created', 'installed', 'verified', 'committed',                      -- enable, in order
                         'direct_verified', 'switched', 'service_removed', 'route_closed',
                         'access_removed', 'tunnel_deleted', 'done',                               -- disable, in order
                         'failed', 'conflict')),                   -- halted: see halted_phase
    halted_phase     TEXT CHECK (halted_phase IS NULL OR halted_phase IN (
                         'started',
                         'token_ready', 'tunnel_created', 'ingress_set', 'access_ready',
                         'dns_created', 'installed', 'verified', 'committed',
                         'direct_verified', 'switched', 'service_removed', 'route_closed',
                         'access_removed', 'tunnel_deleted', 'done')), -- phase held when the operation halted; NULL otherwise
    phase_started_at INTEGER NOT NULL,                           -- adoption of an object requires created_at >= this
    account_id       TEXT NOT NULL,                              -- Cloudflare account the objects live in
    zone             TEXT NOT NULL,                              -- DNS zone name
    instance_id      TEXT NOT NULL,                              -- SuperMgmt instance ID baked into object names
    hostname         TEXT NOT NULL DEFAULT '',                   -- DNS name of the tunnelled node
    tunnel_id        TEXT NOT NULL DEFAULT '',                   -- '' until created; set once
    dns_record_id    TEXT NOT NULL DEFAULT '',                   -- '' until created; set once
    access_app_id    TEXT NOT NULL DEFAULT '',                   -- '' until created; set once
    last_error       TEXT NOT NULL DEFAULT '',                   -- sanitized; never a token, header or response body
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    UNIQUE (node_id, generation),
    CHECK ((phase IN ('failed', 'conflict')) = (halted_phase IS NOT NULL)),
    CHECK (operation = 'enable'  AND (phase NOT IN ('direct_verified', 'switched', 'service_removed', 'route_closed',
                                                   'access_removed', 'tunnel_deleted', 'done')
                                       AND COALESCE(halted_phase, 'started') NOT IN ('direct_verified', 'switched', 'service_removed',
                                                   'route_closed', 'access_removed', 'tunnel_deleted', 'done'))
        OR operation = 'disable' AND (phase NOT IN ('token_ready', 'tunnel_created', 'ingress_set', 'access_ready',
                                                   'dns_created', 'installed', 'verified', 'committed')
                                       AND COALESCE(halted_phase, 'started') NOT IN ('token_ready', 'tunnel_created', 'ingress_set',
                                                   'access_ready', 'dns_created', 'installed', 'verified', 'committed'))),
    CHECK (phase_started_at <= updated_at)
) STRICT;
-- At most one unfinished operation per node. Failed and conflict rows stay active: they hold the node
-- until an operator resumes or resolves them, because Cloudflare objects may exist.
CREATE UNIQUE INDEX tunnel_operations_one_active ON tunnel_operations (node_id)
    WHERE phase NOT IN ('committed', 'done');
-- object IDs are recorded once; a different value is a bug or a hostile write
CREATE TRIGGER tunnel_operations_ids_once BEFORE UPDATE OF tunnel_id, dns_record_id, access_app_id, node_id, generation, operation ON tunnel_operations
WHEN (OLD.tunnel_id <> '' AND NEW.tunnel_id <> OLD.tunnel_id)
  OR (OLD.dns_record_id <> '' AND NEW.dns_record_id <> OLD.dns_record_id)
  OR (OLD.access_app_id <> '' AND NEW.access_app_id <> OLD.access_app_id)
  OR NEW.node_id <> OLD.node_id OR NEW.generation <> OLD.generation OR NEW.operation <> OLD.operation
BEGIN SELECT RAISE(ABORT, 'a tunnel operation keeps its identity and recorded object IDs'); END;

-- Instance-wide Cloudflare state: one row, id fixed to 1. The service-token secret lives in the existing
-- encrypted secret records, never here.
CREATE TABLE cloudflare_state (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    revision                 INTEGER NOT NULL CHECK (revision >= 1),  -- bumped by every write; conditional updates compare it
    account_id               TEXT NOT NULL,
    service_token_id         TEXT NOT NULL,                           -- Cloudflare ID of the active Access service token
    service_token_name       TEXT NOT NULL,                           -- supermgmt-<instance-id>
    service_token_created_at INTEGER NOT NULL,
    service_token_expires_at INTEGER NOT NULL,
    rotation_phase           TEXT NOT NULL DEFAULT 'idle'
                             CHECK (rotation_phase IN ('idle', 'created', 'policy_updated', 'retiring')),
                                                                      -- created: new token exists; policy_updated: both admitted;
                                                                      -- retiring: old removed from policy, awaiting deletion
    pending_token_id         TEXT NOT NULL DEFAULT '',                -- the new token while a rotation runs
    pending_token_name       TEXT NOT NULL DEFAULT '',
    pending_token_created_at INTEGER,
    pending_token_expires_at INTEGER,
    service_policy_id        TEXT NOT NULL DEFAULT '',                -- owned policy "supermgmt service <instance-id>"
    owners_policy_id         TEXT NOT NULL DEFAULT '',                -- owned policy "supermgmt owners <instance-id>"
    last_error               TEXT NOT NULL DEFAULT '',                -- sanitized
    created_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL,
    CHECK ((rotation_phase = 'idle') = (pending_token_id = '')),
    CHECK ((pending_token_id = '') = (pending_token_created_at IS NULL) AND (pending_token_id = '') = (pending_token_expires_at IS NULL))
) STRICT;
