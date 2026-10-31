-- Public routes of an app through the node's Cloudflare Tunnel (ADR-0040). Conventions as in 000001 and 000007:
-- STRICT tables, timestamps in Unix milliseconds, enumerations as CHECKs. No existing table changes. Nothing here
-- holds a secret: Cloudflare object IDs, hostnames and sanitized error text only.

-- One row per hostname exposed from an app target. The row survives a crash so a takeover can reconcile it against
-- Cloudflare before mutating anything, and it outlives the objects as the record of what was removed.
CREATE TABLE app_routes (
    id                TEXT PRIMARY KEY,
    app_target_id     TEXT NOT NULL REFERENCES app_targets (id),
    node_id           TEXT NOT NULL REFERENCES nodes (id),       -- the target's node; its tunnel carries the route
    hostname          TEXT NOT NULL CHECK (hostname <> '' AND hostname = lower(hostname)),
    service           TEXT NOT NULL CHECK (service <> ''),       -- compose service that publishes the port
    port              INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    access            TEXT NOT NULL CHECK (access IN ('public', 'owners')),
    phase             TEXT NOT NULL CHECK (phase IN (
                          'waiting',                              -- accepted; the deployed version does not publish the port yet
                          'provisioning', 'ingress_ready', 'access_ready', 'active',  -- expose, in order
                          'removing', 'dns_removed', 'ingress_removed', 'removed',     -- unexpose, in order
                          'failed', 'conflict')),                 -- halted: see halted_phase
    halted_phase      TEXT CHECK (halted_phase IS NULL OR halted_phase IN (
                          'waiting', 'provisioning', 'ingress_ready', 'access_ready', 'active',
                          'removing', 'dns_removed', 'ingress_removed', 'removed')), -- phase held when the route halted; NULL otherwise
    phase_started_at  INTEGER NOT NULL,                          -- adoption of an object requires created_at >= this
    account_id        TEXT NOT NULL,                             -- Cloudflare account the objects live in
    zone              TEXT NOT NULL,                             -- DNS zone name
    instance_id       TEXT NOT NULL,                             -- SuperMgmt instance ID baked into object names
    tunnel_id         TEXT NOT NULL CHECK (tunnel_id <> ''),     -- the node's tunnel when the route was accepted
    tunnel_generation INTEGER NOT NULL CHECK (tunnel_generation >= 1), -- the node's committed enable generation then
    dns_record_id     TEXT NOT NULL DEFAULT '',                  -- '' until created; set once
    access_app_id     TEXT NOT NULL DEFAULT '',                  -- '' until created; set once
    last_error        TEXT NOT NULL DEFAULT '',                  -- sanitized; never a token, header or response body
    plan_id           TEXT REFERENCES plans (id),                -- the plan whose admission wrote the row; NULL only for rows inserted outside a plan
    created_by        TEXT NOT NULL REFERENCES identities (id),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    CHECK ((phase IN ('failed', 'conflict')) = (halted_phase IS NOT NULL)),
    CHECK (phase_started_at <= updated_at)
) STRICT;
-- A hostname belongs to one live route; a removed route releases it. Halted routes stay live: their objects may exist.
CREATE UNIQUE INDEX app_routes_one_live_hostname ON app_routes (hostname) WHERE phase <> 'removed';
-- A plan admits at most one route, so a retried or late job of a removed route finds its row and admits nothing again.
CREATE UNIQUE INDEX app_routes_one_per_plan ON app_routes (plan_id) WHERE plan_id IS NOT NULL;
CREATE INDEX app_routes_target ON app_routes (app_target_id);
CREATE INDEX app_routes_node ON app_routes (node_id) WHERE phase <> 'removed';
-- the route lives on its target's node
CREATE TRIGGER app_routes_node_matches_target BEFORE INSERT ON app_routes
WHEN NEW.node_id IS NOT (SELECT node_id FROM app_targets WHERE id = NEW.app_target_id)
BEGIN SELECT RAISE(ABORT, 'an app route lives on the node of its app target'); END;
-- object IDs are recorded once and the identity snapshot never changes; a different value is a bug or a hostile write
CREATE TRIGGER app_routes_ids_once BEFORE UPDATE OF id, app_target_id, node_id, hostname, service, port, access, account_id, zone,
        instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id, plan_id, created_by, created_at ON app_routes
WHEN (OLD.dns_record_id <> '' AND NEW.dns_record_id <> OLD.dns_record_id)
  OR (OLD.access_app_id <> '' AND NEW.access_app_id <> OLD.access_app_id)
  OR NEW.id <> OLD.id OR NEW.app_target_id <> OLD.app_target_id OR NEW.node_id <> OLD.node_id
  OR NEW.hostname <> OLD.hostname OR NEW.service <> OLD.service OR NEW.port <> OLD.port OR NEW.access <> OLD.access
  OR NEW.account_id <> OLD.account_id OR NEW.zone <> OLD.zone OR NEW.instance_id <> OLD.instance_id
  OR NEW.tunnel_id <> OLD.tunnel_id OR NEW.tunnel_generation <> OLD.tunnel_generation
  OR (OLD.plan_id IS NOT NULL AND NEW.plan_id IS NOT OLD.plan_id) OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'an app route keeps its identity and recorded object IDs'); END;
-- a removed route never changes phase again
CREATE TRIGGER app_routes_final BEFORE UPDATE OF phase ON app_routes
WHEN OLD.phase = 'removed' AND NEW.phase <> OLD.phase
BEGIN SELECT RAISE(ABORT, 'a removed app route does not change phase'); END;
