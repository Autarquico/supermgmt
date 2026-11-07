-- Routes publish a node port (ADR-0043). A route is `hostname -> node, port, access`: it no longer belongs to an app
-- target and no longer waits for a deployment, so app_routes is rebuilt as node_routes without app_target_id and
-- service, and without the phase 'waiting'. Conventions as in 000009.
--
-- A route that still waited for a deployment (phase 'waiting', or halted while waiting) created nothing in Cloudflare,
-- so it becomes 'removed' and keeps a note saying why (appended to any earlier error). Every other row keeps its id, phase and object IDs.
--
-- A route job (a control_plane.apply job whose plan is an app_route.expose or app_route.unexpose) still open (not succeeded, failed or cancelled, or with an operation intent not completed) would resume
-- against a table and an action this version no longer knows. The migration refuses to run then, as 000012 does.
--
-- Two live routes (not removed, not waiting) on one node and port cannot coexist under the new model. The migration
-- refuses to run then, changes nothing, and tells the operator to unexpose one of them with the previous version.

CREATE TABLE node_routes_jobs_guard (open_jobs INTEGER NOT NULL) STRICT;
CREATE TRIGGER node_routes_jobs_refuse BEFORE INSERT ON node_routes_jobs_guard
BEGIN SELECT RAISE(ABORT, 'a route job is unfinished: finish or cancel the route job with the previous SuperMgmt version before upgrading'); END;
INSERT INTO node_routes_jobs_guard
SELECT 1 WHERE EXISTS (SELECT 1 FROM jobs
                       WHERE plan_id IN (SELECT id FROM plans WHERE action IN ('app_route.expose', 'app_route.unexpose'))
                         AND state NOT IN ('succeeded', 'failed', 'cancelled'))
    OR EXISTS (SELECT 1 FROM operation_intents
               WHERE state <> 'completed'
                 AND job_id IN (SELECT id FROM jobs
                                WHERE plan_id IN (SELECT id FROM plans WHERE action IN ('app_route.expose', 'app_route.unexpose'))));
DROP TABLE node_routes_jobs_guard;

CREATE TABLE node_routes_port_guard (conflicting_routes INTEGER NOT NULL) STRICT;
CREATE TRIGGER node_routes_port_refuse BEFORE INSERT ON node_routes_port_guard
BEGIN SELECT RAISE(ABORT, 'two live routes share a node and port: unexpose one of them with the previous SuperMgmt version before upgrading'); END;
INSERT INTO node_routes_port_guard
SELECT 1 WHERE EXISTS (
    SELECT 1 FROM app_routes
    WHERE phase <> 'removed' AND phase <> 'waiting' AND NOT (phase IN ('failed', 'conflict') AND halted_phase = 'waiting')
    GROUP BY node_id, port HAVING count(*) > 1);
DROP TABLE node_routes_port_guard;

CREATE TABLE node_routes (
    id                TEXT PRIMARY KEY,
    node_id           TEXT NOT NULL REFERENCES nodes (id),       -- its tunnel carries the route
    hostname          TEXT NOT NULL CHECK (hostname <> '' AND hostname = lower(hostname)),
    port              INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    access            TEXT NOT NULL CHECK (access IN ('public', 'owners')),
    phase             TEXT NOT NULL CHECK (phase IN (
                          'provisioning', 'ingress_ready', 'access_ready', 'active',  -- expose, in order
                          'removing', 'dns_removed', 'ingress_removed', 'removed',     -- unexpose, in order
                          'failed', 'conflict')),                 -- halted: see halted_phase
    halted_phase      TEXT CHECK (halted_phase IS NULL OR halted_phase IN (
                          'provisioning', 'ingress_ready', 'access_ready', 'active',
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

INSERT INTO node_routes (id, node_id, hostname, port, access, phase, halted_phase, phase_started_at, account_id, zone,
        instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id, last_error, plan_id, created_by,
        created_at, updated_at)
SELECT id, node_id, hostname, port, access,
       CASE WHEN waited THEN 'removed' ELSE phase END,
       CASE WHEN waited THEN NULL ELSE halted_phase END,
       phase_started_at, account_id, zone, instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id,
       CASE WHEN NOT waited THEN last_error
            WHEN last_error = '' THEN 'waited for a deployment; routes no longer wait for one'
            ELSE last_error || '; waited for a deployment; routes no longer wait for one' END,
       plan_id, created_by, created_at, updated_at
FROM (SELECT *, (phase = 'waiting' OR (phase IN ('failed', 'conflict') AND halted_phase = 'waiting')) AS waited
      FROM app_routes);

DROP TRIGGER app_routes_final;
DROP TRIGGER app_routes_ids_once;
DROP TRIGGER app_routes_node_matches_target;
DROP TABLE app_routes;

-- A hostname belongs to one live route; a removed route releases it. Halted routes stay live: their objects may exist.
CREATE UNIQUE INDEX node_routes_one_live_hostname ON node_routes (hostname) WHERE phase <> 'removed';
-- A node port is published by one live route.
CREATE UNIQUE INDEX node_routes_one_live_port ON node_routes (node_id, port) WHERE phase <> 'removed';
-- A plan admits at most one route, so a retried or late job of a removed route finds its row and admits nothing again.
CREATE UNIQUE INDEX node_routes_one_per_plan ON node_routes (plan_id) WHERE plan_id IS NOT NULL;
CREATE INDEX node_routes_node ON node_routes (node_id) WHERE phase <> 'removed';
-- object IDs are recorded once and the identity snapshot never changes; a different value is a bug or a hostile write
CREATE TRIGGER node_routes_ids_once BEFORE UPDATE OF id, node_id, hostname, port, access, account_id, zone,
        instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id, plan_id, created_by, created_at ON node_routes
WHEN (OLD.dns_record_id <> '' AND NEW.dns_record_id <> OLD.dns_record_id)
  OR (OLD.access_app_id <> '' AND NEW.access_app_id <> OLD.access_app_id)
  OR NEW.id <> OLD.id OR NEW.node_id <> OLD.node_id
  OR NEW.hostname <> OLD.hostname OR NEW.port <> OLD.port OR NEW.access <> OLD.access
  OR NEW.account_id <> OLD.account_id OR NEW.zone <> OLD.zone OR NEW.instance_id <> OLD.instance_id
  OR NEW.tunnel_id <> OLD.tunnel_id OR NEW.tunnel_generation <> OLD.tunnel_generation
  OR (OLD.plan_id IS NOT NULL AND NEW.plan_id IS NOT OLD.plan_id) OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'a node route keeps its identity and recorded object IDs'); END;
-- a removed route never changes phase again
CREATE TRIGGER node_routes_final BEFORE UPDATE OF phase ON node_routes
WHEN OLD.phase = 'removed' AND NEW.phase <> OLD.phase
BEGIN SELECT RAISE(ABORT, 'a removed node route does not change phase'); END;
