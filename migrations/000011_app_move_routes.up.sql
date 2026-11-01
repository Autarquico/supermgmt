-- Routes follow their app target when it moves (ADR-0042). Conventions as in 000001 and 000007: STRICT tables,
-- timestamps in Unix milliseconds, enumerations as CHECKs. Nothing here holds a secret: IDs, generations and states only.

-- app_moves gains the routes phases, forward and compensating, in both phase CHECKs. SQLite cannot alter a CHECK, so
-- the table is rebuilt as 000010 rebuilt deployments: its rows go to a scratch table, the table is dropped and created
-- again under the same name (app_move_volumes keeps pointing at it by name), and the rows come back. Foreign keys are
-- deferred for the transaction, so the drop does not trip over app_move_volumes; the rows put back resolve every
-- reference before the commit. Indexes and triggers go with the dropped table and are created again, unchanged.
PRAGMA defer_foreign_keys = ON;
CREATE TABLE app_moves_rebuild AS SELECT * FROM app_moves;
DROP TABLE app_moves;
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
                                'started', 'verified', 'routes_dest_included', 'routes_switched', -- the two routes phases before the commit: a routed move only
                                'committed', 'routes_source_cleaned', 'source_parked', 'done', -- routes_source_cleaned: a routed move only
                                'compensating_routes_restored', 'compensating_routes_withdrawn', -- before committed only, a routed move only; they come first
                                'compensating_b_stopped', 'compensating_source_started',        -- before committed only, in order
                                'compensating_source_verified', 'compensating_b_removed', 'rolled_back',
                                'failed', 'conflict')),             -- halted: see halted_phase
    halted_phase            TEXT CHECK (halted_phase IS NULL OR halted_phase IN (
                                'preflight', 'staged', 'source_stopped', 'data_copied',
                                'started', 'verified', 'routes_dest_included', 'routes_switched',
                                'committed', 'routes_source_cleaned', 'source_parked', 'done',
                                'compensating_routes_restored', 'compensating_routes_withdrawn',
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
INSERT INTO app_moves SELECT * FROM app_moves_rebuild;
DROP TABLE app_moves_rebuild;

-- One row per route the move carries, frozen when the plan is made. It is the durable record of where the route's
-- DNS record and ingress rule stand during the move, and the evidence the app_routes trigger below checks.
CREATE TABLE app_move_routes (
    move_id          TEXT NOT NULL REFERENCES app_moves (id),
    route_id         TEXT NOT NULL REFERENCES app_routes (id),
    frozen_phase     TEXT NOT NULL CHECK (frozen_phase IN ('active', 'waiting')), -- the route's phase when the plan froze it
    from_node_id     TEXT NOT NULL REFERENCES nodes (id),
    from_tunnel_id   TEXT NOT NULL CHECK (from_tunnel_id <> ''),
    from_generation  INTEGER NOT NULL CHECK (from_generation >= 1),
    to_node_id       TEXT NOT NULL REFERENCES nodes (id),
    to_tunnel_id     TEXT NOT NULL CHECK (to_tunnel_id <> ''),
    to_generation    INTEGER NOT NULL CHECK (to_generation >= 1),
    dns_record_id    TEXT NOT NULL DEFAULT '',                  -- the route's record when frozen; '' for a waiting route
    state            TEXT NOT NULL DEFAULT 'pending' CHECK (state IN (
                         'pending',
                         'dest_included', 'dest_published',     -- B's ingress carries the rule: intent, then reconciled
                         'dns_switching', 'dns_switched',       -- forward PATCH: intent, then applied
                         'committed', 'source_cleaned',         -- after the commit
                         'dns_restoring', 'dns_restored',       -- reverse PATCH: intent, then applied
                         'dest_excluded', 'dest_withdrawn')),   -- B's ingress drops the rule on compensation: intent, then reconciled
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (move_id, route_id),
    CHECK (from_node_id <> to_node_id),
    CHECK (created_at <= updated_at)
) STRICT;
CREATE INDEX app_move_routes_by_route ON app_move_routes (route_id);
-- everything but the state and its timestamp is fixed when the plan freezes the route
CREATE TRIGGER app_move_routes_ids_once BEFORE UPDATE OF move_id, route_id, frozen_phase, from_node_id, from_tunnel_id,
        from_generation, to_node_id, to_tunnel_id, to_generation, dns_record_id, created_at ON app_move_routes
WHEN NEW.move_id <> OLD.move_id OR NEW.route_id <> OLD.route_id OR NEW.frozen_phase <> OLD.frozen_phase
  OR NEW.from_node_id <> OLD.from_node_id OR NEW.from_tunnel_id <> OLD.from_tunnel_id OR NEW.from_generation <> OLD.from_generation
  OR NEW.to_node_id <> OLD.to_node_id OR NEW.to_tunnel_id <> OLD.to_tunnel_id OR NEW.to_generation <> OLD.to_generation
  OR NEW.dns_record_id <> OLD.dns_record_id OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'an app move route keeps its frozen identity'); END;

-- app_routes_ids_once as in 000009, except that node_id, tunnel_id and tunnel_generation may change together, as the
-- exact tuple of an app_move_routes row of the route's own target: the move is in routes_switched between the row's
-- nodes, the route's current values are the row's from-values and the new ones its to-values, and the row and the
-- route are in a matching pair (an active route whose record was repointed, or a waiting route still pending). Only
-- the commit of the move writes that update. Any other column changing in the same statement still aborts.
DROP TRIGGER app_routes_ids_once;
CREATE TRIGGER app_routes_ids_once BEFORE UPDATE OF id, app_target_id, node_id, hostname, service, port, access, account_id, zone,
        instance_id, tunnel_id, tunnel_generation, dns_record_id, access_app_id, plan_id, created_by, created_at ON app_routes
WHEN (OLD.dns_record_id <> '' AND NEW.dns_record_id <> OLD.dns_record_id)
  OR (OLD.access_app_id <> '' AND NEW.access_app_id <> OLD.access_app_id)
  OR NEW.id <> OLD.id OR NEW.app_target_id <> OLD.app_target_id
  OR NEW.hostname <> OLD.hostname OR NEW.service <> OLD.service OR NEW.port <> OLD.port OR NEW.access <> OLD.access
  OR NEW.account_id <> OLD.account_id OR NEW.zone <> OLD.zone OR NEW.instance_id <> OLD.instance_id
  OR (OLD.plan_id IS NOT NULL AND NEW.plan_id IS NOT OLD.plan_id) OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at
  OR ((NEW.node_id <> OLD.node_id OR NEW.tunnel_id <> OLD.tunnel_id OR NEW.tunnel_generation <> OLD.tunnel_generation)
      AND NOT EXISTS (
        SELECT 1 FROM app_move_routes r JOIN app_moves m ON m.id = r.move_id
        WHERE r.route_id = OLD.id AND m.app_target_id = OLD.app_target_id AND m.phase = 'routes_switched'
          AND m.source_node_id = r.from_node_id AND r.from_node_id = OLD.node_id
          AND m.dest_node_id = r.to_node_id AND r.to_node_id = NEW.node_id
          AND r.from_tunnel_id = OLD.tunnel_id AND r.to_tunnel_id = NEW.tunnel_id
          AND r.from_generation = OLD.tunnel_generation AND r.to_generation = NEW.tunnel_generation
          AND ((r.state = 'dns_switched' AND r.frozen_phase = 'active' AND OLD.phase = 'active')
            OR (r.state = 'pending' AND r.frozen_phase = 'waiting' AND OLD.phase = 'waiting'))))
BEGIN SELECT RAISE(ABORT, 'an app route keeps its identity and recorded object IDs'); END;
