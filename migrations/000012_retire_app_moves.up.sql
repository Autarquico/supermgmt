-- Retire app moves (ADR-0043). SuperMgmt no longer moves app targets between nodes, so the three move tables go, and
-- with them the extra branch app_routes_ids_once gained in 000011 for a route changing node mid-move.
--
-- A move that is not finished leaves work this version can no longer finish: B or its volumes may hold data, and a
-- cleanup or abandon job may have dispatched commands that were never confirmed. The migration refuses to run then,
-- changes nothing, and tells the operator to finish the move with the previous version. Only 'done' and 'rolled_back'
-- are terminal phases; 'failed' and 'conflict' halt a move that is still open. The jobs of a move are selected by their
-- type, never by their target: ordinary deployments share the same tables and are not touched here.

-- The guard: a row inserted into this table aborts the transaction with a fixed message, and the migration rolls back.
CREATE TABLE retire_app_moves_guard (open_work INTEGER NOT NULL) STRICT;
CREATE TRIGGER retire_app_moves_refuse BEFORE INSERT ON retire_app_moves_guard
BEGIN SELECT RAISE(ABORT, 'an app move is unfinished: finish the app move (or abandon it where it halted) with the previous SuperMgmt version before upgrading'); END;
INSERT INTO retire_app_moves_guard
SELECT 1 WHERE EXISTS (SELECT 1 FROM app_moves WHERE phase NOT IN ('done', 'rolled_back'))
    OR EXISTS (SELECT 1 FROM jobs
               WHERE type IN ('app_target.move', 'app_target.cleanup_source', 'app_target.abandon_move')
                 AND state NOT IN ('succeeded', 'failed', 'cancelled'))
    OR EXISTS (SELECT 1 FROM operation_intents
               WHERE state <> 'completed'
                 AND job_id IN (SELECT id FROM jobs
                                WHERE type IN ('app_target.move', 'app_target.cleanup_source', 'app_target.abandon_move')));
DROP TABLE retire_app_moves_guard;

-- Every move job left is terminal and settled: its locks are leftovers nothing will release, and they would block
-- the project and ports of both nodes. Jobs, plans, intents and events stay as history.
DELETE FROM resource_locks
WHERE job_id IN (SELECT id FROM jobs
                 WHERE type IN ('app_target.move', 'app_target.cleanup_source', 'app_target.abandon_move'));

-- The trigger reads app_move_routes and app_moves, so it goes before them and comes back as 000009 defined it.
DROP TRIGGER app_routes_ids_once;
DROP TABLE app_move_routes;
DROP TABLE app_move_volumes;
DROP TABLE app_moves;
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
