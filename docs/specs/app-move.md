---
codename: supermgmt
title: Move an app target to another node
type: epic
status: shipped
priority: P1
size: XL
issue: 52
prs: [55]
related_issues: [52]
depends_on: []
supersedes: []
related_specs: [m4-apps-deployments, app-expose-tunnel]
created: 2026-10-31
updated: 2026-11-01
---

# Move an app target to another node

## Contexto / problema

An app target is bound to one node for life:
- the API refuses to change it: "Environment, node and Compose project never change" (`internal/api/wire/m4.go:173-177`);
- the repository can write `node_id` (`internal/database/repo_apps.go:272`), but its only caller updates the policy (`internal/app/apps.go:1300`);
- volumes are never copied, and the only backup is a `pg_dump` kept on the same node with no restore path (`internal/app/deploy_backup.go:57`, `internal/app/compose_stage.go:237`).

Moving an app today, for example from a Proxmox VM to an OVH host, means deleting the target, recreating it on the other node, redeploying and copying volumes by hand.

Maintainer goal (2026-10-29): one command moves an app from one node to another, and checks first that the destination can host it.

This spec moves targets **without routes**. Moving a target's Cloudflare routes with it is a separate spec, `app-move-routes`. The split was decided on 2026-11-01 after the plan critique (`.claude/loop/app-move/codex-critique.md`, items 2, 5, 11 and 12).

## Terms

- **A** is the source node and **B** the destination.
- **Stateful** means either of two things: the frozen policy says `stateful` (`internal/manifest/types.go:64`), or the frozen Effective model declares a named volume. `tmpfs` mounts are not data. Bind mounts cannot exist (`internal/deployments/compose/rawschema.go:172-179`).
- **Authority.** Until B is started for the first time, A holds the only data that can be newer. From then on, B may hold writes that A lacks, so SuperMgmt never deletes B's volumes automatically after that point.

## Scope

**Entra:**

1. **`sm apps move <app> <env> --to <node>`**
   - **Policy.** It is a new policy action `app_target.move`, in job mode (`internal/policy/catalog.go:195`), on the app target. It is high risk, needs the capability `docker.compose.deploy` on both nodes, and gets 3 attempts with resume, like `deployment.create` (`catalog.go:300`). Before approval, the CLI prints whether the move stops the app and for how long the data copy is expected to keep it down.
   - **What the plan freezes:**
     - A and B, with their IDs, endpoints and pinned host keys;
     - the target's newest known-good deployment and its content (`internal/app/snapshots.go:196`);
     - whether the move is stateful;
     - the **volume map**. It has one entry per distinct named volume (`<project>_<volume>`), each with:
       - the service whose container is used to export and import it. That is the first service, in name order, that mounts the volume read-write;
       - the mount target;
       - every other service that mounts it.
   - **It refuses at request time, before any node is touched,** when any of these holds:
     - B is A, is not `managed`, or has a different `EnvironmentID` from A (`internal/domain/entity.go:56-57`);
     - the target has no known-good deployment;
     - the target has an open deployment, rollback or move;
     - another target on B uses the same Compose project. The check counts the destinations of open moves as using it (`UNIQUE(node_id, compose_project)`, `migrations/000005_m4.up.sql:43-61`);
     - the target has an `app_routes` row that is not `removed`. The message says to unexpose first and that moving routes comes later;
     - the known-good model binds a host port to an address other than `127.0.0.1` or `0.0.0.0`. The `allowed_bind_addresses` are A's addresses (`internal/app/finalize.go:292`);
     - a named volume is mounted by no service read-write;
     - a health check has control-plane scope (`internal/health/types.go:33`). Such a check does not run on a node (`internal/app/deploy_health.go:118-120`), so it cannot prove that B is healthy.
   - **While a move is open:**
     - deployments and rollbacks of the target are refused, both at request time and at claim time;
     - a new target on B with the same Compose project is refused;
     - an `app_route.expose` of the target is refused.
2. **The move record.** A new migration, `000010`, adds two tables.
   - **`app_moves`** holds:
     - the move ID, the target, A, B and the plan and job IDs;
     - the known-good deployment and B's deployment;
     - `stateful`, and B's started-at time (`b_started_at`, null until the first start);
     - the phase, with the halted/conflict semantics of `tunnel_operations` (`internal/database/repo_tunnel.go:180,205,226`), plus `phase_started_at`, `last_error`, the target revision written by the commit, and timestamps.

     At most one move per target is open, enforced by a partial unique index like `tunnel_operations_one_active` (`migrations/000007_cloudflare_tunnels.up.sql:50`).
   - **`app_move_volumes`** has one row per entry of the volume map. Each row holds the volume name, the export and import service, the mount target, the attempt number, a state (`pending`, `importing`, `imported`, `verified`), the bytes and the manifest digest of each side, and whether this move created the volume on B.
   - **Forward phases:**
     1. `preflight`;
     2. `staged`;
     3. stateful only: `source_stopped`, then `data_copied`;
     4. `started`, `verified`, `committed`, `source_parked` and `done`.
   - **Compensation phases** apply only before `committed`, in this order:
     1. `compensating_b_stopped`;
     2. `compensating_source_started`;
     3. `compensating_source_verified`;
     4. `compensating_b_removed`, which is skipped when B was ever started;
     5. `rolled_back`.
3. **Preflight.** It reads both nodes and changes neither.
   - **On B,** it reuses `runPreflight` (`internal/app/deploy_preflight.go:56`) for capability, ownership, ports and disk. It also checks:
     - **architecture:** `compose.image_size` runs for every image, even one already present, so a missing platform fails ("no unique platform match", `internal/transport/ssh/templates/compose_stage.go:219-226`);
     - **memory and CPU:** a new read template over `docker info` gives `NCPU` and `MemTotal`. The sum of the services' `mem_limit` or `deploy.resources.limits.memory` must fit in `MemTotal`, and no service's `cpus` may exceed `NCPU`. Services without limits are not counted;
     - **volume space:** the size of A's volumes is added to the bytes needed on B's Docker root, with a 10% margin. A's volume sizes come from a new read template over `docker system df -v --format json`. Image sizes count manifest layer bytes, not unpacked size, and the error says so;
     - **no leftover volumes:** none of the volume map's names exist on B. A volume that exists without explanation is a conflict, never adopted or deleted.
   - **On A,** it checks that A runs the known-good deployment:
     - every project container carries the target's owner label and that deployment's label (`internal/deployments/compose/types.go:21,23`);
     - every volume in the map exists.
   - **Decoding.** Every decoder of these reads fails closed on an unknown, missing or overflowing value.
   - **Re-checks under the claim locks.** The request-time checks run again right before `staged` and right before `started`. These are project uniqueness, the open-work refusals, B's management state and environment, and B's capability.
4. **Stage on B.**
   - B gets a deployment row of a new kind, `move`. It carries the known-good content: the same digests, Compose model and secret versions. It is built like a rollback (`internal/app/deployments_rollback.go:28`, `internal/app/finalize.go:393`).
   - Its steps reuse pull, materialize and verify (`internal/app/deploy_handler.go:425-470`), followed by a new `compose create` template. Nothing is started, and A keeps serving.
   - Before `compose create` is dispatched, each volume row is marked as created by this move. That record is the ownership evidence for any later removal: preflight proved the volumes did not exist on B.
5. **Data (stateful only).**
   - **Stop A.** A is stopped with a new `compose stop` template, and every project container is then verified as exited. Downtime starts here. Space on B is checked again with fresh sizes.
   - **Copy each volume, one at a time.** The volume is exported from A's container with `docker cp <container>:<mount>/. -` and imported into B's created container with `docker cp - <container>:<mount>`. The bytes pass through the daemon only, with no helper image. Containers are named `<project>-<service>-1` (`internal/app/deploy_handler.go:89`).
   - **Bounded on the node.** Both ends run under `timeout -k <kill> <deadline>`, rendered by the template, so a command cannot outlive its deadline even when the daemon loses the session.
   - **Intents.**
     - The import is a mutating command. It records an intent with the deadline before it is dispatched, through the same dispatcher as deployment steps (`internal/app/deploy_handler.go:507-515`). Its outcome is known only when both ends exit 0.
     - An import whose outcome is unknown is proven stopped once its deadline plus the kill margin has passed since the intent was recorded. Only then does the volume become `pending` again.
     - The export is a read. It is bounded but records no intent.
   - **Verify independently.** After each import, the daemon exports the volume again from B and compares a manifest of both archives. The manifest lists every entry's path, type, mode, numeric uid and gid, size, link target and content SHA-256. A mismatch fails the attempt.
   - **Retry by replacement.** A volume is never imported twice into the same volume. Before a retry, B's containers are removed (`compose down`, keeping volumes), the volume is removed (allowed only when its row says this move created it), and the arrangement is recreated with `compose create`.
   - **Stateless moves** do not stop A and skip this step.
6. **Start and verify B.**
   - B is started with a new `compose start` template. `b_started_at` is persisted before the dispatch.
   - The target's node-scope health checks then run against B's executor (`internal/app/deploy_health.go:55,113-136`).
7. **Compensation** runs on any failure before `committed`, including the last attempt and a typed halt. It is persisted phase by phase:
   - B is stopped, not removed;
   - A is started (when it was stopped) and must pass its node-scope health checks;
   - only if B was never started, B's containers and the volumes this move created are removed;
   - the move ends `rolled_back`. The target and B's deployment row are left as they were, and the deployment is marked failed.

   If A does not come back healthy, the move halts in its compensation phase and B and its volumes are kept. The target stays blocked by the open move until a new `sm apps move` resumes it or `sm apps move --abandon` records the operator's decision. After `rolled_back`, any volumes left on B are listed, and a new move to B refuses them until the operator removes them.
8. **Commit.** It is one fenced transaction under the job's lease, and it does the following:
   - writes `app_targets.node_id` = B, as a compare-and-set on both the plan's revision and `node_id = A` (`repo_apps.go:272`);
   - settles B's deployment as succeeded and makes it the target's known-good deployment;
   - records the revision the commit wrote;
   - advances the move to `committed`.

   Every statement asserts its row count, and any mismatch rolls the whole transaction back.
9. **Resume.**
   - Before `committed`, claim-time revalidation rebuilds the plan as usual (`internal/app/resolve.go:296`), but against the move's frozen nodes.
   - From `committed` on, the claim is validated against the `app_moves` row instead of the rebuild. The move ID, job, B, B's deployment and the recorded revision must all match. The rebuild of a moved target always differs from its plan.
   - Locks always come from the frozen nodes.
10. **Park A.** After the commit, a stateless A is stopped. Every A is left stopped and is never removed, and volumes are never deleted (`internal/app/compose_run.go:23`).
11. **`sm apps move <app> <env> --cleanup-source`** is its own approval-gated job, `app_target.cleanup_source`.
    - **Its plan freezes** the last `done` move of the target, A, the Compose project and A's deployment.
    - **It refuses** in any of these cases:
      - the target is on A again;
      - another target on A uses the project;
      - any project container on A lacks the frozen deployment's label.
    - **It runs** `compose down` without volumes on A, holding A's project lock, and lists A's volumes, which are kept.
12. **`sm apps move <app> <env> --abandon`** is approval-gated. It moves a move halted in compensation to `rolled_back` and leaves A and B exactly as they are.
13. **Locks.** The move job holds:
    - the target lock;
    - exclusive Compose project and port locks on **both** frozen nodes. Today `deploymentLocks` reads the live `target.NodeID` (`internal/app/locks.go:148`);
    - shared locks on both nodes.

    Cleanup holds the target lock and A's project lock.
14. **Transport.** A new streaming primitive is added for SSH sessions only (`Connector.Local` returns unsupported).
    - **Interface:** `OpenStream(ctx, node, command)` returns a stream with these methods:
      - a stdout reader or a stdin writer;
      - an idempotent `Close`;
      - `Abort`;
      - `Wait() (exit, stderrTail, err)`.
    - **Limits:**
      - a total deadline and an idle deadline;
      - a byte ceiling from the plan's sizes plus a margin;
      - a stderr tail that is bounded and sanitised;
      - transfer that is binary-transparent and uses bounded memory;
      - a slot that counts against `max_sessions` and is released on every path.
    - **Copy behaviour:** importer stdin is closed before waiting. If either end fails, both are aborted.
    - **Templates.** The primitive renders only these streaming templates: `docker.volume_export` and `docker.volume_import`. It does not use `Executor.Run`, which buffers and truncates (`internal/transport/transport.go:26`, `internal/transport/ssh/limits.go`). It also does not use `OpenRelay`, which has no exit status (`internal/transport/ssh/relay.go:22,120-166`).
15. **Reconcile.** The new job types get a reconcile `TypePolicy` (`internal/daemon/assemble.go:258-266`, `internal/jobs/reconcile.go:511-523`). It covers each mutating command: create, stop, start, down, volume removal and import. Each command's evidence is the read that proves its effect. For example, an exited container or an absent volume. For an import, the evidence is the elapsed deadline.
16. **Surfaces.**
    - API: `POST /app-targets/{id}/moves`, `GET /app-targets/{id}/moves`, `POST /app-targets/{id}/moves/cleanup-source` and `POST /app-targets/{id}/moves/abandon`, with wire types and OpenAPI.
    - Client and CLI: `sm apps move`, plus `sm apps moves <app> <env>` with its phase and volumes. TUI palette entry `move`.
    - MCP: write tool `infra_move_app` (plan and approval only) and read tool `infra_list_app_moves`, plus goldens and the route matrix.
    - Audit events: `app_move.started`, `app_move.committed`, `app_move.rolled_back`, `app_move.halted` and `app_move.source_cleaned`.
17. **Docs.**
    - `docs/cli.md`;
    - `docs/deployments.md`;
    - `docs/security.md`: data crosses the daemon in transit over two SSH sessions and is never written to its disk;
    - `docs/project-status.md`;
    - a manual checklist, `docs/manual-checks/app-move.md`.

**No entra:**

- Moving Cloudflare routes, which belongs to `app-move-routes`.
- Live migration without downtime for stateful apps.
- Moving a target between environments or between SuperMgmt instances.
- Database-aware dumps. The copy is a file copy of stopped containers.
- Deleting volumes on A, ever. On B, volumes are deleted only before B's first start, and only the volumes this move created.
- Moving the `pg_dump` backups of `deploy_backup.go`.
- Compressing, deduplicating or resuming a partial volume. A failed copy replaces that volume.

## Criterios de aceptación

### Scenario: a stateless app moves with no downtime
- **Given** a target on A with a known-good deployment, no named volumes and `stateful: false`, and a managed node B in the same environment
- **When** the user runs `sm apps move shop prod --to B` and approves
- **Then** B runs the same image digests and Compose model, `app_targets.node_id` is B, B's deployment is the known-good one, A's containers are stopped and not removed, and A kept running until B passed its health checks

### Scenario: a stateful app's volume data reaches the destination intact
- **Given** a target on A whose named volume holds a nested tree with a symlink, a file with mode 0600 owned by uid 1000, and files seeded by the image
- **When** it moves to B
- **Then** A's containers have exited before the first export, B's `<project>_<volume>` has the same manifest (paths, modes, uid/gid, sizes, link targets, content hashes), B is healthy and A's volume still exists

### Scenario: a volume shared by two services is copied once
- **Given** a named volume mounted read-write by `web` and read-only by `worker`
- **When** it moves
- **Then** the volume is exported and imported once through `web`'s container, and `worker` on B mounts the copied data

### Scenario: preflight refuses an unfit destination without changing either node
- **Given** a B that lacks the image platform, or whose memory is below the services' limits, or whose disk is below images plus volumes plus margin, or that already has one of the target's volumes
- **When** the move runs
- **Then** it fails at `preflight`, only read commands ran on A and B, and A is still running

### Scenario: request-time refusals
- **Given** a B that is A, is unmanaged, is in another environment, or already hosts the Compose project (directly or as an open move's destination); or a target with no known-good deployment, an open deployment, rollback or move, a route that is not removed, a non-loopback bind address, a volume no service mounts read-write, or a control-plane health check
- **When** the user requests the move
- **Then** it is refused with a message naming the reason, and no plan is created

### Scenario: a failed copy is replaced, never merged
- **Given** an import that ends early, an end that exits non-zero, or a manifest mismatch
- **When** the volume is retried
- **Then** B's containers are removed, the move-created volume is removed and recreated empty by `compose create`, and the next import starts from an empty volume

### Scenario: an import with an unknown outcome is not retried while it may still run
- **Given** the daemon loses the session during an import
- **When** the job is retried before the import's deadline plus kill margin has passed
- **Then** the volume stays `importing` and nothing touches it until that time, after which it is replaced and copied again

### Scenario: B fails its health check before it was ever healthy
- **Given** a stateful move whose B was started and fails its health checks
- **When** compensation runs
- **Then** B is stopped first, A is started and passes its health checks, B's volumes are kept and listed because B had been started, `node_id` is A, and the move is `rolled_back`

### Scenario: A does not come back during compensation
- **Given** a compensation where A's health checks fail after its restart
- **When** compensation settles
- **Then** the move halts in `compensating_source_started` or `compensating_source_verified`, B is stopped with its volumes intact, deployments of the target are refused, and `sm apps move --abandon` or a new `sm apps move` is required

### Scenario: a failure before B ever started removes only what the move created
- **Given** a move that fails after `staged` and before `started`
- **When** compensation runs
- **Then** A is running and healthy, and B's containers and the volumes recorded as created by this move are gone, and nothing else on B was removed

### Scenario: the move resumes across the commit
- **Given** a move interrupted after `data_copied`, after `verified` and after `committed`
- **When** the daemon restarts and the job is retried
- **Then** it continues from the recorded phase without copying again, the post-commit claim is validated against the move record rather than the rebuilt plan, and the locks are those of the frozen nodes

### Scenario: the commit is all or nothing
- **Given** a target whose revision or `node_id` changed after the plan
- **When** the commit transaction runs
- **Then** nothing is written, the move does not advance, and compensation runs

### Scenario: cleanup removes the parked source only on request and only if it is still ours
- **Given** a `done` move
- **When** the user runs `sm apps move shop prod --cleanup-source` and approves
- **Then** `compose down` without volumes runs on A, A's volumes still exist and are listed, nothing ran on B
- **And** if the target was moved back to A, or A's project containers carry another deployment's label, cleanup is refused

### Scenario: concurrent work is serialised
- **Given** a move in progress
- **When** a deployment or rollback of the same target, a new target on B with the same project, an expose of the target, or a deployment of another target on B with a conflicting port is requested
- **Then** each is refused or waits for the move's locks, and the move's re-checks under its locks still pass or fail closed

### Scenario: an MCP client requests a move and it waits for approval
- **Given** write tools enabled
- **When** an MCP client calls `infra_move_app`
- **Then** a plan is submitted, nothing runs until approval, and `infra_list_app_moves` shows the move's phase afterwards

## Notas técnicas / riesgos

- **Gate, not verified yet:** the exact semantics of `docker cp <c>:<mount>/. -` and `docker cp - <c>:<mount>` against a created, never-started container's named volume on Compose v5.5.1. Two fixture node daemons can prove it (`test/integration/fixtures_support_test.go:57`, `test/fixtures/node/Dockerfile`). It must hold for root and nested mount targets, image-seeded files, numeric ownership, modes, symlinks and a replaced volume before the job is built on it.
- `deployments.kind` allows only `deploy` and `rollback` (`migrations/000005_m4.up.sql:119`, `internal/deployments/types.go:47-48`). Adding `move` rebuilds the table in `000010` and must keep every index, trigger and dependent row. A migration test runs against populated tables.
- There are no `compose create/start/stop` templates yet (`internal/transport/ssh/templates/compose_run.go:24-45`).
- Crash injection is required around every remote dispatch and every durable checkpoint.
- The feature is experimental and tested only against fakes and fixture daemons until the manual checklist passes with real nodes.

## Referencias

- ADR-0041 (this feature), ADR-0029 (rollback), ADR-0009 (docker_access), ADR-0030 (capabilities), ADR-0040 (routes).
- Plan: `/Users/alex/.claude/plans/resilient-wandering-sky.md`, feature 4. Critique: `.claude/loop/app-move/codex-critique.md`.
