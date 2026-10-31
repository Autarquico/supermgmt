---
codename: supermgmt
title: Move an app target to another node
type: epic
status: active
priority: P1
size: XL
issue: 52
prs: []
related_issues: [52]
depends_on: []
supersedes: []
related_specs: [m4-apps-deployments, app-expose-tunnel, node-enroll-tunnel]
created: 2026-10-31
updated: 2026-10-31
---

# Move an app target to another node

## Contexto / problema

An app target is bound to one node for life:
- the API refuses to change it: "Environment, node and Compose project never change" (`internal/api/wire/m4.go:173-177`);
- the repository can write `node_id` (`internal/database/repo_apps.go:272`), but its only caller updates the policy (`internal/app/apps.go:1300`);
- volumes are never copied, and the only backup is a `pg_dump` kept on the same node with no restore path (`internal/app/deploy_backup.go:57`, `internal/app/compose_stage.go:237`).

Moving an app today, for example from a Proxmox VM to an OVH host, means deleting the target, recreating it on the other node, redeploying, copying volumes by hand and redoing the Cloudflare routes from feature 3 (`docs/specs/app-expose-tunnel.md`).

Maintainer goal (2026-10-29): one command moves an app from one node to another, and checks first that the destination can host it.

## Scope

**Entra:**

1. **`sm apps move <app> <env> --to <node>`**
   - A new policy action `app_target.move`, mode job (`internal/policy/catalog.go:195`), on the app target, risk high, capability `docker.compose.deploy` on both nodes, 3 attempts with resume (like `deployment.create`, `catalog.go:300`).
   - The plan freezes: the source node and the destination node (IDs, endpoint and pinned host key), the target's newest known-good deployment and its content (`internal/app/snapshots.go:196`), whether the move is stateful, the list of named volumes, and the target's routes.
   - **Stateful** means the frozen policy says `stateful` (`internal/manifest/types.go:64`) **or** the frozen Effective model declares any named volume. `tmpfs` mounts are not data. Bind mounts cannot exist (`internal/deployments/compose/rawschema.go:172-179`).
   - **It refuses at request time, before any node is touched,** when:
     - the destination is the source, is not `managed`, or has a different `EnvironmentID` from the source (`internal/domain/entity.go:56-57`);
     - the target has no known-good deployment, or a deployment or move of the target is open;
     - another target on the destination already uses the same Compose project (`UNIQUE(node_id, compose_project)`, `migrations/000005_m4.up.sql:43-61`);
     - the target has routes that are not `removed` and the destination has no committed tunnel (`transport: cloudflare`), or the routes would exceed the destination's 98-route limit (`internal/app/app_routes.go:20`);
     - the known-good model binds a host port to an address other than `127.0.0.1` or `0.0.0.0`: `allowed_bind_addresses` are source-node addresses (`internal/app/finalize.go:292`).
2. **The move record.** A new table `app_moves` (migration `000010`) with the move ID, target, source node, destination node, the plan's known-good deployment, the destination deployment, `stateful`, the volume list, the phase with the halted/conflict semantics of `tunnel_operations` (`internal/database/repo_tunnel.go:180,205,226`), `phase_started_at`, `last_error` and timestamps. At most one open move per target (partial unique index, as `tunnel_operations_one_active`, `migrations/000007_cloudflare_tunnels.up.sql:50`).
   - Phases: `preflight` → `staged` → (`source_stopped` → `data_copied`, stateful only) → `started` → `routes_switched` → `committed` → `source_parked` → `done`. A failure before `committed` compensates and ends `rolled_back`; a halt keeps `halted_phase`.
3. **Preflight on the destination** reuses `runPreflight` (`internal/app/deploy_preflight.go:56`): capability, ownership, ports and disk. It adds:
   - **architecture:** `compose.image_size` runs for every image even when present, so a missing platform fails ("no unique platform match", `internal/app/compose_stage.go:219-226`);
   - **memory and CPU:** a new read template over `docker info` (`NCPU`, `MemTotal`). The sum of the services' `mem_limit` / `deploy.resources.limits.memory` must fit `MemTotal`, and each service's `cpus` must not exceed `NCPU`. Services without limits are not counted;
   - **volume space:** the source volumes' sizes (a new read template over `docker system df -v --format json`) are added to the bytes needed on the destination's Docker root;
   - **no leftover volumes:** none of the target's `<project>_<volume>` volumes may already exist on the destination. Volumes are never adopted;
   - **routes:** the destination has a committed tunnel when routes exist (`internal/app/app_routes_job_ingress.go:87`).
4. **Stage on the destination.** The destination gets a deployment row with the known-good content (same digests, Compose model and secret versions), built like a rollback (`internal/app/deployments_rollback.go:28`, `internal/app/finalize.go:393`), with a new kind `move`. Its steps reuse pull, materialize and verify (`internal/app/deploy_handler.go:425-470`), then a new `compose create` template, without starting. The source keeps serving.
5. **Data (stateful only).**
   - The source is stopped with a new `compose stop` template. Downtime starts here and the command says so before approval.
   - Each named volume is copied as a tar stream from the source container (`docker cp <container>:<mount> -`) through the daemon into the destination container (`docker cp - <container>:<parent>`). There is no helper image. Containers are `<project>-<service>-1` (`internal/app/deploy_handler.go:89`).
   - Streaming needs a new transport primitive: an SSH session whose stdout or stdin is a stream, with an exit status and a deadline. Today `Executor.Run` buffers and truncates (`internal/transport/transport.go:26`, `internal/transport/ssh/limits.go`), and `OpenRelay` has no exit status (`internal/transport/ssh/relay.go:22,120-166`). Both ends must exit 0 and the byte counts must match.
   - A stateless move does not stop the source and skips this step.
6. **Start and health on the destination** with a new `compose start` template, then the target's health verifier (`internal/app/deploy_health.go:55`) against the destination.
   - **On failure before `committed`:** the destination containers are removed (`compose down` without volumes); the volumes this move created on the destination are removed, because the source still has the data and preflight proved they did not exist; a stopped source is started again and health-checked. The move ends `rolled_back`. Routes and the target are untouched. If the source does not come back healthy, the move halts and says so.
7. **Switch routes** (only when the target has routes), holding the instance Cloudflare lock (`internal/app/locks.go:44`):
   - the destination tunnel's ingress gains the target's rules: the ingress builder (`internal/app/app_routes_job_ingress.go:33`) includes routes of a move into that node from `started` on;
   - each CNAME is repointed to the destination tunnel, after the same ownership check as expose (`internal/app/app_routes_job_expose.go:89`). The client gains `UpdateDNSRecord`; today it has create, find and delete only (`internal/providers/cloudflare/dns.go:45,70,84`). The Access app does not depend on the tunnel and is kept;
   - the source tunnel's rules are removed after the commit.
8. **Commit.** One transaction writes `app_targets.node_id` (revision checked, `repo_apps.go:272`), each route's node, tunnel ID and tunnel generation, and the destination deployment as the target's known-good. A migration relaxes `app_routes_ids_once` (`migrations/000009_app_routes.up.sql:50-59`) so those three columns change together only while the target's move is in `routes_switched`. The plan's revision pin accepts exactly this +1 bump, as `acceptOwnSwitch` does (`internal/app/resolve.go:321`).
9. **Park the source.** After the commit, a stateless source is stopped. Every source is left stopped, never removed. Volumes are never deleted (`internal/app/compose_run.go:23`).
10. **`sm apps move <app> <env> --cleanup-source`** runs `compose down` without volumes on the source of the target's last `done` move, as its own approval-gated action `app_target.cleanup_source`. Source volumes are kept and listed.
11. **Locks.** The move job holds the target lock, exclusive Compose-project and port locks on **both** nodes taken from the plan's frozen node IDs (today `deploymentLocks` reads the live `target.NodeID`, `internal/app/locks.go:148`), shared locks on both nodes and, with routes, the instance Cloudflare lock.
12. **Surfaces.**
   - API `POST /app-targets/{id}/moves`, `GET /app-targets/{id}/moves`, `POST /app-targets/{id}/moves/cleanup-source`, wire types and OpenAPI.
   - Client, CLI (`sm apps move`, `sm apps moves <app> <env>`), TUI palette entry `move`.
   - MCP write tool `infra_move_app` (plan + approval only), read tool `infra_list_app_moves`, goldens and route matrix.
   - Audit events `app_move.started`, `app_move.committed`, `app_move.rolled_back`, `app_move.halted`.
13. **Docs.** `docs/cli.md`, `docs/deployments.md` (or the apps page), `docs/security.md` (data crosses the daemon in transit over the two SSH sessions), `docs/project-status.md`, manual checklist `docs/manual-checks/app-move.md`.

**No entra:**

- Live migration without downtime for stateful apps.
- Moving between environments or between SuperMgmt instances.
- Copying anything other than named volumes (bind mounts are already forbidden; images are pulled again).
- Database-aware dumps. The copy is a file copy of a stopped container.
- Automatic deletion of source volumes, ever.
- Moving the `pg_dump` backups of `deploy_backup.go`.
- Compressing or resuming a partially copied volume: a failed copy restarts that volume from scratch.

## Criterios de aceptación

### Scenario: a stateless app moves with no downtime
- **Given** a target on node A with a known-good deployment, no named volumes and `stateful: false`, and a managed node B in the same environment
- **When** the user runs `sm apps move shop prod --to B` and approves
- **Then** B runs the same image digests and Compose model, `app_targets.node_id` is B, the source containers on A are stopped and not removed, and A served until B passed its health check

### Scenario: a stateful app's volume data reaches the destination
- **Given** a target on A with a named volume containing a known file
- **When** it moves to B
- **Then** A's containers are stopped before the copy, the file is in B's `<project>_<volume>` volume with the same content, B is healthy and A's volume still exists

### Scenario: preflight refuses an unfit destination before touching either node
- **Given** a destination that lacks the image platform, or has less memory than the services' limits, or less disk than images plus volumes, or already has one of the target's volumes
- **When** the move runs
- **Then** it fails at `preflight`, the source was not stopped and no command ran on the source

### Scenario: request-time refusals
- **Given** a destination that is the source, unmanaged, in another environment, already hosting the Compose project, without a tunnel while the target has routes, or a target with no known-good deployment, an open deployment, an open move, or a non-loopback bind address
- **When** the user requests the move
- **Then** it is refused with a message naming the reason and no plan is created

### Scenario: a failed destination health check rolls back
- **Given** a stateful move whose destination fails its health check
- **When** the move handles the failure
- **Then** the destination containers and the volumes the move created on B are removed, A is started again and passes its health check, routes and `node_id` are unchanged, and the move is `rolled_back`

### Scenario: routes follow the app
- **Given** a target with an `owners` route `shop.example.com` on A, and B with a committed tunnel
- **When** it moves to B
- **Then** B's ingress serves the rule before the CNAME is repointed, the CNAME points at B's tunnel with the route marker, the Access app is the same object, A's ingress no longer has the rule after the commit, and the route row names B, B's tunnel and its generation

### Scenario: a foreign DNS record halts the switch
- **Given** a route whose CNAME was replaced by a record without the route marker
- **When** the move reaches the route switch
- **Then** it halts before the commit, the foreign record is untouched, and A keeps serving

### Scenario: the move resumes after the daemon dies
- **Given** a move interrupted after `data_copied`, after `routes_switched` and after `committed`
- **When** the daemon restarts and the job is retried
- **Then** it continues from the recorded phase without copying again, without a second CNAME change, and the revision bump of its own commit is not treated as drift

### Scenario: an interrupted copy is not trusted
- **Given** a stream that ends early or an end that exits non-zero
- **When** the copy step settles
- **Then** the volume is copied again from scratch on retry, and the move never starts B with a partial volume

### Scenario: cleanup removes the parked source only on request
- **Given** a `done` move
- **When** the user runs `sm apps move shop prod --cleanup-source` and approves
- **Then** `compose down` without volumes runs on A, A's volumes still exist and are listed, and no command touched B

### Scenario: concurrent work is serialised
- **Given** a move in progress
- **When** a deployment of the same target, a deployment of another target on B with a conflicting port, or a tunnel disable of A or B is requested
- **Then** each waits for the move's locks or is refused, and no port or ingress is shared

### Scenario: an MCP client requests a move and it waits for approval
- **Given** write tools enabled
- **When** an MCP client calls `infra_move_app`
- **Then** a plan is submitted, nothing runs until approval, and `infra_list_app_moves` shows the move's phase afterwards

## Notas técnicas / riesgos

- **Unverified:** whether `docker cp - <created, never-started container>:<mount>` writes into the named volume on Compose v5.5.1. The fixture test with two node daemons (`test/integration/fixtures_support_test.go:57`, `test/fixtures/node/Dockerfile`) must prove it before the rest is built on it.
- `deployments.kind` allows only `deploy` and `rollback` (`migrations/000005_m4.up.sql:119`); adding `move` rebuilds the table in migration `000010`.
- Outcome-unknown node intents need a reconcile policy for the new job type (`internal/daemon/assemble.go:258-266`).
- No `compose create/start/stop` templates exist (`internal/transport/ssh/templates/compose_run.go:24-45`).
- Experimental and tested against fakes and fixture daemons only until the manual checklist passes with real nodes.

## Referencias

- ADR-0041 (this feature), ADR-0040 (routes), ADR-0029 (rollback), ADR-0009 (docker_access), ADR-0030 (capabilities).
- Plan: `/Users/alex/.claude/plans/resilient-wandering-sky.md`, feature 4.
