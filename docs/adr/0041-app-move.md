# ADR-0041: Moving an app target to another node

- Status: Proposed
- Spec: spec `docs/specs/app-move.md`; ADR-0009, ADR-0029, ADR-0030, ADR-0040

## Context

An app target names one node for life: the API refuses to change it, deployments, locks and health all read `target.node_id`, and nothing copies a volume. Moving an app means recreating it by hand and copying data outside SuperMgmt.

## Decision

### A move is one resumable, approved job with its own record

- `sm apps move <app> <env> --to <node>` plans `app_target.move`, a high-risk job on the app target. The plan freezes both nodes, the known-good deployment and its content, and a volume map (one export/import container and mount per distinct named volume).
- `app_moves` records the phase and `app_move_volumes` each volume's attempt, state, sizes and manifest digests. At most one open move per target; deployments, rollbacks, exposes and same-project targets on the destination are refused while it is open.
- Targets with routes are refused. Moving routes is a separate decision (`app-move-routes`).

### The destination is proven before the source is touched

- Request time and again under the claim locks: managed destination in the same environment, no Compose project clash (open moves count), loopback or unspecified binds only, every volume writable by some service, node-scope health checks only.
- Preflight reads both nodes and changes neither: the deploy preflight plus platform, memory, CPU, image and volume bytes on the destination, no pre-existing target volumes there, and the source running the known-good deployment.

### Same content, redeployed like a rollback

- The destination gets a deployment of kind `move` with the known-good digests, model and secret versions, pulled, materialised, verified and created without starting.

### Data is a stopped-container file copy streamed through the daemon

- A stateful move stops the source and verifies every container exited, then streams each volume as tar from `docker cp <c>:<mount>/. -` into `docker cp - <c>:<mount>` on the destination's created container. The daemon is the only path; nothing is written to its disk.
- The transport gains a streaming SSH session with an exit status, deadlines, a byte ceiling and guaranteed session release. Both node commands run under `timeout`, so neither can outlive its deadline.
- The import is a mutating intent. An unknown outcome is settled only once its deadline has passed. A copy counts only when both ends exit 0 and a second export from the destination has the same manifest (paths, types, modes, owners, sizes, links, hashes).
- A retry replaces the volume: it is removed (only if this move created it) and recreated empty before copying again.

### Authority moves at the destination's first start

- Before the destination ever starts, the source holds the only data, so a failure may remove what the move created on the destination.
- Once the destination has started it may hold writes, so its volumes are never removed automatically. Compensation stops it, restarts and health-checks the source, and keeps both copies.
- Compensation is persisted phase by phase. If the source does not come back healthy, the move halts with the destination stopped and intact, and the target stays blocked until the operator resumes or abandons it.

### Commit last, in one fenced transaction

- The commit compares-and-sets the target's revision and node, settles the destination deployment as known-good and advances the move, asserting every row count.
- Before the commit, claims revalidate by rebuilding the plan against the frozen nodes. After it, claims validate against the move record, because a moved target's rebuild always differs from its plan. Locks always come from the frozen nodes.
- After the commit the source is left stopped. `sm apps move --cleanup-source` removes its containers only while they still carry the parked deployment's label and the target is elsewhere; volumes are never deleted.

## Consequences

- Stateful moves have downtime from the source stop until the destination is healthy.
- A consistent copy depends on the app tolerating a cold file copy of stopped containers. Database-aware dumps stay out of scope.
- A failed move after the destination started can leave a second copy of the data on the destination; reclaiming it is the operator's call, and a new move to that node refuses it until then.
- Source volumes are never deleted by SuperMgmt.
