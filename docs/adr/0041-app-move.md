# ADR-0041: Moving an app target to another node

- Status: Proposed
- Spec: spec `docs/specs/app-move.md`; ADR-0009, ADR-0029, ADR-0030, ADR-0040

## Context

An app target names one node for life: the API refuses to change it, deployments, locks and routes all read `target.node_id`, and nothing copies a volume. Moving an app means recreating it by hand and copying data outside SuperMgmt.

## Decision

### A move is one resumable, approved job with its own record

- `sm apps move <app> <env> --to <node>` plans `app_target.move`, a high-risk job on the app target. The plan freezes both nodes, the known-good deployment and its content, the named volumes and the routes.
- An `app_moves` row records the phase. The job resumes from it; a halt keeps the phase and needs a new command; at most one open move per target.

### The destination is proven before the source is touched

- Request time: managed destination in the same environment, no Compose project clash, a tunnel when routes exist, loopback or unspecified binds only.
- Preflight on the destination: the deploy preflight plus platform, memory, CPU, image and volume bytes, and no pre-existing target volumes.
- Nothing runs on the source before preflight passes.

### Same content, redeployed like a rollback

- The destination gets a deployment of kind `move` with the known-good digests, model and secret versions. It is pulled, materialised, verified and created without starting while the source still serves.

### Data is a stopped-container file copy streamed through the daemon

- A stateful move stops the source, then streams each named volume as tar from `docker cp <c>:<mount> -` on the source into `docker cp - <c>:<parent>` on the destination. No helper image, no node-to-node connectivity: the daemon is the only path.
- The transport gains a streaming SSH session with an exit status. A copy counts only when both ends exit 0 and the byte counts match; otherwise it is redone from scratch.
- Stateless moves keep the source running until the destination is healthy.

### Commit last; undo everything before it

- Until the commit the source is the truth. A failure removes the destination's containers and the volumes the move created there, restarts and health-checks the source, and ends `rolled_back`.
- Routes switch before the commit: the destination ingress serves the rule, then the CNAME is repointed (a new `UpdateDNSRecord`), with the expose ownership check. The Access app is kept.
- One transaction then writes the target's node, each route's node and tunnel identity, and the destination deployment as known-good. The route identity trigger allows that change only during the target's move. The plan's revision pin accepts the move's own +1, as tunnel disable does.
- After the commit the source tunnel's rules are removed and the source is left stopped. It is removed only by `sm apps move --cleanup-source`, which never deletes volumes.

### Locks come from the plan, not the live target

- The job holds the target lock, project and port locks on both frozen nodes, shared node locks, and the instance Cloudflare lock when routes exist.

## Consequences

- Stateful moves have downtime from the stop until the destination is healthy.
- Data in transit crosses the daemon over two SSH sessions; nothing is stored on the daemon's disk.
- A consistent copy depends on the app tolerating a cold file copy of a stopped container. Database-aware dumps stay out of scope.
- Source volumes are never deleted by SuperMgmt; reclaiming that space is the operator's call.
