# ADR-0029: Deployment engine

- Status: Proposed
- Spec: §19.1, §20.0–§20.5, §21, §26; ADR-0007, ADR-0008, ADR-0010, ADR-0013, ADR-0015, ADR-0030

## Context

ADR-0013 keeps one coarse job machine and defers "deployment row state mirrored in the same transaction" to M4 (`docs/adr/0013-generic-job-state-machine.md:44`). §20.1 adds a fine machine with two recovery paths after an interruption: a forward resume that re-runs claim revalidation, and a safety recovery by `system` that only rolls back. Today every claim runs the requester's revalidation including quorum and sends a lapsed quorum to `awaiting_approval` (`internal/jobs/claim.go:115-118, 180-191`), and the reconciler only admits `complete` and `not_started` (`internal/jobs/reconcile.go:108-111`), so neither path is reachable without a per-type hook.

## Decision

### Two machines, one transaction

- `deployments.state` holds the §20.1 machine, a pure table in `internal/deployments`. The job carries the coarse state.
- `jobs.TypePolicy.Mirror` runs inside `Store.move`, in the same transaction as every coarse transition: claim → `preparing` (forward) or `rolling_back` (recovery); requeue, approval, fail, cancel and succeed are mirrored too. An error from `Mirror` aborts the transition.
- Fine states inside a running job (`staging`, `deploying`, `verifying`, `rolling_back`) are written by the worker under the lease fence, with their events.
- Job types without a `TypePolicy` behave exactly as before.

### Steps

App. C order, each with a `deployment_steps` row and a deadline:

| Step | Deadline |
|---|---|
| preflight | 2m |
| snapshot | refused in M4 (`deployment_policy.snapshot: true` is `INVALID_ARGUMENT`) |
| pre-deploy-backup | `pre_deploy_backup.timeout` |
| pull | 15m |
| materialize | 1m |
| verify-on-node | 2m |
| deploy | 10m |
| health-check | `attempts × interval + timeout` |

Restore steps (`restore-pull`, `restore-materialize`, `restore-verify-on-node`, `restore-deploy`, `restore-health-check`) redeploy the plan's frozen rollback target with the same deadlines.

### Preflight (read-only, before any pull, backup or materialization)

- Node endpoint and host-key pin.
- Docker version and Compose CLI version in the matrix (ADR-0006).
- **Free disk ≥ Σ image sizes + 1 GiB**, on the Docker root dir (`docker info --format '{{.DockerRootDir}}'`) and on `deploy_root`, free bytes from `df -PB1`. Image size: for each bound image not already on the node, `docker manifest inspect --verbose <repo>@<digest>` on the node, for the node's platform, sum of layer and config sizes; present images count 0. A size that cannot be established is `PREFLIGHT_FAILED`, `details.cause = IMAGE_SIZE_UNKNOWN` (fail closed). No safety factor: the spec states none.
- Project ownership labels; host ports free or owned; the capability of every configured health check.

### Pre-deploy backup

- `pre_deploy_backup` is required for `stateful: true` targets in production; finalization and `app_target.write` reject the target otherwise.
- The plan carries the sub-action `node.backup_template.run`, evaluated by policy at finalization and in every revalidation.
- The worker records a fenced intent and runs template `postgres-dump` (the only backup template in M4) under the policy timeout. It requires exit 0 and an absolute path on the last stdout line inside the fixed backup directory, stored in `deployment_steps.output_ref`.
- Any failure (denied sub-action, nonzero exit, timeout, missing or invalid path, interruption without evidence) fails the deployment before services change.

### Intents and evidence

- pull → `docker image inspect <repo>@<digest>`; materialize → directory and file stat read-back; compose up → `.done` with exit 0, and the node-side `flock /run/supermgmt/locks/<project>.lock` wrapping the marker command.
- Classification from two samples at least 30s apart: containers labeled with this deployment id, the expected digests and labels = `complete`; none = `not_started`; an exactly defined mix with no container in `created`, `restarting` or `removing` = `partial_stable`; anything else is still settling.

### Proof versus classification

- `jobs` keeps the fixed rule: every dispatched intent needs `Proven()` (`.done` with exit 0). A type policy cannot weaken it; missing or nonzero `.done` stays held even when samples are stable.
- What a policy changes is which *proven* classifications may form a confirmed pair: `TypePolicy.Admit`. Deployment types admit `complete`, `not_started` and `partial_stable`; every existing adapter keeps `complete` and `not_started`.

### Reconciliation (deployment `TypePolicy.Reconcile`)

| Evidence | Verdict |
|---|---|
| no completion proof | held with locks (fixed fallback) |
| before `deploying`, services untouched | `failed INTERRUPTED_BEFORE_DEPLOY`, or forward requeue when every earlier step is proven |
| after `deploying`, proven `partial_stable` or unhealthy | requeue in **safety recovery** if rollback is available, else `failed ROLLBACK_UNAVAILABLE` |
| complete and healthy | `succeeded` |
| interrupted in `rolling_back` | `rolled_back` or `rollback_failed` from evidence |

### Durable recovery record and fenced recovery claim

- A requeueing verdict writes, in the reconcile transaction, `deployments.recovery_mode ∈ {forward, safety_recovery}`, `resume_step`, `recovery_reason` (the failed revalidation reason or the evidence classification) and `recovery_target_deployment_id`. The target is always `plan.content.rollback_target.deployment_id`, frozen at finalization, never "the newest known-good now". Lock rows are kept.
- At claim, `TypePolicy.ClaimMode` reads the record. In `safety_recovery` the claim skips the requester `Revalidator` and runs `RevalidateRecovery` (ADR-0007 safety-recovery mode): it never returns `APPROVAL_REQUIRED` and never moves to `awaiting_approval`. It takes the same lock set, records actor `system` with the original reason, and mirrors to `rolling_back`.
- In `forward` mode, a `Revalidator` failure on a job whose deployment has `mutation_started = 1` is converted, inside the claim transaction, into a recovery record (`EscalateToRecovery`) and the claim proceeds as recovery. Before `deploying` the job fails with its reason.
- Under `safety_recovery` the handler dispatches only restore steps; every forward step function refuses (`INTERNAL`, nothing dispatched).
- A restart between requeue and claim reads the same record.

### Rollback

- Rollback redeploys the known-good deployment's frozen snapshot (Compose hash, digests, exact secret versions, its health and policy snapshots) into a new directory.
- Health after a rollback is verified with the known-good deployment's health snapshot, not the target's current configuration.
- Previous deployment directories are kept: the last 5 per project, and a directory is collected only when its deployment is not known-good.

### Ownership and locks

- Preflight refuses (`CONFLICT` / `PROJECT_NOT_OWNED`) any project, volume or network with the project's names lacking `dev.supermgmt.owner=<app_target_id>`. Ports held by anything else are `PREFLIGHT_FAILED`.
- Locks: exclusive app_target, `compose_project:<node>:<project>` and each `port:<node>:<addr>:<port>`; shared every other plan input, including the plan-only input types `repository`, `health_check` and `secret`.

### Health execution

- Every check carries its origin: `manifest` or `control_plane`.
- Manifest checks: scope `node`, destination only `127.0.0.1` or `::1`, and only a port the frozen model publishes on that exact loopback `host_ip`.
- Control-plane node checks may also use an address in the target's `allowed_bind_addresses`, again only if the frozen model publishes that exact `host_ip:port`.
- The destination is resolved from the matching published host port (§21 address selection), never from user input.
- Node scope runs through SSH templates (`curl -q …`; `timeout … bash -c 'exec 3<>/dev/tcp/…'`); `docker-health` through `docker inspect`; `control_plane` scope through netguard (`health.allowed_private_cidrs`; http allowed).
- Types in M4: `http`, `tcp`, `docker-health` (node) and `http`/`https` (control plane). `command-template` and `systemd-active` are rejected for app targets.

### Events

`deployment.*` events use `correlation_id` = the deployment id. Repository and webhook events use `resource_type = provider` with `repository_id` in their data; the events table is not rebuilt.

## Consequences

- A safety recovery cannot be blocked by authorization drift (a revoked requester, a lost quorum, a stale plan): it restores an already-approved state.
- Sampled stability alone never authorizes a mutation; only proven completion does.
- The jobs package gains one seam (`TypePolicy`) and no deployment knowledge.
