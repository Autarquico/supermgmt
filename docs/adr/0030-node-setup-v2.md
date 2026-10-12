# ADR-0030: node.setup v2 — `deploy_root` and `docker.compose.deploy`

- Status: Proposed
- Spec: §12, §17, §20.3 step 9, §21, §46 (ADR-0009 row); extends ADR-0009, ADR-0006, ADR-0010

## Context

ADR-0009 deferred `deploy_root` and the `docker.compose.deploy` capability to `setup_version` 2 in M4. Deployments also need tools the node may lack: a pinned Compose CLI, `flock` for the project lock (§20.4), `jq` for the resolved-environment check (ADR-0010), `curl` and `bash` with `timeout` for health checks (§21).

## Decision

- `setup_version` 2 adds `deploy_root` (default `/srv/supermgmt`, owned by root, mode 0755), created with `install -d`. Project directories below it are owned by `supermgmt`, mode 0750 (§20.3 step 9). The tmpfiles line for `/run/supermgmt/locks` is unchanged.
- `deploy_root` is a `node.setup` plan parameter: absolute, clean, validated; it is part of the plan hash.
- Capability `docker.compose.deploy` is advertised only when **all** hold: setup ≥ 2, `docker_access = true`, the Compose CLI version is in the matrix (ADR-0006), `flock` present, `jq` present. Otherwise it is absent with a reason.
- `health.http` = `curl` present; `health.tcp` = `bash` and `timeout` present. Discovery's tool list gains `curl`, `bash`, `timeout`, `flock` and `jq`.
- Nodes at `setup_version` 1 keep working for everything they did; re-running setup upgrades them. Setup stays idempotent (ADR-0009).

## Consequences

- A node cannot be targeted by a deployment until it has run setup v2 and has the pinned Compose CLI and `jq`.
- The supported tool set of a deploying node is documented in `docs/compatibility.md`.
