# ADR-0007: Execution snapshots

- Status: Proposed
- Spec: §20.2 ("execution reads only the plan snapshot"), §20.4 (claim and resume revalidation), §46, App. C; ADR-0008, ADR-0029

## Context

A deployment plan carries content hashes (App. C `content`), not contents. Workers must execute exactly what was approved, a rollback must redeploy exactly what was once healthy, and §46 asks where those contents live and how long. Two further facts matter: the public Compose model depends on the target (its ownership labels and allowed bind addresses), and the current app configuration may legitimately change after a deployment succeeded.

## Decision

### Table

`execution_snapshots(hash PRIMARY KEY, kind, content TEXT NOT NULL, created_at)`, migration 000005.

- `kind ∈ {compose_model, health, deployment_policy, exceptions, manifest}`.
- `hash` is the exact `sha256:<hex>` value that App. C `content` carries for that kind; `content` is the bytes that hash covers.
- Insert-if-absent; rows are immutable (triggers abort `UPDATE` and `DELETE`).
- Snapshots are written in the finalization transaction, before the plan row. Workers read only these rows plus the plan (§20.2). A row whose content does not hash to its key is `STAGING_FAILED` (`details.cause = SNAPSHOT_MISMATCH`).

### Retention

Kept forever in V1. Each row is at most 256 KiB, which satisfies "at least while known-good chain and job lifetime". Garbage collection is a post-V1 ADR. Snapshots are rows, so backups include them.

### Target-bound Compose model

- `apps.compose_source_hash` is the SHA-256 of the control-plane source text and does not depend on any target.
- The public model (ownership labels `dev.supermgmt.owner=<app_target_id>` and `dev.supermgmt.project=<compose_project>`, `host_ip` checked against that target's `allowed_bind_addresses`) is frozen **per target at finalization**. Its hash is `plan.content.compose_hash` and `deployments.compose_hash`.
- `app.write` validates the source against every existing target; `app_target.write` validates it for that target. No per-target hash is stored outside deployments.

### Revalidation modes

None of them calls GitHub.

- **Forward** (`deployment.create` claim and forward resume): rebuild the spec revisions of `targets` and `inputs` from the database (app, app_target, node endpoint and host key, environment, repository, health checks, secrets); re-read every content hash from its snapshot row; check every bound secret version still exists; plan expiry, requester credential, policy and quorum. The app's `spec_revision` covers `compose_source_hash`; no live target hash is compared.
- **Rollback** (`kind: rollback` claim): the same authorization inputs (app_target spec revision, node pin, environment, requester credential, policy, quorum). Content is the frozen known-good snapshot: the plan's Compose hash, digests, exact secret versions, health and policy hashes must equal the known-good deployment's immutable rows. The current app source is not compared. A missing snapshot row or secret version is `ROLLBACK_UNAVAILABLE` (`SNAPSHOT_GONE` / `SECRET_VERSION_GONE`) before any mutation.
- **Safety recovery** (system, inside an interrupted deployment job; ADR-0029): checks only that the restoration target the plan names is still restorable (snapshot rows, secret versions, node endpoint and host-key pin). No requester credential, policy or quorum.

## Consequences

- Editing an app's Compose source or health checks never breaks a rollback to a deployment that was healthy before the edit.
- One source deployed to two targets yields two public models and two hashes.
- The database grows with every distinct model; V1 accepts that growth.
