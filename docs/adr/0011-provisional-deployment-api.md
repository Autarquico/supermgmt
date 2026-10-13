# ADR-0011: Provisional deployment API

- Status: Accepted
- Spec: §18, §20.0, §20.1, §23, §46; ADR-0007, ADR-0012, ADR-0028, ADR-0029

## Context

A deployment gated on CI exists before its final plan does (§20.0): nothing can be approved, and the requester's credential (often a GitHub Actions OIDC token) may expire long before CI finishes. §46 fixes the constraints: `plan_hash: null` while provisional, inputs and credential context persisted, only `job.cancel` before finalization, approvals only once a final hash exists, and a `deployment.finalized` event carrying the hash.

## Decision

### Request and response

- `POST /api/v1/deployments` (`deployment.create`) with `{app_target_id, kind: "deploy", commit_sha, images: [{service, digest}]}` answers **202** with the `Deployment` resource. While provisional its `plan_id`, `plan_hash` and `job_id` are `null` and `state` is `created` or `waiting_ci`.
- The row in `deployments` holds the commit, the requested images (`requested_json`), the requesting identity and the full credential context (`credential_kind`, `credential_id`, `scopes_json`, `credential_expires_at`).
- `GET /api/v1/deployments`, `GET /api/v1/deployments/{id}` (`deployment.read`) show the same resource with its steps.

### Provisional states and cancellation

- Provisional states: `created`, `waiting_ci`.
- The only action is `job.cancel`, through `POST /api/v1/deployments/{id}/cancel`. Before finalization it moves the deployment to `cancelled`; once a job exists it delegates to that job's cancel, under §20.1's rules.
- `approve` and `reject` act on jobs, and a job exists only after finalization, so they cannot reach a provisional deployment.

### Finalization (one transaction)

1. Target-bound freeze of the Compose model (ADR-0007) from the exact commit's files.
2. Execution snapshots.
3. The plan: actor = the requester; `rollback_target` = the newest known-good deployment of the target **at this moment**, frozen.
4. Policy, including sub-actions (`node.backup_template.run` when `pre_deploy_backup` is set).
5. Job enqueue with the stored credential context.
6. `deployments.plan_id`, `plan_hash`, `job_id` set.
7. Event `deployment.finalized` with `plan_hash`.

A requester credential revoked meanwhile fails the deployment (`CREDENTIAL_REVOKED`). Natural expiry of a `github_oidc` credential does not (§11.1; ADR-0028).

### Rollback requests

`POST /api/v1/deployments/{id}/rollback` (`deployment.rollback`) with `{to_deployment_id?}` creates a new `kind: rollback` deployment on the same app_target. Its target is the newest known-good deployment older than `{id}`, or `to_deployment_id`, which must be known-good on that target. Its plan freezes the known-good snapshot (ADR-0007 rollback mode). There is no CI gate, so it finalizes immediately.

### Webhook

`POST /api/v1/github/webhook` carries the new route marker `exempt:webhook` (ADR-0012 gains a fourth exemption). It authenticates by HMAC (ADR-0028), not by caller identity.

## Consequences

- CI can take longer than any token lifetime: finalization reads the stored credential context and the stored OIDC claims, not the token.
- A client polls `GET /deployments/{id}` (or follows events by correlation id) to see `plan_hash` appear.
