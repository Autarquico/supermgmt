# ADR-0013: Generic job state machine

- Status: Accepted
- Spec: §11.4, §20.1, §20.4 (gap: the spec defines states only for deployments)

## Context

The spec defines an exhaustive state machine for deployments (§20.1) but not for the other job types (`node.probe`, `service.*`, `node.reboot`, `proxmox.*`, `backup.create`, `control_plane.apply`). The job engine needs one closed transition table.

## Decision

Job states: `awaiting_approval`, `queued`, `running`, `interrupted` and the terminal states `succeeded`, `failed`, `cancelled`.

| From | To | Trigger |
|---|---|---|
| (submit) | `awaiting_approval` | plan requires approval |
| (submit) | `queued` | no approval required |
| `awaiting_approval` | `queued` | quorum reached (§11.4) |
| `awaiting_approval` | `failed` | `REJECTED`, `PLAN_EXPIRED`, `CREDENTIAL_REVOKED`, `CREDENTIAL_EXPIRED` |
| `queued` | `running` | claim succeeded (lease, locks, revalidation) |
| `queued` | `awaiting_approval` | claim revalidation: quorum lapsed |
| `queued` | `failed` | claim revalidation failed, or `REJECTED` |
| `queued` | `queued` | idempotent retry with backoff (attempts < max) |
| `running` | `succeeded` / `failed` | executor result |
| `running` | `interrupted` | takeover after lease expiry (§20.4) |
| `interrupted` | `queued` | idempotent job requeued by the reconciler |
| `interrupted` | `succeeded` / `failed` | reconciler evidence, or human resolution (`job.resolve`) |
| `awaiting_approval`, `queued` | `cancelled` | `job.cancel` |

Any other transition is rejected with `CONFLICT`/`INVALID_TRANSITION`. Deployment jobs keep the detailed §20.1 machine on the deployment row and mirror the coarse job state above in the same transaction (M4).

## Consequences

The reconciler and the API have one closed table to test against; resumable deployments are handled by the deployment machine, not by this table.
