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
| `running` | `succeeded` / `failed` | executor result |
| `running` | `queued` | idempotent job failed with attempts < max_attempts (exponential backoff on `scheduled_at`) |
| `running` | `interrupted` | takeover after lease expiry (§20.4) |
| `interrupted` | `queued` | idempotent job requeued by the reconciler |
| `interrupted` | `succeeded` / `failed` | reconciler evidence, or human resolution (`job.resolve`) |
| `awaiting_approval`, `queued` | `cancelled` | `job.cancel` |
| `awaiting_approval`, `queued` | `failed` | `PLAN_EXPIRED` sweep |

Any other transition is rejected with `CONFLICT`/`INVALID_TRANSITION`.

### Atomicity, locks and events

- Every transition is persisted together with its audit event in **one** writer transaction (`BEGIN IMMEDIATE`). If the event cannot be written, the transition does not happen.
- The claim (`queued → running`) is one transaction: increment `lease_generation`, set owner and `lease_until`, insert `resource_locks`, run revalidation and the quorum check **through the same transaction** (never through the reader pool). On a lock conflict or revalidation failure the transaction is rolled back and a **second** writer transaction applies the resulting transition (`queued → failed`, `queued → awaiting_approval`, or requeue with backoff) with its event, guarded by `state = 'queued'`.
- Fencing: every worker write (state, intents, events, heartbeats, locks) runs in a writer transaction whose first statement verifies `lease_generation`, `lease_owner` and `lease_until > now` for the job; otherwise the transaction aborts with `ErrLeaseLost` and the worker cancels its context.
- Locks are acquired on `queued → running`, held in `running` and **in `interrupted`**, and released in the same transaction as any transition to a terminal state, to `queued` (requeue) or to `awaiting_approval`.
- The reconciler without completion evidence never re-dispatches: the job stays `interrupted` with its locks (§20.4 fallback). Concrete evidence adapters (SSH, Docker, systemd, Proxmox) arrive with their milestones; M0 ships the engine and interfaces with fake adapters. Deployment jobs keep the detailed §20.1 machine on the deployment row and mirror the coarse job state above in the same transaction (M4).

## Consequences

The reconciler and the API have one closed table to test against; resumable deployments are handled by the deployment machine, not by this table.
