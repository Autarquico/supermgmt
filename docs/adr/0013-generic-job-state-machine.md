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
- Locks are acquired on `queued → running` and are **held until the job reaches a terminal state** (spec §20.5: "held until the job is terminal, including while `interrupted`"). They survive `running`, `interrupted` and a requeue (`running`/`interrupted → queued`), so a retrying or resuming job cannot lose its resources to a rival between attempts. The next claim replaces the job's own lock rows with the newly planned set. This supersedes the first draft of this ADR, which released locks on requeue and on return to `awaiting_approval`; the spec wins.
- Known consequence: a job returned to `awaiting_approval` by a lapsed-quorum reclaim after an earlier attempt still holds its lock rows (they are released only at a terminal state). Until the `PLAN_EXPIRED` sweep (`awaiting_approval`/`queued` → `failed`) exists, such a job blocks its resources until it is approved, cancelled or rejected. The sweep is an M1 must.
- Why a lock table row per resource: `resource_locks(resource_type, resource_id, job_id)` stores `LockSpec.Key` split at its first colon. Exclusive conflicts with any other holder, shared only with an exclusive one; the conflict check ignores the job's own rows.
- A claim blocked by a lock conflict leaves the job `queued` and pushes `scheduled_at` back by one backoff step (spec §20.4 step 2) in the same transaction.
- Takeover uses `lease_until <= now`. The spec writes `<`; the fence requires `lease_until > now`, so `<=` is its exact complement and no instant exists at which both the old worker and the reconciler may write.
- Claim-time errors are classified: a typed `*smerr.Error` from revalidation or lock planning fails that job (or returns it to `awaiting_approval` for `APPROVAL_REQUIRED`); database, connection and context errors abort the claim; any other error is a per-job data fault and fails only that job with `INTERNAL`, so a poison job cannot block the queue.
- The reconciler never re-dispatches. It acts only on a quiescent job: lease expired, generation bumped, and every dispatched intent either carrying exit-0 completion proof or past `deadline_at + reconcile_grace`. Every dispatched intent (including ones the worker marked completed) needs *confirmed* proof: `done` with exit status 0, plus a classification (`complete` or `not_started`) observed identically in two samples at least 30s apart. The outcome a worker recorded is kept apart from that proof; a contradiction holds the job. Collection stops at `deadline_at + 5m`. `partial_stable`, `unknown`, missing or contradictory evidence leave the job `interrupted` with its locks; `job.reconcile_held` is emitted when a job enters that state or its reason changes. A resumable job with no attempts left is held, not failed. Concrete evidence adapters (SSH, Docker, systemd, Proxmox) arrive with their milestones; M0 ships the engine and interfaces with fake adapters. Deployment jobs keep the detailed §20.1 machine on the deployment row and mirror the coarse job state above in the same transaction (M4).

## Consequences

The reconciler and the API have one closed table to test against; resumable deployments are handled by the deployment machine, not by this table.
