# ADR-0025: Proxmox power jobs, task correlation and quiescence

- Status: Accepted
- Spec: §11.2 (`proxmox.vm.power`), §15.4, §20.4; ADR-0009 (recovery by task correlation only), ADR-0013

## Context

Proxmox calls cannot carry a node-side marker. §20.4 requires the UPID to be persisted as soon as the API returns it, success to mean task `stopped` with `exitstatus OK`, and missing or contradictory evidence to leave the job `interrupted`. The generic quiescence rule (`deadline_at + grace`) does not prove a Proxmox task has stopped.

## Decision

### Handler

1. Recheck `VM.PowerMgmt` and resolve the guest's current `pve_node`.
2. Record the intent: operation `proxmox.vm.power.<verb>`, target the node row, `pre_state` = `{type, vmid, pve_node, token_user, status}`, marker = intent id (never placed on a node).
3. `MarkDispatched` (commits `dispatched_at`), then POST `…/status/<verb>`.
4. Persist the UPID in `operation_intents.external_ref` (fenced) **before the first poll**.
5. Poll `…/tasks/<upid>/status` on the node encoded in the UPID until `stopped` or the deadline.

Deadlines are handler constants: start, reboot and shutdown 5m; stop 2m. The PVE shutdown `timeout` is below the deadline.

### POST outcomes

- **Rejected**: an HTTP 4xx, or a 5xx with a PVE error body, received before any UPID (e.g. 403, validation, "does not exist" after a migration). The job fails; nothing was accepted.
- **Uncertain**: anything else without a UPID (timeout, reset, 5xx without body, unparsable body). The job goes `interrupted` and is **never retried**; correlation decides.

### Correlation without a UPID

- Candidates: the task lists of every cluster node, all pages.
- Window: `starttime ∈ [dispatched_at − 120s, dispatched_at + http_timeout + 120s]`.
- The decoded UPID must match exactly: task type for the verb and guest type, `id == vmid`, `user == token_user`.
- Exactly one match is used. Zero or several leave the job `interrupted` for `job.resolve`. Zero matches never imply safe re-dispatch.

### Quiescence

- Intents whose operation starts with `proxmox.` are task-tracked. For them `quiescent()` ignores `deadline_at + grace` and requires stored evidence that the correlated task is `stopped`, written by the handler or the reconciler's observation pass (`RecordTaskStop`, fenced by lease generation).
- `Resolve` requires the same proof, or `assume_quiescent: true` (recorded and audited, as for an unreachable node).

### Evidence encoding

| Task | `Done` | `ExitStatus` | `Proof` | `Classification` | `Fingerprint` |
|---|---|---|---|---|---|
| stopped, `OK` | true | 0 | `pve_task` | `complete` | `{"upid","status","exitstatus"}` |
| stopped, other | true | 0 | `pve_task` | `not_started` | same |
| running / uncorrelated | — error (no evidence yet) | | | | |

`ExitStatus 0` means "evidence was collected"; the reconciler maps `not_started` to failed. Tests run the real `Store.Reconcile` with two samples across `SampleGap`.

### Residuals (M6)

- **Clock skew.** The window assumes the PVE host's clock and the control plane's agree within the 120s margins. Each sync records the skew from the PVE `Date` header (`SyncReport.ClockSkew`), and doctor's `providers` check warns above 60s.
- **SEC-9.** Dispatch re-checks the guest's type, VMID, name and non-template state against `/cluster/resources`, and a guest that reappears after being absent gets a new incarnation. A guest destroyed and recreated with the same type, VMID and name with no sync in between still receives an approved power operation. Only an actor holding `VM.Allocate` can cause that; it is a documented residual and a row of `docs/manual-checks/m3-real-pve.md`.

## Consequences

- Schema: migration 000004 adds `operation_intents.external_ref`.
- A job can never release its locks while its Proxmox task may still run, short of an audited human override.
