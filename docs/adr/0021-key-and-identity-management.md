# ADR-0021: Key and identity management

- Status: Proposed
- Spec: §8.4, §10 (1.4.3: export transport; 1.4.4: approval), §12, §29.2, §46; extends ADR-0003 and ADR-0016 (does not replace them)

## Context

ADR-0016 shipped the envelope, file KEKs and the instance SSH identity, and deferred key rotation, retirement, export/import, secret import, identity rotation and host-key re-pinning to M2. In M1, `FileKeys` is an immutable map loaded at start with no lock, while `Store.Put` reads the active KEK. An online rotation must not race it.

## Decision

### Concurrency

- `FileKeys` holds an immutable snapshot `{active, keys}` behind an atomic pointer, read by `Active` and `Key`.
- One process-wide `keyOps` mutex serializes rotate, retire, export, `Store.Put` and backup KEK reservations (ADR-0020). Reads (`Get`, signers) do not take it.
- Rotation order: (1) write `<new>.key` (0600, fsynced, directory fsynced) and compute its check record; (2) one SQLite transaction stores the check record, unwraps and rewraps every DEK, updates `kek_id`, and sets `settings.active_kek_id`; (3) after commit, publish the new snapshot. A crash before commit leaves an orphan, unreferenced `.key` that is ignored and reported by `doctor`. A crash after commit leaves the new state, and the old key is still on disk.
- Cached signers are keyed by `(name, version)`; a rewrap changes no version, so they stay valid.

### Commands (action `secret.write`, high risk, audited, never with secret values in events)

| Command | Route / mode |
|---|---|
| `sm secrets rotate-master-key` | `POST /secrets/master-key/rotate` |
| `sm secrets retire-key <kek_id> [--external-backups-handled]` | `POST /secrets/master-key/retire` |
| `sm secrets export-key <kek_id> --out <file>` | `POST /secrets/master-key/export`, local-mode Unix socket only; `--offline` in server mode |
| `sm secrets import --name <n> (--from-file F \| stdin)` | `POST /secrets`; `--offline` variant for the installer (§3.5 step 5) |
| `sm secrets import-key --offline --from <file>` | offline only, no route (§10) |
| `sm ssh-key rotate` | `POST /ssh-key/rotate` |

- **Export transport (spec 1.4.3).** The export carries a wrapped master key, so it is never served over HTTPS or the admin socket (§23.1 allows only four admin routes). In server mode `sm secrets export-key --offline` runs with the service stopped: it takes the database lock, reads the key file and verifies it against the check record. The passphrase (≥ 12 characters) comes from a TTY or stdin, never an argument.
- **SMKEY1** exactly §10: `magic | version | lp(kek_id) | log2N | r | p | salt(16) | nonce(12) | AES-256-GCM(scrypt(...), nonce, KEK, aad = preceding bytes)`, via `golang.org/x/crypto/scrypt`. Export uses N = 2^17, r = 8, p = 1. Import accepts 2^15 ≤ N ≤ 2^20, r = 8, p ∈ 1..4 only.
- **import-key** writes `<kek_id>.key.pending` (0600). If a database exists and references the id, the key is verified against its check record and renamed to `.key`; otherwise it waits for a restore (§29.2). The daemon never loads `.pending`.
- **retire-key** refuses while any `secrets` row, any archive manifest in `backup.directory`, or any in-progress backup reservation references the key. An unreadable manifest also refuses. `--external-backups-handled` records an audited acknowledgement (§10).

### Approval of `secret.write` (spec 1.4.4)

`secret.write` is high risk, so §11.3 step 8 always requires approval: each command above is a plan and a `control_plane.apply` job (`Keys` answers `Pending`), executed after approval by the job handler through the same `KeyAdmin`/`Store` code as a direct call. The jobs are `non_retryable` with one attempt: repeating a rotation would make a second key, so a failed or interrupted one is resolved by an operator. They run outside the fenced job transaction, because rotation and activation open their own; the lease is fenced before the operation and before its audit event. A plan never holds a secret value or a passphrase.

- **rotate-master-key, retire-key, ssh-key rotate**: no secret in the payload; the job performs the operation.
- **Re-pin** (`node.update` with `host_public_key`): the public key is in the plan; `applyApproved` re-pins first (event `node.host_key.repinned`), then applies the other fields. A re-pin to the pinned key is a no-op, so a retried job converges.
- **Import**: the value is sealed under the active KEK when the request is made, as a *staged* secret version stored with a negative `version` (one per request, so several can wait under one name; `GetSecret`, `Store.Get` and `Signer` never see them). The plan carries only `staged_id` and `value_sha256`. The job decrypts the staged row, checks the digest, and gives it the next positive version; a repeated activation returns the same version. Staged rows are rewrapped by rotation and counted by `retire-key` like any secret row. A trigger on `jobs` (migration 000003) deletes the staged row when its job ends `failed` or `cancelled`: rejection, plan expiry, cancel and failure all end there. A request that fails after staging discards the row; a crash between the two transactions can leave an unreferenced staged row, which keeps its KEK from being retired until it is removed.
- **Export**: `export-key` without a passphrase is the request: the job exports nothing. After approval (job `succeeded`) the same identity repeats the call with the passphrase and receives the export once, within 24h of the approval; the use is an `secret.master_key.exported` event on the request's resource, recorded in the transaction that follows the key derivation, so a failed derivation leaves the request unspent. A second execution or a late one is `CONFLICT`, another identity's is `POLICY_DENIED`, none at all is `APPROVAL_REQUIRED`. The execution never goes through the Idempotency-Key store. Local socket only, as before.

### SSH identity rotation

`sm ssh-key rotate` stores a new version of `ssh/default` (event with the new fingerprint only). Nodes keep signing with the version pinned in their setup metadata until `sm nodes setup <node>` re-runs and authorizes the new key (ADR-0016). Versions are never reused or deleted.

### Host-key re-pin

`PATCH /nodes/{id}` with `host_public_key` (action `node.update`, `If-Match` required) re-pins a node. The CLI (`sm nodes repin <node>`) scans the key, shows the SHA256 fingerprint and requires explicit confirmation. The event `node.host_key.repinned` carries the old and new fingerprints. The pool drops the node's connection. There is no automatic re-pinning.

### Lost KEK

A KEK lost without an export is not recoverable. The documented recovery is a fresh data directory; there is no destructive "forget key" command in M2.

## Consequences

- Key operations and secret writes are serialized; they are rare and short.
- Server-mode export requires a short service stop.
- Every online key operation waits for an approver; a single-operator instance needs `security.allow_self_approval` or a second identity.
