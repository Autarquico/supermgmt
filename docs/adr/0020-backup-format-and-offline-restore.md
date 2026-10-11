# ADR-0020: Backup format, offline restore and startup order

- Status: Proposed
- Spec: §2.1.1, §9, §10, §29.1, §29.2; ADR-0013, ADR-0016

## Context

§29 fixes the archive members, the three restore phases and the hold. It leaves open how the journal survives a crash at every step, where recovery sits in the daemon's start, and how restored jobs reach the reconciler. M1's job engine already has a hold gate (`jobs.Store.SetRestoreHold`) and a quiescence rule that requires intents to carry a lease generation lower than the job's.

## Decision

### Archive

- `<backup.directory>/supermgmt-<instance>-<UTC timestamp>.tar.zst`: a tar stream inside zstd (`github.com/klauspost/compress/zstd`, BSD-3-Clause).
- Members, exactly: `manifest.json`, `supermgmt.db`, `config/config.yaml`, `config/policies.yaml` (when a policy file is in force), `known_hosts` (when present).
- The DB member comes from the SQLite online backup API through the driver (`VACUUM INTO` only if the API proves unusable, recorded in this ADR before merge).
- `config/` is written from `settings.config_snapshot`, not from disk. The snapshot (config bytes, policy bytes, generation) is written in the same transaction as the static-config reconcile, which is the moment the daemon activates a configuration. M2 has no policy hot reload.
- The archive is written to a 0600 temp file, fsynced, renamed, and the directory fsynced. KEK files are never included.
- Creation holds the `keyOps` lock (ADR-0021) while it records a reservation of the KEK ids it references, so `retire-key` cannot remove a key an in-progress backup needs.
- Retention prunes the oldest archives beyond `backup.retention` (`system` actor). Scheduled runs use `backup.schedule` (5-field cron, own parser) in server mode, and in local mode only when `daemon.resident` is true.

### Startup order (daemon and offline restore)

1. Acquire the database lock (`<db>.lock`, which is never moved by a restore).
2. `backup.Recover(dataDir)`: finish or discard an interrupted restore.
3. Open the database and migrate.
4. Load `settings.restore_hold`; an unreadable value refuses the start; call `SetRestoreHold`.
5. Assemble services; start workers, refresher, reconciler and schedules (the backup scheduler only without hold).

### Phase A — stage (live files untouched)

Rejected with exit 9 (exit 2 for unusable input), leaving every live file byte-identical:

- unreadable or invalid manifest; format version unknown; schema version newer than the binary;
- a member not listed, listed twice, absolute, containing `..`, a symlink, hardlink or device;
- a member over its size cap (DB 4 GiB, others 16 MiB) or a total decompressed size over 8 GiB;
- a checksum mismatch;
- a staged database that fails `PRAGMA integrity_check` or the migrations;
- a referenced KEK with no `.key` or `.key.pending` that passes the check record in the staged database (the error names the ids).

### Neutralization (one transaction on the staged database)

| Job state | Becomes | Locks |
|---|---|---|
| `awaiting_approval`, `queued` | `failed`, reason `RESTORED_UNDISPATCHED` | deleted |
| `running`, `interrupted` | `interrupted` | kept |
| terminal | unchanged | — |

- Fencing for kept jobs: `lease_generation = max(job, its intents) + 1`, `lease_owner = NULL`, `lease_until = restore time`, so the reconciler's quiescence rule can act; evidence or `job.resolve` decides.
- Approvals on non-terminal jobs deleted; every other lock row deleted.
- All sessions and API tokens revoked; identities and role bindings kept.
- Unconsumed bootstrap codes and join tokens invalidated.
- `restore_hold = true`.
- Then `PRAGMA wal_checkpoint(TRUNCATE)`, `journal_mode=DELETE`, close, fsync.

### Phase B — journal protocol

- `restore.journal` is JSON `{id, state, moves: [{from, to, status}]}`, `status` ∈ `planned|intent|done`. It is only ever replaced atomically: write `restore.journal.tmp`, fsync it, rename it over the journal, fsync the directory.
- For each move: write the journal with the move at `intent` → rename → fsync the source and destination directories → write the journal with the move at `done`.
- Moves: live `supermgmt.db`, `-wal`, `-shm` and config files into `pre-restore-<ts>/`, then the staged files into place.
- After the last move: journal `complete`, then delete it and fsync the directory.

### Recovery (`Recover`)

Decided from the journal and the filesystem, never from guesses. It is idempotent: running it again after a crash inside it is safe.

- No journal, or no move past `planned` → discard the staging directory; the live state stands.
- A move at `intent`: source present and destination absent → redo the rename; source absent and destination present → mark it `done`; both present → the staged copy wins only if its checksum matches the manifest, else abort with exit 9 and keep the live files.
- Then finish the remaining moves forward.
- `complete` → delete the journal.
- A torn or unparsable journal: if the staging directory is intact and no live file has moved (every live path present, no `pre-restore-<ts>` content), discard it; otherwise refuse with exit 9 and instructions. Recovery never guesses.

Crash points are compiled in only with build tag `crashpoints`; a test asserts the release binary has none. Tests crash before and after every rename and every journal write, truncate the journal, and interrupt recovery itself repeatedly.

### Phase C — hold

- Writes are refused with `CONFLICT`/`RESTORE_HOLD` inside the shared write paths (`commit` and the direct-mutation entry), not per handler.
- Exceptions: `job.resolve`, `system` reconciliation and observation writes, OIDC login and session creation, the bootstrap exchange (accepted during hold even with admin bindings, §29.2), and `restore-complete` on the admin socket.
- The job engine claims nothing and the backup scheduler is off. Discovery, refreshers and the reconciler run.

### Frozen CLI contract (used by `sm install restore`)

- `sm secrets import-key --offline --from <file>`: passphrase on stdin.
- `sm backup restore --offline <archive>`.
- Exit codes: 0 ok, 2 invalid arguments, 4 prerequisite (daemon running, lock held), 9 restore failure.

## Consequences

- A restore never opens the live database in Phase B, and a crash at any point leaves either the old or the new state, or a refusal that names what to do.
- Idempotent jobs that were running are also held as `interrupted` (conservative): the archive cannot prove they never dispatched.
