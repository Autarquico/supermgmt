# Operations

How to run a SuperMgmt server (`instance.mode: server`) after it is installed: backups and restores, master keys, approvals of secret operations, and recovery access. Sources: SPEC §10, §11.5, §29, [ADR-0020](adr/0020-backup-format-and-offline-restore.md), [ADR-0021](adr/0021-key-and-identity-management.md), and the code under `internal/backup`, `internal/secrets`, `internal/app`, `internal/cli`.

> **Verification status.** The commands below were read against the implementation. The end-to-end acceptance suite (task T13: install from a signed release in a Debian systemd container, crash-injected restore on a fresh host, Dex login) was **not part of the code this page was written against**; where a flow depends on it the text says "not verified". Nothing here has run on a real VM or a real identity provider other than the Dex test setup.

Run `sm` commands that talk to the service from a machine with a signed-in profile (`sm login`); run `sm admin`, the online `sm doctor` and the offline commands on the server as root or the service user `supermgmt`.

## Backups

### What a backup is

A backup is a job (`backup.create`) that writes one archive into `backup.directory` (default `<instance.data_dir>/backups`):

```text
supermgmt-<instance>-<UTC timestamp>.tar.zst
  manifest.json          format version, sm version, schema version, created_at,
                         kek_ids referenced, config generation, SHA-256 of every other member
  supermgmt.db           SQLite online-backup snapshot (secrets stay encrypted inside it)
  config/config.yaml     the configuration in force, taken from the database snapshot, not from disk
  config/policies.yaml   only when a policy file is in force
  known_hosts            only when the file exists
```

- **Master keys (KEKs) are never in an archive.** Without the matching key, the encrypted secrets in the archive, including the instance SSH identity, cannot be read. Back the keys up separately ([Key management](#key-management)).
- **The archive is not encrypted.** It holds the full control-plane database: audit events, node inventory, role bindings and the hashes of credentials. Treat it like the database itself. (Encrypting archives was considered and declined for M2.)
- Written to a temporary file with mode 0600, fsynced and renamed into place; the directory is fsynced too.
- A backup cannot be made before the daemon has activated a configuration once (`CONFLICT`: nothing consistent to archive).

```bash
sm backup create       # submits the job; prints the submission
sm backup list         # NAME, BYTES, CREATED, SCHEMA, SM, KEYS (the kek ids each archive needs)
```

Whether `backup.create` waits for approval follows your policy; the built-in policy gives it to `admin`. Not verified whether the built-in rules ever park it.

### Schedule and retention

- `backup.schedule` is a 5-field cron expression (own parser: `*`, numbers, ranges, lists, steps, month and weekday names; weekday 7 is Sunday). It is evaluated in **UTC**. Default in server mode: `0 3 * * *`. In local mode there is no default, and a schedule only runs when `daemon.resident: true`.
- The scheduler acts as the `system` identity, remembers its last run only in memory, and **skips runs the daemon was down for**; it does not replay them. It is off while a restore hold is in force and resumes when the hold ends.
- `backup.retention` (default 14) keeps the newest N archives that SuperMgmt itself made in `backup.directory`, pruning after each backup (event `backup.pruned`). Files it did not make, including archives you copied in by hand, are never touched.
- The default `ReadWritePaths` of the systemd unit is `/var/lib/supermgmt` only. A `backup.directory` or `security.keys_dir` outside it is not writable by the service unless you extend the unit (`systemctl edit supermgmt`).
- Copy archives off the machine yourself; SuperMgmt does not ship them anywhere.

### KEK reservation

While an archive is being made, the service records which KEK ids it references and refuses to retire those keys until the archive is published or abandoned. Afterwards the ids live in the archive's manifest, and `sm secrets retire-key` refuses while *any* archive manifest in `backup.directory` names the key. An archive whose manifest cannot be read also blocks retirement, so a corrupt file is visible rather than silently ignored. Archives you keep elsewhere are invisible to this check; that is what `--external-backups-handled` acknowledges.

## Restore

Restore is **offline**: the service is stopped and the command takes the database lock (`<db>.lock`, never moved by a restore). It refuses (exit 4) if a daemon holds the lock.

### Flow on an existing server

```bash
sudo systemctl stop supermgmt

# 1. Put the master key(s) the archive needs in place. Run as the service user so the file is owned by it.
sudo -u supermgmt sm secrets import-key --offline --from /root/kek-export.smkey --config /etc/supermgmt/config.yaml
#    (asks for the export passphrase on the terminal, or reads it from stdin)

# 2. Restore. The archive must be readable by the service user.
sudo -u supermgmt sm backup restore --offline /path/to/supermgmt-prod-20261010T030000Z.tar.zst --config /etc/supermgmt/config.yaml

# 3. The restore does NOT write /etc/supermgmt. Review and copy the archived configuration yourself.
sudo ls /var/lib/supermgmt/restored-config/        # config.yaml, policies.yaml (if any)
sudo diff /var/lib/supermgmt/restored-config/config.yaml /etc/supermgmt/config.yaml
sudo cp /var/lib/supermgmt/restored-config/config.yaml /etc/supermgmt/config.yaml   # if you want it

sudo systemctl start supermgmt
```

Then sign in again (OIDC, or a bootstrap code, below) and:

```bash
sudo sm doctor                  # online, over the admin socket
sm jobs list                    # review the jobs left "interrupted"
sudo sm admin restore-complete  # ends the hold; audited
```

On a fresh host use `install.sh restore --archive FILE --key-export FILE` ([installation.md](installation.md)); it runs steps 1 and 2 as the service user, starts the service in hold and prints the reminder. The installer renders its own `config.yaml` from its flags and keeps an existing one, so step 3 still applies.

Why step 3 is manual: the restore runs as the service user, which cannot write `/etc/supermgmt` (root-owned, group-readable). The configuration is placed in `<data_dir>/restored-config/` for review. A custom `ssh.known_hosts_file` is not honoured by restore: the archived `known_hosts` is placed at `<data_dir>/known_hosts`.

### The three phases

1. **Stage** (live files untouched). The archive is extracted into `<data_dir>/restore-<id>/`. It is rejected, with the live files byte-identical, for: an unreadable manifest or unknown format; a schema newer than the binary; a member that is unlisted, duplicated, absolute, contains `..`, or is a symlink, hardlink or device; a member over its size cap (database 4 GiB, others 16 MiB; 8 GiB in total); a checksum mismatch; a staged database that fails `PRAGMA integrity_check` or the migrations; or a referenced KEK with no `.key` or `.key.pending` that passes the check record stored in the staged database (the error names the ids). The staged database is then migrated forward and *neutralized* in one transaction.
2. **Activate** (journaled). `restore.journal` lists each move (live database, `-wal`, `-shm`, restored config into `pre-restore-<timestamp>/`, then staged files into place, then promotion of pending keys). It is only ever replaced atomically. Every start of the daemon and of `sm backup restore --offline` first runs recovery: an interrupted restore is finished forward, or discarded when nothing had moved, or refused with instructions (exit 9) when the state is ambiguous. Recovery never guesses. The old files stay in `<data_dir>/pre-restore-<timestamp>/` until you delete them.
3. **Hold.** See below.

Exit codes of `sm backup restore --offline`: 0 done, 2 invalid input (unreadable archive, invalid config), 4 prerequisite (daemon running, lock held), 9 restore failure.

### Restore hold

The restored control plane starts with `settings.restore_hold = true`. The state of the database was neutralized so nothing can dispatch work you did not review:

| In the archive | After restore |
|---|---|
| jobs `awaiting_approval`, `queued` | `failed` with reason `RESTORED_UNDISPATCHED`; their locks are deleted. Re-create them. |
| jobs `running`, `interrupted` | `interrupted`; locks kept; fenced so the reconciler can act on evidence or you can `sm jobs resolve` them |
| terminal jobs | unchanged |
| approvals on non-terminal jobs | deleted |
| all sessions and API tokens | revoked (identities and role bindings are kept) |
| unconsumed bootstrap codes and join tokens | invalidated |

While the hold is in force:

- the job engine claims nothing and the backup scheduler is off;
- discovery, refreshers and the reconciler run against the real targets, so anything changed since the backup is found by evidence, not assumed;
- every write returns `CONFLICT` with reason `RESTORE_HOLD`, except `job.resolve`, the admin-socket operations (`bootstrap-code`, `grant`, `restore-complete`), OIDC login and session creation, the bootstrap exchange, and token self-service (`exempt:auth`, `exempt:self` in `internal/app/hold.go`);
- an unreadable hold value fails closed: writes are refused and the service refuses to start.

`sm admin restore-complete` ends the hold. Review `sm doctor` and the interrupted jobs first; idempotent jobs that were running are also held as interrupted because an archive cannot prove they never dispatched.

## Key management

All online key operations are the high-risk `secret.write` action. They are audited, never carry secret values in events, and (since spec 1.4.4) are **jobs that wait for approval** ([Approvals](#approvals-for-secretwrite)).

```bash
sm secrets keys                       # kek ids, which is active, loaded, created; never the keys
sm secrets rotate-master-key          # new KEK, every secret rewrapped under it
sm secrets retire-key <kek-id> --external-backups-handled
sm secrets export-key <kek-id> ...    # see below
sm secrets import-key --offline --from FILE
sm secrets import --name providers/pve/token [--from-file F]   # value from the terminal, stdin or a 0600 file
sm ssh-key rotate
sm nodes repin <node>
```

- **Rotate.** The new key file is written and fsynced, then one transaction rewraps every secret and switches the active id. The old key stays on disk and loaded until you retire it. A crash before the commit leaves an unreferenced `.key` that is ignored (ADR-0021 says `doctor` reports it; `doctor` does not do so yet, so compare the key directory with the output of `sm secrets keys`). Rotation jobs are not retried: a failed or interrupted one is resolved by an operator, since repeating it would make a second key.
- **Retire.** Refuses while any stored secret (staged ones included), any archive manifest in `backup.directory` or any in-progress backup references the key. `--external-backups-handled` is mandatory in the CLI and records an audited acknowledgement that copies of backups kept elsewhere were re-made or discarded. Archives that need a retired key become unrestorable.
- **Export.** A key export is a passphrase-protected `SMKEY1` file (scrypt N = 2^17, r = 8, p = 1, AES-256-GCM). The passphrase has at least 12 characters and comes from the terminal or stdin, never an argument. The file is created with mode 0600 and `O_EXCL`; without `--out` it is written to stdout only when that is not a terminal.
  - **Local mode:** `sm secrets export-key <id>` only *requests* the export (a job that exports nothing). After it is approved, run `sm secrets export-key <id> --execute --out FILE`: the same identity receives the file once, within 24 hours of approval. A second or late execution is `CONFLICT`; another identity's is `POLICY_DENIED`.
  - **Server mode:** it is **never served over HTTPS or the admin socket** (the CLI refuses on a remote profile). Stop the service and run `sudo -u supermgmt sm secrets export-key <id> --offline --out FILE` on the server; it reads the key file under the database lock and checks it against the database.
- **Import key (offline only).** Writes `<kek-id>.key.pending` (0600). When a database here already references the id, the key is verified against its check record and activated at once; otherwise it waits for a restore to validate it. The daemon never loads `.pending` files. Run it as the service user, or the key file is owned by root and the daemon refuses to start.
- **SSH identity rotation.** `sm ssh-key rotate` stores a new version of `ssh/default`. Nodes keep the version pinned at their last setup until you re-run `sm nodes setup <node>` for each; versions are never deleted or reused.
- **Host-key re-pin.** `sm nodes repin <node>` scans the host key, shows its SHA256 fingerprint and needs explicit confirmation. It is a `node.update` with `If-Match`; the event `node.host_key.repinned` carries the old and new fingerprints. There is no automatic re-pinning.
- **Secrets import.** The value is sealed under the active KEK when you make the request, as a staged version; the plan holds only a digest. Approval activates it as the next version; rejection, cancellation or failure deletes it. A crash between the two transactions can leave an unreferenced staged row, which keeps its KEK from being retired until removed (orphan sweeping is not built).
- **Lost KEK.** Not recoverable. If the key file is lost and there is no export, the daemon names the missing ids and does not start. The only remedy is a fresh data directory (new instance SSH identity, `node.setup` re-run on every node). There is no "forget key" command.

Keep exports and their passphrases apart from the backups they unlock, and in different places from each other.

## Approvals for `secret.write`

`secret.write` is high risk, so section 11.3 step 8 always requires approval. Each command above becomes a plan and a job that stays `awaiting_approval` until a different person approves it:

```bash
sm jobs list
sm jobs approve <job-id> --plan-hash <hash>
sm jobs reject  <job-id> --plan-hash <hash> --reason "..."
```

In server mode `security.allow_self_approval` defaults to `false`. **A single operator therefore cannot complete any key operation or secret import** until a second identity with approval rights exists, or until you set `security.allow_self_approval: true` in `config.yaml` and restart. That setting weakens every approval on the instance, not only secret operations; revert it when a second approver exists. Local mode defaults to `true`.

## Enabling OIDC on a fresh server

Bootstrapping with OIDC needs a completed OIDC login, and OIDC needs its client secret in the secret store, which needs an admin. So the order is:

1. Install without OIDC and bootstrap the first admin ([installation.md](installation.md#after-a-server-install)).
2. Store the client secret: `sm secrets import --name auth/oidc-client-secret`, then approve the job (see above; a single operator needs `allow_self_approval`).
3. Edit `/etc/supermgmt/config.yaml`: `auth.oidc.enabled: true`, `issuer`, `client_id`, `client_secret_ref: secret://auth/oidc-client-secret`, `allowed_domains`, and `allowed_endpoint_origins` only if the IdP serves endpoints from another origin. Restart the service.
4. Register the redirect URI at the IdP: `http://127.0.0.1:<port>/callback` (loopback, RFC 8252). An IdP that matches redirect URIs exactly (a Dex confidential client does) needs one fixed port: register it and sign in with `sm login --callback-port <port>`. The device grant (`sm login --device`) needs the IdP's own device callback registered (Dex: `/device/callback`).
5. `sm login`. A new OIDC identity has **no roles**. The admin from step 1 gives it one on the server: `sudo sm admin grant <identity-id> admin` (the id is printed by `sm login`).

Discovery of the IdP happens on first use, not at start: a wrong issuer or an unreachable IdP shows up as `PROVIDER_ERROR` at login time, and the service starts anyway (the ADR text says "refuses the start"; the code is lazy, `internal/daemon/login.go`). Identity-provider endpoints must be `https`; private ranges are allowed, loopback and cloud-metadata addresses are never allowed, so an IdP on `127.0.0.1` cannot be used. Redirects from the IdP are not followed.

This sequence is derived from the code and has not been run end to end. See also the device-flow caveat in [security.md](security.md#oidc-and-the-device-flow-client-secret).

## Recovery access

- **Bootstrap code.** `sudo sm admin bootstrap-code` (admin socket; root or the service user) issues a new one-time code (valid `auth.bootstrap.code_ttl`, default 24h), invalidates any unconsumed older one, and prints only the code on stdout (expiry on stderr). It works only while no `admin` binding exists, or during a restore hold. Exchange it with `sm login --bootstrap`.
- **Grant.** `sudo sm admin grant <identity-id> <role>` binds a role when no administrator can log in. Audited.
- **API tokens.** `sm tokens create --name N --expires-in 90d [--scope ACTION]...` (default 90 days, at most 365; scopes only narrow what the creator can do); the value is shown once. `sm tokens revoke <id>` takes effect on the next request. `sm login --token-stdin` stores a token for a profile. The first API token issued by a no-OIDC bootstrap lives 90 days (the spec is silent; this is what the code does).
- **Sessions** last `security.session_ttl` (default 12h). `sm logout` revokes the session on the server.
- **Admin socket.** `server.admin_socket` (default `/run/supermgmt/admin.sock`, mode 0660, owned by the service user). The server checks that the peer is root or the service user; the client checks that the process that answered owns the socket file. It serves exactly `bootstrap-code`, `grant`, `restore-complete` and read-only `doctor`.
- **Doctor.** `sudo sm doctor` asks the running server (mode, restore hold, whether an admin is bound, its checks); `sm doctor --offline` checks files and the database with the service stopped.

## Limits worth knowing

- Rate limits are fixed constants: `/auth/*` and `/enroll` 10 per minute with a burst of 5 per remote address, writes 60 per minute with a burst of 20 per identity; an exceeded limit is 429 with `Retry-After` (the error code is `TIMEOUT`, as the spec has no rate-limit code). Behind a proxy the remote address is the forwarded client address, taken only from `trusted_proxies`.
- `GET /events/stream` allows 4 open streams per identity; the credential is re-checked every 30 seconds and on revocation events.
- `sm install upgrade`, `uninstall` and `proxmox-lxc` do not exist yet (M3). Upgrade by hand: back up, stop, replace `/usr/local/bin/sm`, start (not verified).
