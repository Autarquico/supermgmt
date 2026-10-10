# ADR-0009: Node provisioning (`node.setup`) and the dedicated `supermgmt` user

- Status: Accepted
- Spec: §46, §6.4, §8.4, §11.2, §11.3, §12 step 7, §16, §17, §20.4

## Context

§12 step 7 lets the add-node flow create a dedicated `supermgmt` user and a scoped sudo policy through an explicit plan. §16 and §20.4 already assume that user: journal group membership, exact sudoers lines, and a marker directory "owned by `supermgmt`, created at enrollment". §46 requires a `node.setup` job (high risk, approval-gated, idempotent) and forbids advertising non-retryable mutating capabilities on nodes without it. The spec does not fix the user's home, shell, groups or key, nor how setup authenticates before the user exists. Spec 1.4.2 adds the catalog row, the composite rule, the endpoint `admin_user` and the marker-first exception this ADR relies on.

## Decision

### Action and policy

- Catalog row `node.setup | node | high | job | idempotent | node.ssh | 3`, granted in `builtin-admin`.
- Parameters (closed schema):
  - `docker_access`: `"true"` or `"false"`, required. It has no default, because the `docker` group is root-equivalent (§17), so the TUI and CLI must ask and show that warning.
  - `logs_mode`: `journal-group` or `broker`.
  - `grants`: optional list of `"<verb> <unit>"` strings, one per sudoers line.
- A `node.setup` plan is composite (§11.3). It lists the sub-action `sudoers.write` on the node (always) and `log_broker.install` (broker mode). Each is evaluated like a target, and approval and quorum are the maximum. So "sudoers grants are `sudoers.write`" (§16) holds for policy, while execution keeps setup's idempotent semantics.
- No standalone `sudoers.write` or `log_broker.install` job is exposed in V1. Changing the unit set or the log mode means re-running `node.setup` with new parameters.

### Two endpoint users

- `endpoint.user` (default `supermgmt`) is the dedicated account. `endpoint.admin_user` (required) is the operator's own account, e.g. `root` or a personal login. `admin_credential_ref` authenticates it; the local-mode default is `ssh-agent://default` and `file://` is allowed.
- **Connection rule:** automated sessions use `user` if and only if the node has the capability `node.setup`. Otherwise they use `admin_user`, for read-only probes only. Setup and interactive sessions (§8.4, "the user's own credentials") always use `admin_user`.
- Setup never rewrites configured state, so it works for config-origin nodes too. Success is recorded as the observed capability `node.setup`, with no `spec_revision` bump.

### Bootstrap privilege

- Bootstrap is one-time per run, explicit and audited.
- `admin_user = root`: commands run directly. Otherwise every privileged command is `sudo -n <exact argv>`; there is no password prompting.
- If neither works, preflight fails `CAPABILITY_UNAVAILABLE` ("admin_user needs root or passwordless sudo for setup").
- The plan shows the bootstrap identity. The job emits `node.setup.privileged_session` start and end events.
- Documentation recommends revoking any temporary NOPASSWD after setup. SuperMgmt needs it again only to re-run setup.

### The dedicated user

- `useradd --system --user-group --home-dir /var/lib/supermgmt --create-home --shell /bin/sh supermgmt`, then `usermod -p '*' supermgmt`.
  - `*` means no password but not `!`-locked, so sshd with `UsePAM no` still accepts keys.
  - `/bin/sh`, because §12 exec runs through the login shell.
- Paths and modes:
  - home `/var/lib/supermgmt`: 0750, `supermgmt:supermgmt`;
  - `markers/`: 0700;
  - `.ssh/`: 0700;
  - `.ssh/authorized_keys`: 0600, fully managed. It holds one line, `restrict <authorized_key> supermgmt@<instance_id>`: no pty and no forwarding, automated use only.
- Groups:
  - `systemd-journal` (or `adm`) in `journal-group` mode, removed in `broker` mode;
  - `docker` only when `docker_access` is `"true"`. Without it, Docker capabilities disappear once sessions switch to `supermgmt`.
- Sudo: only `/etc/sudoers.d/supermgmt` (0440 root, checked with `visudo -cf`). It holds exact lines `supermgmt ALL=(root) NOPASSWD: <systemctl_path> <verb> <unit>`, one per granted unit and verb, plus the broker line in broker mode (§16). `supermgmt` has no other sudo rights.
- `/etc/tmpfiles.d/supermgmt.conf` holds `d /run/supermgmt/locks 0700 supermgmt supermgmt -`, applied with `systemd-tmpfiles --create`. Broker mode also installs the broker files of §16.

### Key

- `authorized_key` is the public half of the instance identity `secret://ssh/default`, generated and stored by SuperMgmt (ADR-0016).
- The setup metadata pins `{key_ref, key_version, key_fingerprint}`. The executor signs automated sessions with exactly that version, so a future identity rotation never breaks a set-up node until setup is re-run.

### Steps, idempotency and recovery

Every step runs over `admin_user`. File content goes on **stdin** to a temporary file, never on the command line. Every step is an "ensure":

1. User: `getent passwd supermgmt`.
   - Absent: create it.
   - Present with exactly our home, shell and a system UID: keep it.
   - Anything else: `CONFLICT`. An existing account is never hijacked.
2. Directories and modes.
3. `authorized_keys`.
4. Groups, added or removed to match the parameters.
5. tmpfiles.
6. Broker (broker mode only).
7. Sudoers drop-in.
8. **Verify** over a fresh connection as `supermgmt`, with the pinned host key: `id`, markers writable, and `sudo -n -l` equal to the rendered lines exactly.
9. A fenced transaction writes the capability `node.setup` with metadata `{setup_version: 1, systemctl_path, units: [{unit, verbs}], logs_mode, docker_access, key_ref, key_version, key_fingerprint}`.

Additional rules:

- Files are installed as temp → validate → `install` to a temporary name → `mv -f`. An interruption leaves the old file or the new one, never a partial one.
- The retry class is `idempotent`, so an interrupted setup is requeued (§20.4 table).
- Markers are not consulted. The setup steps are the only mutating templates exempt from marker-first, because they create the marker directory; they render only through `RenderSetup` (ADR-0015).
- Exhausted attempts or a failed verify end the job `failed`. The capability is not written, and the node keeps using `admin_user` read-only.

### Gating

- Discovery advertises the following only on nodes with `node.setup`:
  - `service.start|stop|restart` for granted units;
  - those verbs on Docker containers when `docker_access` is true;
  - broker `service.logs`.
- The app preflight refuses those actions otherwise.
- Read capabilities never depend on setup.
- The local provider has no setup and no mutating capability in M1.

### Deferred

- `deploy_root` and `docker.compose.deploy` (`setup_version` 2, M4).
- Automated teardown of the user: V1 documents the manual steps.
- Join (§13, M2) keeps `join.sh`, enrollment tokens, `/enrollments`/`/enroll`, node-initiated enrollment and private connectivity. It will reuse these steps; nothing of join is pulled forward.
- Server-mode key authorization (M2).

## Consequences

- After setup, SuperMgmt holds no standing root on the node. `supermgmt` can run exactly the granted `systemctl` lines and, when granted, use Docker.
- The bootstrap needs root or passwordless sudo once per setup run. Operators who grant temporary NOPASSWD must revoke it themselves.
- `useradd` flags are verified on Debian (CI fixture). The RHEL family is a documented assumption.
- A foreign `supermgmt` account blocks setup with `CONFLICT` until the operator resolves it.
