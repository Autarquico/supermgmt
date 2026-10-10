# ADR-0015: SSH transport and command templates

- Status: Accepted
- Spec: §6.4, §8.4, §12, §16, §17, §20.4, §30, §41

## Context

§12 fixes strict host keys, one persistent connection per node, bounded dials and sessions, and the template catalog with allowlist validators and POSIX quoting. It leaves open several mechanisms: the SSH library, how trust is anchored, how mutating commands carry the node-side marker and the completion proof of §20.4, and how sudo-executed commands stay byte-equal to their sudoers lines.

## Decision

### Split

- Automated sessions use `golang.org/x/crypto/ssh` (the maintained SSH package, §41).
- Interactive sessions use the system OpenSSH client (§8.4, §17.1).

### Trust

- The database-pinned `host_public_key` is the only trust anchor (§6.4). The host-key callback compares exact key bytes. `ssh.known_hosts_file` is not consulted.
- First trust is a keyscan plus an explicit SHA256 confirmation. Adding the node stores the *confirmed* key, so a key change between the scan and the first authenticated probe fails with `SSH_HOST_KEY_MISMATCH`.
- CA trust is deferred.

### Pool

- One connection per node.
- Semaphores bound the sessions per connection (`max_sessions_per_connection`) and the dials in flight (`max_dials_in_flight`).
- `max_connections` is enforced by closing the least recently used idle connection.
- Connections idle longer than `idle_connection_ttl` close; keepalives run on every connection.
- An unreachable node backs off exponentially (×2, capped at 5m) without holding a dial slot.

### Transport-neutral executor

`transport.Executor` is bound to one node. It is either `ssh.Pool.For(target)` or the local provider's executor (`/bin/sh -c <line>`); both run the same rendered templates.

### Rendering (`internal/transport/ssh/templates`)

- Commands come only from the catalog. Every argument passes three checks, in order:
  1. a universal admissibility check: non-empty valid UTF-8, no NUL, **no leading `-`**;
  2. its parameter's allowlist validator;
  3. POSIX single-quote escaping.
- Templates put `--` before positional arguments, **except** sudo-executed commands. Those must equal their sudoers line byte for byte, so the catalog rejects a sudo template that contains ` -- `, and the validators alone guard their arguments.
- Content that must reach the node (setup files) travels on stdin (`Command.Stdin`), never on the command line.
- `Render` serves read templates, `RenderMutating` mutating ones and `RenderSetup` the `node.setup` steps (ADR-0009). Each refuses the other kinds.

### Mutating wrapper

`M` is `/var/lib/supermgmt/markers`, created by `node.setup` and never by a template:

```sh
: > M/<m> && { timeout --kill-after=10s <deadline> <cmd>; rc=$?; printf '%d\n' "$rc" > M/<m>.done.tmp && mv -f M/<m>.done.tmp M/<m>.done; exit "$rc"; }
```

- The marker exists before the command starts. Creating it fails when the directory is missing, so nothing runs on a node without setup.
- `.done` is written through a temporary file, so it is either absent or complete.
- `.done` containing exit status 0 is completion proof, which generalizes the Compose row of §20.4 to every templated mutation. A missing or nonzero `.done` is no proof.

### Reads

- Reads are bounded by `ssh.command_timeout` and by the template's byte and line limits.
- Remote output is untrusted (§30). `Sanitize` strips ANSI, C0 and C1 controls and repairs UTF-8 at the transport boundary.

### Credential references (M1)

- `secret://ssh/default@<version>` is the automated identity, a signer from the secret store (ADR-0016).
- `ssh-agent://default` and `file://`, with the §8.4 checks, serve only `admin_user`: probes before setup, the setup bootstrap and interactive sessions.
- Any other `secret://` name fails with `CAPABILITY_UNAVAILABLE` in M1.

### Sudoers grammar

- The granted line is `<user> ALL=(root) NOPASSWD: <systemctl_path> <verb> <unit>`. `systemctl_path` is resolved at setup and stored in the setup metadata.
- The executed argv is identical: `sudo -n <systemctl_path> <verb> <unit>`.
- Unit allowlist: `^[A-Za-z0-9][A-Za-z0-9@._-]*\.service$`. It allows no `:` and no `\`; a unit that needs escapes is `UNIT_NOT_ELIGIBLE`.
- User allowlist: `^[a-z_][a-z0-9_-]{0,31}$`.
- Together these exclude every sudoers metacharacter (`, : = \ # !` and whitespace). A renderer test asserts this.

### Completion evidence per runtime

Proof and outcome are judged and persisted separately. A pair of samples counts only when the classification **and** the canonical fingerprint bytes are identical across two samples at least `SampleGap` apart (ADR-0013 "observed identically").

| Case | Proof | Outcome |
|---|---|---|
| marker absent after quiescence | `marker_absent` | `not_started` |
| systemd, `systemctl list-jobs` shows a job for the unit | none (still settling) | — |
| systemd restart, no job queued | `systemd_no_jobs` | InvocationID changed ∧ `ActiveState=active` → `complete`; unchanged → `not_started`; changed ∧ not active → `unknown` (held) |
| systemd start/stop | as restart | ActiveState/SubState vs the verb; start also needs a new InvocationID |
| Docker verbs, `.done` with exit 0 | `done_file` | `State.StartedAt > pre_state.StartedAt ∧ Running` (start, restart) or `¬Running` (stop) → `complete`; otherwise `unknown` |
| Docker, `.done` missing or nonzero | none | held for `job.resolve` (§20.4 fixed fallback) |

Persisted evidence carries the proof kind, the post-state fingerprint and the pre-state captured before dispatch.

## Consequences

- Interactive sessions depend on a system OpenSSH client. It is isolated from user and system configuration (`-F /dev/null`, a temporary `known_hosts` keyed by `HostKeyAlias`, and every proxy, command and control option set to `none`/`no`).
- Units whose names need systemd escaping cannot be granted in V1.
- Docker actions without a `.done` proof always wait for a human.
- Docker restart evidence compares `State.StartedAt` with the pre-state's `StartedAt`, both read from the node's own clock. The spec's `dispatched_at` is the daemon's clock, so comparing the two would misjudge any node with clock skew. `dispatched_at` is no longer used for Docker.
