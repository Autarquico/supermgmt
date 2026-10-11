# Security

Authoritative sources: SPEC §30 (threat model), §11 (policy and approvals), §2.1.1 (local trust boundary), §12 and §16 (nodes). Vulnerability reporting: [`../SECURITY.md`](../SECURITY.md).

SuperMgmt is **pre-alpha**. M0 delivered the controls below as libraries; M1 puts them behind a local daemon, an SSH connector and a TUI; M2 adds server mode over HTTPS with sessions, tokens and OIDC, the full secret store, backup and restore, and a signed-release installer. There is still no MCP endpoint, nothing has been released, and there is no independent security audit. **[M0]**, **[M1]** and **[M2]** mark what is implemented in the repository now; **[planned Mx]** is not implemented. Statements about M2 were read against the code; what ran only in CI with test keys, a Dex container or fakes is said so, and the production signing key, a real VM, a real Cloudflare and any identity provider other than Dex were not exercised ([manual checks](manual-checks/m2-handoff.md)).

## Trust boundaries in one page

Read this before you point SuperMgmt at a machine you care about.

1. **The local boundary is the OS user.** The daemon listens on a Unix socket and accepts connections from its own UID only. Anything running as you can drive SuperMgmt, approve its own plans (`security.allow_self_approval` defaults to `true` in local mode) and use the instance SSH identity. Local mode does not defend against malicious software under your user. **[M1]**
2. **The node credential can read all logs in `journal-group` mode.** That mode puts `supermgmt` in `systemd-journal` (or `adm`), so a stolen node credential reads the node's entire system journal, not only selected units. Mediation by the API limits what clients see, not what the credential can read. `broker` mode avoids the group: see [Log modes](#log-modes-on-a-node).
3. **Docker access is root.** The `docker` group is equivalent to root on the node. Setup asks for `docker_access` explicitly, has no default, and shows this warning.
4. **A unit grant is a trust profile, not a proof.** Granting restart on a unit trusts everything that unit executes.
5. **The KEK files are separate from the database and from backup archives and must be backed up separately.** `sm secrets export-key` produces a passphrase-protected copy ([operations.md](operations.md#key-management)).
6. **Setup needs root once.** Afterwards SuperMgmt holds no standing root on the node.
7. **Server mode puts the control plane on the network.** Every request on the HTTPS listener must carry a bearer token; a reverse proxy in front (including Cloudflare) can read that token and the traffic. The admin socket trusts root and the service user on the host.
8. **`curl | bash` trusts the `main` branch.** The review-first path with an out-of-band key does not ([installation.md](installation.md)).

## Threat model summary (SPEC §30)

| Threat | Main mitigation | Status |
|---|---|---|
| Stolen browser or OIDC session | session TTL (12h default), revocation on logout, no cookies so no CSRF surface, `no-store` and `nosniff` headers, no CORS | **[M2]**; there is no browser UI yet |
| Compromised MCP client; malicious prompt asking for a privileged action | MCP is its own actor type with no inherited roles; hard approval floor for operational writes; MCP can never approve | policy rules **[M0]**; MCP itself planned M5 |
| Compromised managed node | least privilege on the node, bounded and sanitized output, timeouts | **[M1]** |
| Malicious repository or PR | closed-schema Compose pipeline, immutable digests | planned M4 |
| Forged or replayed GitHub webhook | signature check and replay dedupe | planned M4 |
| SSH MITM or host key change | pinned host key compared byte for byte; a changed key fails the job | **[M1]** |
| Leaked API token | SHA-256-only storage, expiry (at most 365 days), scopes that only narrow, revocation effective on the next request, rate limits | **[M2]** |
| Another local user reaching the daemon | socket directory 0700, peer UID checked on both ends, `Authorization` header rejected | **[M1]**; refusal of a second user is tested on Linux CI only, on macOS it rests on the same-UID test and a manual check |
| Terminal escape sequences in remote logs | ANSI, C0 and C1 controls stripped and UTF-8 repaired at the transport boundary | **[M1]** |
| Command injection via names or parameters | closed command catalog, per-parameter allowlists, no leading `-`, POSIX quoting, setup content on stdin | **[M1]** |
| SSRF via health URLs or provider endpoints | outbound request filter (`internal/netguard`) | **[M2]** for the identity-provider endpoints; health URLs planned M4 |
| Supply-chain compromise | pinned dependencies, scanning, signed releases | CI scanning **[M0]**; signed pipeline and verifying installer **[M2]**, production key and provenance not yet exercised |
| Tampered installer download | embedded-key signature check of checksums and archive before anything runs | **[M2]**, tamper tests with a test key in CI; `curl \| bash` still trusts `main` |
| Backup theft; control-plane database theft | envelope encryption of secrets; KEKs never in the archive | **[M2]**. The archive itself is not encrypted |

MCP content is untrusted input: a model asking for an action has no more authority than its authenticated identity and policy grant.

## Controls implemented in M0

### Default deny policy engine **[M0]**

`internal/policy` evaluates a request in the order of SPEC §11.3: catalog, capability, rule match, deny override, default deny, destructive gate, credential scopes, approval and quorum, then combination across targets and sub-actions.

- No matching allow rule means deny. Any matching deny wins over every allow.
- Destructive actions require an allow rule that explicitly sets `allow_destructive`.
- Credential scopes only narrow what an actor may do.
- MCP identities need approval for operational-or-higher actions as a fixed floor, and `mcp` and `system` identities can never approve or reject.
- Property and table tests assert that adding allow rules never overrides a deny and that adding targets never relaxes a decision.
- The built-in default policy is embedded; a user policy file replaces it entirely, and the engine can diff the two.

### Approvals bound to the plan hash **[M0]**

A plan lists every input that can change what executes, including the `spec_revision` of each configured resource, and is serialized with RFC 8785 canonical JSON and hashed with SHA-256. Observation data, timestamps, random values and secrets never enter the plan. Approval records are tied to that hash, so any change to an input yields a new hash and earlier approvals do not transfer. Quorum counts distinct approvers, approvals expire, and self-approval is controlled by `security.allow_self_approval`. Claim-time revalidation in `internal/app` recomputes the plan from current state: a changed plan hash or input fails the job with `PLAN_STALE`, an expired plan fails with `PLAN_EXPIRED`, and credentials, policy and quorum are re-checked.

### Append-only audit **[M0]**

The `events` table is protected by database triggers that reject `UPDATE` and `DELETE` (migration `000001_initial.up.sql`). The emitter assigns the event ID and timestamp itself, so callers cannot backdate the trail, and every event carries actor, resource and correlation ID. Denied actions and unavailable capabilities are audited as well as accepted ones (SPEC §30): `internal/app` writes a `policy.<decision>` event with result `denied` for every DENY and CAPABILITY_UNAVAILABLE outcome on plan creation, submission, revalidation and approval decisions.

### Redaction **[M0]**

`internal/audit` defines a `Secret` type that renders as `[REDACTED]` through every formatting, JSON, text and logging path, and redacts values by sensitive key name (password, token, authorization, cookie, session, private key and similar, matched case-insensitively) and bearer-token patterns. Over-redaction is the intended failure mode. Values under sensitive keys are always masked. The single exception is a credential reference (`secret://<path>`, `ssh-agent://default`, `file:///<abs-path>`): it stays visible only in a field whose name ends in `_ref` (such as `credential_ref`) and whose whole value matches the reference grammar, because a reference points at a secret and is not one. Plaintext secrets must never reach SQLite, logs, config examples or error messages (SPEC §45 rule 9).

### Strict configuration **[M0]**

Unknown configuration fields fail validation, credential references are limited to a closed set of schemes, and validation reports every problem with its YAML path. See [configuration.md](configuration.md).

### Storage and build **[M0]**

SQLite runs in WAL mode with `synchronous=FULL` and a single writer ([ADR-0001](adr/0001-sqlite-driver.md)). CI runs `go vet`, `golangci-lint` (including `gosec`), tests with the race detector on Linux and macOS, `govulncheck`, CodeQL and dependency review.

## Controls implemented in M1

### Local socket and daemon **[M1]**

([ADR-0014](adr/0014-local-api-and-daemon-lifecycle.md))

- The socket directory must be a real directory (no symlink) owned by the daemon user with mode exactly 0700; otherwise the daemon refuses to start. The daemon runs with umask 0177.
- The daemon reads the peer UID of every connection (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS) and closes it on a mismatch or on a lookup error, before reading any byte. The client checks the listener's UID the same way before its first request, so it does not talk to another user's daemon.
- Any `Authorization` header gets 401 `UNAUTHENTICATED`; tokens arrive with MCP in M5.
- The caller is the `human` identity `local:<uid>`, bound to `admin`.
- Every route maps to exactly one catalog action, enforced by a test. Every POST, PATCH and DELETE needs an `Idempotency-Key`; a key reused with a different request gets 409.
- Two daemons on one database, or two databases on one socket, are refused (exit 2).

### Host keys **[M1]**

([ADR-0015](adr/0015-ssh-transport-and-command-templates.md))

- The `host_public_key` stored in the database is the only trust anchor. The check compares the exact key bytes. `ssh.known_hosts_file` is not consulted, and neither are the user's `~/.ssh/known_hosts` or `ssh_config`.
- First trust is explicit. `sm nodes add` scans the key and shows its SHA256 fingerprint; nothing is trusted until you confirm it (type `yes`, or pass `--fingerprint SHA256:...` verified out of band). The confirmed key is the one stored, so a key that changes between the scan and the first authenticated probe fails with `SSH_HOST_KEY_MISMATCH`.
- A changed host key fails the connection; there is no automatic re-pinning. Since M2, `sm nodes repin <node>` replaces a pinned key after you confirm the new fingerprint ([operations.md](operations.md#key-management)).
- SSH CA trust is not supported (not scheduled).

### Command execution on nodes **[M1]**

- Commands come only from a closed catalog. Each argument is checked for non-empty valid UTF-8, no NUL and no leading `-`, then against its parameter's allowlist, then quoted for POSIX `sh`. Content that must reach a node (setup files) travels on stdin.
- Reads are bounded by `ssh.command_timeout` and by per-template byte and line limits. Remote output is untrusted: ANSI, C0 and C1 control characters are stripped before anything is stored or rendered.
- Mutating commands are wrapped so that a marker file exists before the command starts and a `.done` file records its exit status. Without the marker directory (created only by `node.setup`) nothing runs.
- Sudo-executed commands equal their sudoers line byte for byte: `sudo -n <systemctl_path> <verb> <unit>`. Unit names must match `^[A-Za-z0-9][A-Za-z0-9@._-]*\.service$`, which excludes every sudoers metacharacter. A unit whose name needs systemd escaping cannot be granted in V1.

### Unit trust profile **[M1]**

Before a unit gets a sudoers line, and again at every action, SuperMgmt reads the unit's `systemctl show` properties and requires that the unit file, every drop-in, every executable named in an `Exec*` line, every `EnvironmentFile` and the `WorkingDirectory` are root-owned and not group- or other-writable, as is every parent directory up to `/`. When an `Exec*` program is an interpreter (`sh`, `bash`, `dash`, `python*`, `perl`, `ruby`, `node`, `php`), its script arguments must satisfy the same rule and inline code (`-c`, `-e`) is refused. Anything that cannot be resolved to a plain path makes the unit ineligible, and the action is refused with `CAPABILITY_UNAVAILABLE` naming the failing path (`internal/runtimes/systemd/trust.go`).

This is a **trust profile, not a proof**. It narrows what an unprivileged user on the node can tamper with. It does not make the unit safe: a restart grant lets SuperMgmt run, as root, whatever that unit executes, so grant it only for units whose code you already trust as root. A file that changes between the check and the action, or an executable that behaves differently when run, is outside what the profile can see.

### Log modes on a node

| Mode | What `supermgmt` gets | Consequence |
|---|---|---|
| `journal-group` (default in the TUI) | membership of `systemd-journal`, or `adm` if the node has no such group | can read the whole system journal of that node |
| `broker` (opt-in, `setup <node> broker`) | no journal group; may run only the root-owned `/usr/local/libexec/supermgmt/unit-logs` through sudo | reads only units listed in `/etc/supermgmt/allowed-units`, at most 10000 lines |

In both modes `journalctl` itself is never granted through sudo. Log lines are bounded and sanitized before display. The config key `ssh.logs_mode` is validated but, in M1, the mode of a node comes from the `logs_mode` parameter of its `node.setup` plan, not from that key.

### Docker access

`docker_access` is a required `"true"` or `"false"` parameter of `node.setup`. When true, `supermgmt` joins the `docker` group on the node, which is equivalent to root there: anyone holding the node credential can start a privileged container and read or write the whole host. Without it, Docker capabilities disappear once automated sessions switch to `supermgmt`. Grant it only on nodes where handing SuperMgmt root is acceptable, and treat any policy rule that allows Docker-level actions on a node as a root grant. The API/policy layer limits what SuperMgmt asks for, not what the credential could do.

### Secrets and the instance SSH identity **[M1]**

([ADR-0016](adr/0016-m1-secrets-slice-and-ssh-identity.md), [ADR-0003](adr/0003-aes-gcm-envelope.md))

At first start the daemon generates one Ed25519 key, the **instance SSH identity**, and stores the private half in the `secrets` table inside an AES-256-GCM envelope: a fresh data-encryption key per secret version, wrapped by a key-encryption key (KEK). Nodes authenticate `supermgmt` with this key; its public half is printed by `sm ssh-key show` and authorized on a node by `node.setup`.

- **KEK files.** KEKs live in `security.keys_dir` (default `<instance.data_dir>/secrets/keys`) as `<kek_id>.key`: 32 random bytes, mode 0600, a regular file owned by the daemon user, opened without following symlinks. The directory must be mode 0700. Wrong permissions, a symlink or a wrong owner refuse to start. `*.pending` files are ignored.
- **The database does not contain the KEK.** A copy of the database alone cannot decrypt the identity. Because the default `keys_dir` sits inside the data directory, copying the whole data directory copies both: keep database backups and KEK backups in different places, and put the KEK copy somewhere with its own access control.
- **Back the KEK files up separately.** Since M2 there is a passphrase-protected export (`sm secrets export-key`, `import-key`; see [operations.md](operations.md#key-management)). If a KEK file is lost, the daemon fails at start (exit 4) and names the missing KEK ids, and the encrypted identity cannot be recovered. The remedy is to generate a new identity and re-run `node.setup` on every node so they authorize the new key. There is no command that performs that reset (M2 added none); expect to start from a fresh data directory.
- **Plaintext.** The private key is decrypted into memory on first use and cached as a signer; buffers are zeroed best effort. It does not appear in logs, events, API responses, errors or plans, and the events about it carry the fingerprint only. Tests scan the database file, its WAL and the data directory for the key bytes. The KEK files are the one place on disk where key material is not encrypted (by design of the envelope).
- **Rotation.** A node keeps working with the key version pinned at setup; since M2, `sm ssh-key rotate` creates a new version and each node needs `sm nodes setup` re-run to authorize it.

### Bootstrap privilege during setup **[M1]**

`node.setup` is a high-risk, approval-gated job that runs as the node's `admin_user`, with your own credential (`ssh-agent://default` by default):

- `admin_user: root`: commands run directly.
- Any other `admin_user`: every privileged command is `sudo -n <exact command>`; SuperMgmt never prompts for a password. If the account is neither root nor able to run passwordless sudo, setup fails before changing anything with `CAPABILITY_UNAVAILABLE` ("admin_user needs root or passwordless sudo for setup").
- The plan shows the bootstrap identity, and the job writes `node.setup.privileged_session` events when the privileged session starts and ends.
- If you grant a temporary `NOPASSWD` rule to make setup possible, **you** must revoke it afterwards. SuperMgmt only needs it again to re-run setup.

### Interactive SSH isolation **[M1]**

`s` in the TUI and `sm ssh` open a shell as `admin_user` (or `--user`) with **your** credential; `d` and `sm docker` run `lazydocker` the same way. The terminal is handed to the system OpenSSH client, but the client builds the command (from connection details the daemon returns) so that nothing on your machine can redirect it (`internal/client/interactive.go`):

- `-F /dev/null`: your `~/.ssh/config` and the system config are not read.
- A temporary `known_hosts` containing only the node's pinned key under `HostKeyAlias=sm-<node id>`, with `UserKnownHostsFile` pointing at it, `GlobalKnownHostsFile=/dev/null`, `StrictHostKeyChecking=yes`, `UpdateHostKeys=no` and `CheckHostIP=no`. The file is removed when the session ends.
- `ProxyCommand=none`, `ProxyJump=none`, `KnownHostsCommand=none`, `ControlMaster=no`, `ControlPath=none`, `PermitLocalCommand=no`.
- No shell is involved: the arguments are validated again on the client and passed as an argv. The remote command is a fixed literal (none for a shell, `lazydocker`, `btop` or `tmux`).

The session is issued and ended through the API, so it is audited with the exit code. What stays yours: the credential `ssh` picks (your agent and OpenSSH's default identity handling), and everything you type in the remote shell. The shell is as privileged as `admin_user`, and SuperMgmt does not restrict or record it. SuperMgmt never installs `lazydocker`; when it is missing the TUI shows where to get it.

## The dedicated `supermgmt` user and how to remove it

([ADR-0009](adr/0009-node-provisioning.md)) `node.setup` creates exactly this on a node and nothing else. No SuperMgmt binary or daemon is installed there.

| What | Where | Notes |
|---|---|---|
| User and group `supermgmt` | home `/var/lib/supermgmt`, shell `/bin/sh` | system account, no password, not locked (so key login works) |
| Authorized key | `/var/lib/supermgmt/.ssh/authorized_keys` (0600) | one line: `restrict <instance key> supermgmt@<instance id>`; no pty, no forwarding |
| Marker directory | `/var/lib/supermgmt/markers` (0700) | completion evidence for mutating commands |
| Sudoers drop-in | `/etc/sudoers.d/supermgmt` (0440, root) | one line per granted unit and verb: `supermgmt ALL=(root) NOPASSWD: <systemctl> <verb> <unit>`; checked with `visudo -cf` |
| Group membership | `systemd-journal` or `adm`, in `journal-group` mode; `docker` only if `docker_access` is true | see above |
| tmpfiles entry | `/etc/tmpfiles.d/supermgmt.conf` | creates `/run/supermgmt/locks` |
| Log broker (broker mode only) | `/usr/local/libexec/supermgmt/unit-logs`, `/etc/supermgmt/allowed-units` | root-owned |

An existing `supermgmt` account that does not match is never taken over: setup fails with `CONFLICT`. Setup re-runs are idempotent.

**There is no automated teardown in M1.** To remove SuperMgmt's footprint from a node, as root:

1. In SuperMgmt, retire the node (`sm nodes remove <node>`; its history is kept). Do this first, or the node will start failing probes.
2. Delete `/etc/sudoers.d/supermgmt`.
3. In broker mode, delete `/usr/local/libexec/supermgmt/unit-logs` and `/etc/supermgmt/allowed-units`.
4. Delete `/etc/tmpfiles.d/supermgmt.conf` and, if present, `/run/supermgmt`.
5. End the user's sessions, then `userdel -r supermgmt`. This removes the account, its group, `.ssh/authorized_keys` and `markers/`. Check that `/var/lib/supermgmt` is gone.
6. Revoke any temporary `NOPASSWD` rule you created for the bootstrap.

Steps 2 to 6 are derived from the list above. Only `userdel -r supermgmt` is exercised by the test fixtures (as cleanup); the sequence as a whole has not been tested.

## Controls implemented in M2

### HTTPS transport, credentials and sessions **[M2]**

([ADR-0017](adr/0017-server-transport-credentials-sessions.md))

- `sm server` serves the same handlers as the local socket over HTTPS. TLS is either terminated by the daemon (`direct`, TLS 1.2 or newer, certificate re-read on `SIGHUP`) or by a reverse proxy (`proxy`); no ACME. In proxy mode forwarding headers are believed only from `server.trusted_proxies`, a forwarded proto other than `https` is a 400, and a loopback peer gets no special trust. Plain HTTP on a non-loopback address is refused by config validation.
- Credentials are bearer tokens `sm<kind>_<base64url(32 random bytes)>`: `s` session, `t` API token, `b` bootstrap code, `j` join token. Only the SHA-256 is stored, in a unique column; nothing is cached, so a revocation takes effect on the next request. A token of the wrong kind for an endpoint is refused before lookup. The HTTPS listener accepts `Authorization: Bearer` only; the Unix socket still refuses it.
- API tokens have a mandatory expiry of at most 365 days, scopes that can only narrow the creator's permissions, and a unique name per identity. Sessions last `security.session_ttl`.
- No cookies, so no CSRF surface. Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; no CORS headers are sent, so browsers refuse cross-origin calls.
- Token buckets: 10 per minute with a burst of 5 per remote address on `/auth/*` and `/enroll`; 60 per minute with a burst of 20 per identity on writes. Fixed constants; 429 with `Retry-After`.
- Event stream (`GET /events/stream`): at most 4 per identity, a heartbeat every 15 s, and the credential and `event.read` are re-checked every 30 s and on revocation events.

### Admin socket **[M2]**

`server.admin_socket` (mode 0660, owned by the service user). The server checks the peer UID (root or the service user; a lookup error refuses); the `sm admin` client checks that whoever answered owns the socket file before sending anything. It serves exactly `bootstrap-code`, `grant`, `restore-complete` and read-only `doctor`, and never key management. The first admin comes from a one-time bootstrap code (at least 128 bits, stored hashed, valid `auth.bootstrap.code_ttl`, a new code invalidates the old); once an admin exists it is refused except during a restore hold. In server mode the daemon never creates a `local:<uid>` admin.

### OIDC **[M2]**

([ADR-0018](adr/0018-oidc-adapter.md)) The server is the OIDC client. Authorization Code with PKCE S256 over a loopback redirect, or the device grant. Discovery must return the exact configured issuer and `https` endpoints on the issuer origin or an origin in `auth.oidc.allowed_endpoint_origins`; the userinfo endpoint is never called. ID tokens are verified with `go-oidc` (RS256, ES256 or EdDSA; issuer, audience, `azp`, expiry, nonce, verified email, optional domain list); a `jti` is recorded to refuse replays. Login state is held in memory (a restart invalidates logins in progress, never sessions); the device code never leaves the server, polls are rate-shaped (`slow_down`), and completion is single use. Exercised only against Dex, by hand; other providers are untested.

#### OIDC and the device-flow client secret

With the device grant, **Dex echoes the client secret into the verification URL it shows in the browser**, so the secret of the configured client ends up in the browser address bar and history of the person signing in. Observed in the Dex spike (`ghcr.io/dexidp/dex:v2.45.1`); not observed with other providers.

- SuperMgmt has one OIDC client (`auth.oidc.client_id` and `client_secret_ref`) and sends its secret to the device endpoint as a form field because Dex ignores HTTP Basic there. **There is no separate device-flow client key**, so the secret cannot be kept out of that URL today.
- Recommended: use the loopback flow (`sm login --callback-port N`) and do not use `sm login --device` against Dex unless you accept that exposure. A public client for the device flow (no secret to leak) is the intended remedy, but it needs a new configuration key and a spec change; it is not built.
- If you must use the device flow with Dex, register a client used by nothing else and treat its secret as exposed to the people who sign in; rotate it if a browser profile is shared.

### Outbound filter **[M2]**

`internal/netguard` (SPEC §21.1) resolves a name once, normalizes IPv4-mapped, IPv4-compatible and NAT64 forms, refuses cloud-metadata, loopback, link-local, multicast and reserved ranges for every caller, refuses private and special ranges unless the caller's allowlist names them, then dials the vetted address while TLS verifies the original hostname. Redirects are off by default, bodies are capped, and ambient proxy variables are never read (`outbound.proxy` is the only proxy). In M2 only the identity-provider client uses it (private ranges allowed). 6to4 and Teredo are not unwrapped.

### Secrets and keys **[M2]**

([ADR-0021](adr/0021-key-and-identity-management.md)) Rotation, retirement, export and import of master keys, secret import, and instance SSH-key rotation are the high-risk `secret.write` action, so each is a job that waits for approval. Plans carry no secret value or passphrase: an imported value is sealed under the active KEK as a staged version when requested, and approval activates it. Key export is a passphrase-protected `SMKEY1` file (scrypt, AES-256-GCM) with a passphrase of at least 12 characters read from a terminal or stdin; it is served on the local-mode socket only and, on a server, by `--offline` with the service stopped. Import is offline only and installs a `.key.pending` file that the daemon never loads until a database or restore validates it. See [operations.md](operations.md#key-management). A single operator on a server cannot approve their own key operations unless `security.allow_self_approval` is turned on.

### Backup and restore **[M2]**

([ADR-0020](adr/0020-backup-format-and-offline-restore.md)) Archives are not encrypted and never contain a KEK. Restore is offline, stages and checks the archive first (safe extraction, checksums, integrity check, key check), neutralizes the staged database (undispatched jobs fail, running jobs become interrupted, approvals, sessions and tokens revoked, codes invalidated) and then moves files under a write-ahead journal with recovery at every start. The restored server starts in a hold where nearly every write is refused until `sm admin restore-complete`. Crash injection at every journal step is tested in CI with a build tag that release binaries do not carry (a test asserts it). Not tested on a real VM.

### Releases and the installer **[M2]**

([ADR-0019](adr/0019-release-pipeline-and-installer.md), [installation.md](installation.md)) Releases are built from `v*` tags in a protected environment, with OpenSSH signatures on `checksums.txt`, `install.sh`, `join.sh` and the channel files, SPDX SBOMs, and build provenance on tag builds. `install.sh` verifies the verifier first, checks signed channel freshness (30-day maximum validity), a version-and-channel-bound checksum list and the archive hash, and only then runs `sm`. A revocation list is embedded. The embedded production key is a placeholder until the owner creates the key: **production signing and provenance are unverified**, and every real install fails closed until then.

### Join **[M2]**

([ADR-0022](adr/0022-join-enrollment.md)) A join token is limited to a number of node slots, lives at most 24 hours, can be limited to source networks, and is stored hashed. It lets a node pin its own host key and receive the instance public key; it grants no sudo, docker or journal access. A stolen token yields at most an unprivileged, read-only node entry pinned to the thief's key.

### Client credential storage **[M2]**

`sm login` stores the session or API token in the macOS keychain (through `security -i` with the token on stdin), the Secret Service (`secret-tool store`, token on stdin), or a mode-0600 file when neither exists. A token is never an argument or an environment variable, and tokens are checked against the alphabet SuperMgmt issues before they reach the OS tools. Unit-tested with fakes; the real keychain and `secret-tool` are manual checks. Whether `security -i` on current macOS keeps a token on stdin out of the process list is also a manual check.

## Planned controls

Not implemented; listed so nothing is mistaken for shipped.

- SSH CA trust and per-node keys (not scheduled)
- Upgrade and uninstall flows (M3)
- Outbound request filter for health URLs and the closed-schema Compose pipeline (M4)
- Webhook signature and replay protection (M4)
- MCP registration, tokens, OAuth protected-resource layer and security tests (M5)
- Fuzzing and security scans across all parsers (M6)

## Accepted limitations

- Local mode does not protect against malicious code running as the same OS user.
- `journal-group` logs mode exposes the node's whole journal to the node credential; `docker_access` exposes root on the node; a unit grant trusts the unit's code.
- The KEK files are not backed up by SuperMgmt. `export-key` exists, but if a key is lost without an export the data it protected is gone and the remedy is a fresh data directory (a new identity and a new setup on every node).
- Backup archives are not encrypted.
- Dex puts the OIDC client secret in the device-flow verification URL (see above); no separate device client is configurable.
- Only Dex has been tested as an identity provider.
- A reverse proxy or Cloudflare in front of the server terminates TLS and can read bearer tokens. SuperMgmt consumes no Cloudflare assertion ([cloudflare.md](cloudflare.md)).
- With a single operator, key operations need `security.allow_self_approval: true` or a second identity.
- Refusal of another local user on the socket is tested on Linux CI only; on macOS it relies on the same-UID test and a manual check.
- Real terminal emulators are not automated; restoring the terminal after an interactive session is covered by a pseudo-terminal test and the [manual checklist](manual-checks/m1-handoff.md).
- Node setup is verified in CI on Debian only. Other distributions are an assumption.
- The `curl | bash` installer path trusts the repository's `main` branch; the review-first path with an out-of-band key avoids that (SPEC §3.2). The installer requires OpenSSH 8.2 or newer, stricter than the spec's 8.1.
- No release exists and the production signing key has not been generated; the placeholder trust root makes real installs fail closed.
- No independent security audit has been performed.
