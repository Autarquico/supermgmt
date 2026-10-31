# Security

This page explains what SuperMgmt trusts, what it defends against and how, topic by topic. Start with the trust boundaries: they decide whether SuperMgmt fits the machines you want to manage.

SuperMgmt is **pre-alpha**. Nothing has been released, and there has been no independent security audit. Everything on this page is implemented in the repository unless it is listed under [Planned controls](#planned-controls). Each section says how its controls were tested. Where something ran only in CI with test keys, a Dex container or fakes, the section says so. The production signing key, a real VM, a real Cloudflare setup and any identity provider other than Dex have not been exercised.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Trust boundaries in one page

Read this before you point SuperMgmt at a machine you care about.

1. **The local boundary is the OS user.** The daemon listens on a Unix socket and accepts connections from its own UID only. Anything running as you can drive SuperMgmt, approve its own plans (`security.allow_self_approval` defaults to `true` in local mode) and use the instance SSH identity. Local mode does not defend against malicious software under your user.
2. **The node credential can read all logs in `journal-group` mode.** That mode puts `supermgmt` in `systemd-journal` (or `adm`), so a stolen node credential reads the node's entire system journal, not only selected units. Mediation by the API limits what clients see, not what the credential can read. `broker` mode avoids the group: see [Log modes on a node](#log-modes-on-a-node).
3. **Docker access is root.** The `docker` group is equivalent to root on the node. Setup asks for `docker_access` explicitly, has no default, and shows this warning. Compose deployments need it: see [Apps, GitHub and deployments](#apps-github-and-deployments).
4. **A unit grant is a trust profile, not a proof.** Granting restart on a unit trusts everything that unit executes.
5. **The KEK files are separate from the database and from backup archives and must be backed up separately.** `sm secrets export-key` produces a passphrase-protected copy ([operations.md](operations.md#key-management)).
6. **Setup needs root once.** Afterwards SuperMgmt holds no standing root on the node.
7. **Server mode puts the control plane on the network.** Every request on the HTTPS listener must carry a bearer token; a reverse proxy in front (including Cloudflare) can read that token and the traffic. The admin socket trusts root and the service user on the host.
8. **`curl | bash` trusts the `main` branch.** The review-first path with an out-of-band key does not ([installation.md](installation.md)).

## Threat model summary

| Threat | Main mitigation | Status |
|---|---|---|
| Stolen browser or OIDC session | session TTL (12h default), revocation on logout, no cookies so no CSRF surface, `no-store` and `nosniff` headers, no CORS | implemented in server mode; there is no browser UI yet |
| Compromised MCP client; malicious prompt asking for a privileged action | MCP is its own actor type with no inherited roles; hard approval floor for operational writes; MCP can never approve | implemented; tested with the Go SDK client and a fake authorization server, not with real MCP clients ([MCP](#mcp)) |
| Compromised managed node | least privilege on the node, bounded and sanitized output, timeouts | implemented |
| Malicious repository or PR | closed-schema Compose pipeline, immutable digests, repository Compose refused in production | implemented; tested against a fake GitHub ([Apps, GitHub and deployments](#apps-github-and-deployments)) |
| Forged or replayed GitHub webhook | HMAC signature check, delivery de-duplication, the payload only nudges a re-check | implemented; tested against a fake GitHub |
| SSH MITM or host key change | pinned host key compared byte for byte; a changed key fails the job | implemented |
| Leaked API token | SHA-256-only storage, expiry (at most 365 days), scopes that only narrow, revocation effective on the next request, rate limits | implemented in server mode |
| Another local user reaching the daemon | socket directory 0700, peer UID checked on both ends, `Authorization` header rejected | implemented; refusal of a second user is tested on Linux CI only, on macOS it rests on the same-UID test and a manual check |
| Terminal escape sequences in remote logs | ANSI, C0 and C1 controls stripped and UTF-8 repaired at the transport boundary | implemented |
| Command injection via names or parameters | closed command catalog, per-parameter allowlists, no leading `-`, POSIX quoting, setup content on stdin | implemented |
| SSRF via health URLs or provider endpoints | outbound request filter (`internal/netguard`) | implemented for identity-provider, GitHub and MCP authorization-server endpoints and for control-plane health checks |
| Supply-chain compromise | pinned dependencies, scanning, fuzzing, signed releases | scanning and fuzz seeds run on every change ([automated scanning](../SECURITY.md#automated-security-scanning)); signed pipeline and verifying installer implemented, production key and provenance not yet exercised |
| Tampered installer download | embedded-key signature check of checksums and archive before anything runs | implemented, tamper tests with a test key in CI; `curl \| bash` still trusts `main` |
| Backup theft; control-plane database theft | envelope encryption of secrets; KEKs never in the archive | implemented. The archive itself is not encrypted |

MCP content is untrusted input: a model asking for an action has no more authority than its authenticated identity and policy grant.

## Policy and approvals

### Default-deny policy engine

`internal/policy` evaluates a request in a fixed order: catalog, capability, rule match, deny override, default deny, destructive gate, credential scopes, approval and quorum, then combination across targets and sub-actions.

- No matching allow rule means deny. Any matching deny wins over every allow.
- Destructive actions require an allow rule that explicitly sets `allow_destructive`.
- Credential scopes only narrow what an actor may do.
- MCP identities need approval for operational-or-higher actions as a fixed floor, and `mcp` and `system` identities can never approve or reject.
- Property and table tests assert that adding allow rules never overrides a deny and that adding targets never relaxes a decision.
- The built-in default policy is embedded; a user policy file replaces it entirely, and the engine can diff the two.

### Approvals bound to the plan hash

A plan lists every input that can change what executes, including the `spec_revision` of each configured resource. It is serialized with RFC 8785 canonical JSON and hashed with SHA-256. Observation data, timestamps, random values and secrets never enter the plan.

Approval records are tied to that hash, so any change to an input yields a new hash and earlier approvals do not transfer. Quorum counts distinct approvers, approvals expire, and self-approval is controlled by `security.allow_self_approval`.

When a worker claims the job, `internal/app` recomputes the plan from current state. A changed plan hash or input fails the job with `PLAN_STALE`, an expired plan fails with `PLAN_EXPIRED`, and credentials, policy and quorum are checked again.

## Audit and redaction

### Append-only audit

The `events` table is protected by database triggers that reject `UPDATE` and `DELETE` (migration `000001_initial.up.sql`). The emitter assigns the event ID and timestamp itself, so callers cannot backdate the trail, and every event carries actor, resource and correlation ID.

Denied actions and unavailable capabilities are audited as well as accepted ones: `internal/app` writes a `policy.<decision>` event with result `denied` for every DENY and CAPABILITY_UNAVAILABLE outcome on plan creation, submission, revalidation and approval decisions.

### Redaction

`internal/audit` defines a `Secret` type that renders as `[REDACTED]` through every formatting, JSON, text and logging path. It also redacts values by sensitive key name (password, token, authorization, cookie, session, private key and similar, matched case-insensitively) and bearer-token patterns. Over-redaction is the intended failure mode, and values under sensitive keys are always masked.

The single exception is a credential reference (`secret://<path>`, `ssh-agent://default`, `file:///<abs-path>`). It stays visible only in a field whose name ends in `_ref` (such as `credential_ref`) and whose whole value matches the reference grammar, because a reference points at a secret and is not one. Plaintext secrets must never reach SQLite, logs, config examples or error messages.

## Configuration, storage and build

- **Strict configuration.** Unknown configuration fields fail validation, credential references are limited to a closed set of schemes, and validation reports every problem with its YAML path. See [configuration.md](configuration.md).
- **Storage.** SQLite runs in WAL mode with `synchronous=FULL` and a single writer.
- **Build.** CI runs `go vet`, `golangci-lint` (including `gosec`), tests with the race detector on Linux and macOS, `govulncheck`, secret scanning, a licence check, fuzz seeds, CodeQL and dependency review. The full list, with what each check covers, is in [SECURITY.md](../SECURITY.md#automated-security-scanning).

## The local daemon and its socket

- The socket directory must be a real directory (no symlink) owned by the daemon user with mode exactly 0700; otherwise the daemon refuses to start. The daemon runs with umask 0177.
- The daemon reads the peer UID of every connection (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS) and closes it on a mismatch or on a lookup error, before reading any byte. The client checks the listener's UID the same way before its first request, so it does not talk to another user's daemon.
- A request with no `Authorization` header is the local human. A request with an MCP client token (`smm_...`) is that MCP client. Any other `Authorization` header, including every other token kind, gets 401 `UNAUTHENTICATED` without being resolved.
- The local human is the `human` identity `local:<uid>`, bound to `admin`.
- Every route maps to exactly one catalog action, enforced by a test. Every POST, PATCH and DELETE needs an `Idempotency-Key`; a key reused with a different request gets 409.
- Two daemons on one database, or two databases on one socket, are refused (exit 2).

## Nodes

### Host keys

- The `host_public_key` stored in the database is the only trust anchor. The check compares the exact key bytes. `ssh.known_hosts_file` is not consulted, and neither are your `~/.ssh/known_hosts` or `ssh_config`.
- First trust is explicit. `sm nodes add` scans the key and shows its SHA256 fingerprint; nothing is trusted until you confirm it (type `yes`, or pass `--fingerprint SHA256:...` verified out of band). The confirmed key is the one stored, so a key that changes between the scan and the first authenticated probe fails with `SSH_HOST_KEY_MISMATCH`.
- A changed host key fails the connection; there is no automatic re-pinning. `sm nodes repin <node>` replaces a pinned key after you confirm the new fingerprint ([operations.md](operations.md#key-management)).
- SSH CA trust is not supported and not scheduled.

### Command execution on nodes

- Commands come only from a closed catalog. Each argument is checked for non-empty valid UTF-8, no NUL and no leading `-`, then against its parameter's allowlist, then quoted for POSIX `sh`. Content that must reach a node (setup files) travels on stdin.
- Reads are bounded by `ssh.command_timeout` and by per-template byte and line limits. Remote output is untrusted: ANSI, C0 and C1 control characters are stripped before anything is stored or rendered.
- Mutating commands are wrapped so that a marker file exists before the command starts and a `.done` file records its exit status. Without the marker directory (created only by `node.setup`) nothing runs.
- Sudo-executed commands equal their sudoers line byte for byte: `sudo -n <systemctl_path> <verb> <unit>`. Unit names must match `^[A-Za-z0-9][A-Za-z0-9@._-]*\.service$`, which excludes every sudoers metacharacter. A unit whose name needs systemd escaping cannot be granted today.

### Unit trust profile

Before a unit gets a sudoers line, and again at every action, SuperMgmt reads the unit's `systemctl show` properties. It requires that the unit file, every drop-in, every executable named in an `Exec*` line, every `EnvironmentFile` and the `WorkingDirectory` are root-owned and not group- or other-writable, as is every parent directory up to `/`.

When an `Exec*` program is an interpreter (`sh`, `bash`, `dash`, `python*`, `perl`, `ruby`, `node`, `php`), its script arguments must satisfy the same rule and inline code (`-c`, `-e`) is refused. Anything that cannot be resolved to a plain path makes the unit ineligible, and the action is refused with `CAPABILITY_UNAVAILABLE` naming the failing path (`internal/runtimes/systemd/trust.go`).

This is a **trust profile, not a proof**. It narrows what an unprivileged user on the node can tamper with. It does not make the unit safe: a restart grant lets SuperMgmt run, as root, whatever that unit executes, so grant it only for units whose code you already trust as root. A file that changes between the check and the action, or an executable that behaves differently when run, is outside what the profile can see.

### Log modes on a node

| Mode | What `supermgmt` gets | Consequence |
|---|---|---|
| `journal-group` (default in the TUI) | membership of `systemd-journal`, or `adm` if the node has no such group | can read the whole system journal of that node |
| `broker` (opt-in, `setup <node> broker`) | no journal group; may run only the root-owned `/usr/local/libexec/supermgmt/unit-logs` through sudo | reads only units listed in `/etc/supermgmt/allowed-units`, at most 10000 lines |

In both modes `journalctl` itself is never granted through sudo. Log lines are bounded and sanitized before display. The mode of a node is the `logs_mode` parameter of its `node.setup` plan; a plan that leaves it out gets `ssh.logs_mode` (`internal/app/plans.go`).

### Docker access

`docker_access` is a required `"true"` or `"false"` parameter of `node.setup`. When true, `supermgmt` joins the `docker` group on the node, which is equivalent to root there: anyone holding the node credential can start a privileged container and read or write the whole host. Without it, Docker capabilities disappear once automated sessions switch to `supermgmt`.

Grant it only on nodes where handing SuperMgmt root is acceptable, and treat any policy rule that allows Docker-level actions on a node as a root grant. The API and policy layer limit what SuperMgmt asks for, not what the credential could do.

### Bootstrap privilege during setup

`node.setup` is a high-risk, approval-gated job that runs as the node's `admin_user`, with your own credential (`ssh-agent://default` by default):

- `admin_user: root`: commands run directly.
- Any other `admin_user`: every privileged command is `sudo -n <exact command>`; SuperMgmt never prompts for a password. If the account is neither root nor able to run passwordless sudo, setup fails before changing anything with `CAPABILITY_UNAVAILABLE` ("admin_user needs root or passwordless sudo for setup").
- The plan shows the bootstrap identity, and the job writes `node.setup.privileged_session` events when the privileged session starts and ends.
- If you grant a temporary `NOPASSWD` rule to make setup possible, **you** must revoke it afterwards. SuperMgmt only needs it again to re-run setup.

### Interactive SSH isolation

`s` in the TUI and `sm ssh` open a shell as `admin_user` (or `--user`) with **your** credential; `d` and `sm docker` run `lazydocker` the same way. The terminal is handed to the system OpenSSH client, but the client builds the command (from connection details the daemon returns) so that nothing on your machine can redirect it (`internal/client/interactive.go`):

- `-F /dev/null`: your `~/.ssh/config` and the system config are not read.
- A temporary `known_hosts` containing only the node's pinned key under `HostKeyAlias=sm-<node id>`, with `UserKnownHostsFile` pointing at it, `GlobalKnownHostsFile=/dev/null`, `StrictHostKeyChecking=yes`, `UpdateHostKeys=no` and `CheckHostIP=no`. The file is removed when the session ends.
- `ProxyCommand=none` (on a [Cloudflare tunnel node](#cloudflare-tunnel-nodes) the client's own `cloudflared access ssh` for the validated hostname), `ProxyJump=none`, `KnownHostsCommand=none`, `ControlMaster=no`, `ControlPath=none`, `PermitLocalCommand=no`.
- No shell is involved: the arguments are validated again on the client and passed as an argv. The remote command is a fixed literal (none for a shell, `lazydocker`, `btop` or `tmux`).

The session is issued and ended through the API, so it is audited with the exit code. What stays yours: the credential `ssh` picks (your agent and OpenSSH's default identity handling), and everything you type in the remote shell. The shell is as privileged as `admin_user`, and SuperMgmt does not restrict or record it. SuperMgmt never installs `lazydocker`; when it is missing the TUI shows where to get it.

### Node enrollment with join tokens

A join token is limited to a number of node slots, lives at most 24 hours, can be limited to source networks, and is stored hashed. It lets a node pin its own host key and receive the instance public key; it grants no sudo, docker or journal access. A stolen token yields at most an unprivileged, read-only node entry pinned to the thief's key.

## Cloudflare tunnel nodes

**Experimental, tested against fakes only.** Setup and use are in [Cloudflare](cloudflare.md#reach-nodes-through-cloudflare-tunnel); this section is the security model.

### Trust boundary

Cloudflare routes the connection and carries the outer stream. It sees connection metadata (hostname, timing, volume) and can deny service. It cannot impersonate a node, because SuperMgmt enforces the pinned SSH host key over the tunnel: a tunnel that reaches a different key fails, and no step repins automatically (`TestTunnelEnforcesThePinnedHostKeyAndReapsTheChild`). The SSH session is encrypted between SuperMgmt and the node's `sshd`; Cloudflare does not hold those keys. Whoever controls the Cloudflare account can change Access policies and DNS for the node hostnames, so the account belongs to your trust base. Passing Access grants neither an SSH login (an authorised key is still required) nor any SuperMgmt privilege.

### Three credentials, split by purpose

| Credential | Lives | Read by | Can do |
|---|---|---|---|
| Cloudflare API token | The secret store, at `cloudflare.api_token_ref` (`secret://cloudflare/api-token` by default) | Tunnel jobs only: setup with `--tunnel`, disable, rotation | Create and delete tunnels, Access applications, policies and service tokens in the whole account, and edit DNS in the zone. Not read when dialling. The store cannot delete it: revoke it in the Cloudflare dashboard after provisioning, and `sm doctor` then warns instead of failing. Rotation and disable need a valid one again |
| Access service token | The secret store, at `cloudflare.access_token_ref`, as `client_id:client_secret`; one per instance | The dialler, at dial time, and the rotation job | Passes the Access Service Auth policy of the instance's node hostnames. It is not an SSH credential |
| Tunnel credential | On the node: `/etc/supermgmt/cloudflared/token`, root, mode 0600. Fetched from Cloudflare inside the setup job | `cloudflared` on the node | Lets that `cloudflared` serve that one tunnel |
| Tunnel credential of an enrollment | The secret store, under the enrollment, from creation until the node is saved, the enrollment expires or it is cancelled; then every version is purged. A backup taken while the enrollment was open still holds it, sealed like every secret in an archive. Shown on the operator's terminal and returned only by the enrollment's token endpoint, to the identity that started the enrollment, never to an MCP client. On the node, the same file as above, written by `sm join --tunnel` from the terminal or standard input | The operator, once, to paste it on the node | The same as the tunnel credential |

A node added through the tunnel ([enrollment](cloudflare.md#add-a-node-that-has-no-inbound-path)) is bound to SuperMgmt only by the operator comparing the host key fingerprint the node printed with the one SuperMgmt scanned through the tunnel, the same trust `sm nodes add` asks for when it scans directly. The confirmation names that exact key. The proof and the saved node use it and the SSH identity taken when the enrollment started, so a key presented later, or a rotated identity, cannot slip in. The line run on the node carries no secret, and `sm join --tunnel` refuses the credential as an argument.

None of them appears in plans, job payloads, events, logs, views, errors, child arguments, units or the node's journal by design. What the tests establish: the tunnel credential travels only as standard input of one sensitive staging command and in no error or formatted parameter (`TestTheTokenReachesTheNodeOnlyAsSensitiveStdinOfTheTokenStagingStep`, `TestTheTokenNeverReachesAnErrorOrAFormattedParameter`); `cloudflared`'s stderr is bounded and scrubbed before it reaches an error (`TestChildDyingDuringHandshakeIsReapedAndItsStderrIsScrubbed`, `TestSanitizeDiagnosticBoundsLengthAndMasksSecrets`); backup archives keep the records and never plaintext credentials (`TestArchiveKeepsTunnelRecordsAndNeverTheirPlaintextCredentials`). Not yet established: that `cloudflared` itself never logs the tunnel credential on the node (a manual check) and a scan of every artefact with a real account.

### Two `cloudflared` hazards and how they are neutralised

- **Debug logging dumps request headers, service token secret included.** This is read from `cloudflared`'s source, not observed. SuperMgmt never starts it with debug logging or a log file, and gives the child a minimal environment: exactly `TUNNEL_SERVICE_TOKEN_ID`, `TUNNEL_SERVICE_TOKEN_SECRET` and `HOME` (a private empty directory), so no ambient log, proxy or tunnel variable is inherited (`TestTunnelSpawnsCloudflaredWithExactArgvAndEnvironment`). The secret is in the child's environment, not its arguments.
- **`cloudflared` opens a browser when Access answers with a login page, and has no flag to turn that off.** Two layers: the child has no `PATH` and is started by absolute path, so the browser command cannot be found; and before spawning, the daemon sends its own HTTPS request with the service-token headers to the tunnel hostname and refuses to dial when Access redirects to its login (`TestTunnelRefusesWithoutSpawningWhenAccessRedirectsToLogin`, `TestTunnelDoesNotRefuseOtherRedirects`). The preflight uses the same rule as `cloudflared` (a 302 whose `Location` path starts with `/cdn-cgi/access/login`) and also refuses 401 and 403 (`TestPreflightRefusesWhatCloudflaredWouldTurnIntoALoginFlow`). The error is "Cloudflare Access did not admit the service token". How Access really answers valid and invalid tokens is a manual check.

The `cloudflared` path is never searched through `PATH`, on the daemon or on the client: fixed directories only. On the daemon host the binary is also refused when, after resolving symlinks, it is not a regular file, is writable by group or others, or is not owned by root or the daemon's user, and the same test applies to each directory above it (`TestCloudflaredThatOthersCanReplaceIsNotTrusted`); the child's `HOME` is a private 0700 directory owned by the daemon user (`TestAConfiguredHomeDirectoryIsTightenedToPrivate`). A missing binary is a clear error, not a fallback (`TestCloudflaredPathMustBeAbsoluteAndExecutable`).

### Ownership and conflicts

Every object SuperMgmt creates in Cloudflare carries its instance ID and the node ID in its name (and a comment on the DNS record). After a lost response it looks the object up by name and adopts it only when its own record shows that phase started and the object was created then; anything else with the expected name is a conflict that stops the job (`TestAnObjectWithTheExpectedNameButAnotherOwnerIsAConflictNeverAdopted`). The hostname is created last on setup and removed first on disable, so it is never routable without its Access application.

### Interactive sessions

`sm ssh` and the TUI's `s` on a tunnel node set `ProxyCommand` to the client's own `cloudflared access ssh` for the validated hostname, so the operator's own Access login applies and no SuperMgmt token is handed over. Every other isolation option stays; unknown transports and hostile hostnames or paths are refused before ssh starts (`TestInteractiveCommandCloudflareOnlyChangesTheProxyCommand`, `TestInteractiveCommandCloudflareRefusesHostileHostnamesAndUnknownTransports`).

### Privileged steps on the node

Tunnel setup, run as the admin account, adds an apt source, a keyring whose fingerprint is pinned in the build, the `cloudflared` package, a token file and its own systemd unit. The keyring file is SuperMgmt's own, `/etc/apt/keyrings/supermgmt-cloudflare.gpg`: a key that Cloudflare's guide placed elsewhere is never read, replaced or removed (`TestSetupNeverTouchesTheSharedCloudflareKeyring`), and a `cloudflared` installed from that guide is used and never removed by disable (`TestAnInstalledCloudflaredWithTheGuidesSourceIsUsedAndLeftAlone`). The unit is sandboxed: a dynamic user, an empty capability set, `NoNewPrivileges`, a read-only system (`ProtectSystem=strict`), a private `/tmp` and `/dev`, only IP and Unix sockets, and the tunnel credential delivered with `LoadCredential` so the process cannot read the root-only file (`TestTheTunnelUnitIsSandboxed`). That the unit starts under these directives on a real host is not verified. Setup aborts if the installed key differs from the pinned bytes. The paths are allowlisted in the command templates, and removal touches only what setup installed (`TestRemoveTunnelRemovesOnlyWhatSetupInstalled`). Whether the pinned key matches Cloudflare's key today is a manual check.

## The dedicated `supermgmt` user and how to remove it

`node.setup` creates exactly this on a node and nothing else. No SuperMgmt binary or daemon is installed there.

| What | Where | Notes |
|---|---|---|
| User and group `supermgmt` | home `/var/lib/supermgmt`, shell `/bin/sh` | system account, no password, not locked (so key login works) |
| Authorized key | `/var/lib/supermgmt/.ssh/authorized_keys` (0600) | one line: `restrict <instance key> supermgmt@<instance id>`; no pty, no forwarding |
| Marker directory | `/var/lib/supermgmt/markers` (0700) | completion evidence for mutating commands |
| Sudoers drop-in | `/etc/sudoers.d/supermgmt` (0440, root) | one line per granted unit and verb: `supermgmt ALL=(root) NOPASSWD: <systemctl> <verb> <unit>`; checked with `visudo -cf` |
| Group membership | `systemd-journal` or `adm`, in `journal-group` mode; `docker` only if `docker_access` is true | see [Log modes on a node](#log-modes-on-a-node) and [Docker access](#docker-access) |
| tmpfiles entry | `/etc/tmpfiles.d/supermgmt.conf` | creates `/run/supermgmt/locks` |
| Log broker (broker mode only) | `/usr/local/libexec/supermgmt/unit-logs`, `/etc/supermgmt/allowed-units` | root-owned |

An existing `supermgmt` account that does not match is never taken over: setup fails with `CONFLICT`. Setup re-runs are idempotent.

**There is no automated teardown.** To remove SuperMgmt's footprint from a node, as root:

1. In SuperMgmt, retire the node (`sm nodes remove <node>`; its history is kept). Do this first, or the node will start failing probes.
2. Delete `/etc/sudoers.d/supermgmt`.
3. In broker mode, delete `/usr/local/libexec/supermgmt/unit-logs` and `/etc/supermgmt/allowed-units`.
4. Delete `/etc/tmpfiles.d/supermgmt.conf` and, if present, `/run/supermgmt`.
5. End the user's sessions, then `userdel -r supermgmt`. This removes the account, its group, `.ssh/authorized_keys` and `markers/`. Check that `/var/lib/supermgmt` is gone.
6. Revoke any temporary `NOPASSWD` rule you created for the bootstrap.

Steps 2 to 6 are derived from the list above. Only `userdel -r supermgmt` is exercised by the test fixtures (as cleanup); the sequence as a whole has not been tested.

## Secrets and keys

### Secrets and the instance SSH identity

At first start the daemon generates one Ed25519 key, the **instance SSH identity**. It stores the private half in the `secrets` table inside an AES-256-GCM envelope: a fresh data-encryption key per secret version, wrapped by a key-encryption key (KEK). Nodes authenticate `supermgmt` with this key; its public half is printed by `sm ssh-key show` and authorized on a node by `node.setup`.

- **KEK files.** KEKs live in `security.keys_dir` (default `<instance.data_dir>/secrets/keys`) as `<kek_id>.key`: 32 random bytes, mode 0600, a regular file owned by the daemon user, opened without following symlinks. The directory must be mode 0700. Wrong permissions, a symlink or a wrong owner refuse to start. `*.pending` files are ignored.
- **The database does not contain the KEK.** A copy of the database alone cannot decrypt the identity. Because the default `keys_dir` sits inside the data directory, copying the whole data directory copies both: keep database backups and KEK backups in different places, and put the KEK copy somewhere with its own access control.
- **Back the KEK files up separately.** `sm secrets export-key` and `import-key` make and restore a passphrase-protected copy ([operations.md](operations.md#key-management)). If a KEK file is lost, the daemon fails at start (exit 4) and names the missing KEK ids, and the encrypted identity cannot be recovered. The remedy is to generate a new identity and re-run `node.setup` on every node so they authorize the new key. No command performs that reset: expect to start from a fresh data directory.
- **Plaintext.** The private key is decrypted into memory on first use and cached as a signer; buffers are zeroed best effort. It does not appear in logs, events, API responses, errors or plans, and the events about it carry the fingerprint only. Tests scan the database file, its WAL and the data directory for the key bytes. The KEK files are the one place on disk where key material is not encrypted (by design of the envelope).
- **Rotation.** A node keeps working with the key version pinned at setup. `sm ssh-key rotate` creates a new version, and each node needs `sm nodes setup` re-run to authorize it.

### Key management

Rotation, retirement, export and import of master keys, secret import, and instance SSH-key rotation are the high-risk `secret.write` action, so each is a job that waits for approval. Plans carry no secret value or passphrase: an imported value is sealed under the active KEK as a staged version when requested, and approval activates it.

Key export is a passphrase-protected `SMKEY1` file (scrypt, AES-256-GCM) with a passphrase of at least 12 characters read from a terminal or stdin. It is served on the local-mode socket only and, on a server, by `--offline` with the service stopped. Import is offline only and installs a `.key.pending` file that the daemon never loads until a database or restore validates it. See [operations.md](operations.md#key-management).

A single operator on a server cannot approve their own key operations unless `security.allow_self_approval` is turned on.

### Backup and restore

Archives are not encrypted and never contain a KEK. Restore is offline:

1. It stages and checks the archive first: safe extraction, checksums, integrity check, key check.
2. It neutralizes the staged database: undispatched jobs fail, running jobs become interrupted, approvals, sessions and tokens are revoked, codes are invalidated.
3. It moves files under a write-ahead journal with recovery at every start.

The restored server starts in a hold where nearly every write is refused until `sm admin restore-complete`. Crash injection at every journal step is tested in CI with a build tag that release binaries do not carry (a test asserts it). Not tested on a real VM.

## Server mode

### HTTPS transport, credentials and sessions

- `sm server` serves the same handlers as the local socket over HTTPS. TLS is either terminated by the daemon (`direct`, TLS 1.2 or newer, certificate re-read on `SIGHUP`) or by a reverse proxy (`proxy`); no ACME. In proxy mode forwarding headers are believed only from `server.trusted_proxies`, a forwarded proto other than `https` is a 400, and a loopback peer gets no special trust. Plain HTTP on a non-loopback address is refused by config validation.
- Credentials are bearer tokens `sm<kind>_<base64url(32 random bytes)>`: `s` session, `t` API token, `b` bootstrap code, `j` join token. Only the SHA-256 is stored, in a unique column; nothing is cached, so a revocation takes effect on the next request. A token of the wrong kind for an endpoint is refused before lookup. The HTTPS listener accepts `Authorization: Bearer` only; the Unix socket still refuses it.
- API tokens have a mandatory expiry of at most 365 days, scopes that can only narrow the creator's permissions, and a unique name per identity. Sessions last `security.session_ttl`.
- No cookies, so no CSRF surface. Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; no CORS headers are sent, so browsers refuse cross-origin calls.
- Token buckets: 10 per minute with a burst of 5 per remote address on `/auth/*` and `/enroll`; 60 per minute with a burst of 20 per identity on writes. Fixed constants; 429 with `Retry-After`.
- Event stream (`GET /events/stream`): at most 4 per identity, a heartbeat every 15 s, and the credential and `event.read` are re-checked every 30 s and on revocation events.

### Admin socket

`server.admin_socket` has mode 0660 and is owned by the service user. The server checks the peer UID (root or the service user; a lookup error refuses); the `sm admin` client checks that whoever answered owns the socket file before sending anything. It serves exactly `bootstrap-code`, `grant`, `restore-complete` and read-only `doctor`, and never key management.

The first admin comes from a one-time bootstrap code: at least 128 bits, stored hashed, valid for `auth.bootstrap.code_ttl`, and a new code invalidates the old one. Once an admin exists the code is refused, except during a restore hold. In server mode the daemon never creates a `local:<uid>` admin.

### OIDC

The server is the OIDC client. It uses Authorization Code with PKCE S256 over a loopback redirect, or the device grant.

- Discovery must return the exact configured issuer and `https` endpoints on the issuer origin or an origin in `auth.oidc.allowed_endpoint_origins`; the userinfo endpoint is never called.
- ID tokens are verified with `go-oidc` (RS256, ES256 or EdDSA; issuer, audience, `azp`, expiry, nonce, verified email, optional domain list); a `jti` is recorded to refuse replays.
- Login state is held in memory, so a restart invalidates logins in progress, never sessions. The device code never leaves the server, polls are rate-shaped (`slow_down`), and completion is single use.

Exercised only against Dex, by hand; other providers are untested.

#### OIDC and the device-flow client secret

With the device grant, **Dex echoes the client secret into the verification URL it shows in the browser**, so the secret of the configured client ends up in the browser address bar and history of the person signing in. Observed with `ghcr.io/dexidp/dex:v2.45.1`; not observed with other providers.

- SuperMgmt has one OIDC client (`auth.oidc.client_id` and `client_secret_ref`) and sends its secret to the device endpoint as a form field because Dex ignores HTTP Basic there. **There is no separate device-flow client key**, so the secret cannot be kept out of that URL today.
- Recommended: use the loopback flow (`sm login --callback-port N`) and do not use `sm login --device` against Dex unless you accept that exposure. A public client for the device flow (no secret to leak) is the intended remedy, but it needs a new configuration key and a specification change; it is not built.
- If you must use the device flow with Dex, register a client used by nothing else and treat its secret as exposed to the people who sign in; rotate it if a browser profile is shared.

### Client credential storage

`sm login` stores the session or API token in the macOS keychain (through `security -i` with the token on stdin), the Secret Service (`secret-tool store`, token on stdin), or a mode-0600 file when neither exists. A token is never an argument or an environment variable, and tokens are checked against the alphabet SuperMgmt issues before they reach the OS tools.

Unit-tested with fakes; the real keychain and `secret-tool` are manual checks. Whether `security -i` on current macOS keeps a token on stdin out of the process list is also a manual check.

### Outbound filter

`internal/netguard` guards every outbound request the control plane makes:

- It resolves a name once and normalizes IPv4-mapped, IPv4-compatible and NAT64 forms.
- It refuses cloud-metadata, loopback, link-local, multicast and reserved ranges for every caller, and refuses private and special ranges unless the caller's allowlist names them.
- It then dials the vetted address while TLS verifies the original hostname.
- Redirects are off by default, bodies are capped, and ambient proxy variables are never read (`outbound.proxy` is the only proxy).

Callers: the identity-provider client (private ranges allowed), the GitHub connector (exact `api_url` origin only, redirects pinned to that origin), control-plane health checks (only `health.allowed_private_cidrs`) and the remote-MCP authorization-server endpoints (see [Remote MCP as an OAuth protected resource](#remote-mcp-as-an-oauth-protected-resource)). 6to4 and Teredo are not unwrapped.

## Releases and the installer

Releases are built from `v*` tags in a protected environment, with OpenSSH signatures on `checksums.txt`, `install.sh`, `join.sh` and the channel files, SPDX SBOMs, and build provenance on tag builds.

`install.sh` verifies the verifier first, checks signed channel freshness (30-day maximum validity), a version-and-channel-bound checksum list and the archive hash, and only then runs `sm`. A revocation list is embedded. See [installation.md](installation.md).

The production public key is embedded in `install.sh` and `scripts/join.sh`, and its fingerprint is published in [SECURITY.md](../SECURITY.md). **Production signing and provenance are unverified** until a person checks the first release run on a real tag.

## Proxmox and the appliance installer

Verified against fakes only; the real-host checks are in the [Proxmox manual checklist](manual-checks/m3-real-pve.md).

- **Per-install identities.** The installer creates a Proxmox user, token and roles whose names carry a random install id. It grants the token only audit privileges (and, unless `SUPERMGMT_PVE_POWER=0`, `VM.PowerMgmt` on `/vms`), and never adopts, changes or deletes a resource it did not create. Nothing for snapshots, backups, console or deletion is granted. Anyone who can read the provider's token from the secret store can power guests on that cluster; the token is sealed under the instance master key like any secret.
- **Token transfer.** The token is created on the host, staged in a 0600 file in a 0700 directory, pushed to a tmpfs inside the container (verified to be tmpfs, with the service account present, before the token exists), imported offline and deleted at both ends. It is never in an argument, an environment variable, stdout, stderr, the journal or a log; those commands run in a capture mode that returns sanitized errors.
- **Proxmox TLS.** `verify_tls` must be `true` (a `false` is a configuration error). The CA is `/etc/pve/pve-root-ca.pem` or `SUPERMGMT_PVE_CA_FILE`, and the chain the endpoint actually serves is verified from inside the container before any token exists.
- **Container shape.** Unprivileged, no nesting or keyctl, no mounts, no raw `lxc.*` keys, read back after creation. A privileged container is never created.
- **Host commands.** Proxmox tools run by absolute path, with a clean environment, never through a shell; storage, bridge, hostname, VMID and paths are validated first.
- **Appliance TLS.** A self-signed CA generated in the container; clients pin it with `--ca-file`. No renewal flow (CA 10 years, leaf 5 years).
- **Power actions** are jobs that are never retried; `stop` is high risk and needs approval. A power request that may have reached Proxmox is settled from the task it created, never by sending it again ([providers.md](providers.md#interrupted-power-jobs-and-task-correlation)).
- **Upgrade and uninstall** keep the previous binary and never delete data without a separate typed confirmation; the pre-upgrade archive is unencrypted like every backup.

- **Proxmox through a node** (`via_node`):
  - **No forwarding.** The dedicated key stays `restrict`. The API is reached by one argument-free command (`socat STDIO TCP:127.0.0.1:8006`, with the `socat` path limited to the system binary directories), so no API, configuration or plan can point it at another destination.
  - **Trust.** The PVE CA is read through the connection whose host key is pinned, and every handshake verifies that CA and the recorded name before the token is sent.
  - **The token.** It is created by a setup command whose output is secret. The executor, the setup stepper and every error drop that output. A lost token is deleted and created again, never read back. Audit records only its ID.
  - **The relay command.** It is the one command the dedicated account gains. It reaches only the API, whose authority is already the token's.

Not verified on a real Proxmox host: the privilege model, the permission propagation rules, the task API shapes and the installer's host commands.

## Apps, GitHub and deployments

Verified against a fake GitHub, a virtual Sigstore and a Docker fixture node only; nothing was run against real GitHub, GHCR or Sigstore. The real-GitHub checks are in the [GitHub manual checklist](manual-checks/m4-real-github.md) and are **deferred**. Operating details: [deployments.md](deployments.md).

### Docker access is root-equivalent, and deployments use it

A deployment runs `docker compose up` as the `supermgmt` user, which is in the `docker` group. Anyone who can make SuperMgmt run a Compose file can therefore get root on that node. The controls below reduce what SuperMgmt asks for; they do not change what the credential could do.

- Compose files go through a closed pipeline: two allowlist passes around the pinned `compose-go` loader. `privileged`, bind mounts, host networking, devices and every key not on the allowlist are rejected (`COMPOSE_REJECTED`). `cap_add`, `sysctls`, `extra_hosts` and `shm_size` pass only as exact, admin-approved per-service exceptions, with a fixed capability set. Tests: `TestCheckRaw_*`, `TestCheckModel_RejectsDeniedServiceKeys`, `TestExceptions_*`, e2e `TestM4_RepositoryComposePrivilegedRejected`.
- The control plane freezes the model and the node's `docker compose config` must match it (**5.5.1** is the only Compose CLI accepted; the equivalence corpus was run for that version only).
- **Repository Compose is refused in production.** A Compose file read from the repository is code from a repository whose CI passed; production targets take their Compose text only from the control plane (`TestAppsUpdate_RefusesARepositorySourceWhileAProductionTargetExists`).
- Published ports must bind `127.0.0.1`, `::1` or an address in the target's `allowed_bind_addresses`. Preflight refuses a project, volume or network that lacks `dev.supermgmt.owner=<app_target_id>` and ports held by something else.
- `deploy_root` is owned by the `supermgmt` user (0750) so the dedicated user can create project directories; it is not root-owned. It must be outside `/var/lib/supermgmt`, and a symlink there is refused.
- Nothing is pulled by tag: the node pulls `<repository>@<digest>`, and a digest must be bound to the commit by an attestation, verified Actions claims, or the app's pinned list.

### GitHub connector

- **Token scope.** The provider token is read-only. It is attached only to requests whose origin equals `api_url`; a redirect to any other origin, scheme or port is refused before a request is made, at most three hops (`TestRedirect_OriginPinned`, `TestClient_TokenNeverOffOrigin`, `TestTokenNeverAppearsInErrors`). File contents are read through the JSON contents API, so no content host is contacted. How real GitHub redirects is **not verified**.
- **Actions OIDC.** Tokens are verified against the Actions JWKS (RS256, issuer, audience, age of at most 5 minutes, `jti` accepted once, restricted to the claims of the app's CI policy; pull-request and fork-style events never match). Tests: `TestOIDC_*`, `TestMatchClaims`. The token proves who asks, not that tests passed: SuperMgmt checks the required checks itself. The automation identity has no role until an admin grants one, and its credentials carry only `deployment.create` and `deployment.read`.
- **No environment claim.** No environment requires the token's `environment` claim, because the specification defines no field for it. An Actions job in any environment of the configured repository, workflow and branch that is entitled by the role you grant can request a deployment. Use `approvals_required` on production to add a human.
- **Webhooks.** `POST /api/v1/github/webhook` is served on the HTTPS listener only (not on the local socket). It is exempt from bearer tokens and acts only after an HMAC-SHA256 check of the raw body (constant time). Bodies over 1 MiB are refused; deliveries are de-duplicated by `X-GitHub-Delivery`; requests are rate-limited per client; the payload only nudges a re-check, so a forged or replayed delivery cannot approve anything (`TestWebhookForgedDeliveriesAreRefusedAndActOnNothing`, `TestWebhookReplayedDeliveryIsAcknowledgedAndNotReevaluated`, `TestWebhookOversizeBodyIsRefused`, `TestWebhookIsRateLimitedPerClient`, `TestTheWebhookIsNotServedOnTheLocalSocket`).
- **Attestations.** Verified with `sigstore-go` against the Sigstore public-good and GitHub trusted roots, refreshed through TUF via the outbound filter with the last good copy cached; a stale or unreachable root fails closed, never "unverified" (`internal/providers/github/trustroot.go`). **The GitHub TUF trust anchor (version 1 `root.json` of `tuf-repo.github.com`) was fetched once by hand on 2026-10-12 and has not been independently verified**; it is on the manual checklist. The real TUF refresh walk is untested (tests stub the fetch), and attestations were verified only against a virtual Sigstore.
- **Provenance requirement.** `require_provenance: true` on an environment accepts only an attestation for the deployed service.

### Approvals, recovery and secrets in deployments

- App, target and GitHub-provider writes go through the approval path; an approved write is validated again and applied exactly as planned (`TestApplyApproved_AppComposeEditProduction`, `TestApplyApproved_GitHubProvider`). A deployment's plan hash binds the frozen Compose model, digests, secret versions, health and policy snapshots, so an approval cannot be reused for different content (`TestRevalidateDeploy_StaleInputs`).
- A job interrupted while changing a node is never re-run blind. Recovery after a partial update restores only the plan's frozen rollback target, as the `system` actor, without asking the requester's credential or quorum again (`TestClaimRecovery_StalePlanRevokedRequesterLostQuorum`). That is intentional: the recovery target was approved with the plan.
- Secret values reach the node over stdin, are written to `secrets/<service>.env` on the node, are compared there only as hashes, and are never in plans, API views, events, logs or control-plane backups (`TestM4_SecretNeverOnControlPlane`, `TestFixtures_EnvHashResolvedPrecedenceAndTamper`). The end-to-end scan does not cover the node and CLI stdout. Old secret versions are kept encrypted so rollbacks can restore them; there is no deletion API yet.
- Pre-deploy database dumps are written on the node under `/var/lib/supermgmt/db-backups` (0700) and are not encrypted.

## MCP

Verified with the official Go SDK client, hand-written raw JSON-RPC goldens and a fake authorization server. **Not verified with any real MCP client or real authorization server**; those checks are in the [MCP manual checklist](manual-checks/m5-real-mcp-clients.md) and are deferred. The operator guide, [mcp.md](mcp.md), names the test behind each claim.

### Identity, tokens and registration

- An MCP client is an identity of type `mcp` with no role bindings, even when an admin registered it. The built-in policy grants it only `*.read` and `plan.create`; `service.logs` and `node.connect` are not granted.
- Registration (`mcp_client.register`) is high risk and goes through approval under the normal floors. The token (`smm_...`, 32 random bytes, only its SHA-256 stored) is issued once, only to the requester, only while the client waits for it and within 24 hours of the approval; expiry is mandatory (default 90 days, at most 365).
- `sm mcp clients add` checks the destination (a 0600 file created exclusively, or the native keychain with no file fallback) before issuing, and never prints the token. `smm_` tokens work on the local socket only and are refused on HTTPS; with `mcp.enabled: false` the daemon refuses them.
- Deleting a client revokes its token and every OAuth token seen for it, disables the identity and removes its role bindings; rows are kept. Restore revokes all MCP and OAuth tokens. A credential that is gone by the time a queued job is claimed fails the job.
- A remote client is registered by hand as the triple (issuer, subject, client_id). Re-registering a deleted triple reuses the identity with no roles, and tokens issued before the registration (by `iat`) stay refused.

### What MCP can never do

These rules are enforced in the application layer before policy. They hold for the MCP tools, for raw API calls with the MCP token and for the in-process path of remote MCP, whatever a custom policy grants and whatever `mcp.write_tools_enabled` says. An MCP identity can never:

- approve or reject a job;
- perform a credential-issuing action (API tokens, MCP tokens, enrollment), register or delete MCP clients, or write identities or role bindings (`MCP_ACTION_FORBIDDEN`);
- open an interactive node session (`node.connect`) or resolve an interrupted job (`job.resolve`).

An operational-or-higher write by an MCP identity always needs approval, and approval is bound to the exact plan hash.

### Writes are off by default

With `mcp.write_tools_enabled: false` (the default) the write tools are not registered and every non-query action by an MCP identity is denied `MCP_WRITES_DISABLED`, including deployment admission, before any row, CI watch or provider call. Plans can still be created and carry the denial as their verdict.

### Remote MCP as an OAuth protected resource

- Server mode only, off by default. SuperMgmt validates tokens and never issues them. Access tokens are accepted at `/mcp` only and never on `/api/v1`; tool calls reach the API in process as the admitted client, and no header can choose that caller.
- JWT access tokens must be RFC 9068 `at+jwt` with matching `iss`, `aud` (exactly `<public_url origin>/mcp`), `exp`, `iat`, `client_id` and every required scope; ID-token shapes, `alg: none`, HMAC and tokens with `nonce` are refused. Introspection (RFC 7662) is authenticated with a `secret://` client credential and never cached.
- Every `/mcp` and metadata request first draws on the per-address limiter, before any token parsing, so bad-token floods cannot drive JWKS or introspection calls.
- Stateless HTTP, protocol versions `2026-07-28`, `2025-11-25`, `2025-06-18`, an `Origin` check against `server.public_url`.
- JWKS and introspection calls use the outbound filter as provider endpoints. Loopback, link-local and metadata ranges are refused; **private non-loopback hosts are allowed**, as for OIDC.
- Known deviation: root-path metadata discovery does not match RFC 9728 section 3.3 for strict clients; the `401` challenge names the correct URL.

### Output shown to the model

Tool results are allowlisted views. Text that came from remote systems (log lines, service metadata, event data, deployment step errors) is sanitized, bounded, scrubbed and marked `untrusted_remote_output`.

**The scrubbing is pattern-based:** Bearer/Basic credentials, PEM keys, SuperMgmt tokens, JWT-shaped values and values under secret-looking keys are removed, independent of `security.redact_command_output`. An unknown secret under a harmless name is not detected and reaches the model. See [mcp.md](mcp.md#the-redaction-boundary).

## Planned controls

Not implemented; listed so nothing is mistaken for shipped.

- SSH CA trust and per-node keys (not scheduled).
- Fuzz targets for the parsers that have none yet: the fuzz inventory lists them as gaps.

## Accepted limitations

- Local mode does not protect against malicious code running as the same OS user.
- `journal-group` logs mode exposes the node's whole journal to the node credential; `docker_access` exposes root on the node; a unit grant trusts the unit's code.
- The KEK files are not backed up by SuperMgmt. `export-key` exists, but if a key is lost without an export the data it protected is gone and the remedy is a fresh data directory (a new identity and a new setup on every node).
- Backup archives are not encrypted.
- Dex puts the OIDC client secret in the device-flow verification URL (see [OIDC and the device-flow client secret](#oidc-and-the-device-flow-client-secret)); no separate device client is configurable.
- Only Dex has been tested as an identity provider.
- A reverse proxy or Cloudflare in front of the server terminates TLS and can read bearer tokens. SuperMgmt consumes no Cloudflare assertion ([cloudflare.md](cloudflare.md)).
- With a single operator, key operations need `security.allow_self_approval: true` or a second identity.
- Refusal of another local user on the socket is tested on Linux CI only; on macOS it relies on the same-UID test and a manual check.
- Real terminal emulators are not automated; restoring the terminal after an interactive session is covered by a pseudo-terminal test and the [interactive-session manual checklist](manual-checks/m1-handoff.md).
- Node setup is verified in CI on Debian only. Other distributions are an assumption.
- The `curl | bash` installer path trusts the repository's `main` branch; the review-first path with an out-of-band key avoids that. The installer requires OpenSSH 8.2 or newer (`valid-after` in `allowed_signers`).
- No stable release exists yet: the default `stable` channel of `install.sh` has nothing to download, and the installer has not been verified on a clean machine.
- Deployments need a root-equivalent `docker` group; a Compose file that passes the allowlist can still run any image whose digest was bound.
- Production Compose content comes only from the control plane; a repository Compose source is refused there. No exception mechanism exists.
- Actions OIDC tokens are not required to carry an `environment` claim.
- The GitHub TUF trust anchor is not independently verified; real attestations, real Actions tokens, redirect behavior and GHCR pulls are unverified.
- Health check bounds (timeout 30s, interval 1m, 60 attempts) and the Compose CLI pin (5.5.1) are implementation choices, not specification text.
- Old deployment directories are garbage-collected after a success (newest 5 kept, never the current one, a known-good or the rollback target); a GC failure only emits `deployment.gc_failed`.
- MCP: redaction of remote text is pattern-based and unknown secrets are not detected; no real MCP client or authorization server has been tested; root-path OAuth metadata discovery deviates from RFC 9728 section 3.3; JWT access tokens must be `at+jwt` (otherwise use introspection); remote MCP does not support a path-prefixed reverse proxy.
- Cloudflare tunnel nodes: the API token has account-wide tunnel and Access edit rights while it exists, and since rotation needs it, the one-year service token cannot be rotated without creating an account-wide token again; a node whose direct path is closed depends on Cloudflare's availability; the permission labels, the pinned package key and the absence of the tunnel credential from `cloudflared`'s own logs are unverified until the [real-account checklist](manual-checks/cloudflare-tunnel.md) passes.
- No independent security audit has been performed.

## References

- Specification: [SUPERMGMT-SPEC.md](spec/SUPERMGMT-SPEC.md), sections 30 (threat model), 11 (policy and approvals), 2.1.1 (local trust boundary), 12 and 16 (nodes), 21.1 (outbound requests), 3.2 (installer trust).
- Policy, plans and storage: [ADR-0001](adr/0001-sqlite-driver.md), [ADR-0003](adr/0003-aes-gcm-envelope.md).
- Local daemon and nodes: [ADR-0009](adr/0009-node-provisioning.md), [ADR-0014](adr/0014-local-api-and-daemon-lifecycle.md), [ADR-0015](adr/0015-ssh-transport-and-command-templates.md), [ADR-0016](adr/0016-m1-secrets-slice-and-ssh-identity.md).
- Server mode, keys, backup and releases: [ADR-0017](adr/0017-server-transport-credentials-sessions.md), [ADR-0018](adr/0018-oidc-adapter.md), [ADR-0019](adr/0019-release-pipeline-and-installer.md), [ADR-0020](adr/0020-backup-format-and-offline-restore.md), [ADR-0021](adr/0021-key-and-identity-management.md), [ADR-0022](adr/0022-join-enrollment.md).
- Proxmox: [ADR-0023](adr/0023-pve-identity-privileges-compatibility.md).
- Deployments: [ADR-0006](adr/0006-pinned-compose-go-and-cli-equivalence.md), [ADR-0012](adr/0012-route-metadata.md), [ADR-0029](adr/0029-deployment-engine.md).
- Cloudflare tunnel nodes: [ADR-0037](adr/0037-cloudflare-tunnel-transport.md).
- MCP: [ADR-0031](adr/0031-mcp-server-sdk-transports-tools.md), [ADR-0032](adr/0032-mcp-clients-tokens-identity.md), [ADR-0033](adr/0033-remote-mcp-oauth-protected-resource.md).
- Manual checklists for what CI cannot run: [interactive sessions](manual-checks/m1-handoff.md), [server mode](manual-checks/m2-handoff.md), [real Proxmox](manual-checks/m3-real-pve.md), [real GitHub](manual-checks/m4-real-github.md), [real MCP clients](manual-checks/m5-real-mcp-clients.md), [Cloudflare Tunnel](manual-checks/cloudflare-tunnel.md).
