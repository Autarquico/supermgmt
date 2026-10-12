# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a first release. Nothing has been released yet.

## [Unreleased]

Milestones M0 (repository and core), M1 (local daemon, SSH, TUI), M2 (server, auth, releases) and M3 (Proxmox and the appliance installer). Pre-alpha: nothing is released.

### Added in M3

- Proxmox VE provider (`internal/providers/proxmox`): HTTPS API client with a pinned CA (`ca_file`; `verify_tls: false` is a configuration error), UPID parsing, task listing and correlation. Supported: Proxmox VE 9.x, amd64 (ADR-0023).
- Discovery (ADR-0024): cluster nodes, VMs and containers as discovered nodes with configured CPU/RAM/disk and metrics, storages as provider observations, `absent` versus `inaccessible` from the token's effective permissions, capability `proxmox.vm.power` per guest. `POST /api/v1/providers/{id}/refresh` (`provider.read`, rate limited), `sm providers list|get|refresh|check`, `sm nodes list --tree`, doctor `providers` check, TUI tree and `refresh proxmox`.
- Power actions (ADR-0025): `sm nodes power <node> start|shutdown|reboot|stop [--wait]` and the TUI palette. Non-retryable jobs; exactly one POST per request; task id persisted before polling; interrupted jobs are settled by task correlation across the cluster, and a task-tracked job is quiescent only on stored proof that its task stopped (`job.resolve --assume-quiescent` is the audited override). `stop` is high risk. Migration `000004` (`operation_intents.external_ref`).
- Per-install Proxmox identities: user `sm-<id>@pve`, token with privilege separation, roles `SMAudit-<id>` and `SMPower-<id>` (`SUPERMGMT_PVE_POWER=0` omits the latter).
- `sm install proxmox-lxc` (ADR-0026): unprivileged LXC, self-signed appliance TLS (`sm install server --tls self-signed --no-start`, `sm server init`), the Proxmox chain verified from inside the container before any token exists, token transfer through tmpfs and `sm secrets import --offline --from-file --delete-source`, write-ahead journal with commit protocol and crash recovery, variables `SUPERMGMT_VMID|HOSTNAME|STORAGE|TEMPLATE_STORAGE|BRIDGE|NETWORK|IP|GATEWAY|DNS|CORES|MEMORY|SWAP|DISK_GIB|PVE_POWER|PVE_ENDPOINT|PVE_CA_FILE`. Installer mode `auto`.
- `sm install upgrade` and `sm install uninstall` (ADR-0027): stop-verified read-only offline backup (`sm backup create --offline`), phase state, `sm.prev`, revert only when the schema did not move, `--allow-downgrade`; uninstall keeps data unless `--purge-data` plus a separate confirmation; on a Proxmox host both act on the appliance after record and tag proof (`--vmid`), and a purge removes that install's Proxmox identities only.
- Test infrastructure: `pvefake`, the `pvesim` command shims, `make e2e-appliance` and `make e2e-upgrade`, compatibility matrix `docs/compatibility.md`.
- Documentation: Proxmox, upgrade, uninstall and `auto` in `docs/installation.md`, `docs/providers.md`, `docs/operations.md`, `docs/security.md`, and the deferred real-host checklist `docs/manual-checks/m3-real-pve.md`.

### Changed in M3

- Installer modes `auto`, `proxmox-lxc`, `upgrade` and `uninstall` no longer exit 3; exit codes 6 to 9 gained the meanings in `docs/installation.md#exit-codes`.
- A Proxmox provider in the configuration file is no longer ignored. A guest renamed in Proxmox bumps its `spec_revision`, so pending plans for it go stale.

### Known limits in M3

- **No real Proxmox VE host was used.** Everything Proxmox is verified against fakes built from the documentation; the real-host run (`docs/manual-checks/m3-real-pve.md`) is deferred and "Proxmox auto-LXC install works" stays unchecked.
- Proxmox VE 8.x (upstream end of life 2026-08) and arm64 hosts are unsupported.
- Not built: snapshot, backup and console handlers and task-history listings, `POST /api/v1/providers`, promoting discovered guests to managed.
- The appliance certificate is self-signed and not renewed; it names the container address at install time. `--allow-downgrade` is not yet an audit event.

### Added in M2

- Server mode (`sm server`): the API over HTTPS, either terminated by the daemon (`server.tls.mode: direct`, certificate re-read on `SIGHUP`) or behind a reverse proxy (`proxy`, forwarding headers believed only from `server.trusted_proxies`). No ACME (ADR-0017).
- Bearer credentials: sessions, API tokens with expiry and narrowing scopes, bootstrap codes and join tokens, stored as SHA-256 only. Admin socket (`sm admin bootstrap-code|grant|restore-complete`, read-only `sm doctor`), rate limits, response headers, event stream (`GET /events/stream`). Migration `000003`.
- OIDC login: Authorization Code with PKCE (loopback, `--callback-port`) and the device grant, discovery-trust rules and the new key `auth.oidc.allowed_endpoint_origins` (ADR-0018, spec 1.4.3). Exercised against Dex only.
- Client profiles, `sm login|logout`, `sm profile`, `sm tokens`, remote TUI over SSE, and a credential store (macOS keychain, `secret-tool`, 0600 file fallback).
- Secrets: `sm secrets import|keys|rotate-master-key|retire-key|export-key|import-key`, `sm ssh-key rotate`, `sm nodes repin`. Key operations are approval-gated `secret.write` jobs (spec 1.4.4); key export is local-socket only or `--offline` on a server (ADR-0021).
- Outbound request filter `internal/netguard` (SPEC §21.1), used for identity-provider endpoints.
- Backup and restore: `sm backup create|list`, scheduled backups (`backup.schedule`, `backup.retention`), offline `sm backup restore --offline` with a crash-safe journal and restore hold, `sm admin restore-complete` (ADR-0020).
- Join: `sm enrollments create`, `sm join`, `scripts/join.sh` (ADR-0022).
- Release pipeline: GoReleaser archives, OpenSSH signatures, SPDX SBOMs, provenance on tag builds, signed channel pointers, and `install.sh` with `sm install local|server|client|restore` (ADR-0019). The production key is a placeholder, so real installs fail closed.
- OpenAPI description with a drift check (`make api-check`), ADR-0012 route metadata, and `make snapshot`, `make release-check`, `make install-test`.
- Documentation: `docs/installation.md`, `docs/operations.md`, `docs/cloudflare.md` (guide only), updates to `docs/configuration.md` and `docs/security.md`, and the manual checklist `docs/manual-checks/m2-handoff.md`.

### Known limits in M2

- Nothing is signed with a production key; production signing and provenance are unverified. The "clean Debian VM" acceptance is amended to a systemd container and a VM run is deferred.
- `install.sh` requires OpenSSH 8.2 or newer (the spec says 8.1) and its default mode `auto`, like `upgrade`, `uninstall` and `proxmox-lxc`, exits 3 until M3.
- Dex puts the OIDC client secret in the device-flow verification URL; there is no separate device client key. Only Dex has been exercised.
- Backup archives are not encrypted. A lost master key without an export is unrecoverable.
- Cloudflare is a guide, not tested against a real account. The real macOS keychain and `secret-tool` are manual checks.
- Not built: SSH CA trust, per-node keys.

### Added in M1

- Local daemon (`sm daemon`) that owns the database, serving `/api/v1` on a Unix socket with peer-credential checks in both directions, a typed client with autostart, API idempotency keys, and idle exit that waits for clients and unfinished jobs (ADR-0014).
- Agentless SSH nodes: pinned host key confirmed by fingerprint, pooled connections with bounded dials and sessions, and a closed catalog of remote commands with allowlisted, quoted arguments (ADR-0015).
- `node.setup`: an approval-gated job that creates the dedicated `supermgmt` user with a restricted `authorized_keys`, scoped sudoers lines, optional `docker` group and optional log broker, then verifies as that user (ADR-0009). Bootstrap as `root` or with `sudo -n`.
- systemd and Docker discovery, bounded and sanitized logs, the unit trust profile, and start/stop/restart as policy-gated jobs with completion evidence for crash recovery (production waits for approval).
- Instance SSH identity (Ed25519) stored in an AES-256-GCM envelope with file-based KEKs in `security.keys_dir` (ADR-0016). Migration `000002_m1`.
- TUI (Dashboard, Resources, Node, Services, Logs, Jobs, Approvals, Events, Help; command palette) and CLI (`nodes`, `services`, `jobs`, `approvals`, `events`, `status`, `ssh`, `docker`, `ssh-key`, `daemon`, `tui`).
- Interactive SSH handoff (`s`, `d`, `sm ssh`, `sm docker`) through the system OpenSSH client, isolated from user configuration, with the session audited. SuperMgmt never installs `lazydocker`.
- Local provider (this machine, read-only).
- Documentation: `docs/providers.md`, trust boundaries in `docs/security.md`, and the manual terminal checklist `docs/manual-checks/m1-handoff.md`.

### Known limits in M1

- Not built: SSE, SSH CA trust, the secrets CLI and `secret.write`, identity rotation, per-node keys, key export (M2); Applications, Deployments and Wizard screens (M4); the metrics endpoint; automated node teardown (manual steps in `docs/security.md`).
- `sm doctor` without `--offline` is not implemented.
- `ssh.known_hosts_file`, `ssh.host_key_policy` and `ssh.logs_mode` are validated but not read.
- Refusal of another local user on the socket is tested on Linux CI only. Terminal restoration after a handoff is covered by a PTY test plus a manual checklist that has not been run yet.
- Node setup is verified on a Debian fixture only.

### Added in M0

- Go module `github.com/autarquico/supermgmt` and the `sm` command skeleton with `sm version` and `sm completion`.
- Domain model with stable UUIDv7 identifiers, configured-versus-observed state and `spec_revision`, and a typed error model.
- Strict configuration loader: unknown fields fail, `SUPERMGMT_*` environment overrides, validation that reports every problem with its YAML path, and a generated environment table in `docs/configuration.md`.
- Audit events, secret redaction and correlation IDs for structured logging. Values under sensitive keys are always masked; a `secret://`, `ssh-agent://` or `file://` reference stays visible only in a field whose name ends in `_ref` and whose value matches the reference grammar.
- SQLite storage (pure Go driver, WAL), embedded migrations, database lock, and append-only protection of audit events.
- Canonical action plan with RFC 8785 hashing.
- Action catalog and policy engine: default deny, deny override, destructive gate, credential scopes, approval rules and quorum.
- Architecture decision records ADR-0001 to ADR-0005 and ADR-0013.
- Continuous integration (format, vet, lint, tests on Linux and macOS, race detector, module tidy, generate drift, cross-build, govulncheck), CodeQL, dependency review and Dependabot.
- Application services (`internal/app`): plan creation and submission, approvals and rejections with quorum, claim-time revalidation of plan inputs, credentials and policy, and lock planning. Denied and capability-unavailable decisions are written to the audit trail.
- Durable job engine (`internal/jobs`): claim with revalidation, lease generations and fencing, intents, shared and exclusive resource locks held until the job is terminal, retry classes, and a reconciler that acts only on completion evidence and otherwise holds the job `interrupted`. Only fake evidence adapters exist; real ones arrive with their milestones.
- Shared strict YAML decoder (`internal/yamlstrict`): errors carry the YAML path and line; duplicate keys, aliases, anchors and merge keys are rejected.
- `sm config validate` (with `--policy` and `--json`) and `sm doctor --offline`.
- Integration tests (`test/integration`) and a test that validates every YAML example in the spec and in `examples/` (`test/specexamples`).
- Public documents: README, CONTRIBUTING, SECURITY, GOVERNANCE, ROADMAP, CODE_OF_CONDUCT, `docs/architecture.md`, `docs/security.md`, `docs/configuration.md`.

[Unreleased]: https://github.com/autarquico/supermgmt/commits/main
