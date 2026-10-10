# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a first release. Nothing has been released yet.

## [Unreleased]

Milestones M0 (repository and core) and M1 (local daemon, SSH, TUI). Pre-alpha: nothing is released.

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
