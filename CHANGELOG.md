# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a first release. Nothing has been released yet.

## [Unreleased]

Milestone M0, repository and core. Pre-alpha: the items below are libraries and an offline CLI, not a usable product.

### Added

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
