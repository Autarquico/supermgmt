# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a first release. Nothing has been released yet.

## [Unreleased]

Milestone M0, repository and core. Pre-alpha: the items below are libraries and an offline CLI, not a usable product.

### Added

- Go module `github.com/autarquico/supermgmt` and the `sm` command skeleton with `sm version` and `sm completion`.
- Domain model with stable UUIDv7 identifiers, configured-versus-observed state and `spec_revision`, and a typed error model.
- Strict configuration loader: unknown fields fail, `SUPERMGMT_*` environment overrides, validation that reports every problem with its YAML path, and a generated environment table in `docs/configuration.md`.
- Audit events, secret redaction and correlation IDs for structured logging.
- SQLite storage (pure Go driver, WAL), embedded migrations, database lock, and append-only protection of audit events.
- Canonical action plan with RFC 8785 hashing.
- Action catalog and policy engine: default deny, deny override, destructive gate, credential scopes, approval rules and quorum.
- Architecture decision records ADR-0001 to ADR-0005 and ADR-0013.
- Continuous integration (format, vet, lint, tests on Linux and macOS, race detector, module tidy, generate drift, cross-build, govulncheck), CodeQL, dependency review and Dependabot.
- Public documents: README, CONTRIBUTING, SECURITY, GOVERNANCE, ROADMAP, CODE_OF_CONDUCT, `docs/architecture.md`, `docs/security.md`, `docs/configuration.md`.

### In progress (M0, not yet merged)

- Durable job engine: claim with revalidation, lease fencing, intents, resource locks, retry classes and reconciler interface.
- `sm config validate` and `sm doctor --offline`.

[Unreleased]: https://github.com/autarquico/supermgmt/commits/main
