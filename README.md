<!-- Logo placeholder: replace with the project logo once the name clears the trademark check (SPEC §42). -->
# SuperMgmt

**Your infrastructure, one control plane.**

[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)](ROADMAP.md)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Status: pre-alpha, under construction. Nothing is released.** Milestone M0 (the core libraries and a small offline CLI) is implemented on the integration branch and awaiting release-level review. There is no installer, no daemon, no API, no TUI, no server and no MCP endpoint yet; the daemon and API arrive in M1. Every capability below that is not marked "implemented" is a plan, not a product. See the [feature matrix](#feature-matrix) and the [roadmap](ROADMAP.md).

SuperMgmt is a local-first, terminal-first control plane for developers. Connect Linux machines, Proxmox, Docker, systemd, GitHub repositories and deployments in one place; manage them from a fast TUI/CLI, or expose the same policy-controlled operations to AI agents through MCP.

It works on a laptop, a VPS, or as an automatically provisioned unprivileged LXC on Proxmox. Managed workloads never depend on SuperMgmt to keep running.

*The paragraph above describes the design target. Today only the foundations exist; see the status above.*

## Screenshot

<!-- Placeholder: TUI screenshot or GIF. The TUI arrives in M1; there is nothing to capture yet. -->
_No screenshot yet. The TUI is planned for M1._

## Why SuperMgmt?

- **Local-first.** `sm` is meant to run on a laptop with no server dependency (design goal, SPEC §1.4).
- **Agentless-first.** Linux nodes are managed over SSH; no daemon on every machine (planned, M1).
- **MCP-native, not MCP-controlled.** AI agents use the same policy and audit core as humans and get no privileged bypass (planned, M5; the policy core exists in M0).
- **Provider-independent.** Proxmox is a first-class integration, never a core dependency (planned, M3).

## Architecture

The target architecture (SPEC §2, §6). One daemon owns state; every other surface is a client of its API.

```text
        TUI            CLI            MCP bridge          GitHub Actions
         \              |                 |                    |
          +-------------+--------+--------+--------------------+
                                 |   API (Unix socket / HTTPS)
                        +--------v---------+
                        |      daemon      |  single owner of state
                        |  policy -> plan -> approval -> job   |
                        |  audit  |  SQLite |  reconciler      |
                        +--------+---------+
                                 |  connectors
        +------------+-----------+------------+-------------+
        |            |           |            |             |
       SSH       Proxmox      Docker /      GitHub      (Cloudflare,
     (agentless)  VE API      systemd       API          optional)
```

What exists today (M0): the domain model, typed errors, configuration loading, audit and redaction, the SQLite schema and migrations, canonical plan hashing, the policy engine, the application services for plans and approvals, and the durable job engine. The daemon, API, connectors and every client surface are planned. Details: [docs/architecture.md](docs/architecture.md).

## Quick start

Only what runs today is shown. Requires Go 1.27.

```bash
git clone https://github.com/autarquico/supermgmt.git
cd supermgmt
go build -o dist/sm ./cmd/sm      # or: make build
./dist/sm version
```

Offline checks (they never contact a daemon; neither exists yet):

```bash
./dist/sm config validate --config examples/config.yaml
./dist/sm doctor --offline --config examples/config.yaml
```

`sm config validate` also accepts `--policy <file>` and `--json`. `sm doctor` without `--offline` is rejected until the daemon exists (M1).

Planned, not available yet:

| Step | Command | Available from |
|---|---|---|
| Universal installer (no clone) | `curl -fsSL .../install.sh \| bash` | M2 (local, server), M3 (Proxmox) |
| Proxmox host: automatic unprivileged LXC | same installer, detected automatically | M3 |
| Local laptop install | `sm install local` | M2 |
| Add a Linux machine | `sm nodes add ssh ...` | M1 |
| Open the TUI | `sm` | M1 |

Running `sm` with no arguments today prints help and a notice that the TUI arrives in M1.

## Feature matrix

"Implemented" means merged and tested at the library or CLI level in M0. Nothing here is released.

| Feature | Status | Spec section |
|---|---|---|
| Domain model, stable UUIDv7 IDs, `spec_revision` | Implemented (M0) | §6 |
| Typed error model and exit codes | Implemented (M0) | §38 |
| Strict configuration loader, `SUPERMGMT_*` overrides | Implemented (M0) | §8 |
| Audit events, secret redaction, correlation IDs | Implemented (M0) | §26, §30 |
| SQLite storage, embedded migrations, database lock | Implemented (M0) | §9 |
| Canonical action plan and RFC 8785 hashing | Implemented (M0) | Appendix C |
| Action catalog and policy engine (default deny, approvals, quorum) | Implemented (M0) | §11 |
| Application services: plans, approvals, claim-time revalidation, lock planning (library) | Implemented (M0) | §11.4, §20.4 |
| Durable job engine: claim, lease fencing, intents, resource locks, retry classes, reconciler with completion evidence (library, fake adapters only) | Implemented (M0) | §20.4, ADR-0013 |
| `sm version`, `sm completion`, `sm config validate`, `sm doctor --offline` | Implemented (M0) | §2.1.1, §4 |
| Local daemon, Unix socket API, typed client, API idempotency keys | Planned (M1) | §2.1.1, §23 |
| Agentless SSH nodes, systemd and Docker discovery and logs | Planned (M1) | §12, §16, §17 |
| Service restart as policy-gated jobs, TUI, approvals screen | Planned (M1) | §22 |
| Server mode over HTTPS, sessions, tokens, OIDC | Planned (M2) | §23 |
| Secret storage (AES-256-GCM envelope) | Planned (M2) | §10 |
| Signed releases, `install.sh`, backup and restore | Planned (M2) | §3, §29, §36 |
| Proxmox discovery, appliance installer, power actions | Planned (M3) | §3.5, §15 |
| GitHub connector, apps, CI-gated Compose deployments, rollback | Planned (M4) | §18-§21 |
| MCP server (read tools, plan submission) | Planned (M5) | §24 |
| Fuzzing, security scans, packaging, E2E on all modes | Planned (M6) | §31, §36 |

## Security model

Summary only; see [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

- Default deny: nothing is allowed unless a policy rule grants it, and any matching deny wins.
- Approvals bind to the hash of the exact plan; changing any input invalidates them.
- Audit events are append-only; secrets are redacted before they reach logs or events.
- Local mode trusts code running as the same OS user. Docker access is root-equivalent on the host it controls.
- MCP content is untrusted input; an MCP identity can never approve its own plans (planned, M5).

In M0 these are library-level controls, tested but not yet exposed through any running service. The API (including the idempotency behavior of SPEC §23) and the daemon arrive in M1.

## Supported platforms and integrations

| Target | Status |
|---|---|
| Build and test: Linux and macOS, amd64 and arm64, Go 1.27, `CGO_ENABLED=0` | Cross-compiled in CI |
| Released binaries | None yet (M2) |
| Managed nodes: generic Linux over SSH | Planned (M1) |
| Proxmox VE | Planned (M3) |
| Docker / Compose, systemd | Planned (M1, M4) |
| GitHub | Planned (M4) |
| MCP clients | Planned (M5) |
| Cloudflare | Optional, guide and hooks only (M2) |

## Configuration

See [docs/configuration.md](docs/configuration.md) and [examples/config.yaml](examples/config.yaml). Unknown fields fail validation.

## MCP example

> **Planned for M5. Not implemented.** The shape below illustrates the design and may change.

```jsonc
// Example MCP client configuration (planned)
{
  "mcpServers": {
    "supermgmt": { "command": "sm", "args": ["mcp"] }
  }
}
```

An agent would be able to inspect the infrastructure graph and submit a plan; execution of anything operational in production would wait for human approval of that exact plan.

## Development

```bash
make help          # list targets
make build         # build dist/sm
make test          # unit tests
make test-race     # unit tests with the race detector
make lint          # golangci-lint and format check
make vuln          # govulncheck
make generate      # regenerate generated files and fail on drift
make integration   # integration tests in test/integration
make cross-build   # linux/darwin x amd64/arm64, CGO disabled
```

`make api-check`, `make e2e`, `make snapshot` and `make release-check` are placeholders until M2. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

M0 core (implemented, pending final review), then M1 local daemon and TUI, M2 server and releases, M3 Proxmox, M4 deployments, M5 MCP, M6 hardening. See [ROADMAP.md](ROADMAP.md).

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Report vulnerabilities privately: see [SECURITY.md](SECURITY.md). Do not open public issues for them.

## License and trademark

Licensed under Apache-2.0; see [LICENSE](LICENSE). "SuperMgmt" is a working name: trademark and name availability have not been confirmed, and the name may change before the first release. No affiliation with, or endorsement by, any third-party product named in this document (Proxmox, Docker, GitHub, Cloudflare and others) is implied; all trademarks belong to their owners.
