<!-- Logo placeholder: replace with the project logo once the name clears the trademark check (SPEC §42). -->
# SuperMgmt

**Your infrastructure, one control plane.**

[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)](ROADMAP.md)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Status: pre-alpha, under construction. Nothing is released.** Milestones M0 (core libraries) and M1 (local daemon, agentless SSH nodes, TUI) are implemented on the integration branch and await release-level review. There is no installer, no server mode, no HTTPS API and no MCP endpoint yet. Every capability below that is not marked "Implemented" is a plan, not a product. See the [feature matrix](#feature-matrix) and the [roadmap](ROADMAP.md).

SuperMgmt is a local-first, terminal-first control plane for developers. Connect Linux machines, Proxmox, Docker, systemd, GitHub repositories and deployments in one place; manage them from a fast TUI/CLI, or expose the same policy-controlled operations to AI agents through MCP.

It works on a laptop, a VPS, or as an automatically provisioned unprivileged LXC on Proxmox. Managed workloads never depend on SuperMgmt to keep running.

*The paragraph above describes the design target. Today the local daemon, SSH nodes and TUI exist; see the status above and the matrix below.*

## Screenshot

<!-- Placeholder: TUI screenshot or GIF, to add once the manual handoff checks (docs/manual-checks/m1-handoff.md) have passed. -->
_No screenshot yet._

## Why SuperMgmt?

- **Local-first.** `sm` runs on a laptop with no server dependency (implemented, M1; SPEC §1.4).
- **Agentless-first.** Linux nodes are managed over SSH. Nothing of SuperMgmt runs on them: only a dedicated user, its files and a sudoers drop-in (implemented, M1).
- **MCP-native, not MCP-controlled.** AI agents use the same policy and audit core as humans and get no privileged bypass (planned, M5; the policy core exists since M0).
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

What exists today (M0 and M1): the M0 core (domain model, configuration, audit and redaction, SQLite, plan hashing, policy engine, application services, durable job engine), plus the local daemon with its Unix-socket API and typed client, the SSH connector with systemd and Docker discovery, the encrypted instance SSH identity, `node.setup`, the TUI and the CLI. Not present: HTTPS server mode, Proxmox, GitHub, deployments, MCP. Details: [docs/architecture.md](docs/architecture.md).

## Quick start

Requires Go 1.27. Only what runs today is shown.

```bash
git clone https://github.com/autarquico/supermgmt.git
cd supermgmt
go build -o dist/sm ./cmd/sm      # or: make build
./dist/sm version
```

Offline checks (they never contact the daemon):

```bash
./dist/sm config validate --config examples/config.yaml --policy examples/policies.yaml
./dist/sm doctor --offline --config examples/config.yaml
```

Manage a node. The first command that needs the daemon starts it; it exits after `daemon.idle_exit` unless a client is connected or a job is pending.

```bash
sm ssh-key show                      # the public key SuperMgmt uses on nodes
sm nodes add --name web1 --host 203.0.113.10 --admin-user root
                                     # scans the host key and asks you to confirm its SHA256
sm                                   # open the TUI
# in the TUI: "/" then "setup web1 docker" opens a plan; confirm it, then approve it
```

Until setup, a node is read with read-only probes as your `admin_user`. Starting, stopping and restarting services needs `node.setup` first. Step by step, and what setup changes on the node: [docs/providers.md](docs/providers.md). Trust and risk: [docs/security.md](docs/security.md).

Planned, not available yet:

| Step | Command | Available from |
|---|---|---|
| Universal installer (no clone) | `curl -fsSL .../install.sh \| bash` | M2 (local, server), M3 (Proxmox) |
| Proxmox host: automatic unprivileged LXC | same installer, detected automatically | M3 |
| Local laptop install | `sm install local` | M2 |

Running `sm` with no arguments in an interactive terminal opens the TUI. `sm doctor` without `--offline` is not implemented yet and exits with a usage error.

## Feature matrix

"Implemented" means merged and tested in the milestone shown. Nothing here is released. The M1 acceptance scenarios run against Docker-based node fixtures (`make integration-fixtures`); real terminal emulators are checked by hand ([docs/manual-checks/m1-handoff.md](docs/manual-checks/m1-handoff.md)).

| Feature | Status | Spec section |
|---|---|---|
| Domain model, stable UUIDv7 IDs, `spec_revision` | Implemented (M0) | §6 |
| Typed error model and exit codes | Implemented (M0) | §38 |
| Strict configuration loader, `SUPERMGMT_*` overrides | Implemented (M0) | §8 |
| Audit events, secret redaction, correlation IDs | Implemented (M0) | §26, §30 |
| SQLite storage, embedded migrations, database lock | Implemented (M0) | §9 |
| Canonical action plan and RFC 8785 hashing | Implemented (M0) | Appendix C |
| Action catalog and policy engine (default deny, approvals, quorum) | Implemented (M0) | §11 |
| Application services: plans, approvals, claim-time revalidation, lock planning | Implemented (M0) | §11.4, §20.4 |
| Durable job engine: leases, intents, resource locks, retry classes, reconciler with completion evidence | Implemented (M0); real SSH, systemd and Docker evidence in M1 | §20.4, ADR-0013, ADR-0015 |
| `sm version`, `sm completion`, `sm config validate`, `sm doctor --offline` | Implemented (M0) | §2.1.1, §4 |
| Local daemon: Unix-socket API with peer-credential checks, typed client, idempotency keys, autostart, idle exit | Implemented (M1) | §2.1.1, §23, ADR-0014 |
| Agentless SSH nodes: pinned host key, pooled connections, fixed command templates | Implemented (M1) | §12, ADR-0015 |
| `node.setup`: dedicated `supermgmt` user, scoped sudoers, optional `docker` group, optional log broker | Implemented (M1) | §12, §16, ADR-0009 |
| systemd and Docker discovery, bounded and sanitized logs | Implemented (M1) | §16, §17 |
| Service start, stop and restart as policy-gated jobs; production waits for approval; crash recovery by completion evidence | Implemented (M1) | §20.4, §22 |
| Instance SSH identity (Ed25519) in an AES-256-GCM envelope with file-based KEKs | Implemented (M1, slice of the M2 secret store) | §8.4, §10, ADR-0016 |
| Interactive SSH (`sm ssh`) and `sm docker` (lazydocker over SSH; never installed for you) | Implemented (M1) | §8.4, §17.1 |
| Local provider (this machine, read-only) | Implemented (M1) | §14 |
| TUI: Dashboard, Resources, Node, Services, Logs, Jobs, Approvals, Events, Help; palette for ssh, logs, services, setup, probe, refresh. Polls in tiers | Implemented (M1) | §22 |
| CLI: `nodes`, `services`, `jobs`, `approvals`, `events`, `status`, `ssh`, `docker`, `ssh-key`, `daemon`, `tui` | Implemented (M1) | §4 |
| Server mode over HTTPS, sessions, tokens, OIDC, SSE | Planned (M2) | §23 |
| Secrets CLI and API, identity rotation, key export and import, per-node keys, SSH CA trust | Planned (M2) | §10 |
| Signed releases, `install.sh`, backup and restore, resident-daemon user unit | Planned (M2) | §3, §29, §36 |
| Providers and Settings screens in the TUI | Planned (M2) | §22 |
| Proxmox discovery, appliance installer, power actions | Planned (M3) | §3.5, §15 |
| GitHub connector, apps, deployments, Applications, Deployments and Wizard screens, rollback | Planned (M4) | §18-§21 |
| MCP server (read tools, plan submission) | Planned (M5) | §24 |
| Metrics endpoint, automated node teardown | Planned (not scheduled) | §33 |
| Fuzzing, security scans, packaging, E2E on all modes | Planned (M6) | §31, §36 |

## Security model

Summary only; see [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

- Default deny: nothing is allowed unless a policy rule grants it, and any matching deny wins.
- Approvals bind to the hash of the exact plan; changing any input invalidates them. Operational writes in a `production` environment wait for approval.
- Audit events are append-only; secrets are redacted before they reach logs or events.
- Local mode trusts code running as the same OS user: the daemon socket accepts that user only.
- Nodes: the pinned host key is the only trust anchor, remote output is sanitized, and commands come from a fixed catalog. After setup SuperMgmt holds no standing root on a node.
- The `journal-group` log mode lets the node credential read the node's entire system journal. Docker access is root-equivalent. Granting restart on a unit trusts everything that unit executes (a trust profile, not a proof).
- The KEK files in `security.keys_dir` are not in the database and must be backed up separately. Key export arrives in M2.
- MCP content is untrusted input; an MCP identity can never approve its own plans (planned, M5).

## Supported platforms and integrations

| Target | Status |
|---|---|
| Build and test: Linux and macOS, amd64 and arm64, Go 1.27, `CGO_ENABLED=0` | Cross-compiled in CI |
| Machine running `sm`: Linux and macOS | Implemented (M1). The local provider is read-only; macOS has no systemd |
| Released binaries | None yet (M2) |
| Managed nodes: generic Linux over SSH | Implemented (M1). Verified in CI on Debian only; other distributions are an untested assumption |
| systemd and Docker discovery, service actions | Implemented (M1) |
| Proxmox VE | Planned (M3) |
| Docker Compose deployments | Planned (M4) |
| GitHub | Planned (M4) |
| MCP clients | Planned (M5) |
| Cloudflare | Optional, guide and hooks only (M2) |

## Configuration

See [docs/configuration.md](docs/configuration.md) and [examples/config.yaml](examples/config.yaml). Unknown fields fail validation. A key being accepted does not mean its feature exists; the configuration page says which keys M1 reads.

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
make test-pty      # terminal handoff tests
make lint          # golangci-lint and format check
make vuln          # govulncheck
make generate      # regenerate generated files and fail on drift
make integration   # integration tests in test/integration
make integration-fixtures  # Docker node fixtures (needs a local Docker daemon)
make cross-build   # linux/darwin x amd64/arm64, CGO disabled
```

`make api-check`, `make e2e`, `make snapshot` and `make release-check` are placeholders until M2. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

M0 core and M1 local daemon, SSH and TUI (both implemented, pending release-level review), then M2 server and releases, M3 Proxmox, M4 deployments, M5 MCP, M6 hardening. See [ROADMAP.md](ROADMAP.md).

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Report vulnerabilities privately: see [SECURITY.md](SECURITY.md). Do not open public issues for them.

## License and trademark

Licensed under Apache-2.0; see [LICENSE](LICENSE). "SuperMgmt" is a working name: trademark and name availability have not been confirmed, and the name may change before the first release. No affiliation with, or endorsement by, any third-party product named in this document (Proxmox, Docker, GitHub, Cloudflare and others) is implied; all trademarks belong to their owners.
