<!-- Logo placeholder: replace with the project logo once the name clears the trademark check (SPEC §42). -->
# SuperMgmt

**Your infrastructure, one control plane.**

[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)](ROADMAP.md)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Status: pre-alpha, under construction. Nothing is released.** Milestones M0 (core libraries), M1 (local daemon, agentless SSH nodes, TUI) M2 (server mode over HTTPS with OIDC, secrets and keys, backup and restore, signed-release installer, join) M3 (Proxmox discovery and power actions, the Proxmox appliance installer, upgrade and uninstall), M4 (applications, the GitHub connector and CI-gated Docker Compose deployments with health checks and rollback) and M5 (the MCP server: stdio bridge, read tools, approval-gated plans, optional write tools off by default, remote MCP as an OAuth protected resource) are implemented on the integration branch and await release-level review. **Proxmox was verified against fakes only: nothing has run on a real Proxmox VE host** ([checklist](docs/manual-checks/m3-real-pve.md)). **GitHub was verified against a fake only: no real GitHub, GHCR, attestation or Actions OIDC token has been used** ([checklist](docs/manual-checks/m4-real-github.md)). **MCP was verified only with the official Go SDK's own client, hand-written JSON-RPC goldens and a fake authorization server: no real MCP client (Claude Code, Claude Desktop, MCP Inspector) and no real OAuth authorization server has been used** ([checklist](docs/manual-checks/m5-real-mcp-clients.md)). No signed release exists and the production release key has not been generated, so the installer cannot install anything real yet. Every capability below that is not marked "Implemented" is a plan, not a product. See the [feature matrix](#feature-matrix) and the [roadmap](ROADMAP.md).

SuperMgmt is a local-first, terminal-first control plane for developers. Connect Linux machines, Proxmox, Docker, systemd, GitHub repositories and deployments in one place; manage them from a fast TUI/CLI, or expose the same policy-controlled operations to AI agents through MCP.

It works on a laptop, a VPS, or as an automatically provisioned unprivileged LXC on Proxmox. Managed workloads never depend on SuperMgmt to keep running.

*The paragraph above describes the design target. Today the local daemon, SSH nodes and TUI exist; see the status above and the matrix below.*

## Screenshot

<!-- Placeholder: TUI screenshot or GIF, to add once the manual handoff checks (docs/manual-checks/m1-handoff.md) have passed. -->
_No screenshot yet._

## Why SuperMgmt?

- **Local-first.** `sm` runs on a laptop with no server dependency (implemented, M1; SPEC §1.4).
- **Agentless-first.** Linux nodes are managed over SSH. Nothing of SuperMgmt runs on them: only a dedicated user, its files and a sudoers drop-in (implemented, M1).
- **MCP-native, not MCP-controlled.** AI agents use the same policy and audit core as humans and get no privileged bypass (implemented in M5 and tested with the SDK client only; the policy core exists since M0).
- **Provider-independent.** Proxmox is a first-class integration, never a core dependency (implemented in M3 against fakes; not run on a real host).

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

What exists today (M0 to M5): the M0 core (domain model, configuration, audit and redaction, SQLite, plan hashing, policy engine, application services, durable job engine), the local daemon with its Unix-socket API and typed client, the SSH connector with systemd and Docker discovery, the encrypted secret store, `node.setup`, the TUI and the CLI, and (M2) the HTTPS server with sessions, tokens and OIDC, remote client profiles, backup and restore, join and the installer, and (M3) Proxmox discovery of nodes, VMs, containers and storages, power actions as non-retryable jobs correlated by Proxmox task id, the `proxmox-lxc` appliance installer with a rollback journal, and upgrade and uninstall. and (M4) the GitHub connector (CI checks, contents at one commit, Sigstore attestations, Actions OIDC, webhook), applications and targets, and Compose deployments through a closed pipeline with preflight, health verification and rollback, and (M5) the MCP server (`sm mcp` over stdio, `/mcp` over streamable HTTP in server mode) with registered MCP clients. Details: [docs/architecture.md](docs/architecture.md).

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

Installer and server mode (M2). **Unreleased: the installer's trust root is a placeholder until the owner creates the release key, so a real `install.sh` run fails closed with exit 5.** What it does once a signed release exists, the review-first alternative to `curl | bash`, and the honest trust roots: [docs/installation.md](docs/installation.md). Running a server: [docs/operations.md](docs/operations.md).

```bash
# on a Debian/Ubuntu host with systemd, as root (not verified against a real release)
curl -fsSL https://raw.githubusercontent.com/autarquico/supermgmt/main/install.sh | bash -s -- server --public-url https://mgmt.example.com
```

Proxmox, upgrade and uninstall (M3). **Implemented and tested against fakes (the appliance end to end by `TestM3_Appliance*`, CI job `e2e-appliance`); not run on a real Proxmox VE host.** On a Proxmox VE 9.x host, as root:

```bash
sudo sm install proxmox-lxc          # or install.sh with no mode on a Proxmox host (auto)
sudo sm install upgrade              # replace the installed sm, with a read-only backup first
sudo sm install uninstall            # remove the software, keep configuration and data
```

What each does, its configuration and its failure behaviour: [docs/installation.md](docs/installation.md#proxmox-appliance-proxmox-lxc). Discovery, privileges and power actions: [docs/providers.md](docs/providers.md#proxmox). Recovery: [docs/operations.md](docs/operations.md#upgrade-and-recovery).

Running `sm` with no arguments in an interactive terminal opens the TUI. `sm doctor` without `--offline` asks a running server over its admin socket (run it as root or the service user); on a local install use `--offline`.

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
| Server mode over HTTPS (TLS direct or behind a proxy, no ACME), sessions, API tokens with scopes, admin socket, bootstrap code, rate limits, SSE | Implemented (M2) | §23, §11.5, ADR-0017 |
| OIDC login (PKCE loopback and device grant), tested against Dex only | Implemented (M2) | §23.1, ADR-0018 |
| Remote client profiles, `sm login`, credential store (macOS keychain, `secret-tool`, 0600 file), remote TUI | Implemented (M2); real keychain and `secret-tool` are manual checks | Appendix B |
| Secrets CLI and API, master-key rotate, retire, export and import, instance SSH-key rotation, host-key re-pin, approvals for `secret.write` | Implemented (M2) | §10, ADR-0021 |
| Outbound request filter (identity-provider endpoints) | Implemented (M2); control-plane health URLs and the GitHub `api_url` origin use it in M4 | §21.1 |
| Backup and offline restore with journal, crash-injection tests and restore hold | Implemented (M2); no real-VM run | §29, ADR-0020 |
| Join and enrollment (`sm enrollments create`, `sm join`, `join.sh`) | Implemented (M2) | §13, ADR-0022 |
| Signed release pipeline (GoReleaser, OpenSSH signatures, SBOM, provenance), `install.sh`, `sm install local\|server\|client\|restore` | Implemented (M2); verified with a CI test key only, the production key and provenance are unverified | §3, §36, ADR-0019 |
| Cloudflare Tunnel/Access | Guide only, not verified against a real account; no edge assertion is consumed | §25 |
| Resident-daemon user unit (`sm install local --resident`) | Implemented (M2); not run under real launchd or user systemd | §2.1.1 |
| SSH CA trust, per-node keys | Not scheduled | §10 |
| Providers and Settings screens in the TUI | Not built (still planned) | §22 |
| Proxmox discovery: cluster nodes, VMs and containers with configured CPU, RAM, disk and metrics, storages; guests gone or out of the token's sight kept as `absent` or `inaccessible`; on-demand refresh | Implemented (M3); fake-verified only, real host DEFERRED | §15, ADR-0024 |
| Proxmox power actions (`start`, `shutdown`, `reboot`, `stop`) as non-retryable jobs with persisted task ids and task-based recovery; `stop` needs approval | Implemented (M3); fake-verified only, real host DEFERRED | §15.4, §20.4, ADR-0025 |
| Per-install Proxmox identities and least-privilege roles; Proxmox TLS verified (`verify_tls` must be true, private CA via `ca_file`) | Implemented (M3); fake-verified only, real host DEFERRED | §15.2, ADR-0023 |
| `sm install proxmox-lxc`: unprivileged LXC, self-signed appliance TLS, token transfer, rollback journal with crash recovery | Implemented (M3); fake-verified (`TestM3_Appliance*`, job `e2e-appliance`), real host DEFERRED | §3.5, ADR-0026 |
| `install.sh` mode `auto` (Proxmox host, desktop, or server prompt) | Implemented (M3) | §3.4 |
| `sm install upgrade` (read-only backup, phase state, automatic revert only when the schema did not move) and `sm install uninstall` (data kept unless separately confirmed; per-appliance purge) | Implemented (M3); `TestM3_Upgrade*` and `TestM3_Uninstall*` (job `e2e-upgrade`); no real-host run | §29.3, §29.4, ADR-0027 |
| Proxmox snapshots, backups, console, task-history listings; `POST /providers` for Proxmox; promoting discovered guests to managed | Not built (deferred to M6) | §15.1 |
| GitHub connector: repositories, required CI checks and contents at one commit, webhook (server mode) with backstop polling, Actions OIDC credentials, Sigstore attestation verification; read-only fine-grained token | Implemented (M4); fake-verified only (`ghfake`, virtual Sigstore), real GitHub DEFERRED | §18, ADR-0028 |
| Applications and targets (`sm apps list\|get\|create`, `sm apps target add`), manifest and closed Compose pipeline (compose-go v2.15.0, Compose CLI 5.5.1 only) | Implemented (M4); loader-versus-CLI corpus on the fixture node | §19, §20.3, ADR-0006 |
| Deployments (`sm deploy`, `sm deployments list\|get\|cancel`): the exact CI-passed commit and attested digest, preflight, pre-deploy backup (`postgres-dump`), health verification (http, tcp, docker-health), automatic or manual rollback, interrupted-deployment recovery | Implemented (M4); `TestM4_*` (job `e2e-deploy`) on a fake GitHub, virtual Sigstore and local registry | §20, §21, ADR-0029 |
| Rollback (`sm rollback`) to a known-good deployment's frozen versions | Implemented (M4) | §20.4, ADR-0007 |
| TUI: Applications, Deployments, deployment timeline, creation wizard with plan review; palette `deploy` and `rollback` | Implemented (M4) | §22 |
| Secret env files for apps (byte-exact, resolved-hash check on the node, needs `jq`) | Implemented (M4); fixture-verified | §10, ADR-0010 |
| Several targets per environment, GitHub App tokens, Proxmox snapshot policy, `command-template` and `systemd-active` health, other backup templates | Not built | §19, §21 |
| Deployments against real GitHub, GHCR and real attestations | DEFERRED ([checklist](docs/manual-checks/m4-real-github.md)) | App. E |
| MCP server: `sm mcp` stdio bridge, read tools, `infra_plan_action`; MCP clients registered with `sm mcp clients add\|list\|remove` (approval-gated registration, token issued once to a 0600 file or the OS keychain) | Implemented (M5); verified with the Go SDK client and raw JSON-RPC goldens (`TestE2E_MCPStdioReadsGraph`, job `e2e-mcp`); real MCP clients DEFERRED ([checklist](docs/manual-checks/m5-real-mcp-clients.md)) | §24, ADR-0031, ADR-0032 |
| Write tools (`infra_submit_plan`, `infra_restart_service`, `infra_reboot_node`, `infra_create_deployment`, `infra_rollback_deployment`): absent and denied at the API unless `mcp.write_tools_enabled: true`; an MCP identity can never approve, reject or resolve, nor mint credentials | Implemented (M5); `TestMCPRouteMatrix` and `test/integration/mcp_security_test.go` | §11.2, §24 |
| Remote MCP at `<public_url>/mcp` as an OAuth 2.0 protected resource (RFC 9728 metadata, RFC 9068 JWT or RFC 7662 introspection); SuperMgmt never issues OAuth tokens | Implemented (M5); `TestE2E_MCPRemoteStreamable` against a fake authorization server only; a real authorization server (incl. RFC 8707 `resource`) DEFERRED | §24, ADR-0033 |
| MCP resources and prompts, interactive exec through MCP | Not built (`allow_interactive_exec: true` is refused) | §24 |
| Metrics endpoint, automated node teardown | Planned (not scheduled) | §33 |
| Fuzzing, security scans, packaging, E2E on all modes | Planned (M6) | §31, §36 |

M4 compatibility matrix ([docs/compatibility.md](docs/compatibility.md#deployments-m4)): Docker Compose CLI 5.5.1 and `jq` on the node, and every GitHub behaviour the code relies on, are "verified" against a fixture node or a fake and "not verified" against real GitHub.

M3 compatibility matrix ([docs/compatibility.md](docs/compatibility.md)): every Proxmox behaviour the code relies on is "fake-verified" and "not verified" on a real host. The row "Proxmox auto-LXC install works" of SPEC Appendix E stays unchecked until [docs/manual-checks/m3-real-pve.md](docs/manual-checks/m3-real-pve.md) passes. Supported: Proxmox VE 9.x on amd64 only.

M2 was verified in CI with unit and integration tests, fakes and an in-process test identity provider, and install tamper tests under a test signing key. Dex was exercised by hand in a spike (code flow, device grant) on a developer machine; the Docker-based end-to-end suite (Dex login, install in a Debian systemd container, crash-injected restore) was not part of the code this documentation was written against and is not claimed. Not verified: a real Debian VM (the criterion is amended to a systemd container; a VM run is deferred), the production signing key and provenance, a real Cloudflare account, any identity provider other than Dex, and the real macOS keychain. The steps for those are in [docs/manual-checks/m2-handoff.md](docs/manual-checks/m2-handoff.md).

## Security model

Summary only; see [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

- Default deny: nothing is allowed unless a policy rule grants it, and any matching deny wins.
- Approvals bind to the hash of the exact plan; changing any input invalidates them. Operational writes in a `production` environment wait for approval.
- Audit events are append-only; secrets are redacted before they reach logs or events.
- Local mode trusts code running as the same OS user: the daemon socket accepts that user only.
- Nodes: the pinned host key is the only trust anchor, remote output is sanitized, and commands come from a fixed catalog. After setup SuperMgmt holds no standing root on a node.
- The `journal-group` log mode lets the node credential read the node's entire system journal. Docker access is root-equivalent. Granting restart on a unit trusts everything that unit executes (a trust profile, not a proof).
- The KEK files in `security.keys_dir` are not in the database or in backup archives and must be backed up separately (`sm secrets export-key`). Archives are not encrypted.
- Server mode: every request needs a bearer token (session from OIDC, or an API token); key operations and secret imports are approval-gated jobs. `curl | bash` trusts the `main` branch; the review-first path does not (see [docs/installation.md](docs/installation.md)).
- MCP content is untrusted input; an MCP identity can never approve, reject or resolve plans or jobs, and can never mint credentials. Tool output redacts a fixed set of secret patterns only; unknown secrets in remote text are not detected ([docs/mcp.md](docs/mcp.md)).

## Supported platforms and integrations

| Target | Status |
|---|---|
| Build and test: Linux and macOS, amd64 and arm64, Go 1.27, `CGO_ENABLED=0` | Cross-compiled in CI |
| Machine running `sm`: Linux and macOS | Implemented (M1). The local provider is read-only; macOS has no systemd |
| Released binaries | None yet. The pipeline exists (M2); no signed tag has been built and the release key does not exist |
| Managed nodes: generic Linux over SSH | Implemented (M1). Verified in CI on Debian only; other distributions are an untested assumption |
| systemd and Docker discovery, service actions | Implemented (M1) |
| Proxmox VE | Implemented (M3) for 9.x on amd64 only, against fakes; real host DEFERRED ([docs/compatibility.md](docs/compatibility.md)). 8.x is unsupported (upstream end of life 2026-08) |
| Docker Compose deployments | Implemented (M4) on SSH nodes with `node.setup` v2, Docker Compose CLI 5.5.1 exactly and `jq`; fixture node and fake GitHub only |
| GitHub | Implemented (M4) for github.com-style APIs against a fake; real GitHub and GitHub Enterprise Server not verified |
| MCP clients | Implemented (M5) against the Go SDK client and a fake authorization server; no real MCP client or authorization server verified (DEFERRED) |
| Cloudflare | Optional, guide only ([docs/cloudflare.md](docs/cloudflare.md)); not verified against a real account |

## Configuration

See [docs/configuration.md](docs/configuration.md) and [examples/config.yaml](examples/config.yaml). Unknown fields fail validation. A key being accepted does not mean its feature exists; the configuration page says which keys are read.

## MCP example

Register a client once (the registration may need human approval), then point the MCP host at the bridge. The token goes straight into the file or keychain entry and is never printed:

```bash
sm mcp clients add claude-desktop --token-file ~/.config/supermgmt/mcp-claude-desktop.token
# if approval is pending: sm jobs approve <job> --plan-hash <hash> (both printed), then run the same command again
```

```json
{
  "mcpServers": {
    "supermgmt": {
      "command": "sm",
      "args": ["mcp", "--token-file", "/Users/you/.config/supermgmt/mcp-claude-desktop.token"]
    }
  }
}
```

More host configurations, including the remote `/mcp` endpoint, are in [examples/mcp/](examples/mcp/) (checked by `test/specexamples`). An agent can inspect the infrastructure graph and plan an action; write tools exist only with `mcp.write_tools_enabled: true`, and anything operational in production waits for human approval of that exact plan. **Not verified with a real MCP client** (only the Go SDK client and raw JSON-RPC goldens); see [docs/mcp.md](docs/mcp.md) and [docs/manual-checks/m5-real-mcp-clients.md](docs/manual-checks/m5-real-mcp-clients.md).

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

`make api-check`, `make snapshot`, `make release-check` and `make install-test` run the OpenAPI drift check, a signed snapshot release with a throwaway key, its verification and the `install.sh` tamper matrix. The Docker end-to-end suites are `make e2e-server`, `make e2e-install` (both in `make e2e`), `make e2e-appliance` (simulated Proxmox host) and `make e2e-upgrade` (upgrade from the M2 build, failure boundaries, uninstall); they need Docker and a full git history. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

M0 core, M1 local daemon, SSH and TUI, M2 server and releases, M3 Proxmox and the appliance installer, M4 apps and deployments, and M5 MCP (all implemented, pending release-level review; M3 pending a real-host run, M4 a real-GitHub run, M5 real MCP clients and a real authorization server), then M6 hardening. See [ROADMAP.md](ROADMAP.md).

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Report vulnerabilities privately: see [SECURITY.md](SECURITY.md). Do not open public issues for them.

## License and trademark

Licensed under Apache-2.0; see [LICENSE](LICENSE). "SuperMgmt" is a working name: trademark and name availability have not been confirmed, and the name may change before the first release. No affiliation with, or endorsement by, any third-party product named in this document (Proxmox, Docker, GitHub, Cloudflare and others) is implied; all trademarks belong to their owners.
