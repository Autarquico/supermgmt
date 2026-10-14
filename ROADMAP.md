# Roadmap

Status as of 2026-10-14. The project is **pre-alpha**; nothing is released. Milestones follow `docs/spec/SUPERMGMT-SPEC.md` §31 and each depends only on earlier ones.

Statuses: **in progress**, **implemented** (merged, pending release-level review), **planned**.

### M6 accepted scope and honest deferrals

Built: fuzz targets for every parser of untrusted input with an inventory that fails on an unmapped one; a stress suite; secret scanning, a licence gate, reproducible builds, notices and SBOM checks, provenance verification and a release workflow that builds only when every required check and a `nightly` run succeeded on the exact tag commit; migration fixtures written by real binaries of milestones M1 to M5; install, upgrade, backup, restore and uninstall lifecycle tests in a systemd container and on disposable runners; a real-process crash test at each of the 20 upgrade crash points; an upgrade service hold, a retaken backup on resume, offline downgrade and version-transition audit events, a doctor schema contract, TLS expiry and clock-skew warnings; and the documentation (compatibility matrix, releasing, troubleshooting, dependencies, release checklist).

- **No version is released.** The Appendix E boxes in the spec stay unchecked. The [release checklist](docs/release-checklist.md) maps each of the 52 rows to its tests and jobs and lists 21 human-gated rows, all unchecked, each with an owner and a procedure.
- **Human-gated, never done by an agent:** the signing key and trust root, the real Proxmox, GitHub, MCP and OIDC runs, a real Debian 13 VM, an Intel Mac, an upgrade from a signed release, the legal reading of third-party notices, the licence decision, the name and trademark checks, the Homebrew tap, and the GitHub repository settings.
- **Platforms (SPEC §35).** Supported means CI runs every operation on that platform ([docs/compatibility.md](docs/compatibility.md#platforms-and-operations)): Ubuntu 24.04 amd64 and arm64 (server and local-client) and macOS 15 arm64 (local-client). Debian 13 is container-verified, the Proxmox appliance is fake-verified, Intel macOS is manual, Debian as a local-client host and everything else are not claimed. The jobs were written without a GitHub run.
- **Unresolved, listed rather than hidden:** a second, unexplained failure mode of the daemon-restart test; the residual of a TUI handoff that exits instantly (the case seen is fixed); 25 parsers without a fuzz target; a downgrade to a pre-M6 binary keeps its audit record pending; SEC-7 (Proxmox roles carry no marker), SEC-9 (a guest recreated between two syncs) and the unread upstream behaviour behind SEC-12.
- **Not built, post-V1:** Proxmox `POST /providers`, guest promotion, snapshot, backup, console and task-history handlers, the §33 metrics endpoint, a TLS renewal command, `internal/providers/cloudflare`, Linux packages (a package manager's upgrade would bypass the upgrade protocol), MCP resources and prompts.
- The M4 and M5 migration fixtures contain no deployment and no OAuth access-token row.

### M5 accepted scope and honest deferrals

Built: the MCP server (`internal/mcp`, official Go SDK v1.8.0, ADR-0031): `sm mcp` over stdio and `/mcp` over stateless streamable HTTP in server mode; read tools, `infra_plan_action`, and five write tools registered only with `mcp.write_tools_enabled: true`; registered MCP clients with a once-issued token (ADR-0032, migration `000006`, `sm mcp clients add|list|remove`); remote MCP as an OAuth 2.0 protected resource with RFC 9728 metadata, RFC 9068 JWT validation or RFC 7662 introspection (ADR-0033); an MCP identity can never approve, reject, resolve or mint credentials; tool output is sanitized, scrubbed and flagged as untrusted. Docs and the checklist: `docs/mcp.md` and [docs/manual-checks/m5-real-mcp-clients.md](docs/manual-checks/m5-real-mcp-clients.md) (written by a parallel task; not checked here).

- **No real MCP client and no real OAuth authorization server was used.** MCP is verified with the SDK's own client, hand-written raw JSON-RPC goldens and a fake authorization server (`oauthfake`: JWKS and introspection). Claude Code, Claude Desktop, MCP Inspector and a real authorization server (including RFC 8707 `resource` at authorization and at token exchange) stay **DEFERRED** until the checklist records dated, versioned evidence.
- Redaction in tool output is pattern-based (Bearer, Basic, PEM, SuperMgmt token formats, JWT-shaped values, `key=value` forms with sensitive keys, and sensitive keys in structured data). Arbitrary unknown secrets in remote text are not detected.
- By default MCP identities get no `service.logs` (the built-in policy is unchanged), so `infra_get_service_logs` is denied until a policy grants it.
- Protected-resource metadata is also served at the root well-known path as the spec names it; a strict RFC 9728 client that discovers through the root will reject it. Discovery through the `WWW-Authenticate` challenge is the supported path.
- JWT access tokens must carry `typ: at+jwt`; issuers that cannot emit it must use introspection. No dynamic client registration; clients are registered by an admin.
- No MCP resources or prompts, and no interactive exec (`mcp.allow_interactive_exec: true` is refused).
- A token consumed but not stored is recovered only by removing and re-adding the client.
- The e2e suite (`TestE2E_MCP*`, CI job `e2e-mcp`) needs Docker and was not run while writing these docs. Review-round items recorded in the plan: `views.go` returns nil slices and maps, which the SDK output-schema validation rejects (worked around in `tools_read.go`).

### M4 accepted scope and honest deferrals

Built: the GitHub connector (read-only fine-grained token; repositories, required CI checks, contents at one commit, webhook in server mode with a backstop poll, Actions OIDC credentials, Sigstore attestation verification), applications with targets, the manifest and the closed Compose pipeline (compose-go v2.15.0, Compose CLI 5.5.1 only), CI-gated deployments of the exact commit and digest through preflight, pre-deploy backup, staging, `compose up` and health verification, automatic and manual rollback to a known-good deployment, durable recovery of interrupted deployments, `sm apps`, `sm deploy`, `sm rollback`, `sm deployments`, and the TUI Applications, Deployments, timeline and wizard screens. Design: ADR-0006 to ADR-0008, ADR-0010, ADR-0011, ADR-0028 to ADR-0030.

- **No real GitHub was used.** GitHub REST, GHCR, Sigstore attestations (public and private repositories), the GitHub TUF anchor and refresh, Actions OIDC tokens and redirect behaviour are verified against `ghfake`, a virtual Sigstore and a local registry only. Each assumption is a row of [docs/compatibility.md](docs/compatibility.md#deployments-m4) and an item of [docs/manual-checks/m4-real-github.md](docs/manual-checks/m4-real-github.md). The Appendix E row for a real-GitHub deployment stays unchecked. GitHub Enterprise Server is not verified.
- Docker Compose CLI **5.5.1 only**; any other version makes the node ineligible. `jq` is a required node tool and its version is not pinned.
- GitHub App installation tokens are not supported; the credential is a fine-grained read-only token.
- One target per (application, environment).
- `compose_source: repository` is refused for production environments (stricter than the spec, which allows an admin exception with no defined storage).
- No environment can require an Actions `environment` claim; the spec defines no field for it.
- Health checks: `http`, `tcp` and docker-health on the node, `http(s)` from the control plane; `command-template` and `systemd-active` are rejected for app targets. Manifest health bounds (timeout at most 30 s, interval at most 1 min, at most 60 attempts) are an implementation choice, not in the spec.
- The only pre-deploy backup template is `postgres-dump`. `deployment_policy.snapshot: true` is refused ("not supported in this version"); Proxmox snapshots, `POST /providers` for Proxmox, guest promotion and the M3 deferrals above are post-V1 (decided in M6; none is required by the definition of done in SPEC §43).
- The disk preflight uses registry-reported sizes plus 1 GiB with no decompression safety factor; an unknown size fails the preflight.
- The pull step is proven by a `.done` marker, not a per-image inspect.
- The secret-leak scan of the e2e suite covers the control plane (database, logs, backup archive, API, events), not the node and not CLI stdout.
- The end-to-end suite (`TestM4_*`, CI job `e2e-deploy`) and the fixture suites (`integration-fixtures`, `compose-equivalence`) need Docker; they were not run while writing these docs.
- Open review items carried to the review round: a locked command that exits 75 because a concurrent lock probe held the flock should be retryable; the expected-model helper is duplicated in the fixture test; the unused `vars` parameter of `ExpectedEnvHashes`.

### M3 accepted scope and honest deferrals

Built: Proxmox VE 9.x discovery (cluster nodes, VMs, containers, configured CPU/RAM/disk, metrics, storages; `absent` versus `inaccessible`; on-demand refresh), power actions (`start`, `shutdown`, `reboot`, `stop`) as non-retryable jobs with persisted task ids and recovery by task correlation, per-install Proxmox identities and least-privilege roles, verified Proxmox TLS, `sm install proxmox-lxc` with a rollback journal and crash recovery, `auto` mode, `sm install upgrade` (read-only offline backup, phase state, revert only when the schema did not move) and `sm install uninstall` (data kept unless separately confirmed), CLI and TUI for providers, the node tree and power. Not in M3, or not verified:

- **No real Proxmox host was used.** Every Proxmox interaction is verified against fakes built from the documentation; each assumption is a row of [docs/compatibility.md](docs/compatibility.md) and an item of [docs/manual-checks/m3-real-pve.md](docs/manual-checks/m3-real-pve.md). "Proxmox auto-LXC install works" (SPEC Appendix E) stays **unchecked**. Unconfirmed: the task list `total` and paging, the status of a running task, which verbs and guest types accept `timeout`, `/access/permissions` value semantics (0-valued and non-propagating grants, deeper-ACL replacement), the text of the error for a migrated guest, `pct list` columns, `pvesm`/`pvesh` JSON, `pct push` uid mapping, `runuser` and `pct exec` exit codes in the Debian 13 template, the template name `pveam` offers, and a full install, upgrade and uninstall on PVE 9.
- Proxmox VE 8.x and arm64 hosts are unsupported (PVE 8 reached upstream end of life in 2026-08).
- Deferred (M4 did not build them; post-V1, decided in M6): snapshot, backup and console handlers and task-history listings, `POST /api/v1/providers`, promotion of discovered guests to managed.
- The appliance certificate is self-signed with no renewal (CA 10 years, leaf 5 years) and names the address the container had at install time. M6 added an expiry check to `sm doctor` and a documented manual re-issue; a renewal command is post-V1.
- `--allow-downgrade` was recorded in the upgrade state but not in the audit log, and `sm doctor --offline --json` had no stable schema-version field. Both were closed in M6 (see below), except that a downgrade to a pre-M6 binary leaves its audit record pending.
- A guest renamed in Proxmox bumps its `spec_revision`, so pending plans for it go stale.
- The end-to-end suites (`TestM3_Appliance*`, `TestM3_Upgrade*`, `TestM3_Uninstall*`, CI jobs `e2e-appliance` and `e2e-upgrade`) run in Docker with a simulated Proxmox host; the upgrade fixture is the M2 build at commit e6d5577, so the job needs the full history.

### M2 accepted scope and honest deferrals

Built: server mode over HTTPS (TLS direct or behind a proxy, no ACME), sessions, API tokens, admin socket, bootstrap code, OIDC (PKCE loopback and device grant), remote client profiles and credential store, SSE, secrets CLI and API with key rotate, retire, export and import, backup and offline restore with restore hold, join and enrollment, the signed release pipeline, `install.sh`, `sm install local|server|client|restore`. Not in M2, or not verified:

- **Clean Debian VM acceptance: amended and deferred.** The CI gate is a Debian container with systemd; a real VM run (optional QEMU/KVM job or a recorded manual run) is not done.
- **Production signing and provenance: unverified.** CI uses an ephemeral test key; the owner must create the release key and run a protected tag build ([manual-checks/m2-handoff.md](docs/manual-checks/m2-handoff.md)).
- Identity providers: Dex only, exercised by hand. Dex puts the client secret in the device-flow verification URL; a dedicated public device client needs a new configuration key and spec change.
- Cloudflare: a guide only, never run against a real account. No edge assertion is consumed.
- macOS keychain and Linux `secret-tool` credential stores: unit-tested with fakes, manual checks pending.
- `install.sh` modes `auto`, `upgrade`, `uninstall`, `proxmox-lxc`: built in M3 (see below). The orphan-key report in `sm doctor` is not built.
- SSH CA trust and per-node keys: not scheduled. Providers and Settings TUI screens: not built.
- The installer requires OpenSSH 8.2 or newer; the spec says 8.1.
- A defect candidate: `sm login --bootstrap` on a server without OIDC sends no display name, which the server requires (`internal/cli/login.go`, `internal/app/auth.go`). Not verified end to end.

### M1 accepted scope and honest deferrals

M1 TUI screens: Dashboard, Resources tree, Node detail, Service list and detail, Logs, Jobs, Approvals, Events, Help. The palette supports ssh, logs, services, refresh, setup and probe. Not in M1:

- Applications, Deployments and the Wizard screens: built in M4. Providers and Settings screens: M2.
- SSE: built in M2 for remote profiles; the local TUI still polls in tiers.
- The secrets CLI, `secret.write`, identity rotation and key export: built in M2. SSH CA trust and per-node keys: not scheduled. `ssh.known_hosts_file` is only the file that goes into a backup.
- Resident schedules and a user unit: M2 (`sm install local --resident`); there is no `sm daemon install-user-unit`.
- The metrics endpoint (SPEC §33): not built.
- Scale: the 500-node target is shown with fakes and benchmarks, not with real nodes.
- Peer-credential refusal of another user: Linux CI only; macOS relies on the same-UID test and a manual check.
- Terminal restore after an interactive handoff: PTY tests plus the manual checklist; real emulators are not automated.
- lazydocker: offered only as `ssh -t ... lazydocker` on the node (never installed); no local lazydocker over an SSH Docker context.
- Local provider: read-only; macOS has no systemd.
- `node.setup`: no `deploy_root` (added in M4 by node.setup v2), no automated teardown, no standalone `sudoers.write` or `log_broker.install` jobs (re-run setup instead). Server-mode key authorization was an M2 item; whether setup from a server works against a real node was not verified here.
- `sm doctor` without `--offline`: built in M2 for servers (admin socket).

## Committed for V1

| Milestone | Scope | Status |
|---|---|---|
| M0 Repository and core | Go module, strict config, audit and redaction, SQLite and migrations, domain model, action catalog and policy engine, canonical plans and approvals, durable job engine, offline CLI (`version`, `completion`, `config validate`, `doctor --offline`), CI | **Implemented** on `feat/m0-core`: domain, errors, config, audit, database, plans, policy, application services, job engine and the four offline commands, with integration and spec-example tests. Pending final review. |
| M1 Local daemon, SSH, TUI alpha | `sm daemon` with Unix socket API, typed client, local provider, agentless SSH nodes with `node.setup`, systemd and Docker discovery and logs, policy-gated service actions, TUI | **Implemented** on `feat/m1-local-ssh-tui`: pending the manual terminal checklist ([docs/manual-checks/m1-handoff.md](docs/manual-checks/m1-handoff.md)) and release-level review. Accepted scope and deferrals below. |
| M2 Server, client, auth, release pipeline | HTTPS API, sessions and tokens, OIDC, client profiles, SSE, secrets store, GoReleaser with checksums, signatures, SBOM and provenance, `install.sh`, backup and restore, join | **Implemented** on `feat/m2-server-auth-release`: pending the manual checks in [docs/manual-checks/m2-handoff.md](docs/manual-checks/m2-handoff.md), the production release key and release-level review. Accepted scope and deferrals above. |
| M3 Proxmox provider and appliance installer | Proxmox discovery, `sm install proxmox-lxc` with rollback journal, restricted credentials, power actions, upgrade and uninstall | **Implemented** on `feat/m3-proxmox-installer` against fakes: pending the real-Proxmox run in [docs/manual-checks/m3-real-pve.md](docs/manual-checks/m3-real-pve.md) and release-level review. Accepted scope and deferrals above. |
| M4 Apps, GitHub, deployments | GitHub connector, app manifest, CI-gated Docker Compose deployments, health checks, rollback | **Implemented** on `feat/m4-apps-deployments` against a fake GitHub, a virtual Sigstore and a local registry: pending the real-GitHub run in [docs/manual-checks/m4-real-github.md](docs/manual-checks/m4-real-github.md) and release-level review |
| M5 MCP | MCP client registration, stdio bridge, remote MCP as OAuth protected resource, read tools, plan submission, optional write tools off by default | **Implemented** on `feat/m5-mcp` against the Go SDK client, raw JSON-RPC goldens and a fake authorization server: pending the real-client and real-authorization-server run in [docs/manual-checks/m5-real-mcp-clients.md](docs/manual-checks/m5-real-mcp-clients.md) and release-level review. Accepted scope and deferrals above. |
| M6 Hardening and release | Packaging plan, fuzz and race tests, security scans, compatibility matrix, beta migration tests, E2E across all modes, the release gate | **Implemented** on `feat/m6-hardening`: pending the human rows of the [release checklist](docs/release-checklist.md) (signing key, real hosts, legal and naming decisions, repository settings), a first GitHub run of the new jobs, and release-level review. Accepted scope and deferrals above. |

"Done" for V1 is defined in SPEC §43: install without cloning, Proxmox one-command LXC, agentless SSH nodes, Proxmox/systemd/Docker discovery, TUI, CI-gated Compose deploys with safe rollback, audit timeline, remote server mode, MCP with approvals, tested backup/restore/upgrade/uninstall, and signed releases.

## Exploratory, not V1 promises

These are ideas from SPEC §44. None is scheduled and any may be dropped:

- Hetzner and OVH provider APIs; AWS, GCP and Azure connectors
- Vercel API deployments and status (API-only resources)
- Cloudflare DNS and Tunnel management
- Podman; Kubernetes read-only context
- Optional outbound node agent
- Headscale, Tailscale and WireGuard onboarding helpers
- Scheduled maintenance and security-only unattended updates
- Canary and blue-green strategies
- Notification integrations
- External secret managers
- Multi-user teams and SSO refinements
- HA control plane, only if real demand justifies the complexity

## Human-gated items

These cannot be completed by code alone and block specific milestones. The [release checklist](docs/release-checklist.md) holds the full list as numbered rows, each with a procedure; this table is the summary:

| Item | Needed before | Owner |
|---|---|---|
| M6 release gate: first tag and the gates on a real run, real Debian 13 VM, Intel Mac, upgrade from a signed release, first GitHub run of the lifecycle jobs, Homebrew tap, GitHub repository settings, legal reading of the notices, nightly results ([manual-checks/m6-release.md](docs/manual-checks/m6-release.md)) | First release | Maintainer |
| Real MCP clients (Claude Code and Claude Desktop over stdio, MCP Inspector against `/mcp`) and a real authorization server (including RFC 8707 `resource` at authorization and token exchange), following [manual-checks/m5-real-mcp-clients.md](docs/manual-checks/m5-real-mcp-clients.md); each row needs dated, versioned evidence | M5 acceptance, V1 | Maintainer |
| Real-GitHub acceptance run (GHCR, real attestations in a public and a private repository, real Actions OIDC, redirect behaviour, GitHub TUF anchor and refresh), following [manual-checks/m4-real-github.md](docs/manual-checks/m4-real-github.md); fills the GitHub rows of [compatibility.md](docs/compatibility.md#deployments-m4) | M4 acceptance, V1 | Maintainer |
| Real-Proxmox acceptance run on a supported PVE 9.x host, following [manual-checks/m3-real-pve.md](docs/manual-checks/m3-real-pve.md); fills the real-host column of [compatibility.md](docs/compatibility.md) | M3 acceptance, V1 | Maintainer |
| Release signing key generated, stored in the protected `release` environment (owner as required reviewer), public key embedded in `install.sh` and `scripts/join.sh`, fingerprint published out-of-band | First signed release (M2) | Maintainer |
| M2 manual checks: macOS keychain, Linux `secret-tool`, real OIDC provider, real reverse proxy, real VM install | M2 sign-off | Maintainer |
| Decision on a separate public client for the OIDC device flow (Dex leaks the client secret) | Production use of the device flow | Maintainer |
| Project name and trademark check (GitHub, registries, domain, trademark) | First public release | Maintainer |
| License confirmation (Apache-2.0 by default) and dependency license scan | First public release | Maintainer |
| Replacement of the `<ORG>` placeholder in installer URLs | First release | Maintainer |
| Dedicated security contact address | First release | Maintainer |
