# Roadmap

Status as of 2026-10-15. SuperMgmt is **pre-alpha, with no stable release yet.** The first pre-release, [`v0.1.0-rc.1`](https://github.com/autarquico/supermgmt/releases/tag/v0.1.0-rc.1), is published and signed. Its installer ran on one clean Intel Mac in local mode (2026-10-15), and a second Mac was added as an SSH node from it; a Linux install from a published release is still open, so building from source stays the recommended path. The website is live at <https://autarquico.github.io/supermgmt/>. The code for the first version is written and merged, and waits for release-level review. What stands between it and a first release is mostly work that needs a person, a real host or a real account.

What is verified today, claim by claim, is on one page: [Project status](docs/project-status.md). This page says what is built, what is left and what is deliberately not built.

## Before the first release

These cannot be completed by code alone. The [release checklist](docs/release-checklist.md) holds the full list as numbered rows, each with an owner and a procedure; this table is the summary. Done so far: the release signing key, the first tag run (`v0.1.0-rc.1`), the first nightly run and a first clean-machine install on an Intel Mac; none of the rows below is complete.

| Item | Needed before | Owner |
|---|---|---|
| Release gate: a person checks the first tag run (`v0.1.0-rc.1`: gates, notices, SBOM, provenance, channel pointer, yank), a clean-machine install from the published pre-release, a real Debian 13 VM, an Intel Mac, an upgrade from a signed release, the Homebrew tap, the GitHub repository settings, the legal reading of the notices, a read of the first week of nightly results ([checklist](docs/manual-checks/m6-release.md)) | First release | Maintainer |
| Real MCP clients (Claude Code and Claude Desktop over stdio, MCP Inspector against `/mcp`) and a real authorization server, including RFC 8707 `resource` at authorization and token exchange ([checklist](docs/manual-checks/m5-real-mcp-clients.md)); each row needs dated, versioned evidence | MCP acceptance, first version | Maintainer |
| Real-GitHub run: GHCR, real attestations in a public and a private repository, real Actions OIDC, redirect behaviour, the GitHub TUF anchor and refresh ([checklist](docs/manual-checks/m4-real-github.md)); fills the GitHub rows of [Compatibility](docs/compatibility.md) | Deployments acceptance, first version | Maintainer |
| Real-Proxmox run on a supported Proxmox VE 9.x host ([checklist](docs/manual-checks/m3-real-pve.md)); fills the real-host column of [Compatibility](docs/compatibility.md) | Proxmox acceptance, first version | Maintainer |
| Server-mode checks: macOS keychain, Linux `secret-tool`, a real OIDC provider, a real reverse proxy, a real VM install ([checklist](docs/manual-checks/m2-handoff.md)) | Server-mode sign-off | Maintainer |
| Terminal emulators: the interactive handoff on real terminals ([checklist](docs/manual-checks/m1-handoff.md)) | TUI sign-off | Maintainer |
| Decision on a separate public client for the OIDC device flow (Dex leaks the client secret) | Production use of the device flow | Maintainer |
| Project name and trademark check (GitHub, registries, domain, trademark) | First public release | Maintainer |
| Licence confirmation (Apache-2.0 by default) and dependency licence scan | First public release | Maintainer |
| Dedicated security contact address | First release | Maintainer |

## What is built

Statuses: **implemented** (merged and tested, pending release-level review), **planned**, **not scheduled**.

| Area | Scope | Status |
|---|---|---|
| Core | Strict configuration, audit and redaction, SQLite and migrations, domain model, action catalog and policy engine, canonical plans and approvals, durable job engine, offline commands (`version`, `completion`, `config validate`, `doctor --offline`), CI | **Implemented** |
| Local daemon, SSH nodes and TUI | `sm daemon` with a Unix-socket API and typed client, local provider, agentless SSH nodes with `node.setup`, systemd and Docker discovery and logs, policy-gated service actions, the TUI and the CLI | **Implemented**; the terminal-emulator checklist is open |
| Server, client, auth and releases | HTTPS API, sessions and tokens, OIDC, client profiles, SSE, secrets store, signed release pipeline with checksums, SBOM and provenance, `install.sh`, backup and restore, join | **Implemented**; the server-mode checks and the production release key are open |
| Proxmox and the appliance installer | Proxmox discovery, power actions, restricted credentials, `sm install proxmox-lxc` with a rollback journal, upgrade and uninstall | **Implemented** against a simulated Proxmox host; the real-host run is open |
| Apps, GitHub and deployments | GitHub connector, app manifest, CI-gated Docker Compose deployments, health checks, rollback | **Implemented** against a fake GitHub, a virtual Sigstore and a local registry; the real-GitHub run is open |
| MCP | MCP client registration, stdio bridge, remote MCP as an OAuth protected resource, read tools, plan submission, optional write tools off by default | **Implemented** against the Go SDK client, raw JSON-RPC goldens and a fake authorization server; the real-client run is open |
| Hardening and release | Fuzz and race tests, security scans, compatibility matrix, migration tests, lifecycle tests across modes, the release gate | **Implemented**; the human rows of the release checklist are open |
| Website and documentation | A static site built from `docs/`, a getting-started path, TUI and policy guides, a generated CLI reference, one status page | **Implemented** and published: content from the latest release tag, site tooling from `main`, so a website fix never needs a release |

"Done" for the first version means: install without cloning, a one-command Proxmox LXC, agentless SSH nodes, Proxmox, systemd and Docker discovery, the TUI, CI-gated Compose deploys with safe rollback, an audit timeline, remote server mode, MCP with approvals, tested backup, restore, upgrade and uninstall, and signed releases.

### What CI has run

- `ci` on `main` at `90a2fc5`: every job passed ([run 38599733425](https://github.com/autarquico/supermgmt/actions/runs/38599733425)), including the lifecycle jobs on Ubuntu 24.04 amd64 and arm64 and macOS 15 arm64, the upgrade crash test and chain, and the deployment, MCP, appliance, fixture and website suites.
- `nightly`, first run, at `90a2fc5`: passed ([run 38604246178](https://github.com/autarquico/supermgmt/actions/runs/38604246178)): fuzzing shards, race stress, the TUI flake loop (90 runs on macOS) and the daemon-restart flake loop (150 runs).
- `release` on the tag `v0.1.0-rc.1`: gates, build and the approved signing job passed ([run 38613847284](https://github.com/autarquico/supermgmt/actions/runs/38613847284)). Its artefacts have not yet been checked by a person.
- `pages`: the site built from `v0.1.0-rc.1` is published ([run 38640604619](https://github.com/autarquico/supermgmt/actions/runs/38640604619)).

## Known limits, by area

Listed rather than hidden. Most are also on the [Project status](docs/project-status.md) page or in the [release checklist](docs/release-checklist.md#unresolved-items-and-stated-limitations).

### Local daemon, SSH nodes and TUI

- `node.setup` from the CLI or the TUI grants no systemd unit yet, so a unit restart after setup is refused. Container actions work with `--docker-access`.
- No automated node teardown (manual steps in [Security](docs/security.md)), and no standalone `sudoers.write` or `log_broker.install` jobs: re-run setup instead. Whether setup from a server works against a real node was not verified.
- SSH CA trust and per-node keys: not scheduled. `ssh.known_hosts_file` is only the file that goes into a backup.
- The local TUI polls in tiers; remote profiles use SSE. There is no `sm daemon install-user-unit`; a resident daemon is `sm install local --resident`.
- Scale: the 500-node target is shown with fakes and benchmarks, not with real nodes.
- Refusal of another local user on the socket is tested on Linux CI only; macOS relies on the same-UID test and a manual check.
- Terminal restore after an interactive handoff is covered by PTY tests and a manual checklist; real terminal emulators are not automated.
- lazydocker is offered only as `ssh -t ... lazydocker` on the node and is never installed.
- The local provider is read-only; macOS has no systemd.
- The Providers and Settings screens of the TUI are read-only.

### Server, client, auth and releases

- **Clean Debian VM acceptance: amended and deferred.** The CI gate is a Debian 13 container with systemd; a real VM run is not done.
- **Production signing and provenance: unverified by a person.** The release key exists and signed `v0.1.0-rc.1` in a protected tag build; nobody has yet verified that release's signatures, SBOM and provenance from outside (release checklist H2).
- Identity providers: Dex only, exercised by hand. Dex puts the client secret in the device-flow verification URL; a dedicated public device client needs a new configuration key and a spec change.
- Cloudflare: a guide only, never run against a real account. No edge assertion is consumed.
- macOS keychain and Linux `secret-tool` credential stores: unit-tested with fakes, manual checks pending.
- The orphan-key report in `sm doctor` is not built.
- The installer requires OpenSSH 8.2 or newer; the spec says 8.1.

### Proxmox and the appliance installer

- **No real Proxmox host was used.** Every Proxmox interaction is verified against fakes built from the documentation; each assumption is a row of [Compatibility](docs/compatibility.md) and an item of the [real-host checklist](docs/manual-checks/m3-real-pve.md). Unconfirmed: the task list `total` and paging, the status of a running task, which verbs and guest types accept `timeout`, `/access/permissions` value semantics (0-valued and non-propagating grants, deeper-ACL replacement), the text of the error for a migrated guest, `pct list` columns, `pvesm`/`pvesh` JSON, `pct push` uid mapping, `runuser` and `pct exec` exit codes in the Debian 13 template, the template name `pveam` offers, and a full install, upgrade and uninstall on Proxmox VE 9.
- Proxmox VE 8.x and arm64 hosts are unsupported (Proxmox VE 8 reached upstream end of life in 2026-08).
- Proxmox roles carry no comment field, so rollback recognises them by name only; the token comment marker is unverified against a real `pveum` listing.
- A guest recreated with the same type, VMID and name between two syncs still receives an approved power action.
- The task-list filters `source=all` and `userfilter` were implemented from a finding's text; the Proxmox source was not read.
- The appliance certificate is self-signed with no renewal (CA 10 years, leaf 5 years) and names the address the container had at install time. `sm doctor` checks its expiry and a manual re-issue is documented; a renewal command is not scheduled.
- A guest renamed in Proxmox bumps its `spec_revision`, so pending plans for it go stale.
- An `--allow-downgrade` upgrade to a binary that predates the hardening work leaves its audit record pending until a newer binary starts.
- The end-to-end suites (`TestM3_Appliance*`, `TestM3_Upgrade*`, `TestM3_Uninstall*`, CI jobs `e2e-appliance` and `e2e-upgrade`) run in Docker with a simulated Proxmox host; the upgrade fixture is an early server build (commit `e6d5577`), so the job needs the full history.

### Apps, GitHub and deployments

- **No real GitHub was used.** GitHub REST, GHCR, Sigstore attestations (public and private repositories), the GitHub TUF anchor and refresh, Actions OIDC tokens and redirect behaviour are verified against `ghfake`, a virtual Sigstore and a local registry only. Each assumption is a row of [Compatibility](docs/compatibility.md) and an item of the [real-GitHub checklist](docs/manual-checks/m4-real-github.md). GitHub Enterprise Server is not verified.
- Docker Compose CLI **5.5.1 only**; any other version makes the node ineligible. `jq` is a required node tool and its version is not pinned.
- GitHub App installation tokens are not supported; the credential is a fine-grained read-only token.
- One target per application and environment.
- `compose_source: repository` is refused for production environments (stricter than the spec, which allows an admin exception with no defined storage).
- No environment can require an Actions `environment` claim; the spec defines no field for it.
- Health checks: `http`, `tcp` and docker-health on the node, `http(s)` from the control plane; `command-template` and `systemd-active` are rejected for app targets. Manifest health bounds (timeout at most 30 s, interval at most 1 min, at most 60 attempts) are an implementation choice, not in the spec.
- The only pre-deploy backup template is `postgres-dump`. `deployment_policy.snapshot: true` is refused ("not supported in this version").
- The disk preflight uses registry-reported sizes plus 1 GiB with no decompression safety factor; an unknown size fails the preflight.
- The pull step is proven by a `.done` marker, not a per-image inspect.
- The secret-leak scan of the end-to-end suite covers the control plane (database, logs, backup archive, API, events), not the node and not CLI stdout.
- Open review items: a locked command that exits 75 because a concurrent lock probe held the flock should be retryable; the expected-model helper is duplicated in the fixture test; the `vars` parameter of `ExpectedEnvHashes` is unused.

### MCP

- **No real MCP client and no real OAuth authorization server was used.** MCP is verified with the SDK's own client, hand-written raw JSON-RPC goldens and a fake authorization server (`oauthfake`: JWKS and introspection). Claude Code, Claude Desktop, MCP Inspector and a real authorization server (including RFC 8707 `resource` at authorization and at token exchange) stay **deferred** until the [checklist](docs/manual-checks/m5-real-mcp-clients.md) records dated, versioned evidence.
- Redaction in tool output is pattern-based (Bearer, Basic, PEM, SuperMgmt token formats, JWT-shaped values, `key=value` forms with sensitive keys, and sensitive keys in structured data). Arbitrary unknown secrets in remote text are not detected.
- By default MCP identities get no `service.logs`, so `infra_get_service_logs` is denied until a policy grants it.
- Protected-resource metadata is also served at the root well-known path as the spec names it; a strict RFC 9728 client that discovers through the root will reject it. Discovery through the `WWW-Authenticate` challenge is the supported path.
- JWT access tokens must carry `typ: at+jwt`; issuers that cannot emit it must use introspection. No dynamic client registration; clients are registered by an admin.
- No MCP resources or prompts, and no interactive exec (`mcp.allow_interactive_exec: true` is refused).
- A token consumed but not stored is recovered only by removing and re-adding the client.
- `views.go` returns nil slices and maps, which the SDK output-schema validation rejects; `tools_read.go` works around it.

### Hardening and release

- **No stable version is released;** the signed pre-release `v0.1.0-rc.1` is. The [release checklist](docs/release-checklist.md) maps each of its 52 rows to tests and jobs and lists 22 human-gated rows, all unchecked, each with an owner and a procedure.
- **Platforms.** Supported means CI runs every operation on that platform ([Compatibility](docs/compatibility.md#platforms-and-operations)): Ubuntu 24.04 amd64 and arm64 (server and local client) and macOS 15 arm64 (local client). Debian 13 is container-verified, the Proxmox appliance is fake-verified, Intel macOS is manual, and Debian as a local-client host and everything else are not claimed.
- A second, unexplained failure mode of the daemon-restart test (`TestM1_DaemonKilledMidRestartReconciles`), seen once.
- The residual of a TUI handoff that exits instantly; the case seen is fixed.
- 25 parsers have no fuzz target yet.
- The migration fixtures of the deployment and MCP stages contain no deployment and no OAuth access-token row.

## Next, proposed

| Item | Scope | Status |
|---|---|---|
| Reach nodes from any network | A per-node transport: direct SSH (today), an SSH bastion (ProxyJump), or a Cloudflare Tunnel with an Access service token, so the laptop running `sm` reaches its servers from any network without opening inbound ports. SSH stays end to end, with the pinned host key, the dedicated user, policy and approvals unchanged. `cloudflared` would run on the node (third-party, not SuperMgmt). Until then, a Tailscale or WireGuard network already works with plain SSH nodes | **Planned**; spec not written |

## Not built, after the first version

- Proxmox `POST /providers`, promotion of discovered guests, snapshot, backup, console and task-history handlers.
- A metrics endpoint, a TLS renewal command, a Cloudflare connector (`internal/providers/cloudflare`).
- Linux packages (`.deb`, `.rpm`): a package manager's upgrade would bypass the upgrade protocol.
- MCP resources and prompts.
- Several targets per environment, GitHub App tokens, Proxmox snapshot policy, `command-template` and `systemd-active` health for apps, other backup templates.

## Exploratory, not promises

None of these is scheduled and any may be dropped:

- Hetzner and OVH provider APIs; AWS, GCP and Azure connectors
- Vercel API deployments and status (API-only resources)
- Cloudflare DNS management (Tunnel transport for nodes is proposed above)
- Podman; Kubernetes read-only context
- Optional outbound node agent
- Headscale, Tailscale and WireGuard onboarding helpers
- Scheduled maintenance and security-only unattended updates
- Canary and blue-green strategies
- Notification integrations
- External secret managers
- Multi-user teams and SSO refinements
- HA control plane, only if real demand justifies the complexity

## References

- Milestones and the definition of done: [`docs/spec/SUPERMGMT-SPEC.md`](docs/spec/SUPERMGMT-SPEC.md) §31 (milestones), §43 (definition of done), §44 (exploratory ideas), Appendix E (release rows, all unchecked).
- The areas above map to the spec's milestones: Core = M0 (`feat/m0-core`), Local daemon, SSH nodes and TUI = M1 (`feat/m1-local-ssh-tui`), Server, client, auth and releases = M2 (`feat/m2-server-auth-release`), Proxmox and the appliance installer = M3 (`feat/m3-proxmox-installer`), Apps, GitHub and deployments = M4 (`feat/m4-apps-deployments`), MCP = M5 (`feat/m5-mcp`), Hardening and release = M6 (`feat/m6-hardening`). The [changelog](CHANGELOG.md) is organised by milestone.
- Release checklist finding IDs for the Proxmox residuals above: SEC-7 (roles without a marker), SEC-9 (a guest recreated between two syncs), SEC-12 (task-list filters).
- Decisions: [ADR index](docs/adr/README.md).
