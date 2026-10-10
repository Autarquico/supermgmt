# Roadmap

Status as of 2026-10-10. The project is **pre-alpha**; nothing is released. Milestones follow `docs/spec/SUPERMGMT-SPEC.md` §31 and each depends only on earlier ones.

Statuses: **in progress**, **implemented** (merged, pending release-level review), **planned**.

### M1 accepted scope and honest deferrals

M1 TUI screens: Dashboard, Resources tree, Node detail, Service list and detail, Logs, Jobs, Approvals, Events, Help. The palette supports ssh, logs, services, refresh, setup and probe. Not in M1:

- Applications, Deployments and the Wizard screens: M4. Providers and Settings screens: M2.
- SSE: M2; the TUI polls in tiers.
- SSH CA trust, the secrets CLI and `secret.write`, identity rotation, per-node keys, key export: M2. `ssh.known_hosts_file` is unused.
- `sm daemon install-user-unit` and resident schedules: M2, with backups.
- The metrics endpoint (SPEC §33): not built.
- Scale: the 500-node target is shown with fakes and benchmarks, not with real nodes.
- Peer-credential refusal of another user: Linux CI only; macOS relies on the same-UID test and a manual check.
- Terminal restore after an interactive handoff: PTY tests plus the manual checklist; real emulators are not automated.
- lazydocker: offered only as `ssh -t ... lazydocker` on the node (never installed); no local lazydocker over an SSH Docker context.
- Local provider: read-only; macOS has no systemd.
- `node.setup`: no `deploy_root` (M4), no automated teardown, no server-mode key authorization (M2), no standalone `sudoers.write` or `log_broker.install` jobs (re-run setup instead).
- `sm doctor` without `--offline`.

## Committed for V1

| Milestone | Scope | Status |
|---|---|---|
| M0 Repository and core | Go module, strict config, audit and redaction, SQLite and migrations, domain model, action catalog and policy engine, canonical plans and approvals, durable job engine, offline CLI (`version`, `completion`, `config validate`, `doctor --offline`), CI | **Implemented** on `feat/m0-core`: domain, errors, config, audit, database, plans, policy, application services, job engine and the four offline commands, with integration and spec-example tests. Pending final review. |
| M1 Local daemon, SSH, TUI alpha | `sm daemon` with Unix socket API, typed client, local provider, agentless SSH nodes with `node.setup`, systemd and Docker discovery and logs, policy-gated service actions, TUI | **Implemented** on `feat/m1-local-ssh-tui`: pending the manual terminal checklist ([docs/manual-checks/m1-handoff.md](docs/manual-checks/m1-handoff.md)) and release-level review. Accepted scope and deferrals below. |
| M2 Server, client, auth, release pipeline | HTTPS API, sessions and tokens, OIDC, client profiles, SSE, secrets store, GoReleaser with checksums, signatures, SBOM and provenance, `install.sh`, backup and restore | Planned |
| M3 Proxmox provider and appliance installer | Proxmox discovery, `sm install proxmox-lxc` with rollback journal, restricted credentials, power actions, upgrade and uninstall | Planned |
| M4 Apps, GitHub, deployments | GitHub connector, app manifest, CI-gated Docker Compose deployments, health checks, rollback | Planned |
| M5 MCP | MCP client registration, stdio bridge, remote MCP as OAuth protected resource, read tools, plan submission, optional write tools off by default | Planned |
| M6 Hardening and release | Packaging, fuzz and race tests, security scans, compatibility matrix, beta migration tests, E2E across all modes | Planned |

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

These cannot be completed by code alone and block specific milestones:

| Item | Needed before | Owner |
|---|---|---|
| Real-Proxmox acceptance run on a supported PVE host | M3 acceptance, V1 | Maintainer |
| Release signing key generated, stored in the protected release environment, fingerprint published out-of-band | First signed release (M2) | Maintainer |
| Project name and trademark check (GitHub, registries, domain, trademark) | First public release | Maintainer |
| License confirmation (Apache-2.0 by default) and dependency license scan | First public release | Maintainer |
| Replacement of the `<ORG>` placeholder in installer URLs | First release | Maintainer |
| Dedicated security contact address | First release | Maintainer |
