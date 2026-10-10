# Roadmap

Status as of 2026-10-10. The project is **pre-alpha**; nothing is released. Milestones follow `docs/spec/SUPERMGMT-SPEC.md` §31 and each depends only on earlier ones.

Statuses: **in progress**, **planned**, **done**.

## Committed for V1

| Milestone | Scope | Status |
|---|---|---|
| M0 Repository and core | Go module, strict config, audit and redaction, SQLite and migrations, domain model, action catalog and policy engine, canonical plans and approvals, durable job engine, offline CLI (`version`, `completion`, `config validate`, `doctor --offline`), CI | **In progress.** Domain, errors, config, audit, database, plans and policy are merged; the job engine, `sm config validate` and `sm doctor --offline` are not yet merged. |
| M1 Local daemon, SSH, TUI alpha | `sm daemon` with Unix socket API, typed client, local provider, agentless SSH nodes, systemd and Docker discovery and logs, policy-gated service actions, TUI | Planned |
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
