# ADR-0043: SuperMgmt is an operations plane, not a deployer

- Status: Accepted
- Supersedes: ADR-0011, ADR-0028, ADR-0029, ADR-0041, ADR-0042
- Amends: ADR-0040

## Context

SuperMgmt's purpose is to manage all of one's infrastructure from a single point, from anywhere over the internet: add any node, reach it (directly or through Cloudflare Tunnel), discover what runs there and maintain it.

M4 added a second purpose: owning how applications reach the nodes. The deployment engine binds a CI commit to image digests, freezes a Compose model through a closed allowlist and runs, health-checks and rolls back deployments; app move builds on it to redeploy a target on another node.

Testing v0.1.0-rc.4 against a real project (Autarquico/bisne) showed the cost of that second purpose. Its production Compose file cannot deploy unchanged: the allowlist refuses its project name, its hardening keys (`security_opt`, `cap_drop`), a read-only bind mount, a `profiles`-based migration job, short port syntax and its several CI-built images. Every one of these could be "fixed" in the project, and that is the problem: a deployer makes projects adapt to it. Projects already have CI/CD that knows how to deploy them.

## Decision

### Scope

SuperMgmt reads and operates what exists. The project's CI/CD writes the desired state.

In scope:

- Nodes: add, reach (SSH, tunnel, enrollment without inbound ports), inventory, setup of the dedicated account, health.
- Providers: Proxmox discovery and power.
- Discovery of what runs on a node, without declaring it in SuperMgmt: systemd units, containers and Compose projects with their services, volumes and published ports.
- Maintenance of discovered components: logs, start/stop/restart, audited exec, connections to their databases through the node's transport. On-demand backups later (parked, see below).
- Access from anywhere: `sm ssh` through Cloudflare Access, publishing a node port through the node's tunnel.
- Governance on all of the above: policy, approvals, audit, MCP with its floor.

Out of scope:

- Building, deploying, rolling back or moving applications.
- Owning or validating a project's Compose file, images or CI policy.

### What the operator sees

- **Overview panel:** the machines, the apps discovered on each (a Compose project is an app; its containers are its components), and per app its health and activity: container state and restarts, resource use over time, error rate from its logs, and the state of its external checks (healthchecks.io first).
- **App panel, in the spirit of lazydocker:** one app's insides: components, their logs (live and searchable), resource stats, configuration, volumes and published ports, with restart, exec and database connection as governed actions.
- **The same through MCP, with priority:** every read and action of both panels is an MCP tool, so an AI can answer free-form questions about an app (for example, "review the reservit app and tell me whether anything has been failing") from its logs, stats and checks. This makes [#63](https://github.com/Autarquico/supermgmt/issues/63) and the built-in assistant of [#64](https://github.com/Autarquico/supermgmt/issues/64) part of this scope. Reading an app's logs through MCP then has to be grantable by default for owners' own clients, behind the redaction boundary in `docs/mcp.md`.

### How it is built

- **Statistics are read on demand, with no history.** The panels and MCP read the node at the moment of asking (container state, restarts, resource use, recent logs); SuperMgmt stores no time series. Questions about the past are answered from what the node and the external checks keep.
- **External checks are read and created.** For healthchecks.io SuperMgmt lists an app's checks and their recent pings, and can create a check for an app (an approved action) and hand its ping URL to the operator.
- **Existing tooling first.** SuperMgmt drives tools already on the node or already offered by the service (the container runtime's CLI, `journalctl`, the healthchecks.io API, and when backups come, each database's own dump tool) instead of reimplementing them.
- **Database backups are parked.** Connecting to a database is in scope; backups are not part of the first version.

### Removed

- The deployment engine, deployments and rollbacks (ADR-0011, ADR-0029): `sm deployments`, `internal/deployments`, the Compose allowlist and normalisation.
- The GitHub connector as a deployment input (ADR-0028): CI policy, check and attestation binding.
- App targets as deployment units and app move, with or without routes (ADR-0041, ADR-0042): `sm apps move`, `moves`, cleanup and abandon.

Migrations drop the tables these features own. Their audit events stay readable in the audit log.

### What remains for deployments: hooks for CI/CD

SuperMgmt may provision, on a node it manages, what a project's CI/CD needs to deploy there, and nothing more: a deploy account restricted to its purpose, its authorised key, a deploy directory, membership of the container runtime group when asked, and, for a tunnel node, the Access service token CI/CD uses to reach it. Provisioning is a node setup action under approval; the deployment itself always runs from CI/CD.

### Publishing through the tunnel (amends ADR-0040)

A route publishes a port of a node, not a service of a deployment: `hostname → node, port, access (public | owners)`. It no longer waits for a succeeded deployment; it is active once the ingress, the Access application (owners) and the DNS record exist, in the order ADR-0040 fixes.

## Consequences

- Projects deploy as they are; SuperMgmt never asks them to change.
- A large, experimental part of the code is deleted. It was only tested against fakes and has no users, so removing it before 1.0 is cheap.
- Policy, approval, audit and MCP apply unchanged to the actions that remain.
- Rollbacks and data moves become the responsibility of each project's CI/CD and runbooks; SuperMgmt supports them only through backups and exec.
- `docs/manual-checks/app-expose-tunnel.md` must be rewritten for node routes; `app-move.md` and `m4-real-github.md` are retired.

## Open questions

- Which databases the first version of "connect" supports (proposal: PostgreSQL first, discovered from a container's image).
- Which external check services come after healthchecks.io.
- Apps that are not Compose projects (a systemd service, a plain container): whether they are apps too, and how they are grouped.
