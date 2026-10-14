# Overview

SuperMgmt is a local-first, terminal-first control plane for the machines and services you run yourself. You add Linux machines over SSH, see their systemd services and Docker containers, read their logs and act on them from a fast terminal UI or the `sm` command line. AI agents can reach the same operations through MCP, under the same policy and approvals as you.

> **Pre-alpha. No stable release yet.** Pre-releases may exist, but the installer has not been verified on a clean machine, so build `sm` from source. What runs, what was tested against real systems and what only against fakes is listed on one page: [Project status and what is verified](project-status.md).

## Who it is for

You, if you look after a handful of servers, a home lab or a small team's infrastructure and want one place to see and change it, without installing an agent on every machine and without handing an AI tool root on your servers.

## What it does

- **Manages Linux machines without an agent.** Nothing of SuperMgmt runs on a machine you manage. It connects with the system's own `sshd`, pins the host key the first time, and after a one-off setup works through a dedicated unprivileged account with a narrow sudoers file.
- **Shows what runs there.** systemd units, Docker containers and their logs, gathered by read-only probes. Output from the machine is bounded and stripped of terminal control sequences before you see it.
- **Changes things only through plans.** Every change (restart a service, set up a machine, deploy an app) becomes a plan with a hash. Policy decides whether it may run; in a production environment it waits until someone approves that exact plan. Change any input and the approval no longer applies.
- **Records everything.** Every request, decision and job lands in an append-only audit trail, with secrets redacted.
- **Treats AI agents as clients, not operators.** An MCP client gets its own identity, no roles by default and no way to approve anything. Write tools are off unless you turn them on.
- **Deploys Docker Compose apps from CI.** Only a commit that passed CI and an image digest CI built and attested, with a backup first, health checks after and rollback when they fail.
- **Optionally runs as a server.** The same daemon can serve an HTTPS API with tokens and OIDC login, so several clients share one control plane; it can also be installed as an unprivileged container on Proxmox VE.

Some of these were tested only against fakes (Proxmox, GitHub, MCP clients). The status page says which.

## How it works

One process, the daemon, owns all state. The terminal UI, the CLI and the MCP bridge are clients of its API. On a laptop that API is a Unix socket only you can reach; the first command that needs the daemon starts it.

```text
   TUI        CLI        MCP bridge
     \         |          /
      +--------+---------+
               |  API (Unix socket, or HTTPS in server mode)
        +------v-------+
        |    daemon    |  policy -> plan -> approval -> job
        |  audit · SQLite · reconciler
        +------+-------+
               |  connectors
     +---------+----------+-----------+
     |         |          |           |
    SSH     Proxmox    GitHub      Docker Compose
  (nodes)   VE API     API         on nodes over SSH
```

Your workloads never depend on SuperMgmt to keep running: if the daemon stops, nothing on your machines changes.

The words used across these pages (node, plan, approval, job, environment) are defined in [Concepts](concepts.md).

## What it is not

- Not a monitoring system: there is no metrics endpoint and no alerting.
- Not a hosted service: there is no account, no telemetry and no update check. The outbound connections it can make are listed in [Dependencies and egress](dependencies.md#egress).
- Not finished: see [Project status](project-status.md) for what is missing.

## Next steps

- [Getting started](getting-started.md): build `sm` and manage your first machine from your laptop.
- [Concepts](concepts.md): the vocabulary in one page.
- [Security](security.md#trust-boundaries-in-one-page): the trust boundaries, before you point it at a machine you care about.
- [Project status](project-status.md): what is verified and what is not.

## References

- [README](../README.md)
- [Architecture](architecture.md)
- Licence: Apache-2.0 ([LICENSE](../LICENSE)). "SuperMgmt" is a working name: trademark and name availability have not been confirmed, and the name may change before the first release.
