# SuperMgmt

**Your infrastructure, one control plane.**

[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)](docs/project-status.md)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Pre-alpha. No stable release yet: build `sm` from source.** Pre-releases may exist, but the installer has not been verified on a clean machine. Proxmox, GitHub and MCP clients were tested only against fakes. What is verified, and how: [Project status](docs/project-status.md).

SuperMgmt is a local-first, terminal-first control plane for the machines and services you run yourself. You add Linux machines over SSH, see their systemd services and Docker containers, read their logs and act on them from a fast terminal UI or the `sm` command line. AI agents can reach the same operations through MCP, under the same policy and approvals as you.

Nothing of SuperMgmt runs on the machines you manage, and your workloads never depend on it to keep running.

## Documentation

The website, **https://autarquico.github.io/supermgmt/**, is built from release tags and is not published until the first one. The same pages are here in [`docs/`](docs/):

- [Overview](docs/overview.md): what it does and what it is not.
- [Getting started](docs/getting-started.md): build `sm` and manage your first machine from your laptop.
- [Concepts](docs/concepts.md): nodes, plans, approvals, jobs and environments.
- [Using the TUI](docs/tui.md), [CLI reference](docs/cli.md), [Policies and approvals](docs/policies.md), [AI agents with MCP](docs/mcp.md).
- [Security](docs/security.md): the trust boundaries, before you point it at a machine you care about.
- [Project status and what is verified](docs/project-status.md).

## What it does

- **Manages Linux machines without an agent.** It connects with the machine's own `sshd`, pins the host key the first time, and after a one-off setup works through a dedicated unprivileged account with a narrow sudoers file.
- **Shows what runs there.** systemd units, Docker containers and their logs, gathered by read-only probes.
- **Changes things only through plans.** Every change becomes a plan with a hash. Policy decides whether it may run; in a production environment it waits until someone approves that exact plan.
- **Records everything** in an append-only audit trail, with secrets redacted.
- **Treats AI agents as clients, not operators.** An MCP client can never approve anything, and write tools are off unless you turn them on.
- **Deploys Docker Compose apps from CI**: only a commit that passed CI and an image digest CI attested, with health checks and rollback.
- **Optionally runs as a server** over HTTPS with tokens and OIDC login, or as an unprivileged container on Proxmox VE.

The terminal UI has screens for the dashboard, resources, nodes, services, logs, jobs, approvals, events, applications and deployments, plus read-only Providers and Settings screens; see [Using the TUI](docs/tui.md).

## Quick start

You need macOS or Linux, Go 1.27.3 or newer, `git`, and an SSH key in your SSH agent. No server and no account.

```bash
git clone https://github.com/autarquico/supermgmt.git
cd supermgmt
make build                      # or: go build -o dist/sm ./cmd/sm
export PATH="$PWD/dist:$PATH"
sm version
```

Register your laptop as a read-only node and open the terminal UI:

```bash
sm nodes add --local
sm                              # press ? for help, q to quit
```

Add a Linux machine over SSH, set it up and approve the setup:

```bash
sm nodes add --name web1 --host 203.0.113.10 --admin-user root
                                # compare the SHA256 fingerprint, then type yes
sm nodes setup web1             # shows the plan; setup waits for approval
sm approvals
sm jobs approve <job-id> --plan-hash <hash>
```

The first command that needs the daemon starts it. Every step, what setup changes on the machine and how to undo it: [Getting started](docs/getting-started.md).

## How it works

One process, the daemon, owns all state. The terminal UI, the CLI and the MCP bridge are clients of its API: on a laptop, a Unix socket only you can reach; on a server, HTTPS.

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

More: [Concepts](docs/concepts.md) and [Architecture](docs/architecture.md).

## Security model

Summary only; read [Security](docs/security.md) before you rely on it.

- Default deny: nothing is allowed unless a policy rule grants it, and any matching deny wins.
- Approvals bind to the hash of the exact plan; changing any input invalidates them. Operational writes in a `production` environment wait for approval.
- Audit events are append-only; secrets are redacted before they reach logs or events.
- Local mode trusts code running as the same OS user: the daemon socket accepts that user only.
- Nodes: the pinned host key is the only trust anchor, remote output is sanitized, and commands come from a fixed catalog. After setup SuperMgmt holds no standing root on a node.
- The `journal-group` log mode lets the node credential read the node's entire system journal. Docker access is root-equivalent. Granting restart on a unit trusts everything that unit executes.
- The key files in `security.keys_dir` are not in the database or in backup archives and must be backed up separately (`sm secrets export-key`). Archives are not encrypted.
- MCP content is untrusted input. An MCP identity can never approve, reject or resolve plans or jobs, and can never mint credentials. Tool output redacts a fixed set of secret patterns only; unknown secrets in remote text are not detected.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Platforms

`sm` builds for Linux and macOS, amd64 and arm64. Managed nodes are Linux machines with systemd, reached over SSH; the tests use Debian 13 and Ubuntu 24.04, and other distributions are untested. Proxmox VE support covers 9.x on amd64 only, against a simulator. Per-platform, per-operation evidence: [Compatibility](docs/compatibility.md#platforms-and-operations).

There is no stable release, no Homebrew formula and no Linux packages yet. Installing a server or the Proxmox appliance needs a signed release; pre-releases may exist, but the installer has not been verified on a clean machine until [Project status](docs/project-status.md) says so ([Installation](docs/installation.md)).

## Project

- [Roadmap](ROADMAP.md): what stands between the code and a first release.
- [Changelog](CHANGELOG.md).
- [Contributing](CONTRIBUTING.md) (setup, `make` targets, tests), [Governance](GOVERNANCE.md), [Code of conduct](CODE_OF_CONDUCT.md).

## License and trademark

Licensed under Apache-2.0; see [LICENSE](LICENSE). "SuperMgmt" is a working name: trademark and name availability have not been confirmed, and the name may change before the first release. No affiliation with, or endorsement by, any third-party product named in this document (Proxmox, Docker, GitHub, Cloudflare and others) is implied; all trademarks belong to their owners.
