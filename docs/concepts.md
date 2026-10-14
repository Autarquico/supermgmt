# Concepts

The words these pages use, in the order you meet them. Each entry says what the thing is and where it matters.

## The control plane

**Daemon.** The one process that owns SuperMgmt's state: the database, the job workers and the connections to your machines. Everything else is a client of its API. On a laptop the first command that needs it starts it, and it exits after a period with nothing to do. A job waiting for approval keeps it running.

**Client.** The terminal UI (`sm` or `sm tui`), the CLI (`sm <command>`) and the MCP bridge (`sm mcp`). None of them holds state; each talks to the daemon.

**Local mode.** The default. The daemon serves a Unix socket that only your OS user can reach, and you are its administrator. Anything running as your user can drive it, so local mode does not defend against malicious software under your account.

**Server mode.** The same daemon serving an HTTPS API, so several people and clients share one control plane. Every request carries a bearer token: a session from an OIDC login, or an API token. See [Installation](installation.md) and [Operations](operations.md).

**Profile.** A named connection from a client to a server. `sm login` creates the credentials; without a profile, clients talk to the local daemon.

## What you manage

**Node.** A machine SuperMgmt knows about: a Linux machine over SSH, the machine running `sm`, or a Proxmox VE host, VM or container.

**Provider.** A source of nodes or of data about them. `ssh` and `local` give you nodes; `proxmox` discovers a cluster; `github` gives repositories, CI results and attestations, not nodes. See [Providers](providers.md).

**Local node.** The machine running the daemon, registered with `sm nodes add --local`. It is read-only: SuperMgmt never changes anything on it.

**Agentless.** Nothing of SuperMgmt runs on a managed machine. It connects with the machine's own `sshd`, using the system OpenSSH client for interactive sessions and a fixed catalog of commands for automated work.

**Pinned host key.** The SSH host key you confirmed when you added a node. It is the only key accepted from that node afterwards; a different key fails the connection until you re-pin it on purpose with `sm nodes repin`.

**Admin user.** Your own account on a node (`--admin-user`). SuperMgmt uses it, through your SSH agent, for read-only probes before setup, for setup itself and for interactive sessions.

**Node setup.** A one-off job that creates the dedicated `supermgmt` account on a node, authorizes SuperMgmt's SSH key for it, writes a narrow sudoers file and verifies the result. After setup, automated work uses that account and SuperMgmt holds no standing root on the node. Without setup a node is read-only.

**Service.** Something running on a node that SuperMgmt can see: a systemd unit or a Docker container. Service actions are `start`, `stop` and `restart`.

**Environment.** A label such as `staging` or `production` that you attach to nodes and apps. Its `risk_level` (`development`, `staging` or `production`) drives policy: in `production`, operational writes wait for approval by default.

## How a change happens

Every change follows the same path, whoever asks for it: you in the TUI, a script on the CLI, or an AI agent over MCP.

```text
request ─► plan ─► policy ─► job ─► (approval) ─► run ─► audit
```

**Plan.** The exact description of a change: the action, its targets and every input that could change what runs, including the revision of each resource involved. Observations, timestamps and secrets never enter a plan.

**Plan hash.** A SHA-256 hash of the plan in a canonical form. Two identical plans have the same hash; any changed input gives a new one.

**Policy.** The rules that decide whether an actor may run an action on a resource. Nothing is allowed unless a rule allows it, and any matching deny wins over every allow. A built-in policy applies until you supply your own. See [Configuration](configuration.md).

**Action.** One entry of SuperMgmt's closed action catalog, such as `service.restart`, `node.setup` or `deployment.create`. Each has a risk class that policy takes into account: a high-risk change such as `node.setup` waits for approval whatever the rules say.

**Approval.** A decision by an authorized person that a waiting job may run. It is bound to the plan hash: change the plan and earlier approvals no longer apply. Approvals expire, and a quorum counts distinct approvers. In local mode you may approve your own plans; that is a setting (`security.allow_self_approval`).

**Job.** The durable execution of an approved plan. Its states are `awaiting_approval`, `queued`, `running`, `succeeded`, `failed`, `cancelled` and `interrupted`. Before running, a job re-checks everything its plan depended on; if anything changed, it fails as stale instead of doing something nobody approved.

**Interrupted job.** A job whose worker stopped mid-way, for example because the daemon was killed. SuperMgmt acts on it only with evidence of what happened on the node; without evidence it stays interrupted, with its locks held, until a person resolves it with `sm jobs resolve`. It never re-runs a change blindly.

**Audit event.** A record of a request, a decision or a job transition, with the actor, the resource and a correlation ID. The event log is append-only, denied requests are recorded too, and secrets are redacted before anything is written.

## Identities and secrets

**Actor.** Who asks: a human, an automation identity (such as a CI workflow), an MCP client, or the system itself.

**MCP client.** An AI tool registered with `sm mcp clients add`. It gets its own identity with no roles, can never approve, reject or resolve anything and can never create credentials. Write tools are off unless `mcp.write_tools_enabled` is true. See [MCP](mcp.md).

**Instance SSH identity.** The Ed25519 key pair SuperMgmt authenticates with as the `supermgmt` account on nodes. `sm ssh-key show` prints its public half.

**Master key (KEK).** A key file that encrypts every secret SuperMgmt stores, including the instance SSH identity. It lives outside the database and outside backup archives, so back it up separately with `sm secrets export-key`. A lost master key cannot be recovered.

## Apps and deployments

**App.** One Docker Compose application: the service to deploy, where its Compose file comes from, which images are allowed and which CI checks must pass.

**App target.** An app bound to one environment and one node.

**Deployment.** One request to put a commit's images on a target. SuperMgmt deploys only a commit whose required CI checks passed and image digests CI built; it takes a backup first when configured, checks health afterwards and rolls back when the checks fail.

**Rollback.** A deployment that restores the versions of an earlier known-good deployment.

See [Applications and deployments](deployments.md).

## References

- [Architecture](architecture.md): the process model, the policy and job flow in detail.
- [Security](security.md): the trust boundaries and threat model.
- Decision records: [job state machine](adr/0013-generic-job-state-machine.md), [node provisioning](adr/0009-node-provisioning.md), [daemon process model](adr/0005-daemon-process-model.md).
