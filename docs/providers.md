# Providers

A provider is a source of nodes. M1 has two: **ssh** (a Linux machine reached over SSH) and **local** (the machine running `sm`). Proxmox is planned for M3 and is not described here as available. Sources: SPEC §6.4, §12, §14; [ADR-0009](adr/0009-node-provisioning.md), [ADR-0015](adr/0015-ssh-transport-and-command-templates.md).

## SSH nodes (agentless)

Nothing of SuperMgmt runs on the node. It is reached with the system's own `sshd`, through two accounts:

| Account | Setting | Used for |
|---|---|---|
| Your own account | `admin_user` (required) with `admin_credential_ref` (default `ssh-agent://default` in local mode) | read-only probes before setup, `node.setup` itself, interactive sessions |
| The dedicated account | `user` (default `supermgmt`) with `credential_ref` (default `secret://ssh/default`, the instance identity) | every automated session after setup |

The rule (ADR-0009): automated sessions use the dedicated user if and only if the node has completed `node.setup`; otherwise they use `admin_user`, for read-only probes only.

### Add a node

```bash
sm ssh-key show                      # optional: the public key SuperMgmt will authorize
sm nodes add --name web1 --host 203.0.113.10 --admin-user root
```

`--name`, `--host` and `--admin-user` are required; `--port` (default 22), `--environment` and `--tag` are optional. `sm nodes add` scans the host key and prints its SHA256 fingerprint. Nothing is trusted until you confirm it, by typing `yes` or by passing `--fingerprint SHA256:...` that you checked out of band. The confirmed key is stored and is the only key accepted from then on.

`--user` defaults to `supermgmt`: that is the account setup will create, not the one used to add the node. Until setup the node is read as `--admin-user`.

Probe it and look at what was found:

```bash
sm nodes probe web1
sm nodes get web1
sm services list web1
```

A node can also be declared in the configuration file (`providers:` with `type: ssh`, see [configuration.md](configuration.md)). The daemon applies the file's environments and SSH providers when it starts, as the `system` actor; a change bumps the node's `spec_revision` (so older plans go stale) and is audited, a provider removed from the file retires its node, and nodes created through the API are never touched.

### Set up a node

Without setup a node is read-only. Starting, stopping and restarting services, restricted log modes and Docker container actions all need `node.setup`. In M1 you start it from the TUI palette (there is no CLI command for it):

```text
/ setup web1                  logs via the journal group, no Docker
/ setup web1 docker           also join the docker group (root-equivalent)
/ setup web1 broker           logs through the root-owned broker instead of the journal group
```

The palette opens a plan that names the bootstrap identity and, for `docker`, shows the warning that the docker group is equivalent to root. Confirm it with `y`. The setup job is approval-gated; approve it from the Approvals screen (`4`, then `A`) or with `sm jobs approve`. `docker_access` has no default: omitting `docker` means `"false"`.

Bootstrap privilege:

- `admin_user` is `root`: commands run directly.
- Otherwise `admin_user` needs passwordless sudo: each privileged command runs as `sudo -n ...`. SuperMgmt never prompts for a password; without it setup fails before changing anything.
- If you added a temporary `NOPASSWD` rule for this, revoke it afterwards. SuperMgmt needs it again only to re-run setup.

What setup does, in order, and how it ends:

1. Creates the system user `supermgmt` (home `/var/lib/supermgmt`, shell `/bin/sh`, no password) if it is absent. An existing account that differs is never touched: setup fails with `CONFLICT`.
2. Creates the home, `markers/` and `.ssh/` with fixed modes.
3. Writes `authorized_keys` with one `restrict` line holding the instance public key.
4. Adds or removes the user's groups to match: the journal group (`systemd-journal`, else `adm`) in the default log mode, `docker` only with `docker_access`.
5. Applies a tmpfiles entry; in broker mode installs the broker.
6. Writes `/etc/sudoers.d/supermgmt` (validated with `visudo -cf` before it is moved into place).
7. Verifies over a fresh connection as `supermgmt`, with the pinned host key: the user, writable markers, and `sudo -n -l` equal to the rendered lines exactly.
8. Records the capability `node.setup` with its metadata. If any step fails or the verification does not match, the job fails, the capability is not written and the node stays read-only as `admin_user`.

Every step is an "ensure" step, so an interrupted setup is requeued and re-running it is safe. Full list of what lands on the node and how to remove it: [security.md](security.md#the-dedicated-supermgmt-user-and-how-to-remove-it).

Setup is verified in CI on a Debian fixture. The `useradd` flags on the RHEL family are an assumption.

Limits in M1:

- No standalone `sudoers.write` or `log_broker.install` job: to change the unit set or the log mode, re-run setup with the new parameters.
- No `deploy_root` and no deployments (M4).
- No automated teardown; the manual steps are in [security.md](security.md#the-dedicated-supermgmt-user-and-how-to-remove-it).
- Server-mode instances: `node.setup` authorizes the instance key as in local mode; that flow was not verified in a server-mode run here. A node can also enroll itself with `sm join` (it gets the unprivileged user only; setup still follows), see [installation.md](installation.md#joining-a-node-sm-join).

### What a set-up node can do

| Capability | Without setup | After setup |
|---|---|---|
| Read services, containers and logs | yes, as `admin_user` | yes, as `supermgmt` |
| Start, stop, restart a systemd unit | no | the units and verbs granted in the sudoers file, if the unit passes the trust profile |
| Start, stop, restart a Docker container | no | only with `docker_access` |

Service actions are jobs. In an environment with `risk_level: production` they wait in `awaiting_approval`. The risks that come with these grants (whole-journal read, Docker as root, unit trust) are in [security.md](security.md#trust-boundaries-in-one-page).

### Interactive tools

`s` in the TUI, `sm ssh <node>` and `sm docker <node>` hand your terminal to the system OpenSSH client as `admin_user` (override with `--user`), using your own credentials and the node's pinned key only. Your `ssh_config` is ignored. See [security.md](security.md#interactive-ssh-isolation-m1) for the exact isolation. `lazydocker` is never installed for you; when it is missing, install it on the node yourself. M1 does not offer lazydocker on a local machine over an SSH Docker context.

## Local provider

`sm nodes add --local` registers the machine running the daemon so it appears in the TUI next to your SSH nodes.

- It is **read-only**: the same read templates as for SSH nodes run through `/bin/sh -c`, and every mutating or sudo command is refused. It cannot be set up.
- Capabilities follow what the probe finds. macOS has no systemd, so a Mac has no systemd units to list.
- It asks for consent first: pass `--yes` to skip the prompt.

## Not in M1

- Proxmox: planned for M3.
- Identity rotation (`sm ssh-key rotate`), host-key re-pin (`sm nodes repin`) and the secrets CLI arrived in M2 ([operations.md](operations.md)). SSH CA trust and per-node keys are not scheduled. `ssh.known_hosts_file` is only the file that goes into a backup.
- Hetzner, OVH and cloud providers: exploratory, not scheduled.
