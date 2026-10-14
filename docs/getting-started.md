# Getting started

This page takes you from nothing to a Linux machine managed from your laptop: build `sm`, register your laptop, add a machine over SSH, set it up and approve the setup. You need no server and no account.

> **What works today.** SuperMgmt is pre-alpha and has no release, so you build it from source. Everything on this page runs on your own laptop. The steps were tested in CI against Docker containers that play the managed machine, not against real servers; see [Project status](project-status.md).

## What you need

On your laptop:

- macOS or Linux, amd64 or arm64.
- Go 1.27.2 or newer, and `git`.
- An SSH key loaded in your SSH agent (`ssh-add -l` lists it). SuperMgmt uses your agent to log in as you; it never asks for a password.

For the managed machine (optional; you can stop after [step 3](#3-register-this-machine)):

- A Linux machine you can reach over SSH, with systemd. Debian 13 and Ubuntu 24.04 are what the tests use; other distributions are untested.
- An account on it that is `root` or has passwordless `sudo`, and that accepts your SSH key. SuperMgmt needs that privilege once, for setup.
- Not a machine you cannot afford to experiment on. Read [the trust boundaries](security.md#trust-boundaries-in-one-page) first.

## 1. Build `sm`

```bash
git clone https://github.com/autarquico/supermgmt.git
cd supermgmt
make build                      # or: go build -o dist/sm ./cmd/sm
export PATH="$PWD/dist:$PATH"   # so that `sm` below is the binary you built
sm version
```

`sm version` prints the commit you built and your platform.

## 2. Check the example configuration

These commands work offline and never start anything:

```bash
sm config validate --config examples/config.yaml --policy examples/policies.yaml
sm doctor --offline --config examples/config.yaml
```

You do not need a configuration file to continue. Without one, SuperMgmt runs in local mode with built-in defaults: a daemon for your user only, reached over a Unix socket in your user's state directory.

## 3. Register this machine

```bash
sm nodes add --local
```

The first command that needs the daemon starts it in the background; it exits on its own after a while with nothing to do. `sm nodes add --local` asks for consent (pass `--yes` to skip the prompt). Adding a node changes what SuperMgmt manages, so the default policy turns it into a job that waits for your approval:

```text
job 01a13ad5-… (control_plane.apply) is awaiting_approval; approval required (quorum 1)
```

Look at the plan and approve it with its hash. The hash binds your approval to that exact plan:

```bash
sm approvals                                   # the pending job and its plan hash
sm jobs approve <job-id> --plan-hash <hash>
sm nodes list                                  # your laptop, as the node "local"
```

Your laptop is now a read-only node: SuperMgmt reads what runs there and never changes anything on it. A Mac has no systemd, so the local node has no services view (`sm services list local` says the node does not offer that capability).

Now open the terminal UI:

```bash
sm
```

Running `sm` with no arguments in a terminal opens the TUI. Press `?` for help, `1` to `9` to switch screens, `/` to open the command palette and `q` to quit.

## 4. Add a machine over SSH

SuperMgmt installs nothing on the machine: it logs in with the system's own `sshd`. If `ssh <your-account>@<address>` already works with your key, the machine is ready. Replace the address and account with yours:

```bash
sm nodes add --name web1 --host 203.0.113.10 --admin-user root
```

`--admin-user` is your own account on the machine. SuperMgmt scans the host key and prints its SHA256 fingerprint:

- Compare it with the fingerprint you get on the machine itself (for example `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), then type `yes`.
- Or pass `--fingerprint SHA256:...` if you checked it beforehand.

From then on, that key is the only one SuperMgmt accepts from `web1`. A different key later fails the connection.

As with the local node, the addition waits for your approval: `sm approvals`, then `sm jobs approve <job-id> --plan-hash <hash>`.

Look at what it found:

```bash
sm nodes probe web1
sm nodes get web1
sm services list web1
```

Until setup, SuperMgmt reads the machine as your admin account, with read-only commands only.

## 5. Set up the machine

Setup creates a dedicated, unprivileged `supermgmt` account on the machine, authorizes SuperMgmt's own SSH key for it, writes a narrow sudoers file and verifies the result over a fresh connection. After setup, automated work uses that account, and SuperMgmt holds no standing root on the machine. The full list of what lands on the machine, and how to remove it, is in [Security](security.md#the-dedicated-supermgmt-user-and-how-to-remove-it).

Optionally, look at the public key setup will authorize:

```bash
sm ssh-key show
```

Then ask for setup:

```bash
sm nodes setup web1
```

`sm` shows the plan and whether it needs approval, and asks you to submit it. Setup is a high-risk action, so once submitted the job prints its id and waits in `awaiting_approval`.

Docker access is a separate choice. `sm nodes setup web1 --docker-access` also adds the account to the `docker` group, which is equivalent to root on the machine. Leave it off unless you want SuperMgmt to start, stop and restart containers there.

## 6. Approve it

Approvals are bound to the hash of the exact plan you read. List what waits and copy the plan hash:

```bash
sm approvals
sm jobs approve <job-id> --plan-hash <hash>
sm jobs get <job-id>
```

In local mode you may approve your own plans. When the job succeeds, `sm nodes get web1` shows the node as set up.

You can do the same from the TUI: press `/`, type `setup web1` (or `setup web1 docker`), press `y` to submit, then `4` for the Approvals screen and `A` to approve.

## 7. Use it

```bash
sm services list web1
sm services logs <service-id>
sm ssh web1                      # an interactive shell, with the pinned host key
sm status
sm events
```

The TUI shows the same: the Dashboard, the Node and Services screens, logs, jobs and events.

What setup lets you change:

- **Docker containers:** start, stop and restart, if you chose `--docker-access`. `sm services restart <service-id>` submits the job.
- **systemd units:** `sm nodes setup` and the TUI palette do not yet grant any unit, so a unit restart is refused with `CAPABILITY_UNAVAILABLE`. This was read from the code, not from a run.

Every action is a job. In an environment marked `production`, it waits for approval like the setup did.

## Clean up

- Retire the node in SuperMgmt (its history is kept): `sm nodes remove web1`.
- Remove what setup put on the machine: follow [the manual steps](security.md#the-dedicated-supermgmt-user-and-how-to-remove-it). There is no automated teardown.
- Remove SuperMgmt's own data from your laptop once no `sm` process runs. The data includes the master key that encrypts SuperMgmt's SSH key.
  - macOS: `~/Library/Application Support/SuperMgmt`.
  - Linux: `~/.config/supermgmt`, `~/.local/share/supermgmt` and `~/.local/state/supermgmt`, or the matching `XDG_*` directories.

## If something goes wrong

- **The fingerprint does not match.** Stop. Find out why the machine presents a different key before you trust it.
- **Setup fails before changing anything.** The admin account needs `root` or passwordless `sudo`; SuperMgmt never prompts for a password.
- **Setup fails with `CONFLICT`.** An existing `supermgmt` account on the machine differs from what setup would create. Setup never touches an existing account that differs.
- More: [Troubleshooting](troubleshooting.md).

## Next steps

- [Concepts](concepts.md): nodes, plans, approvals, jobs and environments.
- [Providers](providers.md): SSH nodes, the local machine, Proxmox and GitHub in detail.
- [Configuration](configuration.md): environments, policies and every setting.
- [MCP](mcp.md): let an AI agent read your infrastructure and propose plans.
- [Installation](installation.md): server mode and the Proxmox appliance (not released yet).

## References

- Node setup and the dedicated account: [Providers](providers.md#set-up-a-node).
- Tests behind this flow: `TestM1_ManageTwoNodesWithoutAgent` and `TestFixturesSetup_CreatesTheDedicatedUserAndItsFiles` (job `integration-fixtures`); `TestActRefusesWhatSetupDidNotGrant` (job `test`).
