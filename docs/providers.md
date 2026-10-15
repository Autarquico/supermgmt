# Providers

A provider is a source of nodes. There are four:

- **ssh**: a Linux machine reached over SSH. A Mac can be added too, read-only: the probe reads its system, CPU, memory and disk, but setup is Linux only.
- **local**: the machine running `sm`.
- **proxmox**: a Proxmox VE cluster ([below](#proxmox)).
- **github**: a source of repositories, CI results and attestations, not of nodes ([below](#github)).

New to nodes, setup and approvals? Start with [Getting started](getting-started.md) and [Concepts](concepts.md). What is verified, and how, is on [Project status](project-status.md).

## SSH nodes (agentless)

Nothing of SuperMgmt runs on the node. It is reached with the system's own `sshd`, through two accounts:

| Account | Setting | Used for |
|---|---|---|
| Your own account | `admin_user` (required) with `admin_credential_ref` (default `ssh-agent://default` in local mode) | read-only probes before setup, `node.setup` itself, interactive sessions |
| The dedicated account | `user` (default `supermgmt`) with `credential_ref` (default `secret://ssh/default`, the instance identity) | every automated session after setup |

The rule: automated sessions use the dedicated user if and only if the node has completed `node.setup`; otherwise they use `admin_user`, for read-only probes only.

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

Without setup a node is read-only. Starting, stopping and restarting services, restricted log modes, Docker container actions and deployments all need `node.setup`. Start it from the CLI:

```bash
sm nodes setup web1                          # logs via the journal group, no Docker
sm nodes setup web1 --docker-access          # also join the docker group (root-equivalent)
sm nodes setup web1 --logs-mode broker       # logs through the root-owned broker instead of the journal group
sm nodes setup web1 --unit nginx.service     # allow start, stop and restart of nginx.service
sm nodes setup web1 --unit app.service:restart   # allow only restart
sm nodes setup web1 --no-units               # remove every unit grant
```

or from the TUI palette:

```text
/ setup web1                  logs via the journal group, no Docker
/ setup web1 docker           also join the docker group (root-equivalent)
/ setup web1 broker           logs through the root-owned broker instead of the journal group
/ setup web1 unit nginx.service unit app.service:restart
                              grant systemctl on those units
```

`--unit` (or `unit` in the palette) takes `<unit>[:start,stop,restart]`; without verbs the unit gets all three. The units you pass replace the node's current grants, and the plan shows the old and new lists. Without any unit, re-running setup (after `sm ssh-key rotate`, say) keeps the grants the node has (`TestNodesSetupKeepsTheNodesGrantsUnlessToldOtherwise`). Each grant is one sudoers line, `systemctl <verb> <unit>`, and only units that pass the trust profile are granted.

Both show a plan that names the bootstrap identity and, with Docker access, the warning that the docker group is equivalent to root. Confirm it (`y` in the TUI). The setup job is approval-gated; approve it from the Approvals screen (`4`, then `A`) or with `sm jobs approve`. Docker access is never implied: without `--docker-access` (or `docker` in the palette) it is off. How approvals work is in [Policies and approvals](policies.md).

Bootstrap privilege:

- `admin_user` is `root`: commands run directly.
- Otherwise `admin_user` needs passwordless sudo: each privileged command runs as `sudo -n ...`. SuperMgmt never prompts for a password; without it setup fails before changing anything.
- If you added a temporary `NOPASSWD` rule for this, revoke it afterwards. SuperMgmt needs it again only to re-run setup.

Before it changes anything, setup checks that `admin_user` is root or has passwordless sudo, and that `jq` is installed on the node (deployments need it). Either missing fails the job with nothing changed.

What setup does, in order, and how it ends:

1. Creates the system user `supermgmt` (home `/var/lib/supermgmt`, shell `/bin/sh`, no password) if it is absent. An existing account that differs is never touched: setup fails with `CONFLICT`.
2. Creates the home, `markers/` and `.ssh/` with fixed modes.
3. Writes `authorized_keys` with one `restrict` line holding the instance public key.
4. Adds or removes the user's groups to match: the journal group (`systemd-journal`, else `adm`) in the default log mode, `docker` only with `docker_access`.
5. Applies a tmpfiles entry; in broker mode installs the broker.
6. Writes `/etc/sudoers.d/supermgmt` (validated with `visudo -cf` before it is moved into place).
7. Verifies over a fresh connection as `supermgmt`, with the pinned host key: the user, writable markers, and `sudo -n -l` equal to the rendered lines exactly.
8. Creates `deploy_root` (default `/srv/supermgmt`), owned by `supermgmt` with mode 0750, for deployments ([deployments.md](deployments.md#prerequisites-on-the-node)).
9. Records the capability `node.setup` with its metadata. If any step fails or the verification does not match, the job fails, the capability is not written and the node stays read-only as `admin_user`.

Every step is an "ensure" step, so an interrupted setup is requeued and re-running it is safe. Full list of what lands on the node and how to remove it: [security.md](security.md#the-dedicated-supermgmt-user-and-how-to-remove-it).

Setup is verified in CI on a Debian fixture. The `useradd` flags on the RHEL family are an assumption.

Current limits:

- No standalone `sudoers.write` or `log_broker.install` job: to change the unit set or the log mode, re-run setup with the new parameters.
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

`s` in the TUI, `sm ssh <node>` and `sm docker <node>` hand your terminal to the system OpenSSH client as `admin_user` (override with `--user`), using your own credentials and the node's pinned key only. Your `ssh_config` is ignored. See [security.md](security.md#interactive-ssh-isolation) for the exact isolation. `lazydocker` is never installed for you; when it is missing, install it on the node yourself. SuperMgmt does not offer lazydocker on a local machine over an SSH Docker context.

## Local provider

`sm nodes add --local` registers the machine running the daemon so it appears in the TUI next to your SSH nodes.

- It is **read-only**: the same read templates as for SSH nodes run through `/bin/sh -c`, and every mutating or sudo command is refused. It cannot be set up.
- Capabilities follow what the probe finds. macOS has no systemd, so a Mac has no systemd units to list.
- It asks for consent first: pass `--yes` to skip the prompt.

## Proxmox

> **Status: tested against fakes. No real Proxmox VE host was used.** Discovery and power actions run against a fake Proxmox API (`internal/providers/proxmox/pvefake`) written from the Proxmox documentation and, end to end, against a simulated host in CI (`TestM3_Appliance*`, job `e2e-appliance`). Each assumption is a row in [compatibility.md](compatibility.md) and an item in the [real Proxmox checklist](manual-checks/m3-real-pve.md). Supported: Proxmox VE 9.x only. See [Project status](project-status.md).

The Proxmox provider reads a cluster through its HTTPS API with an API token and shows nodes, VMs and containers next to your SSH nodes. Today it can start, shut down, reboot and stop guests. Snapshots, backups, console, task history, creating providers through the API and promoting a discovered guest to a managed node are not built.

### Configure

A Proxmox provider is declared in the configuration file; the daemon applies it when it starts. The installer writes this block for the appliance ([installation.md](installation.md#proxmox-appliance-proxmox-lxc)); you can write it by hand for an existing server:

```yaml
providers:
  - type: proxmox
    name: pve
    endpoint: https://pve.lan:8006              # https, host and port only
    credential_ref: secret://providers/pve/token
    verify_tls: true                            # must be true
    ca_file: /etc/supermgmt/pve-root-ca.pem     # absolute; the CA that signed the Proxmox certificate
    sync_interval: 30s                          # default
```

- `verify_tls` must be `true`; `false` is a validation error (`internal/config/validate.go`). A Proxmox certificate from a private CA is trusted with `ca_file` (the CA certificate, for example `/etc/pve/pve-root-ca.pem` copied from the host), never by turning verification off. Without `ca_file` the system roots apply. The endpoint is reached through the outbound request filter; redirects are not followed.
- The token is a `secret://` reference. The secret's value is `<user>!<tokenid>=<secret>` and is sent as `Authorization: PVEAPIToken=...`. It never appears in logs, events or errors (redaction tests in `internal/providers/proxmox`). Store it while the service is stopped, as the service user:

  ```bash
  sudo -u supermgmt sm secrets import --offline --name providers/pve/token --config /etc/supermgmt/config.yaml   # value from the terminal or stdin
  ```

- `sm providers check --offline pve` (service stopped) connects with the stored token and reports the version and the number of nodes, guests and storages; `sm providers check --offline --tls-only --endpoint URL --ca-file FILE` only verifies the certificate the endpoint serves. Both exit 8 on failure.

### Identities and privileges

The appliance installer creates a **dedicated identity per install**, named with the install id, and never reuses or changes a shared one ([installation.md](installation.md#per-install-identities)): user `sm-<id>@pve`, token `sm-<id>@pve!sm` with privilege separation, role `SMAudit-<id>` (`VM.Audit, Sys.Audit, Datastore.Audit, Pool.Audit`) on `/` and, unless `SUPERMGMT_PVE_POWER=0`, role `SMPower-<id>` (`VM.Audit, VM.PowerMgmt`) on `/vms`. Both roles are granted to the user and to the token.

A token you create yourself for a hand-written provider needs the same two grants. The installer runs, per resource, `pveum user add`, `pveum role add <role> --privs ...`, `pveum acl modify <path> --roles <role> --users <user>` (and `--tokens <user>!<id>`), and `pveum user token add <user> <id> --privsep 1`. Not verified on real PVE.

The deeper-ACL rule matters. Proxmox does not add a role granted on `/vms` to the one inherited from `/`; the deeper entry replaces it. That is why `SMPower-<id>` carries `VM.Audit` too, and why discovery decides what a token may do from `GET /access/permissions?path=<path>` instead of from role names; the client asks for the exact path, so a path the sparse list omits is never guessed from a parent (`TestPathPermissionsAreEffectivePrivilegesOfTheExactPath`). How real Proxmox treats this, and 0-valued or non-propagating grants, is not verified.

A guest advertises the capability `proxmox.vm.power` only when the token's effective privileges include `VM.PowerMgmt` on it and it is not a template. The power job rechecks that privilege right before it sends anything.

### Discovery

Every `sync_interval`, and on demand, the daemon reads `GET /cluster/resources` (and the permissions) with the provider's token and updates:

- **Nodes** with `kind` `proxmox.node` (cluster hosts), `proxmox.qemu` and `proxmox.lxc` (guests), native ids `node/<name>`, `qemu/<vmid>`, `lxc/<vmid>`. Metadata holds the Proxmox node, VMID, type, template flag, and configured CPU, memory and disk; current CPU, memory, disk and uptime appear as metrics. Everything discovered stays `discovered` (read-only, not managed). Power state is an observation (`proxmox.status`), not reachability.
- **Storages** as a provider observation (`proxmox.storage`: id, node, type, content, usage).
- **Capabilities**, per above.

A guest renamed in Proxmox is renamed here and its `spec_revision` increases, so **a plan made before the rename becomes stale** (the same rule as any other change of a plan's target; resubmit it). Moving a guest to another cluster node only rewrites its metadata. Guests that left the token's view are never deleted:

| Presence | When | Effect |
|---|---|---|
| `absent` | The object is missing from a successful read **and** the token still has the audit privilege on the path where it would be (`VM.Audit` on `/vms/<vmid>`, `Sys.Audit` on the node) | The row stays marked gone; its power capability is dropped. |
| `inaccessible` | It is missing and the token no longer has that privilege (for example the ACL was revoked) | Nothing is known: the row stays, marked inaccessible, capabilities dropped. |

(`TestProxmoxSyncAGuestThatIsGoneIsAbsentWhenTheTokenStillSeesItsPath`, `...ARevokedACLMakesEverythingInaccessibleKeepsTheRowsAndDropsCapabilities`, `...AGuestOutsideTheTokensPathsIsInaccessibleNotAbsent`.) Only one sync per provider runs at a time. Its outcome is on the provider (`status` `ok` or `error`, `last_sync_at`, `last_error`) and is audited when it changes; a provider that leaves the configuration file is marked `removed` and not synced, nothing deleted.

```bash
sm providers list                    # status, last sync, last error
sm providers get pve
sm providers refresh pve             # discover now; exit 0 if it worked, 8 if the cluster could not be read
sm nodes list --tree                 # providers, cluster nodes and their guests
```

`refresh` is `POST /api/v1/providers/{id}/refresh`, authorized as `provider.read` and rate limited per caller and provider (6 per minute, burst 3). It changes nothing on the cluster, only what SuperMgmt knows. In the TUI the palette has `refresh proxmox [provider]`. `sm doctor` has a `providers` check: `ok` after a recent successful sync, `warn` while the first sync is pending or when none succeeded for three intervals, `fail` when the last sync failed; the appliance installer waits for it.

### Power actions

```bash
sm nodes power web-vm start --wait   # start | shutdown | reboot | stop
```

(also `power <node> <verb>` in the TUI palette). A power action is the catalog action `proxmox.vm.power`, a job that is **never retried** (`non_retryable`). `start`, `shutdown` and `reboot` are operational; `stop` cuts power without a clean shutdown, is **high risk** and always waits for approval (`internal/policy/evaluate.go`: the high-risk floor). The CLI shows the plan and the risk and asks before submitting; `--wait` returns 0 only when the job succeeded.

What the job does, in order:

1. Recheck the permission and resolve the guest's current Proxmox node.
2. Record an intent (what, which guest, which token user) and mark it dispatched, durably, **before** anything is sent.
3. Send exactly one `POST` for the verb. It is never repeated.
4. Persist the returned task id (UPID) before the first poll, then poll the task on the node encoded in the UPID until it stops. Deadlines: 5 minutes for `start`, `shutdown`, `reboot`; 2 minutes for `stop`. For `shutdown` and `reboot` the request carries a Proxmox timeout of 240 s, below the deadline. Whether Proxmox accepts that parameter for every verb and guest type is not verified.

Outcomes:

- The task stops with `OK`: the job succeeds. Stops otherwise: the job fails with the task's exit status.
- Proxmox refuses the request with an error document before any task exists (no privilege, bad parameter, the guest does not exist on that node): the job fails, nothing was accepted.
- Anything else without a task id (timeout, connection reset, 5xx without a body, unreadable answer), or the deadline passing while the task still runs: the job becomes **`interrupted`**. The task may exist. It is not retried.

### Interrupted power jobs and task correlation

For an interrupted power job the reconciler looks for the task instead of guessing. Without a stored UPID it lists the tasks of **every** cluster node (all pages) and keeps those that started within the dispatch window (120 s before the dispatch to the request timeout plus 120 s after) whose decoded UPID matches exactly: type for the verb and guest kind (`qmstart`, `vzshutdown`, ...), guest id, and the token user. Exactly one match is used; none or several **hold the job** for a person. A Proxmox call carries no marker SuperMgmt could find again on the node, so the task is the only proof, and missing evidence never makes a retry safe.

For these jobs time alone never makes a job "quiescent". The job can be reconciled, or resolved, only when stored evidence says the correlated task **stopped**: stopped with `OK` settles it as succeeded, stopped otherwise as failed (`TestTaskTrackedIntentIsNeverReconciledByDeadlineAlone`, `TestResolveTaskTrackedRequiresStoppedTask`). Past the deadline, a task that is still running keeps the job interrupted and not resolvable.

When Proxmox is unreachable and you must settle a held job yourself, look at the guest in Proxmox first and then:

```bash
sm jobs get <job-id>
sm jobs resolve <job-id> --plan-hash <hash> --outcome succeeded|failed --note "checked in the Proxmox UI" --assume-quiescent
```

`--assume-quiescent` is your statement that nothing of the task is still running; it is recorded and audited with your note. Without it, `resolve` of a task-tracked job without stop evidence is refused with `CONFLICT`.

## GitHub

> **Status: tested against fakes. Never run against github.com, GHCR, real attestations or real Actions OIDC tokens.** The connector runs against a hand-written fake GitHub API (`internal/providers/github/ghfake`), a virtual Sigstore and a local registry, end to end by `TestM4_*` (CI job `e2e-deploy`). See [compatibility.md](compatibility.md#github-provider-github-internalprovidersgithub), the [real GitHub checklist](manual-checks/m4-real-github.md) and [Project status](project-status.md).

The GitHub provider is read-only. It lists repositories, reads a manifest and Compose file at one commit, checks that the required CI checks passed for that commit, verifies image attestations and verifies GitHub Actions OIDC tokens. It never writes to GitHub.

```yaml
providers:
  - type: github
    name: github
    api_url: https://api.github.com             # https, no query, fragment or trailing slash
    credential_ref: secret://providers/github/token
    webhook_secret_ref: secret://providers/github/webhook   # optional; server mode
    ca_file: /etc/supermgmt/github-ca.pem       # optional, absolute path
```

(`internal/config/github.go`; the fields and checks are the ones that file validates.) A provider can also be registered with `POST /api/v1/providers` for `type: github` (a high-risk `provider.write`: it needs approval); registering a Proxmox provider that way is still not built.

- **Credential.** A fine-grained, read-only personal access token in `credential_ref`. GitHub App installation tokens are not supported. Private repositories work only if the token can read them (not verified against real GitHub).
- **One origin.** The exact origin of `api_url` is the only host the connector talks to and the only redirect target it follows (at most 3 hops, same scheme, host and port); the token is never sent anywhere else. GitHub Enterprise Server uses its own `api_url` (for example `https://ghe.example.com/api/v3`); it is not verified.
- **CI delivery.** In server mode a signed webhook (`POST /api/v1/github/webhook`, `X-Hub-Signature-256`, needs `webhook_secret_ref`) nudges re-evaluation, and a backstop poll at `github.ci_poll_max` covers lost deliveries. In local mode there is no webhook endpoint; CI is polled from `github.ci_poll_initial` up to `github.ci_poll_max`.
- **Attestations.** Verified with Sigstore (public good and GitHub trusted roots, refreshed over TUF through the outbound filter, last-good cached, fail closed when stale). Required only for environments with `require_provenance: true`.
- **Actions OIDC.** A workflow's token is limited to the `deployment.create` and `deployment.read` actions (every other route refuses it), and is accepted only if its repository id, repository owner id and workflow match the linked automation identity. That identity is created with **no role**; an administrator grants `deployer` (or a narrower rule) explicitly.

## Docker Compose apps on SSH nodes

An application is deployed to an SSH node that completed `node.setup` v2. The node needs Docker with Compose CLI **5.5.1 exactly**, `jq`, `flock` and the other tools listed in [compatibility.md](compatibility.md#docker-compose-and-node-tools); `deploy_root` (default `/srv/supermgmt`) is created and owned by the dedicated user. Discovery reports the capability `docker.compose.deploy` as unavailable, with the first unmet requirement as reason, when any of this is missing. The local provider and Proxmox guests without SSH are never deploy targets. The deployment flow is described in [architecture.md](architecture.md#applications-and-deployments) and operated in [deployments.md](deployments.md).

## Not available

- SSH CA trust and per-node keys are not scheduled. Identity rotation (`sm ssh-key rotate`), host-key re-pin (`sm nodes repin`) and the secrets CLI exist; see [operations.md](operations.md). `ssh.known_hosts_file` is only the file that goes into a backup.
- Hetzner, OVH and cloud providers: exploratory, not scheduled.

## References

- Binding specification: [`docs/spec/SUPERMGMT-SPEC.md`](spec/SUPERMGMT-SPEC.md), sections 6.4 (providers), 12 (nodes and setup), 14 and 15 (Proxmox), 18 (GitHub) and 20.4 (resolving interrupted jobs).
- Decision records: [ADR-0009](adr/0009-node-provisioning.md) node provisioning, [ADR-0015](adr/0015-ssh-transport-and-command-templates.md) SSH transport and command templates, [ADR-0023](adr/0023-pve-identity-privileges-compatibility.md) Proxmox identity and privileges, [ADR-0024](adr/0024-proxmox-discovery.md) Proxmox discovery, [ADR-0025](adr/0025-proxmox-power-jobs-task-correlation.md) Proxmox power jobs and task correlation, [ADR-0028](adr/0028-github-connector.md) GitHub connector.
- Code: `internal/app/setup.go` (setup), `internal/app/proxmox_power.go` (power jobs), `internal/api/routes_m3.go` (provider refresh rate limit), `internal/config/github.go` and `internal/config/validate.go` (provider validation).
