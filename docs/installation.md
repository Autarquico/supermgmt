# Installation

> **Status: no stable release yet.** The release key exists and is embedded in `install.sh` ([Release key and custody](#release-key-and-custody)). Pre-releases may exist on the `beta` channel, but the installer has not been verified on a clean machine until [Project status](project-status.md) says so. Build from source (`make build`) and use `sm install` by hand.

## Laptop or server

Pick the row that matches what you want to run.

| You want | Mode | Today |
|---|---|---|
| Manage machines from your own laptop, no server | none, or `local` | Build from source and follow [Getting started](getting-started.md). You need no installer: the first command that needs the daemon starts it. |
| Keep `sm` installed for your user, with the daemon running at login | `local --resident` | Run `sm install local --resident` from the binary you built. It copies that binary to `~/.local/bin`. See [Modes](#modes). |
| Sign in to a shared server from your laptop | `client` | `sm install client`, then `sm profile add` and `sm login`. See [After a server install](#after-a-server-install). |
| Run a shared server for a team | `server` | Linux with systemd, as root. `sm install server` works from a binary you built; `install.sh` has not been verified against a published release yet (release checklist H22). |
| Run the server in a container on Proxmox VE | `proxmox-lxc` | Not tried on a real Proxmox VE host. See [Proxmox appliance](#proxmox-appliance-proxmox-lxc). |

`sm install <mode>` installs the `sm` binary that is running (`internal/cli/install.go`), so it works without a release. `install.sh` downloads and verifies a signed release first, and that is the part that cannot work yet.

The rest of this page describes `install.sh` and every mode in detail.

## Two ways in

### `curl | bash`

```bash
curl -fsSL https://raw.githubusercontent.com/autarquico/supermgmt/main/install.sh | bash -s -- server --public-url https://mgmt.example.com
```

The organisation in the URL is the one `install.sh` uses for downloads (`DEFAULT_BASE_URL`); that the repository is public at that address is not verified.

**This path trusts the `main` branch.** Whoever can change `install.sh` on `main` can replace both the verifier and the embedded public key, so a repository compromise defeats it. The signatures protect what the script downloads *after* it has started; they cannot protect the script itself.

### Review first (verify the script with a key you obtained elsewhere)

```bash
V=v1.2.3
curl -fLO https://github.com/autarquico/supermgmt/releases/download/$V/install.sh
curl -fLO https://github.com/autarquico/supermgmt/releases/download/$V/install.sh.sig
# allowed_signers: written by you from the fingerprint-checked key, see below
ssh-keygen -Y verify -f allowed_signers -I release@supermgmt -n supermgmt-release \
  -s install.sh.sig < install.sh \
  && less install.sh \
  && SUPERMGMT_VERSION=$V bash install.sh server --public-url https://mgmt.example.com
```

`allowed_signers` is one line, `release@supermgmt namespaces="supermgmt-release" ssh-ed25519 AAAA...`, holding the release public key. Get the key and its fingerprint from a source other than the one that served the script: `SECURITY.md` at a signed tag, the project website, the release notes. Check the key with `ssh-keygen -lf` against the published fingerprint:

```text
SHA256:06Bs6zXAk9KcnjRpoR5bslbRKoNv9L9KuI6zzT7OPX4
```

The key is `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBDaUxtppvnxho0KAF62G5IJVRMII+v1e7zJNy1f0F3T release@supermgmt`.

After this check `install.sh` still verifies the checksum list and the archive with the key embedded **in the script you just verified**; the out-of-band step is what makes that embedded key trustworthy.

## What `install.sh` does

POSIX `sh`, no dependency beyond the commands it checks. In order:

1. Detects OS (Linux or macOS), architecture (amd64 or arm64), root, systemd and a terminal, and prints the result. Required commands: `curl tar awk sed grep mktemp ssh-keygen` and `sha256sum` or `shasum`; a missing one is exit 4.
2. Verifies the verifier: `ssh-keygen -Y verify` of an embedded test message **before any download**. Failure is exit 4.
3. Resolves the version: `SUPERMGMT_VERSION=vX.Y.Z` pins it (integrity only, no freshness); `latest` or unset follows `SUPERMGMT_CHANNEL` (`stable` default, or `beta`). A channel pointer is a signed file; it is rejected if its signature fails, it is expired, it is issued more than 5 minutes in the future, or it is valid for more than 30 days.
4. Downloads `checksums.txt` and its signature, verifies the signature against the embedded `allowed_signers` (namespace `supermgmt-release`, principal `release@supermgmt`) and `revoked_keys`, checks that the signed header (`version:`, `channel:`) matches the request, downloads the archive and checks its SHA-256.
5. Unpacks `sm` into a private temporary directory and `exec`s `sm install <mode> ...`. When its stdin is a pipe and a terminal exists, `sm` is given `/dev/tty` so it can prompt; `SUPERMGMT_NONINTERACTIVE` suppresses that.

Environment: `SUPERMGMT_VERSION`, `SUPERMGMT_CHANNEL`, `SUPERMGMT_MODE`, `SUPERMGMT_INSTALL_DIR`, `SUPERMGMT_CONFIG_DIR`, `SUPERMGMT_DATA_DIR`, `SUPERMGMT_NONINTERACTIVE`, `SUPERMGMT_YES`. `SUPERMGMT_RELEASE_BASE_URL` points downloads at a mirror; it never skips a verification step. Secrets are never flags.

### OpenSSH 8.2 or newer

`install.sh` and `scripts/join.sh` refuse an `ssh-keygen` that cannot pass the self-test and tell you "OpenSSH 8.2 or newer is required" (`install.sh` line 79). The release design requires 8.2 as well: the self-test signs with a `valid-after` option in `allowed_signers`, which older releases reject.

### The default mode is `auto`

`install.sh` and `sm install` with no mode run `auto` (`internal/installer/auto.go`):

| Host | Result |
|---|---|
| Proxmox VE host (`pveversion` found) | `proxmox-lxc` |
| macOS, or Linux with `XDG_CURRENT_DESKTOP`, `WAYLAND_DISPLAY` or `DISPLAY` set | `local` |
| Any other Linux, with a terminal | asks whether to install the server on this host; a yes runs `server` |
| Any other Linux, no terminal | exit 2: set `SUPERMGMT_MODE` |
| Any other OS | exit 3 |

Covered by `TestAutoMode` (`internal/installer`). A mode named explicitly (or `SUPERMGMT_MODE`) is never second-guessed.

## Modes

Run as `install.sh <mode> [flags]` or, with the binary, `sm install <mode> [flags]`. Flags for every mode: `--non-interactive` (fail instead of guessing; also `SUPERMGMT_NONINTERACTIVE`), `--yes` (do not ask to confirm the plan; also `SUPERMGMT_YES`).

| Mode | What it does | Needs |
|---|---|---|
| `local` | Binary in `~/.local/bin` (or `SUPERMGMT_INSTALL_DIR`), a config file and a data directory under your user's configuration and data directories ([configuration.md](configuration.md)). `--resident` also registers and starts a user unit (systemd) or launch agent (macOS) so the daemon keeps running. `--name` sets the instance name. | Linux or macOS. `--resident` on Linux needs systemd. |
| `server` | System user `supermgmt`, `/etc/supermgmt` (0750, root:supermgmt), `/var/lib/supermgmt` (0750), `secrets/keys` (0700), a backups directory, binary in `/usr/local/bin/sm`, a hardened systemd unit (`internal/installer/render.go`), a generated config, then starts the unit, waits for `/health/ready` and prints a one-time bootstrap code. | Linux with systemd, run as root. |
| `client` | Binary only, plus an empty profile file (mode 0600) in the config directory. | Linux or macOS. |
| `restore` | Installs like `server` without starting it, imports a master key export, restores an archive offline, then starts the service in restore hold. Does not print a bootstrap code. | As `server`, plus `--archive` and `--key-export`. |
| `auto` | Picks one of the above from the host, see [above](#the-default-mode-is-auto). | |
| `proxmox-lxc` | Creates a dedicated unprivileged LXC on a Proxmox VE host and installs the server in it, see [Proxmox appliance](#proxmox-appliance-proxmox-lxc). | Proxmox VE 9.x, amd64, root. |
| `upgrade` | Replaces the installed `sm` with the one that is running, with a read-only backup first, see [Upgrade](#upgrade). | An existing install. |
| `uninstall` | Removes the software; keeps configuration and data unless separately confirmed, see [Uninstall](#uninstall). | An existing install. |

Server and restore flags:

| Flag | Meaning |
|---|---|
| `--public-url URL` | Required non-interactively. Must be `https`. The prompt asks for it otherwise. |
| `--tls proxy` (default), `--tls direct` or `--tls self-signed` | Who terminates TLS, see below. |
| `--tls-cert FILE`, `--tls-key FILE` | With `--tls direct` only. |
| `--trusted-proxy IP/CIDR` (repeatable) | With `--tls proxy` only. Default `127.0.0.1/32`. |
| `--listen ADDR` | Default `127.0.0.1:8787` for proxy, `0.0.0.0:8443` for direct and self-signed. |
| `--no-start` | Server only: write and load the unit without enabling or starting it. The appliance installer uses it; the unit is enabled later, after the credential is in place. |
| `--name NAME` | Instance name, default `supermgmt`. |

Restore adds `--archive FILE` and `--key-export FILE` (the unlock phrase is read from stdin or the terminal, never a flag).

The installer **keeps an existing config file and data**. If it finds an existing installation or several candidate configurations it fails without a terminal (exit 4) and asks with one. It never overwrites configuration or the database.

The config the installer writes holds only `instance` and `server`. OIDC and everything else is edited in afterwards ([configuration.md](configuration.md)).

### TLS: proxy or direct

There is **no ACME**. You bring the certificate, or a reverse proxy that has one, or ask for a self-signed one.

- `--tls proxy` (default): the daemon speaks plain HTTP on a loopback or Unix address and a reverse proxy in front terminates TLS. `X-Forwarded-For` and `X-Forwarded-Proto` are believed only from a peer inside `trusted_proxies`; a forwarded proto other than `https` is rejected with 400; a connection from loopback gets no special trust. A non-loopback plain-HTTP listener is refused. Keep the default `127.0.0.1/32` only when the proxy runs on the same host.
- `--tls direct`: the daemon terminates TLS 1.2 or newer with the pair you give it. The installer checks that the pair matches, has not expired and covers the host of `--public-url`. The pair is re-read on `SIGHUP` (a failed reload keeps the old pair).

- `--tls self-signed`: direct TLS with a certificate authority generated on the host (`internal/installer/selfsigned.go`): a CA valid 10 years and a server certificate valid 5 years, valid for the host of `--public-url` (a DNS name or an IP) plus the loopback names, so `--public-url` must be the address clients really use. The CA certificate and its SHA-256 fingerprint are printed; copy the CA to each client and run `sm profile add <name> --url <public URL> --ca-file <ca.pem> --use`. There is no renewal flow: after the leaf expires you reinstall or supply your own pair with `--tls direct`. The proxmox-lxc mode uses this arrangement.

Cloudflare Access/Tunnel is a proxy arrangement: see [cloudflare.md](cloudflare.md).

### After a server install

The installer prints a bootstrap code (valid `auth.bootstrap.code_ttl`, default 24h, single use, shown once). On your own machine:

```bash
sm profile add prod --url https://mgmt.example.com --use
sm login --bootstrap          # reads the code from the terminal or stdin
```

On a server **without OIDC**, `sm login --bootstrap --display-name <name>` creates the first admin; on a terminal the name is prompted for, defaulting to `$USER`.

With OIDC configured, the code is exchanged *after* a normal `sm login` by the identity that is to become admin. OIDC needs its client secret in the secret store first: store it with `sm secrets import --offline` while the service is stopped. See [operations.md](operations.md#enabling-oidc-on-a-fresh-server).

## Proxmox appliance (`proxmox-lxc`)

> **Verification status.** Read against the code and exercised against **fakes**: a fake Proxmox API and fake `pct`/`pveam`/`pvesh`/`pveum` commands that reject unknown flags and endpoints ([compatibility.md](compatibility.md#proxmox-ve)). The end-to-end run in a simulated Proxmox host is covered by `TestM3_Appliance*` (CI job `e2e-appliance`). **No run on a real Proxmox VE host has happened.** The real-host checklist is [manual-checks/m3-real-pve.md](manual-checks/m3-real-pve.md); until it passes, "Proxmox auto-LXC install works" stays unchecked in the [release checklist](release-checklist.md). Everything on this page about Proxmox behaviour is not verified on real PVE.

Run on the Proxmox host, as root:

```bash
sudo ./sm install proxmox-lxc           # or: install.sh proxmox-lxc, or install.sh with no mode on a Proxmox host
```

Refused otherwise (`internal/installer/proxmox.go`): `pveversion` present and reporting **9.x** (8.x and anything else exit 3; PVE 8 reached end of life in 2026-08 per the Proxmox FAQ, see [compatibility.md](compatibility.md)), linux/amd64 (exit 3), root (exit 4), no other installer running (a lock, exit 4).

### Configuration

`sm install proxmox-lxc` has only `--non-interactive` and `--yes`; everything else is an environment variable. Unset means "choose": the installer detects, asks on a terminal, or fails with exit 2 when the choice is ambiguous and there is no terminal.

| Variable | Default / meaning |
|---|---|
| `SUPERMGMT_VMID` | First free VMID from 900. A VMID in use is refused and left untouched. |
| `SUPERMGMT_HOSTNAME` | `supermgmt` |
| `SUPERMGMT_STORAGE` | Container root storage; must be active and hold `rootdir` content. Asked, or exit 2, when several qualify. |
| `SUPERMGMT_TEMPLATE_STORAGE` | Where the template lives (`vztmpl` content). Same rule. |
| `SUPERMGMT_BRIDGE` | `vmbr0` when it exists, otherwise the only bridge, otherwise asked or exit 2. |
| `SUPERMGMT_NETWORK` | `dhcp` (default) or `static`; static needs `SUPERMGMT_IP` (CIDR) and `SUPERMGMT_GATEWAY`, optionally `SUPERMGMT_DNS` (comma-separated). |
| `SUPERMGMT_CORES`, `SUPERMGMT_MEMORY`, `SUPERMGMT_SWAP`, `SUPERMGMT_DISK_GIB` | 2 cores, 2048 MiB, 512 MiB swap, 16 GiB |
| `SUPERMGMT_PVE_POWER` | `0` omits the power role (read-only access). Anything else grants power on/off as well. |
| `SUPERMGMT_PVE_ENDPOINT` | `https://<host address on the bridge>:8006`. Must be `https://host[:port]`. |
| `SUPERMGMT_PVE_CA_FILE` | `/etc/pve/pve-root-ca.pem` |

Storage and bridge names are checked against what the host reports, and every value is validated before use (`TestPVE_ArgvValidation`). Proxmox tools run by absolute path with a clean environment, never through a shell.

### The plan

Before any change the installer prints what it decided (PVE version, VMID, hostname, template and whether it will be downloaded, storage, bridge, network, size, the API endpoint and the CA it is verified against, and whether access is read-only or read plus power) and what it will not do: open router ports, install Docker on the host, mount host paths into the container, create a privileged container, delete the template cache or any pre-existing resource. On a terminal it asks to proceed; `--yes` or `SUPERMGMT_YES=1` skips the question, and so does running without a terminal.

### What it does, in order

The order is the failure matrix (`internal/installer/proxmox_steps.go`).

1. Fix an `install_id` (8 hex digits) and create a write-ahead journal `/var/lib/supermgmt-installer/journals/<id>/journal.jsonl` (root-only directories, 0700; file 0600) before any side effect. Journals that earlier builds left in `/var/tmp/supermgmt-installer-<id>/` are still found and recovered.
2. Download the Debian 13 `standard` template with `pveam` if none is on the template storage (highest version wins). **A downloaded template is never rolled back or deleted** (shared cache); it is reported.
3. `pct create`: unprivileged, `nesting=0,keyctl=0`, no mount points, no raw `lxc.*` keys, start on boot, tag `supermgmt`, description `supermgmt install <id>`. The configuration is read back; any mismatch rolls back.
4. Start it and wait up to 120 s for an IPv4 address.
5. Push the **running** `sm` into the container and compare its SHA-256 with the host's copy.
6. Inside, as root: `sm install server --no-start --tls self-signed --public-url https://<container address>:8443`. The unit is written but **not enabled**.
7. As the `supermgmt` user: `sm server init`. Every later in-container `sm` command runs as that user, so the database and keys belong to it.
8. Verify `/run` is tmpfs and the account exists; create `/run/supermgmt-bootstrap` (0700, owned by `supermgmt`).
9. Put the Proxmox CA in the container and verify, **from inside it**, the certificate chain the endpoint actually serves (`sm providers check --offline --tls-only`). A failure here happens before any token exists and exits 8; the message asks whether port 8006 on the host is reachable from the container.
10. Create the per-install Proxmox identities (below), then the API token.
11. Hand the token over: a 0600 file in a 0700 directory on the host, `pct push` to `/run/supermgmt-bootstrap`, owner and mode readback (with a `chown`/`chmod` fallback), delete the host copy, then `sm secrets import --offline --from-file ... --delete-source` as `supermgmt`. The token is never an argument, an environment variable or a log line, and the commands that carry it run in a mode that captures their output (`TestProxmoxLXC_TokenNeverInArgvEnvOutputLogsJournal`).
12. Append the Proxmox provider (`verify_tls: true`, `ca_file`, `credential_ref: secret://providers/pve/token`, `sync_interval: 30s`) to the container's configuration and run `sm providers check --offline pve`.
13. `systemctl enable --now supermgmt`, wait up to 120 s for `/health/ready` over the appliance's own CA, then up to 120 s for the admin doctor `providers` check to report `ok` (the first discovery).
14. Obtain a bootstrap code and **commit**: write `/var/lib/supermgmt-installer/appliances/<vmid>.json`, append `committed` to the journal, remove the journal. Print the address, the CA certificate and fingerprint, and the bootstrap code.

### Per-install identities

Every Proxmox resource carries the install id, so a name collision means "not ours": the installer fails and never adopts it. Created on the Proxmox side:

| Resource | Name | Privileges and path |
|---|---|---|
| User (realm `pve`, no password) | `sm-<id>@pve` | |
| API token, privilege separation on | `sm-<id>@pve!sm` | |
| Read role | `SMAudit-<id>` | `VM.Audit, Sys.Audit, Datastore.Audit, Pool.Audit` on `/` |
| Power role (unless `SUPERMGMT_PVE_POWER=0`) | `SMPower-<id>` | `VM.Audit, VM.PowerMgmt` on `/vms` |

Both roles are granted to the user **and** to the token (with privilege separation the token's rights are the intersection). `SMPower-<id>` repeats `VM.Audit` because Proxmox replaces a role inherited from `/` by the one granted on a deeper path; without it guests would vanish from the inventory. That rule is modelled in the fake and is not verified on real PVE. Nothing for snapshots, backups, console or deletion is granted.

### Using the new server

Save the printed CA certificate to a file on your workstation and run:

```bash
sm profile add supermgmt --url https://<container address>:8443 --ca-file supermgmt-ca.pem --use
sm login --bootstrap
```

The certificate is valid for the address the container had at install time. With DHCP, reserve that lease, or the certificate no longer matches after the address changes (there is no renewal flow, see [TLS](#tls-proxy-or-direct)). Then back up the instance ([operations.md](operations.md#backups)) and keep the key export somewhere safe. Discovery and power actions: [providers.md](providers.md#proxmox).

### Failure, rollback and recovery

If a step fails, the installer rolls back **only what the journal says this run created**, newest first, reading each resource back before removing it: a Proxmox resource is removed only when its name carries the install id, the container only when its description carries it. Anything else is kept and reported.

- Fully rolled back: exit with the code of the original failure and "everything this install created was rolled back".
- Something could not be undone: exit 7 with the list of kept resources and the journal path.
- A Proxmox task still holds the container (for example a slow create) after the bounded wait: exit 6, journal kept, "pending recovery".
- Interrupted (power loss, kill): the next `sm install proxmox-lxc` looks at the journals first. One that was committed (or whose appliance record exists) is only cleaned up; an uncommitted one is rolled back after you confirm. Without a terminal it refuses with exit 7 and names the journal directory, so you can remove the listed resources by hand.

Covered by `TestProxmoxLXC_FailureAtEveryStepUndoesOnlyCreated`, `TestProxmoxLXC_CrashAtEveryJournalBoundary`, `TestProxmoxLXC_CommitBoundaries` and `TestProxmoxLXC_RollbackStillPendingKeepsTheJournalAndExits6` (the crash tests need the `crashpoints` build tag); the end-to-end rollback is `TestM3_Appliance*` (CI job `e2e-appliance`). Not verified on real PVE.

## Upgrade

```bash
sudo ./sm install upgrade                     # replace the installed sm with this one
sudo ./sm install upgrade --binary /path/sm   # replace it with another binary
install.sh upgrade                            # download, verify and install the release
sudo ./sm install upgrade --allow-downgrade   # deliberately install an older version
```

`install.sh upgrade` verifies the release exactly like a fresh install and then runs the new `sm install upgrade`, so the binary doing the upgrade is the one being installed. The policy (`internal/installer/upgrade.go`):

1. Refuse a lower version (exit 2) unless `--allow-downgrade`; a version that cannot be ordered is treated the same way. An unchanged binary ends with "nothing to upgrade".
2. Check free disk for the staged binary and the backup (exit 4).
3. Stage `sm.new`, hard-link the live binary as `sm.prev`, and record the phase in `/var/lib/supermgmt/upgrade.json`.
4. **Hold the service**, then stop it and **verify it terminated and the database lock is free**. The hold (systemd: a drop-in `50-upgrade-hold.conf` that refuses manual start, plus `disable`; launchd: `launchctl disable`) is applied *before* the stop, so nothing, including a reboot or a dependency, can start the old service while the upgrade is unfinished. Starting the service again lifts it.
5. Take a **read-only offline backup with the new binary** (`sm backup create --offline`): it opens the database read-only, never migrates and never activates, and the archive's schema version must equal the database's. The archive goes to the configured backups directory. If the installer is killed after the backup and rerun before the swap, it **takes the archive again** under the database lock and removes the superseded one, so the archive always matches the database that is about to be migrated.
6. Replace `sm` by rename (the live path is never missing), start the service and wait up to 60 s for `/health/ready`. The new daemon migrates the database forward.

Each phase (`prepared`, `stopped`, `backed_up`, `swapped`, `started`, `done`) is recorded durably. A rerun after a crash resumes from the recorded phase, or abandons an upgrade whose binary is no longer the one at hand, and never overwrites the known-good binary. `sm.prev` stays after a successful upgrade.

| Where it fails | Result |
|---|---|
| After the service stopped but before the swap (the backup fails) | The old service is started again, the state is cleared, exit 9. A refused version, too little disk or a new binary that will not run are caught earlier, before anything stops (exit 2 or 4). |
| After the swap, schema unchanged | The previous binary is put back and started, exit 9. |
| After the swap, schema advanced (the migration ran) | The service is left **stopped**, the restore commands are printed, exit 9. Nothing is restored automatically. |

`--allow-downgrade` is recorded in `upgrade.json` and, before the swap, as a pending audit record in `<data dir>/audit-pending/`. The first start of a daemon that knows this record (the current version and later) imports it as the event `instance.downgrade_authorized` (who, from, to) and deletes the file; a downgrade to an older build, which does not know the record, leaves it pending until a build that knows it starts. Every start also records `instance.version_changed` when the binary's version differs from the previous start. What to do after the third outcome: [operations.md](operations.md#upgrade-and-recovery).

On a Proxmox host with an appliance record, `sm install upgrade` upgrades **the appliance**. It requires both the record (`/var/lib/supermgmt-installer/appliances/<vmid>.json`) and the container's own marks (description with the install id and the `supermgmt` tag), refuses a container without them, pushes the binary, checks its SHA-256 and runs `sm install upgrade` inside, forwarding `--allow-downgrade` and keeping the inner exit code. With several appliances `--vmid` is required. A Proxmox host with no record upgrades its own `sm` like any host.

Covered by `TestUpgrade_*` and `TestUpgradeAppliance_*` (`internal/installer`) and `TestM3_Upgrade*` (CI job `e2e-upgrade`, which upgrades from an earlier build at commit e6d5577 and kills the run at each phase). The installer is also killed at each of its 20 crash points and rerun (`TestM6_CrashUpgrade_*`, CI job `e2e-crash`); the oldest recorded build is upgraded to the latest in one jump (`TestM6_UpgradeChainOldestToLatestInOneJump`, CI job `e2e-chain`); the database and archive of every recorded build are migrated and restored (job `migration-test`). The full lifecycle per platform is in [compatibility.md](compatibility.md#supported-platforms). Real-host runs of Proxmox: not verified.

## Uninstall

```bash
sudo ./sm install uninstall                   # remove the software, keep configuration, data and backups
sudo ./sm install uninstall --purge-data      # also delete them, after a typed confirmation
```

Uninstall stops the service, verifies it terminated, disables it, removes the unit, `sm` and the `sm.prev`/`sm.new` leftovers, and **keeps configuration, data and backups**. Deleting them is a separate decision:

- On a terminal, `--purge-data` asks you to type `delete my data`.
- Without a terminal, deleting needs `--purge-data` **and** `SUPERMGMT_YES=1` (the code also accepts `--yes` for the second); `--yes` without `--purge-data` deletes nothing.
- System directories (`/`, `/etc`, `/var`, `/usr`, ...) and the home directory are refused whatever the configuration says. The service account `supermgmt` is left in place.
- A server install deletes the data and configuration directories; a local install deletes the data directory and `config.yaml` but keeps client profiles.
- `--purge-data` also works after an earlier plain uninstall, to remove what was left.

On a Proxmox host with an appliance record (same ownership proof as upgrade, `--vmid` when there are several):

- The default runs `sm install uninstall` **inside** the container and stops the container. The container, its data, the appliance record and the Proxmox identities stay.
- `--purge-data` destroys the container (only if it carries the install id) and removes **this install's** Proxmox user, token, roles and ACLs, then the record. It asks you to type the VMID; without a terminal it needs `--vmid <id>`, `--purge-data` and `SUPERMGMT_YES=1` (or `--yes`). A record naming any identity other than the ones derived from its own install id is refused, and other appliances' identities are untouched (`TestUninstallAppliance_PurgeLeavesTheOtherApplianceAndForeignIdentitiesAlone`). The template stays.

Covered by `TestUninstall_*`, `TestUninstallAppliance_*` and `TestM3_Uninstall*` (CI job `e2e-upgrade`), and, per platform, by the lifecycle tests listed in [compatibility.md](compatibility.md#supported-platforms). Not verified on real PVE.

## Joining a node (`sm join`)

A node can enroll itself instead of being added over SSH. Join creates the unprivileged `supermgmt` user and its `restrict`ed authorized key only; it grants no sudo, no docker and no journal access. Those stay `node.setup`, an approval-gated job run with an `admin_user`.

On a machine signed in as an admin:

```bash
sm enrollments create --expires-in 1h --tag prod --max-nodes 1 --source-cidr 203.0.113.0/24
```

The token (`smj_...`, at most 24h, shown once) goes to stdout; the command to run goes to stderr. On the node, as root, either:

```bash
printf '%s' "$TOKEN" | sm join --server https://mgmt.example.com --token-stdin
# or, where sm is not installed yet (verifies the signed sm exactly like install.sh):
printf '%s' "$TOKEN" | sudo ./join.sh --server https://mgmt.example.com --token-stdin
```

Options: `--token-file FILE`, `--ca-file FILE` (CA of the server certificate, default system roots), `--hostname NAME`, `--ssh-port N`. The token is never an argument. `join.sh` has the same trust shape as `install.sh` (same placeholder key, same OpenSSH requirement) and ships signed as `join.sh` and `join.sh.sig` next to `install.sh` in a release.

`sm join` is safe to re-run after a lost response. A joined node reads as managed and read-only until `sm nodes setup <node>` runs. Authorizing the instance key on a node always goes through that step.

Whether `join.sh` was exercised against a real signed release: not verified.

## Exit codes

| Code | Meaning | Raised by |
|---|---|---|
| 0 | success | |
| 2 | invalid arguments or configuration (also: an ambiguous storage or bridge without a terminal, a refused downgrade, `auto` with nowhere to ask) | `install.sh`, `sm install` |
| 3 | unsupported platform (`proxmox-lxc` needs Proxmox VE 9.x on linux/amd64; an unsupported OS) | both |
| 4 | prerequisite failure (not root, a missing command, an ambiguous existing install, another installer running, not enough disk, `ssh-keygen` too old) | both |
| 5 | download, checksum or signature failure | `install.sh` only |
| 6 | resource creation failure (user, directories, container); on `proxmox-lxc` also "rollback pending: a Proxmox task still holds the container" | `sm install` |
| 7 | installation or configuration failure (files, unit, service start); on `proxmox-lxc` also "not fully rolled back, kept for manual recovery" | `sm install` |
| 8 | connectivity failure (the service did not become ready within 60s; on `proxmox-lxc` the container network, readiness or first discovery within 120s, or a Proxmox API that fails the provider check from the container) | `sm install` |
| 9 | restore failure (a failing `sm secrets import-key` or `sm backup restore` step keeps its own 2 or 4); also a failed, aborted or reverted upgrade | `sm install restore`, `sm install upgrade` |
| 10 | cancelled by the user | `sm install` |

Sources: `internal/installer/errors.go` and the header of `install.sh`. [Troubleshooting](troubleshooting.md#installing) says what to do about each.

## Release key and custody

The production key exists; its fingerprint is published above. How it is held:

- The private key exists only as the secret `SM_RELEASE_SIGNING_KEY` of the GitHub environment **`release`**, whose required reviewer is the repository owner. `release.yml` (on `v*` tags) and `channels.yml` (weekly, re-signs `channels/stable.json` and `channels/beta.json`) both run in that environment, so each run waits for the owner's approval. No other workflow may reference the environment; the `workflow-policy` CI job checks it.
- CI proves the whole chain with an ephemeral test key rendered into a test copy of `install.sh`. The committed `install.sh` and `scripts/join.sh` embed the production public key.
- Production signing and build provenance are **not verified** until the first protected tag run. Provenance (`actions/attest-build-provenance`) runs on tag builds only.
- Rotation: announce the new key in a release signed by the old one and embed both in `install.sh` for the overlap. Revocation: add the key to the embedded `revoked_keys` list. Both scripts embed the trust roots separately, so both must be updated together.

Steps the owner must do are in [manual-checks/m2-handoff.md](manual-checks/m2-handoff.md).

## Client credential storage

`sm login` keeps the session token in the macOS keychain (`security -i`, token on stdin), in the Secret Service through `secret-tool` on Linux, or in a mode-0600 `credentials.json` in the config directory when neither is usable (`internal/client/credstore.go`). The token is never an argument. The OS stores are unit-tested with fakes; real keychain and `secret-tool` runs are manual checks.

## References

- Code: `install.sh`, `internal/installer`, `internal/cli/install.go`.
- [Specification](spec/SUPERMGMT-SPEC.md): section 3 (installer, exit codes), section 8.1 (local paths), section 13 (join), sections 29.3 and 29.4 (upgrade and uninstall), Appendix A (systemd unit).
- Release pipeline, installer and key custody: [ADR-0019](adr/0019-release-pipeline-and-installer.md); OpenSSH release signatures: [ADR-0004](adr/0004-openssh-release-signatures.md).
- Join and enrollment: [ADR-0022](adr/0022-join-enrollment.md).
- Proxmox identities and privileges: [ADR-0023](adr/0023-pve-identity-privileges-compatibility.md); appliance failure matrix: [ADR-0026](adr/0026-appliance-installer.md).
- Upgrade and uninstall: [ADR-0027](adr/0027-upgrade-and-uninstall.md); upgrade paths, crash points and the service hold: [ADR-0035](adr/0035-upgrade-paths-migration-fixtures-crash-points.md#service-hold).
