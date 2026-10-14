# Troubleshooting

Each entry is a symptom, the usual cause and what to do. The causes come from the pages linked in the entry, or from the code and tests it names; where a cause is a guess it says so. Nothing here was exercised on a real host unless the linked page says it was ([Project status](project-status.md) says what is verified, [compatibility.md](compatibility.md) what CI runs per platform).

Using SuperMgmt from your laptop? Start with [On your laptop](#on-your-laptop). Running a server? First, two commands that answer most questions. Run them on the server as root or as the service user:

```bash
sudo sm doctor              # asks the running server: mode, restore hold, admin bound, TLS, providers
sm doctor --offline --json  # files and database, with the service stopped
```

Installer exit codes are in [installation.md](installation.md#exit-codes).

## On your laptop

These come up while you follow [Getting started](getting-started.md). The entries were written from the code and its tests, not from runs on real laptops.

### `sm` prints help instead of opening the TUI

`sm` with no arguments opens the TUI only when both its input and its output are a terminal; otherwise it prints the help (`TestBareCommandOutsideATerminalPrintsHelp`). Run it directly in a terminal window, not through a pipe or an editor's task runner. `sm tui` fails with "the TUI needs an interactive terminal" in the same situation.

### `daemon is not reachable`

Exit 4. Every command that is not offline talks to a daemon over a Unix socket, and starts one when none is running. The TUI waits up to 10 seconds for it before taking the screen, so a daemon that does not start shows up as this error, not as an empty screen. The end of the message says which case you hit:

- **`the daemon did not start within 5s; see .../daemon.log`**: the daemon was started but did not answer in time (`TestAutostartGivesUpAfterTheWaitAndPointsAtTheLog`). Read the log it names, in your state directory (`~/.local/state/supermgmt` on Linux, `~/Library/Application Support/SuperMgmt/state` on macOS). A configuration file the daemon rejects is one possible cause; `sm config validate --config <file>` checks it without starting anything.
- **`no daemon is running and autostart is off`**: `SUPERMGMT_NO_AUTOSTART` is set in your environment (`TestMissingDaemonWithoutAutostartIsReportedNotSpawned`). Unset it, or start the daemon yourself with `sm daemon`.
- **`cannot start the daemon`**: `sm` could not run itself again, or could not create the log file. The rest of the message says which.

### `refusing to talk to ...`

The socket is owned by another user, or its owner could not be identified, so `sm` sent nothing to it (`TestPeerWithAnotherUIDIsNeverSentAnything`, `TestPeerLookupFailureFailsClosed`). Run `sm` as the user who owns the daemon, and check where `daemon.socket` or `XDG_RUNTIME_DIR` points ([configuration.md](configuration.md)).

### `socket path is ... bytes, over the platform limit`

Unix socket paths are short: 104 bytes on macOS, 108 on Linux. A long home directory or state directory pushes the default path over the limit, and `sm` says so instead of cutting the path (`TestOverlongSocketPathIsAnExplicitErrorNotASilentTruncation`). Set `daemon.socket` to a shorter path in your configuration file.

### `SSH_AUTH_SOCK is not set` or `cannot reach the ssh-agent`

`CAPABILITY_UNAVAILABLE` (`TestAgentUnavailableIsCapabilityUnavailable`). Until a machine is set up, SuperMgmt logs in as your admin account through your SSH agent, and it is the daemon, not the command you typed, that talks to the agent. The daemon keeps the environment of the command that started it, so a daemon started from a shell without an agent cannot use the agent you load later.

1. Check that `ssh-add -l` lists your key in your shell.
2. Let the daemon go: it exits on its own after `daemon.idle_exit` (10 minutes by default) once no client is connected and no job is unfinished, including jobs waiting for approval. Or stop the `sm daemon` process.
3. Run the command again from the shell where your agent works.

This was read from the code (`internal/transport/ssh/creds.go`, `internal/client/autostart.go`), not seen on a laptop.

### `SSH_HOST_KEY_MISMATCH`

The machine presented a host key other than the one SuperMgmt pinned when you added it. The message names both fingerprints. SuperMgmt refuses the connection and never re-pins on its own.

Find out why before you do anything else. A reinstalled machine or regenerated host keys explain it; anything else may be someone between you and the machine. Once you have checked the new fingerprint on the machine itself (for example `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), pin it:

```bash
sm nodes repin web1                                  # shows the new fingerprint and asks you to confirm
sm nodes repin web1 --fingerprint SHA256:...         # or pass the fingerprint you checked
```

`sm nodes repin` refuses a fingerprint other than the one it scans, and refuses when the key has not changed (`TestNodesRepinRefusesAFingerprintOtherThanTheOneYouVerified`, `TestNodesRepinRefusesWhenTheKeyHasNotChanged`). The change is audited with the old and new fingerprints ([operations.md](operations.md#key-management)).

### Setup fails, or the machine shows no units

See [If something goes wrong](getting-started.md#if-something-goes-wrong) in Getting started: the admin account needs `root` or passwordless `sudo`, an existing `supermgmt` account that differs makes setup fail with `CONFLICT`, and a Mac has no systemd, so it shows no units.

## Installing

### `install.sh` exits 5

Download, checksum or signature failure; it always fails closed. The causes, most likely first:

- **No stable release exists yet.** The script on `main` embeds the release key, but the default `stable` channel has nothing to download until the first stable release is published. Pre-releases, if any, are on the `beta` channel, and the installer has not been verified on a clean machine ([installation.md](installation.md)). Build from source meanwhile.
- **The channel pointer expired** ("channel file has expired"). The weekly `channels` workflow did not run; the owner reruns it ([releasing.md](releasing.md#versions-and-channels)). `SUPERMGMT_VERSION=vX.Y.Z` pins a version and skips the pointer, with integrity but no freshness check.
- **A mirror served something else.** With `SUPERMGMT_RELEASE_BASE_URL` set, check the mirror holds the files of that release unmodified.

### Exit 4 before anything is downloaded

A prerequisite failed: not root, a missing command, another installer running, not enough disk, or `ssh-keygen` older than OpenSSH 8.2. The message names which. Nothing was changed.

### Exit 3

The platform is not supported. `proxmox-lxc` needs Proxmox VE 9.x on linux/amd64 ([compatibility.md](compatibility.md#proxmox-ve)); other combinations are listed under [Supported platforms](compatibility.md#supported-platforms).

### Exit 8: the service did not become ready

The installer waits 60 seconds for `/health/ready` (120 on the appliance). Look at `systemctl status supermgmt` and `journalctl -u supermgmt`, then `sm doctor --offline`. A configuration the daemon rejects is the usual cause; fix it in `/etc/supermgmt/config.yaml` and start the service.

### `sm install proxmox-lxc` failed or was interrupted

The installer rolls back only what its journal says it created. Exit 7 lists what was kept; exit 6 means a Proxmox task still holds the container. Rerun from a terminal: it finds the journal in `/var/lib/supermgmt-installer/journals/<id>/` (and the older `/var/tmp/supermgmt-installer-<id>/`) and offers to finish. Without a terminal it refuses and names the journal. Remove kept resources by hand; each carries the install id in its name ([operations.md](operations.md#proxmox-appliance-recovery)).

## Upgrading

### `sm install upgrade` exits 9

Three different cases, told apart by the message ([installation.md](installation.md#upgrade)):

| What happened | State | Do |
|---|---|---|
| The old service was started again | Nothing changed except the backup; the state is cleared | Fix the cause (usually the backup step: disk, permissions) and rerun |
| The previous binary was put back and started ("reverted") | The new binary failed before it changed the schema | Look at the new version's log; rerun when fixed |
| The service is **stopped** and restore commands were printed | The new version migrated the database, then failed. Nothing is restored automatically | Follow [operations.md](operations.md#the-new-version-failed-after-the-database-was-migrated) |

### The service will not start after an interrupted upgrade

That is the hold working: while `/var/lib/supermgmt/upgrade.json` exists the unit refuses manual start, dependency start and boot start (a drop-in `50-upgrade-hold.conf` plus `disable`; `launchctl disable` on macOS). `systemctl start` printing a refusal is expected. Run `sm install upgrade` again with the same binary: it resumes from the recorded phase and lifts the hold when it starts the service. To abandon the upgrade, rerun it with the old binary. Rerunning while `upgrade.json` says `failed` only prints the restore instructions.

### `sm install upgrade` refuses with exit 2

The binary is older than the installed one, or its version cannot be ordered. Use `--allow-downgrade` only deliberately: the database does not migrate backwards, so a downgrade after a migration needs the pre-upgrade archive restored ([releasing.md](releasing.md#yank-and-rollback)).

## Restoring

### Every write returns `CONFLICT` with `RESTORE_HOLD`

The server is in the restore hold after a restore. Review `sm doctor` and the interrupted jobs, then `sudo sm admin restore-complete` ([operations.md](operations.md#restore-hold)).

### Restore exits 4, or says the archive needs a key

Exit 4 means a daemon holds the database lock: stop the service. An archive without its master key is refused; import the key export first with `sm secrets import-key --offline` ([operations.md](operations.md#restore)). Master keys are never in an archive.

### `backup.create` returns `CONFLICT`

Either no configuration has been activated yet (nothing consistent to archive) or `backup.directory` is outside the unit's `ReadWritePaths` (default `/var/lib/supermgmt`) ([operations.md](operations.md#schedule-and-retention)).

## Running

### Doctor reports `tls` warn or fail

Only with `server.tls.mode: direct`. Warn: the certificate expires within 30 days. Fail: it is expired or unreadable. Replace the certificate files and restart; with a proxy in front the check is absent.

### A power action is held as uncertain, or doctor warns about clock skew

After a power action SuperMgmt finds the Proxmox task by matching its start time against a window around the dispatch (120 seconds either side). The sync records the difference between the Proxmox host's clock and this one; `sm doctor` warns above 60 seconds. If the clocks drift, a task can fall outside the window and the job is held for a person instead of retried ([providers.md](providers.md#interrupted-power-jobs-and-task-correlation)). Synchronize both clocks with NTP; then settle a held job with `sm jobs get` and `sm jobs resolve`, after looking at the guest in Proxmox. A skew that could not be read (no `Date` header) is not warned about.

### A Proxmox provider shows `error`

`sm providers refresh <name>` shows the error. Usual causes: a rotated Proxmox certificate not covered by `ca_file`, a revoked token or ACL (guests turn `inaccessible`), or port 8006 blocked ([operations.md](operations.md#proxmox-appliance-recovery)). `sm providers check` also fails (exit 8) unless the token has `Sys.Audit` on `/`.

### OIDC login fails with `PROVIDER_ERROR`

Discovery runs at the first login, not at start. The discovery document's `issuer` must equal `auth.oidc.issuer` byte for byte, and its endpoints must be `https` on the issuer's origin ([configuration.md](configuration.md)). A trailing slash or a different host name is enough to fail.

### HTTP 429

The fixed rate limits were exceeded (`/auth/*` and `/enroll`: 10 per minute; writes: 60 per minute). Wait for `Retry-After`. Behind a proxy, the limit is per forwarded client address, and only addresses in `trusted_proxies` are believed ([operations.md](operations.md#limits-worth-knowing)).

### MCP: 401, 403 or 400

- **401** with `WWW-Authenticate`: the client must follow `resource_metadata` and obtain a token for the resource `<origin>/mcp`.
- **403**: the `Origin` header differs from the origin of `server.public_url`. An absent `Origin` is served.
- **400**: the protocol version is not one of the three the server speaks.
- A token that verifies but belongs to a subject nobody registered is refused. An administrator registers each `(iss, sub, client_id)` ([mcp.md](mcp.md)).

### A deployment waits, fails or is unavailable

- **`waiting_ci` for a long time**: the required checks are pending. It ends at `github.ci_timeout` (default 2 h) with `CI_TIMEOUT`, or with `CHECK_MISSING` when a required check never appeared ([deployments.md](deployments.md)).
- **`docker.compose.deploy` unavailable on a node**: the Compose CLI there is not exactly 5.5.1, or `jq`, `flock`, `bash`, `timeout`, `ss`, `sha256sum`, `base64` or `df` is missing ([compatibility.md](compatibility.md#deployments)).
- **`ROLLBACK_UNAVAILABLE`**: a secret version or snapshot the known-good deployment bound is gone; the rollback is refused before anything changes.
- **Deployments from GitHub fail verification**: the GitHub path was only exercised against fakes; see the deferred list in [compatibility.md](compatibility.md#deployments).

## Still stuck

Collect `sm version`, `sm doctor` output, the exit code and the message, and open an issue; follow [SECURITY.md](../SECURITY.md) instead when the problem looks like a vulnerability. Do not paste tokens, archives or key exports.
