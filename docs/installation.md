# Installation

> **Status: nothing is released.** No signed release exists yet, and `install.sh` on `main` holds a placeholder instead of the release public key, so every verification fails closed with exit 5 ([install.sh](../install.sh) line 23). Everything below describes what the installer does once the owner has created the release key ([Release key and custody](#release-key-and-custody)) and cut a protected tag build. Until then, build from source (`make build`) and use `sm install` by hand, or run the test installer in CI.

Sources: SPEC §3, [ADR-0019](adr/0019-release-pipeline-and-installer.md), [ADR-0004](adr/0004-openssh-release-signatures.md), `install.sh`, `internal/installer`, `internal/cli/install.go`.

## Two ways in

### `curl | bash`

```bash
curl -fsSL https://raw.githubusercontent.com/autarquico/supermgmt/main/install.sh | bash -s -- server --public-url https://mgmt.example.com
```

The organisation in the URL is the one `install.sh` uses for downloads (`DEFAULT_BASE_URL`); that the repository is public at that address is not verified.

**This path trusts the `main` branch.** Whoever can change `install.sh` on `main` can replace both the verifier and the embedded public key, so a repository compromise defeats it (SPEC §3.2). The signatures protect what the script downloads *after* it has started; they cannot protect the script itself.

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
SHA256:<RELEASE-KEY-FINGERPRINT-NOT-PUBLISHED-YET>
```

That value is a placeholder. The key does not exist yet and the fingerprint will be published at the first signed tag.

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

`install.sh` and `scripts/join.sh` refuse an `ssh-keygen` that cannot pass the self-test and tell you "OpenSSH 8.2 or newer is required" (`install.sh` line 79). SPEC §3.2 and ADR-0019 require 8.2 as well: the self-test signs with a `valid-after` option in `allowed_signers`, which older releases reject.

### The default mode does not work yet

`install.sh` defaults to mode `auto` (SPEC §3.4). In M2, `sm install auto`, `proxmox-lxc`, `upgrade` and `uninstall` all exit 3 with "arrives in milestone M3" (`internal/cli/install.go` lines 16 and 40). Always name the mode: `local`, `server`, `client` or `restore`.

## Modes

Run as `install.sh <mode> [flags]` or, with the binary, `sm install <mode> [flags]`. Flags for every mode: `--non-interactive` (fail instead of guessing; also `SUPERMGMT_NONINTERACTIVE`), `--yes` (do not ask to confirm the plan; also `SUPERMGMT_YES`).

| Mode | What it does | Needs |
|---|---|---|
| `local` | Binary in `~/.local/bin` (or `SUPERMGMT_INSTALL_DIR`), a config file and a data directory under the user paths of SPEC §8.1. `--resident` also registers and starts a user unit (systemd) or launch agent (macOS) so the daemon keeps running. `--name` sets the instance name. | Linux or macOS. `--resident` on Linux needs systemd. |
| `server` | System user `supermgmt`, `/etc/supermgmt` (0750, root:supermgmt), `/var/lib/supermgmt` (0750), `secrets/keys` (0700), a backups directory, binary in `/usr/local/bin/sm`, the systemd unit of SPEC Appendix A, a generated config, then starts the unit, waits for `/health/ready` and prints a one-time bootstrap code. | Linux with systemd, run as root. |
| `client` | Binary only, plus an empty profile file (mode 0600) in the config directory. | Linux or macOS. |
| `restore` | Installs like `server` without starting it, imports a master key export, restores an archive offline, then starts the service in restore hold. Does not print a bootstrap code. | As `server`, plus `--archive` and `--key-export`. |

Server and restore flags:

| Flag | Meaning |
|---|---|
| `--public-url URL` | Required non-interactively. Must be `https`. The prompt asks for it otherwise. |
| `--tls proxy` (default) or `--tls direct` | Who terminates TLS, see below. |
| `--tls-cert FILE`, `--tls-key FILE` | With `--tls direct` only. |
| `--trusted-proxy IP/CIDR` (repeatable) | With `--tls proxy` only. Default `127.0.0.1/32`. |
| `--listen ADDR` | Default `127.0.0.1:8787` for proxy, `0.0.0.0:8443` for direct. |
| `--name NAME` | Instance name, default `supermgmt`. |

Restore adds `--archive FILE` and `--key-export FILE` (the unlock phrase is read from stdin or the terminal, never a flag).

The installer **keeps an existing config file and data**. If it finds an existing installation or several candidate configurations it fails without a terminal (exit 4) and asks with one. It never overwrites configuration or the database.

The config the installer writes holds only `instance` and `server`. OIDC and everything else is edited in afterwards ([configuration.md](configuration.md)).

### TLS: proxy or direct

There is **no ACME and no certificate generation**. You bring the certificate, or a reverse proxy that has one.

- `--tls proxy` (default): the daemon speaks plain HTTP on a loopback or Unix address and a reverse proxy in front terminates TLS. `X-Forwarded-For` and `X-Forwarded-Proto` are believed only from a peer inside `trusted_proxies`; a forwarded proto other than `https` is rejected with 400; a connection from loopback gets no special trust. A non-loopback plain-HTTP listener is refused. Keep the default `127.0.0.1/32` only when the proxy runs on the same host.
- `--tls direct`: the daemon terminates TLS 1.2 or newer with the pair you give it. The installer checks that the pair matches, has not expired and covers the host of `--public-url`. The pair is re-read on `SIGHUP` (a failed reload keeps the old pair).

Cloudflare Access/Tunnel is a proxy arrangement: see [cloudflare.md](cloudflare.md).

### After a server install

The installer prints a bootstrap code (valid `auth.bootstrap.code_ttl`, default 24h, single use, shown once). On your own machine:

```bash
sm profile add prod --url https://mgmt.example.com --use
sm login --bootstrap          # reads the code from the terminal or stdin
```

On a server **without OIDC**, `sm login --bootstrap --display-name <name>` creates the first admin; on a terminal the name is prompted for, defaulting to `$USER`.

With OIDC configured, the code is exchanged *after* a normal `sm login` by the identity that is to become admin. OIDC needs its client secret in the secret store first: store it with `sm secrets import --offline` while the service is stopped. See [operations.md](operations.md#enabling-oidc-on-a-fresh-server).

## Joining a node (`sm join`)

A node can enroll itself instead of being added over SSH (SPEC §13, [ADR-0022](adr/0022-join-enrollment.md)). Join creates the unprivileged `supermgmt` user and its `restrict`ed authorized key only; it grants no sudo, no docker and no journal access. Those stay `node.setup`, an approval-gated job run with an `admin_user`.

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

Whether `join.sh` was exercised against a real signed release: not verified (no release exists).

## Exit codes

| Code | Meaning | Raised by |
|---|---|---|
| 0 | success | |
| 2 | invalid arguments or configuration | `install.sh`, `sm install` |
| 3 | unsupported platform, or a mode that arrives in M3 | both |
| 4 | prerequisite failure (not root, a missing command, an ambiguous existing install, `ssh-keygen` too old) | both |
| 5 | download, checksum or signature failure | `install.sh` only |
| 6 | resource creation failure (user, directories) | `sm install` |
| 7 | installation or configuration failure (files, unit, service start) | `sm install` |
| 8 | connectivity failure (the service did not become ready within 60s) | `sm install` |
| 9 | restore failure (a failing `sm secrets import-key` or `sm backup restore` step keeps its own 2 or 4) | `sm install restore` |
| 10 | cancelled by the user | `sm install` |

Sources: SPEC §3.7, `internal/installer/errors.go`, the header of `install.sh`.

## Release key and custody

Nothing about the production key exists yet. The design (ADR-0019):

- The private key exists only as the secret `SM_RELEASE_SIGNING_KEY` of the GitHub environment **`release`**, whose required reviewer is the repository owner. `release.yml` (on `v*` tags) and `channels.yml` (weekly, re-signs `channels/stable.json` and `channels/beta.json`) both run in that environment, so each run waits for the owner's approval. No other workflow may reference the environment; the `workflow-policy` CI job checks it.
- CI proves the whole chain with an ephemeral test key rendered into a test copy of `install.sh`. The committed `install.sh` and `scripts/join.sh` carry a placeholder block that verifies nothing.
- Production signing and build provenance are **not verified** until the first protected tag run. Provenance (`actions/attest-build-provenance`) runs on tag builds only.
- Rotation: announce the new key in a release signed by the old one and embed both in `install.sh` for the overlap. Revocation: add the key to the embedded `revoked_keys` list. Both scripts embed the trust roots separately, so both must be updated together.

Steps the owner must do are in [manual-checks/m2-handoff.md](manual-checks/m2-handoff.md).

## Client credential storage

`sm login` keeps the session token in the macOS keychain (`security -i`, token on stdin), in the Secret Service through `secret-tool` on Linux, or in a mode-0600 `credentials.json` in the config directory when neither is usable (`internal/client/credstore.go`). The token is never an argument. The OS stores are unit-tested with fakes; real keychain and `secret-tool` runs are manual checks.
