# ADR-0019: Release pipeline and installer

- Status: Accepted
- Spec: §3, §3.2, §3.4, §3.6, §3.7, §13, §36, Appendix A; ADR-0004

## Context

ADR-0004 chose OpenSSH signatures for releases. M2 builds the pipeline, the `install.sh` bootstrap and `sm install local|server|client|restore`. The real release key needs human custody; CI must prove the whole chain without it.

## Decision

### Artifacts (GoReleaser v2, a CI tool, not a module)

- `sm_<version>_<os>_<arch>.tar.gz` for linux/darwin × amd64/arm64, `CGO_ENABLED=0`, `-trimpath`, version/commit/date via ldflags.
- `checksums.txt` starts with two header lines, `version: vX.Y.Z` and `channel: stable|beta`, followed by `<sha256>  <file>` lines (§3.2 step 4).
- `ssh-keygen -Y sign -n supermgmt-release` signatures: `checksums.txt.sig`, `install.sh.sig`, `join.sh.sig`, and `channels/<channel>.json.sig`.
- SBOM (SPDX JSON via Syft) per archive.
- Provenance via `actions/attest-build-provenance`, on tag builds only.

### Workflows and key custody

- `release.yml` runs on `v*` tags only, in GitHub environment `release` with the owner as required reviewer, `permissions: contents: write, id-token: write, attestations: write` and nothing else.
- `channels.yml` re-signs `channels/stable.json` and `channels/beta.json` on a schedule (at least every 14 days; `valid_until − issued_at ≤ 30 days`), in the same environment.
- The private key exists only as a secret of environment `release`. No other workflow references that environment or its secrets; the `workflow-policy` CI job checks this with actionlint plus a grep over `.github/workflows/`.
- CI generates an ephemeral test key per run and renders it into a test copy of `install.sh`. The committed `install.sh` holds the production `allowed_signers` block. Until the owner generates the key, that block holds a placeholder that verifies nothing, so installs fail closed (exit 5).
- Production signing and provenance are unverified until the first protected tag run.

### `install.sh` (POSIX sh, < 300 lines)

1. Detect OS, architecture, root, systemd, TTY and the required commands, and print the result.
2. Verify the verifier: `ssh-keygen -Y verify` of an embedded test message and signature. Failure, or OpenSSH < 8.2, is exit 4 (`valid-after` in `allowed_signers` needs 8.2). This runs before any download.
3. Resolve the version: `SUPERMGMT_VERSION=vX.Y.Z` > `latest`/`SUPERMGMT_CHANNEL` > `stable`. Channel files are verified and must satisfy `issued_at ≤ now + 5 min`, `now ≤ valid_until`, `valid_until − issued_at ≤ 30 days`.
4. Download `checksums.txt`, its signature and the archive; verify the signature against the embedded `allowed_signers` (with `valid-after`/`valid-before`) and `revoked_keys` (`-r`); check the header against the request; check the archive SHA-256.
5. Unpack into a `mktemp -d` directory and `exec sm install <mode>`.

- Any download, checksum or signature failure is exit 5.
- Release assets live on GitHub Releases; channel files on a `channels` rolling release. `SUPERMGMT_RELEASE_BASE_URL` overrides the base URL for mirrors and tests. It never disables a verification step.
- `scripts/join.sh` has the same verification shape and ends with `exec sm join`.
- A modified `install.sh` or `join.sh` fails `ssh-keygen -Y verify` in the review-first flow (§3.1). A `curl | bash` from `main` trusts `main` itself, as §3.2 states.

### `sm install` (`internal/installer`)

- `local`: binary in `~/.local/bin` (or `SUPERMGMT_INSTALL_DIR`), config and data directories per §8.1, optional systemd user unit (or launchd agent on macOS) for a resident daemon.
- `server`: system user `supermgmt`, `/etc/supermgmt` (0750), `/var/lib/supermgmt` (0750, `secrets/keys` 0700), binary `/usr/local/bin/sm`, unit exactly Appendix A. The TLS arrangement is explicit: `--tls proxy` (default; listen `127.0.0.1:8787`) or `--tls direct --tls-cert PATH --tls-key PATH`. The installer starts the unit, waits for `/health/ready`, runs `sm admin bootstrap-code` and prints it with access instructions.
- `client`: binary only, plus an empty profile file.
- `restore`: installs like `server` without starting it, then runs the frozen offline commands of ADR-0020 (`sm secrets import-key --offline`, `sm backup restore --offline`), then starts.
- `upgrade`, `uninstall` and `proxmox-lxc` are M3.
- Every system interaction (users, systemctl, file writes) sits behind an interface with a fake. Non-interactive mode fails rather than guess. Secrets are never flags (§3.6). Exit codes are §3.7.
- Hardening directives of Appendix A are tested in the Debian systemd container with a real SSH probe; only directives shown incompatible are relaxed, and each relaxation is documented.

## Consequences

- No release is installable until the owner creates the production key and runs a protected tag build.
- The CI acceptance runs in a Debian systemd container; a real VM run is a separate, optional job (spec note on M2 acceptance).
