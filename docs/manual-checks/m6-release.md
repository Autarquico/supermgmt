# M6 manual checks: the release gate

**Status: DEFERRED. Nothing on this page has been run.** These are the checks of the M6 release that no agent and no CI job can do: they need the production signing key, real hosts and machines, real services, legal and naming decisions, and repository settings that only the owner can change. Each section is the procedure behind a row of the [release checklist](../release-checklist.md); the row stays unchecked until the section's table below has a dated entry.

Record, for every check, the date, the `sm version` commit (or the tag), the platform, and the person who ran it. A check that was skipped says so; it is not left blank.

Checks that already have their own page are not repeated here: [m1-handoff.md](m1-handoff.md) (terminal), [m2-handoff.md](m2-handoff.md) (key, credential stores, OIDC, proxy, real VM), [m3-real-pve.md](m3-real-pve.md) (Proxmox), [m4-real-github.md](m4-real-github.md) (GitHub) and [m5-real-mcp-clients.md](m5-real-mcp-clients.md) (MCP clients).

## 1. Signing key and trust root

Owner only, one time. Follow check 0 of [m2-handoff.md](m2-handoff.md#0-release-environment-and-key-owner-only-one-time). An agent never handles the private key.

1. The key, the `release` environment (required reviewer, deployment restricted to `v*` and `main`) and the secret `SM_RELEASE_SIGNING_KEY` exist.
2. The public key is in both trust blocks (`install.sh`, `scripts/join.sh`) and the diff was read by a person.
3. The fingerprint is published out of band and replaces the placeholders in `SECURITY.md` and `docs/installation.md` at the signed tag. Until then the placeholder stays; every signature check fails closed.

Expected: a release candidate (section 2) installs on a clean machine with `SUPERMGMT_CHANNEL=beta`.

## 2. First tag: release candidate and gate behaviour

Procedure: [releasing.md](../releasing.md#cutting-a-release). The scripts and the workflow are tested with throwaway keys only, so the first protected run is the first proof of these:

1. `gates` reads the check runs of the exact tag commit through `gh api` and stops the release when one is missing, pending or not successful. Push the tag while a check is still running and confirm the release stops before `build`.
2. `nightly` has to have succeeded on that commit: dispatch `nightly.yml` on the candidate before tagging, and note how long it took (the fuzz shards have a 60 minute budget that no run has measured).
3. `sign-publish` runs `check.sh` (notices and SBOM against the compiled binary) and `verify-provenance.sh`. The attestation predicate field names and the `builder.id` format are assumed from the SLSA v1 convention. If `verify-provenance.sh` rejects a genuine statement, the script is wrong, not the release: record the real statement and fix the script.
4. The SBOM module names written by the real syft match what `sbom-check.sh` expects.
5. `gh attestation verify sm_<version>_linux_amd64.tar.gz --repo autarquico/supermgmt` verifies.
6. Dispatch `channels.yml`, approve it, and install the release candidate with the beta channel.
7. Yank rehearsal: make the candidate a draft, dispatch `channels.yml`, and confirm the pointer moves back and `SUPERMGMT_VERSION=<tag>` fails with a download error.

## 3. Real Debian 13 VM

CI proves Debian 13 in a systemd container only. On a fresh Debian 13 virtual machine (amd64; repeat on arm64 if you publish for it):

1. Install the release candidate in server mode with `install.sh` and a public URL you control.
2. `sm doctor`, sign in, add a node.
3. Upgrade to a later build with `sm install upgrade`; confirm the service is held during the upgrade (`systemctl cat supermgmt` shows the `50-upgrade-hold.conf` drop-in while stopped) and that the drop-in is gone afterwards.
4. Back up, restore on a second fresh VM with the exported key, and uninstall with and without `--purge-data`.

Expected: the same as the container lifecycle. Record any difference; a difference changes the Debian row of [compatibility.md](../compatibility.md#platforms-and-operations) from container-verified to a manual finding.

## 4. Intel macOS

The `darwin_amd64` archive is built in CI and never run. On an Intel Mac (macOS 15 or the oldest you claim):

1. Install the archive in local mode, start the daemon, add a node, open the TUI.
2. `sm install local --resident`, log out and in, confirm the launchd agent starts the daemon, then upgrade and uninstall.

Expected: no Rosetta-only behaviour, and the resident daemon survives a login.

## 5. First runs on GitHub of the lifecycle jobs

The jobs `e2e-lifecycle-container`, `e2e-lifecycle-linux`, `e2e-lifecycle-macos`, `e2e-crash` and `e2e-chain` were written without a GitHub run, and the arm64 and macOS legs were never executed anywhere. On the first run:

1. Every leg is green, or the failure is classified as a test defect or a product defect (the flake policy in [CONTRIBUTING.md](../../CONTRIBUTING.md#flaky-tests)).
2. Assumptions to confirm: `loginctl enable-linger` gives a usable `systemd --user` and bus on the hosted runner, passwordless `sudo -E` works, `launchctl bootstrap` of a disabled label fails (the hold), `launchctl print` is a valid "active" probe, and uninstall of a launchd agent leaves nothing behind.
3. Delete the sentence in [compatibility.md](../compatibility.md#platforms-and-operations) that says the jobs have not been seen running.

## 6. Upgrade from an authentic signed release

No release tag exists, so every upgrade test builds an older milestone from its merge commit under a synthetic version. After the first signed tag, install that tag on a clean machine, then upgrade it to the next build with `sm install upgrade`, and restore a backup archive written by the tagged binary. Expected: it migrates, the data is intact, the archive restores.

## 7. Third-party notices: legal reading

Procedure for the owner or counsel:

1. Read `THIRD_PARTY_LICENSES` from a published archive against [dependencies.md](../dependencies.md).
2. For every module whose `LICENSE` file is only the Apache header notice, decide whether the full licence text must be added (see `packaging/release/license-overrides.txt`).
3. Confirm the licence of the project itself (Apache-2.0 by default) is the one you want to ship: it determines the dependency allowlist in `dependency-review.yml` and `make licenses`.

## 8. Name, trademark and registries

Before the first public tag, with the working name "SuperMgmt": search the GitHub organisation and repository name, the Go module path, the Homebrew formula name (`supermgmt`), the domain, container registry names and trademark registers in the jurisdictions you sell in. A conflict means a rename before any announcement. Record what was searched, where and when.

## 9. Homebrew tap

1. Create the repository `autarquico/homebrew-tap` (the CI holds no token for it).
2. After a stable tag, render the formula from the signed `checksums.txt` as described in [packaging/homebrew/README.md](../../packaging/homebrew/README.md), commit it to the tap, and run `brew audit --strict` and `brew install autarquico/tap/supermgmt` on a Mac.

Expected: `sm version` reports the tag, and the formula's checksums equal the signed list.

## 10. GitHub repository settings

Owner only. Record a screenshot or the `gh api` output for each.

1. Secret scanning and push protection are enabled (the repository scan in `secret-scan` covers history; these cover the future).
2. Branch protection on `main` requires the checks listed in `packaging/release/required-checks.txt`, except `nightly`, which is a release-time gate.
3. The `release` environment has the owner as required reviewer and is restricted to `v*` tags and `main`.
4. Private vulnerability reporting is on, as `SECURITY.md` promises.
5. A dedicated security contact address replaces the placeholder in `SECURITY.md`.

## 11. Interactive journal recovery

`sm install proxmox-lxc` offers to roll back a kept journal only on a terminal, and no e2e test uses one. On a host (or the pvesim container with a pty) with a kept journal in `/var/lib/supermgmt-installer/journals/`, run `sm install proxmox-lxc` in a terminal. Expected: it finds the journal, offers the rollback, and leaves no journal behind. The real-host variant is row 5.9 of [m3-real-pve.md](m3-real-pve.md).

## 12. Downgrade to a pre-M6 binary (stated limitation)

`sm install upgrade --allow-downgrade` to a build older than M6 leaves the offline audit record in `<DataDir>/audit-pending/` because that binary cannot import it. Confirm: after such a downgrade the file is present; after the next start of an M6 or newer binary the event `instance.downgrade_authorized` appears once and the file is gone. This is a limitation, not a defect to close: it is listed as unresolved in the [release checklist](../release-checklist.md#unresolved-items-and-stated-limitations).

## 13. Nightly and flake loops

After the first week of `nightly.yml`: read the fuzz shards (any crasher becomes a regression input and a fix task), the `race-stress` run, and the `flake-loop` results (the daemon-restart test 20 times, the PTY suite 50 times on macOS). A flake that appears is classified and either fixed with a before-and-after proof or listed as unresolved.

## Results

| Section | Date | Environment | Pass / fail / skipped | Evidence (link, commit, tag) |
|---|---|---|---|---|
| 1 Signing key and trust root | | | | |
| 2 First tag and gates | | | | |
| 3 Real Debian 13 VM | | | | |
| 4 Intel macOS | | | | |
| 5 First runs of the lifecycle jobs | | | | |
| 6 Upgrade from a signed release | | | | |
| 7 Third-party notices | | | | |
| 8 Name and trademark | | | | |
| 9 Homebrew tap | | | | |
| 10 GitHub settings | | | | |
| 11 Interactive journal recovery | | | | |
| 12 Downgrade to a pre-M6 binary | | | | |
| 13 Nightly and flake loops | | | | |
