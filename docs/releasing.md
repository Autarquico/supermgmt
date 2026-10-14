# Releasing

For the repository owner. Sources: [ADR-0019](adr/0019-release-pipeline-and-installer.md), [ADR-0034](adr/0034-release-hardening-gates.md), [ADR-0036](adr/0036-distribution-notices-platform-claims.md), `.github/workflows/release.yml`, `.github/workflows/channels.yml`, `packaging/release/`.

**Nothing here has run against a real tag.** The scripts and the workflow policy are tested with throwaway keys (`make snapshot`, `make release-check`, `make install-test`, `go test ./test/install/`); the protected `release` environment, the production key, the provenance attestation and the first publish are not verified until the first protected tag run ([installation.md](installation.md#release-key-and-custody)).

## One-time setup: the key ceremony

The signing key, the `release` environment, its required reviewer and the trust blocks in `install.sh` and `scripts/join.sh` are created once, by the owner, on a trusted machine. The procedure is check 0 of [manual-checks/m2-handoff.md](manual-checks/m2-handoff.md#0-release-environment-and-key-owner-only-one-time). Until it is done, no release can be installed and the fingerprint in `SECURITY.md` and [installation.md](installation.md#review-first-verify-the-script-with-a-key-you-obtained-elsewhere) stays a placeholder.

## Versions and channels

| Tag | Channel | GitHub release |
|---|---|---|
| `vX.Y.Z` | `stable` | normal |
| `vX.Y.Z-<suffix>`, for example `v1.0.0-rc.1` | `beta` | marked pre-release (`release.yml`, "publish") |

- A release candidate is a tag with a suffix. It reaches only users of the `beta` channel; the signed `channel:` line in `checksums.txt` is derived from the tag by `finalize.sh`, and `select-version.sh` keeps a pointer from naming another channel's release.
- `channels.yml` signs the pointers `stable.json` and `beta.json` every Monday 06:17 UTC and on dispatch, valid for 21 days. `install.sh` refuses an expired pointer and one valid for more than 30 days (exit 5). If the workflow stops for three weeks, installs from the channel fail closed; running it again fixes that.
- `finalize.sh` refuses a tag that is not `vMAJOR.MINOR.PATCH` with an optional suffix.

## Cutting a release

1. **Candidate commit.** The commit is on `main` and every job of `ci.yml` is green on it. `sign-publish` refuses a tag that is not an ancestor of `origin/main`.
2. **Nightly on that commit.** Dispatch the slow gates on the exact commit you will tag: `gh workflow run nightly.yml --ref main`, then wait for the `nightly` check. It fails unless fuzzing, race stress, the flake loops and the Homebrew audit all passed. A nightly run of an earlier commit does not count.
3. **Human checklist.** Work through the `[human]` rows of the release checklist (`docs/release-checklist.md`, written with the release-gate task). A row stays unchecked until a person has run its procedure and recorded the date.
4. **Release candidate first.** Tag `vX.Y.Z-rc.N` on the candidate commit and push the tag. Let it complete, install it on a clean machine with `SUPERMGMT_CHANNEL=beta` (`SUPERMGMT_VERSION=vX.Y.Z-rc.N` before the channel moves), and only then tag `vX.Y.Z` on the same commit (or a later one that again passed steps 1 and 2).
5. **Approve.** `release.yml` runs `gates`, then `build` (no secret, no write permission), then `sign-publish`, which waits in the `release` environment for your approval. Before approving, read the `build` job: the archives and SBOMs it recorded are what `sign-publish` will sign.
6. **Verify what was published** (below).
7. **Move the channel.** Dispatch `channels.yml` from `main` (`gh workflow run channels.yml --ref main`) and approve it, or wait for the Monday run. Until then `install.sh` follows the previous pointer.
8. **Homebrew, stable tags only.** Render the formula from the signed `checksums.txt` and commit it to the tap: [packaging/homebrew/README.md](../packaging/homebrew/README.md). CI holds no tap token, so this is always a manual step.

## The gates

All of them must hold before a release exists. Each is a script or a CI job, so none depends on remembering.

| Gate | Where | What stops the release |
|---|---|---|
| Every CI job, and `nightly`, succeeded on the tag commit | `gates` job, `packaging/release/require-checks.sh`, the names in `packaging/release/required-checks.txt` | A required check that is missing, pending, skipped, neutral, cancelled or failed, or that was created by anything other than GitHub Actions. The gate does not wait: if CI was still running when you pushed the tag, rerun the workflow once it finishes |
| The required list matches `ci.yml` | `go test ./test/install/` (`TestWorkflowPolicy_RequiredChecksMatchCI`) | A job added to `ci.yml` and not to the list, or the reverse |
| Reproducible build | CI job `reproducible` | Two builds of the real release configuration from independent clean roots differ in any of the four binaries or archives |
| Notices | `packaging/release/check.sh` in `sign-publish` | An archive's `THIRD_PARTY_LICENSES` differs from the modules in its binary's build info |
| SBOM completeness | `check.sh` in `sign-publish` | A module of the binary is missing from the SPDX document, or has another version |
| Signatures | `check.sh` against the trust root embedded in `install.sh` | A signature that does not verify with the shipped key |
| Provenance | `packaging/release/verify-provenance.sh` before `publish` | A subject digest that differs from a published file, a source commit that is not the tag commit, or a builder that is not `release.yml` of this repository at the tag |
| Signing key reachable only here | `workflow-policy` job | Any other workflow that references the `release` environment or the key |

Unresolved flakes and tools that could not be run are listed in the release checklist, not hidden by a retry ([CONTRIBUTING.md](../CONTRIBUTING.md) states the flake policy).

## Verifying a published release

Anyone can do the first two; the third needs the GitHub CLI.

```bash
V=v1.2.3
# 1. the checksum list is signed by the release key (allowed_signers as in installation.md)
ssh-keygen -Y verify -f allowed_signers -I release@supermgmt -n supermgmt-release \
  -s checksums.txt.sig < checksums.txt
# 2. the archive matches the list
sha256sum -c --ignore-missing checksums.txt
# 3. the archive was built from this repository by release.yml
gh attestation verify sm_${V}_linux_amd64.tar.gz --repo autarquico/supermgmt
```

`install.sh` performs the first two itself on every install and upgrade. Step 3 is not part of `install.sh` and is not exercised by any test in this repository: the scripts check the provenance statement before publishing, and a reader who wants an independent check runs the command above.

## Yank and rollback

A published release is not rewritten. If it is bad:

1. **Stop new installs of it.** Turn the release into a draft (`gh release edit vX.Y.Z --draft`) so that `channels.yml` no longer sees it (it lists releases with `--exclude-drafts`), then dispatch `channels.yml`. The pointer moves to the newest remaining tag of that channel. A draft also removes the download URLs, so `SUPERMGMT_VERSION=vX.Y.Z` fails with a download error. Neither step has been exercised.
2. **Do not reuse the tag.** Fix forward with a new patch version; a reused tag would break the reproducibility and provenance checks for anyone holding the old one.
3. **Homebrew.** Revert the formula commit in the tap.
4. **Installs that already upgraded.** The upgrade protocol never rolls the database back once the new version migrated it ([operations.md](operations.md#upgrade-and-recovery)). To go back to the previous version: stop, put the previous binary back, and restore the pre-upgrade archive that the upgrade printed. `sm install upgrade` refuses a lower version unless `--allow-downgrade`, which is recorded as an audit event.

## Rotating the signing key

The mechanism is in [installation.md](installation.md#release-key-and-custody): announce the new key in a release signed by the old one and embed both keys in `install.sh` for the overlap; revoke by adding the old key to the embedded `revoked_keys`. Both `install.sh` and `scripts/join.sh` carry their own trust block, so update both in the same commit. Then replace the `SM_RELEASE_SIGNING_KEY` secret of the `release` environment (never a repository secret), and publish the new fingerprint through the channels listed in the ceremony.

A key you believe is compromised is a different case: revoke it first (the `revoked_keys` entry), release a build that carries the revocation, and say so in the release notes. No tested procedure covers how copies that are already installed learn about the revocation.
