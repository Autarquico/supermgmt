#!/usr/bin/env bash
# Fixtures and assertions for the install.sh tests. Sourced by run.sh.
# Every case gets a fresh "world": a trusted key, an untrusted key, a rendered install.sh that trusts
# only the trusted key, and signed fake releases v1.0.0, v1.0.1 and v1.1.0-beta.1 served from disk.

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
REL="$REPO/packaging/release"
FAILURES=0
CASES=0

iso_at() { # seconds from now -> UTC timestamp
	local ts=$(($(date -u +%s) + $1))
	date -u -d "@$ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$ts" +%Y-%m-%dT%H:%M:%SZ
}
DAY=86400

# render_install SRC DEST ALLOWED_FILE [REVOKED_FILE]: replace the trust-root blocks of install.sh.
render_install() {
	awk -v allowed="$3" -v revoked="${4:-/dev/null}" '
		function emit(file,   line) { while ((getline line < file) > 0) print line; close(file) }
		/^# BEGIN allowed_signers$/ { print; emit(allowed); skip = 1; next }
		/^# BEGIN revoked_keys$/    { print; emit(revoked); skip = 1; next }
		/^# END (allowed_signers|revoked_keys)$/ { skip = 0 }
		!skip { print }' "$1" >"$2"
	chmod +x "$2"
}

# build_release ROOT VERSION KEYDIR: signed fake release with a stub sm that records its execution.
build_release() {
	local root=$1 version=$2 keydir=$3 stage pkg target
	stage=$(mktemp -d)
	pkg=$(mktemp -d)
	mkdir -p "$root/$version"
	# shellcheck disable=SC2016 # the stub expands its own variables
	printf '#!/bin/sh\ntouch "$SM_MARKER"\necho "stub-sm $*"\n' >"$pkg/sm"
	chmod +x "$pkg/sm"
	for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
		tar -czf "$stage/sm_${version#v}_$target.tar.gz" -C "$pkg" sm
		printf '{"spdxVersion":"SPDX-2.3","name":"%s"}\n' "$target" >"$stage/sm_${version#v}_$target.tar.gz.spdx.json"
	done
	SM_SIGNING_KEY_FILE="$keydir/key" "$REL/finalize.sh" "$stage" "$version" >/dev/null
	cp "$stage"/* "$root/$version/"
	rm -rf "$stage" "$pkg"
}

# new_world: sets W (root dir), BASE (file:// mirror), INSTALL (rendered install.sh), MARKER.
new_world() {
	W=$(mktemp -d)
	"$REL/testkey.sh" "$W/trusted" >/dev/null 2>&1
	"$REL/testkey.sh" "$W/other" >/dev/null 2>&1
	BASE="file://$W/rel"
	INSTALL="$W/install.sh"
	MARKER="$W/sm-ran"
	mkdir -p "$W/rel/channels" "$W/stubs"
	render_install "$REPO/install.sh" "$INSTALL" "$W/trusted/allowed_signers"
	build_release "$W/rel" v1.0.0 "$W/trusted"
	build_release "$W/rel" v1.0.1 "$W/trusted"
	build_release "$W/rel" v1.1.0-beta.1 "$W/trusted"
	publish_channel stable v1.0.0 "$(iso_at -DAY)" "$(iso_at $((20 * DAY)))"
	publish_channel beta v1.1.0-beta.1 "$(iso_at -DAY)" "$(iso_at $((20 * DAY)))"
}

publish_channel() { # channel version issued_at valid_until
	SM_SIGNING_KEY_FILE="$W/trusted/key" "$REL/channel.sh" "$1" "$2" "$3" "$4" "$W/rel/channels"
}

sign_with() { # keydir file
	SM_SIGNING_KEY_FILE="$1/key" "$REL/sign.sh" "$2"
}

# run_install SHELL [ENV=VALUE...] -- [install.sh args]: sets OUT and RC; PATH keeps $W/stubs first.
run_install() {
	local sh=$1
	shift
	local envs=()
	while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
	[ $# -eq 0 ] || shift
	rm -f "$MARKER"
	OUT=$(env "SUPERMGMT_RELEASE_BASE_URL=$BASE" "SM_MARKER=$MARKER" "PATH=$W/stubs:$PATH" SUPERMGMT_NONINTERACTIVE=1 \
		${envs[@]+"${envs[@]}"} "$sh" "$INSTALL" "$@" 2>&1 </dev/null)
	RC=$?
}

# expect NAME WANT_RC [OUTPUT_SUBSTRING]: also asserts sm only ran on success.
expect() {
	CASES=$((CASES + 1))
	local name=$1 want=$2 needle=${3:-} ok=1
	[ "$RC" -eq "$want" ] || ok=0
	if [ -n "$needle" ]; then case $OUT in *"$needle"*) ;; *) ok=0 ;; esac; fi
	if [ "$want" -ne 0 ] && [ -e "$MARKER" ]; then ok=0; name="$name (sm executed before verification)"; fi
	if [ "$want" -eq 0 ] && [ ! -e "$MARKER" ]; then ok=0; fi
	if [ "$ok" -eq 1 ]; then
		printf 'ok   %s\n' "$name"
	else
		FAILURES=$((FAILURES + 1))
		printf 'FAIL %s: rc=%s want=%s\n%s\n' "$name" "$RC" "$want" "$OUT" | sed 's/^/     /'
	fi
}

expect_rc() { # NAME WANT_RC (for commands that are not install.sh)
	CASES=$((CASES + 1))
	if [ "$RC" -eq "$2" ]; then printf 'ok   %s\n' "$1"; else
		FAILURES=$((FAILURES + 1)); printf 'FAIL %s: rc=%s want=%s\n%s\n' "$1" "$RC" "$2" "$OUT" | sed 's/^/     /'
	fi
}

finish() {
	printf '%s cases, %s failures\n' "$CASES" "$FAILURES"
	[ "$FAILURES" -eq 0 ]
}
