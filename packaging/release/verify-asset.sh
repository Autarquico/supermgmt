#!/bin/sh
# Verify FILE against FILE.sig with ssh-keygen -Y verify. Exit 5 on any failure (spec 3.7).
# TRUST is either an allowed_signers file or a file with "# BEGIN allowed_signers" /
# "# BEGIN revoked_keys" blocks (install.sh); the latter is the review-first and release-check path.
# Usage: verify-asset.sh FILE TRUST
set -eu

[ $# -eq 2 ] || { echo "usage: verify-asset.sh FILE TRUST" >&2; exit 2; }
file=$1
trust=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

block() { awk -v b="$1" '$0 == "# END " b { on = 0 } on { print } $0 == "# BEGIN " b { on = 1 }' "$trust"; }

if grep -q '^# BEGIN allowed_signers$' "$trust"; then
	block allowed_signers >"$work/allowed"
	block revoked_keys >"$work/revoked"
else
	cp "$trust" "$work/allowed"
fi
echo '# none' >>"$work/revoked"

if ssh-keygen -Y verify -f "$work/allowed" -r "$work/revoked" -I release@supermgmt -n supermgmt-release \
	-s "$file.sig" <"$file" >/dev/null 2>&1; then
	echo "ok: $file"
else
	echo "signature verification failed: $file" >&2
	exit 5
fi
