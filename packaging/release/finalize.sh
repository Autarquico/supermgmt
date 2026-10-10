#!/bin/sh
# Turn GoReleaser output into the signed release set (spec 3.2, 36).
# Writes checksums.txt (two header lines, then sha256 of archives and SBOMs), copies install.sh and
# scripts/join.sh (when present) next to it, and signs all of them.
# Usage: finalize.sh DIST VERSION        Env: SM_SIGNING_KEY_FILE
set -eu
LC_ALL=C
export LC_ALL

[ $# -eq 2 ] || { echo "usage: finalize.sh DIST VERSION" >&2; exit 2; }
dist=$1
version=$2
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo "invalid version: $version" >&2; exit 2; }
case $version in *-*) channel=beta ;; *) channel=stable ;; esac

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

write_checksums() {
	{
		printf 'version: %s\nchannel: %s\n' "$version" "$channel"
		for path in "$dist"/sm_*.tar.gz "$dist"/sm_*.tar.gz.spdx.json; do
			printf '%s  %s\n' "$(sha256_of "$path")" "${path##*/}"
		done
	} >"$dist/checksums.txt"
}

for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
	[ -f "$dist/sm_${version#v}_$target.tar.gz" ] || { echo "missing archive for $target in $dist" >&2; exit 1; }
done

write_checksums
cp "$root/install.sh" "$dist/install.sh"
[ ! -f "$root/scripts/join.sh" ] || cp "$root/scripts/join.sh" "$dist/join.sh"
for f in checksums.txt install.sh join.sh; do
	[ ! -f "$dist/$f" ] || "$here/sign.sh" "$dist/$f"
done
echo "finalized $version ($channel) in $dist"
