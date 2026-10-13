if [ -n "${SM_RELEASE_CHECK_STRUCTURE_ONLY:-}" ] && { [ "${GITHUB_REF_TYPE:-}" = tag ] || [ -n "${GITHUB_ACTIONS:-}" ] && [ "${GITHUB_WORKFLOW:-}" = release ]; }; then
	echo "check.sh: SM_RELEASE_CHECK_STRUCTURE_ONLY is refused for a release build" >&2
	exit 2
fi
#!/bin/sh
# Assert a finalized release directory is complete and verifiable (make release-check, release.yml).
# Usage: check.sh DIST TRUST      (TRUST: see verify-asset.sh)
# Also needs go, jq and the module cache (notices.sh, sbom-check.sh).
# SM_RELEASE_CHECK_STRUCTURE_ONLY=1 skips the notices/SBOM comparison against the compiled sm; it exists
# for the install tamper matrix, whose fake releases ship a stub sm that has no Go build info.
set -eu

[ $# -eq 2 ] || { echo "usage: check.sh DIST TRUST" >&2; exit 2; }
if [ -n "${SM_RELEASE_CHECK_STRUCTURE_ONLY:-}" ] && { [ "${GITHUB_REF_TYPE:-}" = tag ] || [ "${GITHUB_WORKFLOW:-}" = release ]; }; then
	echo "check.sh: SM_RELEASE_CHECK_STRUCTURE_ONLY is refused for a release build" >&2
	exit 2
fi
dist=$1
trust=$2
here=$(cd "$(dirname "$0")" && pwd)

fail() { echo "release-check: $*" >&2; exit 1; }

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# assert_supply_chain ARCHIVE SBOM: the notices and the SBOM match the modules compiled into the archive's sm.
assert_supply_chain() {
	unpacked="$scratch/${1##*/}"
	mkdir -p "$unpacked"
	tar -xzf "$1" -C "$unpacked" sm THIRD_PARTY_LICENSES 2>/dev/null || fail "${1##*/} does not contain sm and THIRD_PARTY_LICENSES"
	"$here/notices.sh" verify "$unpacked/sm" "$unpacked/THIRD_PARTY_LICENSES" || fail "${1##*/}: notices do not match the compiled modules"
	"$here/sbom-check.sh" "$unpacked/sm" "$2" || fail "${2##*/}: SBOM does not match the compiled modules"
}

[ -f "$dist/checksums.txt" ] || fail "checksums.txt is missing"
version=$(sed -n 's/^version: //p;1q' "$dist/checksums.txt")
[ -n "$version" ] || fail "checksums.txt has no version header"
sed -n 2p "$dist/checksums.txt" | grep -Eq '^channel: (stable|beta)$' || fail "checksums.txt has no channel header"

[ -f "$dist/install.sh" ] || fail "install.sh is missing"
for f in checksums.txt install.sh join.sh; do
	[ ! -f "$dist/$f" ] || "$here/verify-asset.sh" "$dist/$f" "$trust" >/dev/null || fail "$f signature does not verify"
done

for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
	archive="sm_${version#v}_$target.tar.gz"
	for name in "$archive" "$archive.spdx.json"; do
		[ -f "$dist/$name" ] || fail "$name is missing"
		want=$(awk -v n="$name" 'NR > 2 && $2 == n { print $1 }' "$dist/checksums.txt")
		[ -n "$want" ] && [ "$want" = "$(sha256_of "$dist/$name")" ] || fail "$name is not covered by a matching checksum"
	done
	tar -tzf "$dist/$archive" | grep -qx 'sm' || fail "$archive does not contain sm"
	grep -q '"spdxVersion"' "$dist/$archive.spdx.json" || fail "$archive.spdx.json is not an SPDX document"
	[ -n "${SM_RELEASE_CHECK_STRUCTURE_ONLY:-}" ] || assert_supply_chain "$dist/$archive" "$dist/$archive.spdx.json"
done
echo "release-check: $dist ok ($version)"
