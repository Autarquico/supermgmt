#!/bin/sh
# Render the Homebrew formula from the signed checksums.txt of a stable release (ADR-0036, Q4).
# The formula is a derived artifact: version and digests come only from checksums.txt, and when
# TRUST is given the checksums signature is verified first (see verify-asset.sh for TRUST).
# Usage: brew-formula.sh CHECKSUMS [TRUST]      Env: SM_RELEASE_BASE_URL (default: GitHub releases)
# Writes the formula to stdout.
set -eu
LC_ALL=C
export LC_ALL

[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: brew-formula.sh CHECKSUMS [TRUST]" >&2; exit 2; }
checksums=$1
here=$(cd "$(dirname "$0")" && pwd)
template="$here/../homebrew/supermgmt.rb.tmpl"
base_url=${SM_RELEASE_BASE_URL:-https://github.com/autarquico/supermgmt/releases/download}

fail() { echo "brew-formula: $*" >&2; exit 1; }

[ -f "$checksums" ] || fail "$checksums is missing"
[ $# -lt 2 ] || "$here/verify-asset.sh" "$checksums" "$2" >/dev/null || fail "checksums signature does not verify"

tag=$(sed -n 's/^version: //p;1q' "$checksums")
printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail "not a stable version: '$tag'"
[ "$(sed -n 2p "$checksums")" = "channel: stable" ] || fail "checksums are not for the stable channel"
version=${tag#v}

digest_of() {
	name="sm_${version}_$1.tar.gz"
	digest=$(awk -v n="$name" 'NR > 2 && $2 == n { print $1; c++ } END { exit c != 1 }' "$checksums") ||
		fail "$name is not listed exactly once"
	printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' || fail "$name has no sha256 digest"
	printf '%s\n' "$digest"
}

darwin_arm64=$(digest_of darwin_arm64)
darwin_amd64=$(digest_of darwin_amd64)
linux_arm64=$(digest_of linux_arm64)
linux_amd64=$(digest_of linux_amd64)

sed -e "s|@BASE_URL@|$base_url|g" \
	-e "s|@VERSION@|$version|g" \
	-e "s|@SHA_DARWIN_ARM64@|$darwin_arm64|" \
	-e "s|@SHA_DARWIN_AMD64@|$darwin_amd64|" \
	-e "s|@SHA_LINUX_ARM64@|$linux_arm64|" \
	-e "s|@SHA_LINUX_AMD64@|$linux_amd64|" \
	"$template"
