#!/bin/sh
# Assert an SPDX document lists every module in a binary's build info with the same version (ADR-0034).
# Usage: sbom-check.sh BINARY SBOM.json
set -eu

[ $# -eq 2 ] || { echo "usage: sbom-check.sh BINARY SBOM.json" >&2; exit 2; }
binary=$1
sbom=$2
here=$(cd "$(dirname "$0")" && pwd)

fail() { echo "sbom-check: $*" >&2; exit 1; }

[ -f "$sbom" ] || fail "$sbom does not exist"
jq -e '.packages | type == "array"' "$sbom" >/dev/null 2>&1 || fail "$sbom is not an SPDX document with packages"
listed=$(jq -r '.packages[] | "\(.name) \(.versionInfo // "")"' "$sbom")

modules=$("$here/notices.sh" modules "$binary") || exit 1
problems=$(printf '%s\n' "$modules" | while IFS= read -r module; do
	printf '%s\n' "$listed" | grep -qxF -- "$module" || echo "$module"
done | tr '\n' ',')
[ -z "$problems" ] || fail "$sbom lacks these modules at the binary's version: $problems"
