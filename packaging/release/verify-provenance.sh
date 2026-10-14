#!/bin/sh
# Check an in-toto SLSA provenance statement (JSON, as attested by release.yml) against what is
# about to be published. Exit 1 on any mismatch. Runs before `publish`. Requires jq.
#   - every subject names a file in DIST and carries that file's sha256;
#   - every sm_*.tar.gz and checksums.txt in DIST is a subject;
#   - the source commit equals the tag SHA;
#   - the builder is release.yml of REPO at refs/tags/TAG.
# Usage: verify-provenance.sh STATEMENT DIST TAG_SHA REPO TAG
set -eu

[ $# -eq 5 ] || { echo "usage: verify-provenance.sh STATEMENT DIST TAG_SHA REPO TAG" >&2; exit 2; }
statement=$1 dist=$2 tag_sha=$3 repo=$4 tag=$5
failed=0
fail() { echo "provenance: $*" >&2; failed=1; }

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

jq -e '(.subject | type) == "array" and (.subject | length) > 0' "$statement" >/dev/null 2>&1 || {
	fail "statement has no subjects"
	exit 1
}

subjects=$(mktemp)
trap 'rm -f "$subjects"' EXIT
jq -r '.subject[] | [.name, (.digest.sha256 // "")] | @tsv' "$statement" >"$subjects"
tab=$(printf '\t')
while IFS=$tab read -r name digest; do
	file=$dist/$(basename "$name")
	if [ ! -f "$file" ]; then
		fail "subject $name is not in $dist"
	elif [ "$(sha256 "$file")" != "$digest" ]; then
		fail "subject $name has digest '$digest', the file is $(sha256 "$file")"
	fi
done <"$subjects"

[ -f "$dist/checksums.txt" ] || fail "checksums.txt is missing from $dist"
for file in "$dist"/sm_*.tar.gz "$dist"/checksums.txt; do
	[ -f "$file" ] || continue
	jq -e --arg n "$(basename "$file")" 'any(.subject[]; (.name | split("/") | last) == $n)' "$statement" >/dev/null ||
		fail "$(basename "$file") is not a subject"
done

source_sha=$(jq -r '[.predicate.buildDefinition.resolvedDependencies[]?.digest.gitCommit // empty] | first // ""' "$statement")
[ "$source_sha" = "$tag_sha" ] || fail "source commit is '$source_sha', want $tag_sha"

builder=$(jq -r '.predicate.runDetails.builder.id // ""' "$statement")
want_builder="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag"
[ "$builder" = "$want_builder" ] || fail "builder is '$builder', want $want_builder"

[ "$failed" -eq 0 ] || exit 1
echo "provenance ok: $tag at $tag_sha"
