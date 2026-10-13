#!/bin/sh
# Build the release twice, from two independent source extractions with separate Go caches and
# temp dirs, and require the 4 sm binaries and the 4 archives to be byte-identical (make reproducible).
# Uses the real .goreleaser.yaml. Requires git and goreleaser v2 (and syft unless SM_REPRO_BUILD is set).
#
# Environment:
#   SM_REPRO_BUILD  command run in each root instead of the GoReleaser snapshot (test seam)
#   SM_REPRO_MIN    minimum number of binaries and of archives that must be produced (default 4)
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
min=${SM_REPRO_MIN:-4}
build=${SM_REPRO_BUILD:-goreleaser release --snapshot --clean}
work=$(mktemp -d)
trap 'st=$?; chmod -R u+w "$work" 2>/dev/null; rm -rf "$work" 2>/dev/null || true; exit $st' EXIT

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

commit=$(git -C "$repo" rev-parse HEAD)
stamp=$(git -C "$repo" log -1 --format=%cI HEAD)

build_in_clean_root() {
	root=$work/$1
	mkdir -p "$root/src" "$root/gocache" "$root/gomodcache" "$root/gopath" "$root/tmp"
	git -C "$repo" archive "$commit" | tar -x -C "$root/src"
	(
		cd "$root/src"
		git init -q
		git add -A
		GIT_AUTHOR_NAME=repro GIT_AUTHOR_EMAIL=repro@invalid GIT_AUTHOR_DATE=$stamp \
			GIT_COMMITTER_NAME=repro GIT_COMMITTER_EMAIL=repro@invalid GIT_COMMITTER_DATE=$stamp \
			git -c commit.gpgsign=false commit -q -m "reproducibility build of $commit"
		git tag v0.0.0
		GOCACHE=$root/gocache GOMODCACHE=$root/gomodcache GOPATH=$root/gopath TMPDIR=$root/tmp \
			sh -c "$build" >"$root/build.log" 2>&1 || { cat "$root/build.log" >&2; exit 1; }
	)
}

# One "<digest> <relative path>" line per binary and archive, sorted.
manifest() {
	(
		cd "$work/$1/src/dist"
		find . -type f \( -name sm -o -name 'sm_*.tar.gz' \) | sort | while read -r f; do
			printf '%s %s\n' "$(sha256 "$f")" "$f"
		done
	)
}

build_in_clean_root a
build_in_clean_root b
manifest a >"$work/a.manifest"
manifest b >"$work/b.manifest"

bins=$(grep -c '/sm$' "$work/a.manifest" || true)
archives=$(grep -c '\.tar\.gz$' "$work/a.manifest" || true)
if [ "$bins" -lt "$min" ] || [ "$archives" -lt "$min" ]; then
	echo "expected at least $min binaries and $min archives, got $bins and $archives" >&2
	exit 1
fi

if ! diff -u "$work/a.manifest" "$work/b.manifest" >&2; then
	echo "build is not reproducible: the two clean roots differ" >&2
	exit 1
fi
echo "reproducible: $bins binaries and $archives archives identical across two clean roots"
