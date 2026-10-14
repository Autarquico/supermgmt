#!/bin/sh
# Drives the fuzz inventory (ADR-0034). The inventory is scripts/fuzz-inventory.txt.
# Usage: fuzz.sh count             number of distinct mapped fuzz targets
#        fuzz.sh list              "<target> <package dir> <weight>" per target, in inventory order
#        fuzz.sh reach             run every target over its seeds; fail when a mapped function has zero coverage
#        fuzz.sh shard INDEX COUNT fuzz the targets of one shard (INDEX in 0..COUNT-1) for FUZZTIME each (default 5m)
# FuzzReadArchive is slow (a 128 MiB zstd window, about 7 execs/s), so it weighs SLOW_WEIGHT targets
# when shards are balanced: its 5 minutes cost more than another target's.
set -eu
cd "$(dirname "$0")/.."

inventory=scripts/fuzz-inventory.txt
module=github.com/autarquico/supermgmt
fuzztime=${FUZZTIME:-5m}
slow_targets="FuzzReadArchive"
slow_weight=2

fail() { echo "fuzz: $*" >&2; exit 1; }

mapped_rows() {
	awk '/^#/ || NF < 2 || $2 ~ /^exempt:/ { next } { print $1, $2 }' "$inventory"
}

target_dir() {
	file=$(grep -rl --include='*_test.go' -e "^func $1(" internal test | head -n 1) || true
	[ -n "$file" ] || fail "no test file declares $1"
	dirname "$file"
}

weight_of() {
	for slow in $slow_targets; do
		[ "$slow" = "$1" ] && { echo "$slow_weight"; return; }
	done
	echo 1
}

targets() {
	mapped_rows | awk '!seen[$2]++ { print $2 }'
}

list() {
	targets | while read -r target; do
		echo "$target $(target_dir "$target") $(weight_of "$target")"
	done
}

count() {
	targets | wc -l | tr -d ' '
}

# reach_target TARGET: its seeds must execute every function the inventory maps to it.
reach_target() {
	target=$1
	dir=$(target_dir "$target")
	rows=$(mapped_rows | awk -v t="$target" '$2 == t { print $1 }')
	packages=$(printf '%s\n' "$rows" | sed "s|^$module/||; s|\.[^/]*$||" | sort -u | sed 's|^|./|' | paste -sd, -)
	profile=$(mktemp)
	trap 'rm -f "$profile"' EXIT
	go test -count=1 -run "^$target\$" -coverpkg="$packages" -coverprofile="$profile" "./$dir" >/dev/null ||
		fail "$target failed over its seeds"
	covered=$(go tool cover -func="$profile" | awk '$NF != "0.0%" { sub(/:[0-9]+:$/, "", $1); print $1 " " $2 }')
	status=0
	for row in $rows; do
		rest=${row#"$module"/}
		pkg=${rest%%.*}
		name=${rest##*.}
		printf '%s\n' "$covered" | grep -q "^$module/$pkg/[^/]*\.go $name\$" || {
			echo "fuzz: $row is mapped to $target but its seeds never execute it" >&2
			status=1
		}
	done
	return $status
}

reach() {
	status=0
	for target in $(targets); do
		( reach_target "$target" ) || status=1
	done
	[ "$status" -eq 0 ] && echo "reach: every mapped function is executed by its target's seeds"
	return $status
}

# shard INDEX COUNT: greedy balancing by weight, in inventory order, so every shard is deterministic.
shard_targets() {
	list | awk -v want="$1" -v n="$2" '
		{
			best = 0
			for (s = 1; s < n; s++) if (load[s] < load[best]) best = s
			load[best] += $3
			if (best == want) print $1, $2
		}'
}

shard() {
	index=$1
	total=$2
	case $index$total in *[!0-9]*) fail "shard INDEX COUNT must be numbers" ;; esac
	[ "$index" -lt "$total" ] || fail "shard INDEX must be below COUNT"
	status=0
	shard_targets "$index" "$total" | while read -r target dir; do
		echo "=== $target ($dir) for $fuzztime"
		go test -run '^$' -fuzz "^$target\$" -fuzztime "$fuzztime" "./$dir" || echo "$target" >>"${FUZZ_FAILED:-/dev/null}"
	done
	if [ -n "${FUZZ_FAILED:-}" ] && [ -s "$FUZZ_FAILED" ]; then
		echo "fuzz: failed targets:" >&2
		cat "$FUZZ_FAILED" >&2
		status=1
	fi
	return $status
}

usage() { echo "usage: fuzz.sh count | list | reach | shard INDEX COUNT" >&2; exit 2; }

[ "$#" -ge 1 ] || usage
case $1 in
count) count ;;
list) list ;;
reach) reach ;;
shard) [ "$#" -eq 3 ] || usage; FUZZ_FAILED=${FUZZ_FAILED:-$(mktemp)}; export FUZZ_FAILED; : >"$FUZZ_FAILED"; shard "$2" "$3" ;;
*) usage ;;
esac
