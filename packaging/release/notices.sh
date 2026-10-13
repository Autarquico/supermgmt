#!/bin/sh
# Third-party notices from the modules in a compiled binary's build info (ADR-0034, ADR-0036).
# Usage: notices.sh modules  BINARY          list "module version" per dependency
#        notices.sh generate BINARY OUT      write THIRD_PARTY_LICENSES for BINARY
#        notices.sh verify   BINARY NOTICES  fail unless NOTICES is exactly what generate would write
# Needs go and the module cache (GOMODCACHE); SM_LICENSE_OVERRIDES replaces license-overrides.txt.
set -eu
LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)
overrides=${SM_LICENSE_OVERRIDES:-$here/license-overrides.txt}

fail() { echo "notices: $*" >&2; exit 1; }

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

build_info() {
	[ -f "$1" ] || fail "$1 does not exist"
	go version -m "$1" || fail "$1 has no Go build info"
}

modules() {
	info=$(build_info "$1")
	list=$(printf '%s\n' "$info" | awk -F'\t' '
		$2 == "dep" { print $3 " " $4 }
		$2 == "=>"  { print "notices: replaced module " $3 > "/dev/stderr"; bad = 1 }
		END { exit bad }') || fail "replaced modules need a manual licence review"
	[ -n "$list" ] || fail "$1 lists no modules in its build info"
	printf '%s\n' "$list" | sort
}

go_version_of() {
	build_info "$1" | sed -n '1s/.*: //p'
}

# Module cache directory names lower-case every upper-case letter and prefix it with "!".
cache_dir() {
	modcache=${GOMODCACHE:-$(go env GOMODCACHE)}
	escaped=$(printf '%s@%s' "$1" "$2" | awk '{
		for (i = 1; i <= length($0); i++) {
			c = substr($0, i, 1)
			out = out (c ~ /[A-Z]/ ? "!" tolower(c) : c)
		}
		print out }')
	printf '%s/%s\n' "$modcache" "$escaped"
}

override_of() {
	[ -f "$overrides" ] || return 0
	awk -F'\t' -v m="$1" -v v="$2" '$1 !~ /^#/ && $1 == m && $2 == v { print; exit }' "$overrides"
}

notice_files() {
	find "$1" -maxdepth 1 -type f \( -iname 'LICEN[CS]E*' -o -iname 'COPYING*' -o -iname 'UNLICENSE*' -o -iname 'NOTICE*' -o -iname 'PATENTS*' \) |
		sed 's|.*/||' | sort
}

print_file() {
	printf -- '--- %s ---\n' "$2"
	cat "$1/$2"
	[ -z "$(tail -c1 "$1/$2")" ] || echo
}

module_section() {
	path=$1
	version=$2
	dir=$(cache_dir "$path" "$version")
	[ -d "$dir" ] || fail "$path $version is not in the module cache ($dir)"
	files=$(notice_files "$dir")
	override=$(override_of "$path" "$version")
	if [ -n "$override" ]; then
		file=$(printf '%s' "$override" | cut -f4)
		want=$(printf '%s' "$override" | cut -f5)
		[ -f "$dir/$file" ] || fail "override for $path $version names $file, which the module does not have"
		[ "$(sha256_of "$dir/$file")" = "$want" ] || fail "$path $version: $file differs from the reviewed override; review it again"
		files=$(printf '%s\n%s\n' "$files" "$file" | sed '/^$/d' | sort -u)
	fi
	[ -n "$override" ] || printf '%s\n' "$files" | grep -Eiq '^(licen[cs]e|copying|unlicense)' || fail "$path $version has no licence file; add a reviewed override"
	printf '=== %s %s ===\n' "$path" "$version"
	[ -z "$override" ] || printf 'SPDX-License-Identifier: %s (reviewed override)\n' "$(printf '%s' "$override" | cut -f3)"
	printf '%s\n' "$files" | while IFS= read -r file; do print_file "$dir" "$file"; done
}

stdlib_section() {
	root=$(go env GOROOT)
	# Homebrew installs the toolchain under libexec and leaves LICENSE one level up.
	[ -f "$root/LICENSE" ] || root=$(dirname "$root")/$(basename "$root")/..
	[ -f "$root/LICENSE" ] || fail "no Go LICENSE in $(go env GOROOT) or its parent"
	printf '=== go-stdlib %s ===\n' "$1"
	for file in LICENSE PATENTS; do
		[ ! -f "$root/$file" ] || print_file "$root" "$file"
	done
}

render() {
	list=$(modules "$1")
	goversion=$(go_version_of "$1")
	printf 'THIRD PARTY LICENSES\n\nThis binary contains the components below. Each section is a module (or the Go\nstandard library) followed by the licence and notice files shipped with it.\n\n'
	printf '%s\n' "$list" | while read -r path version; do
		module_section "$path" "$version"
		echo
	done
	stdlib_section "$goversion"
}

# Sections that hold at least one licence text, as "module version".
licensed_sections() {
	awk '
		/^=== .* ===$/ { if (name != "" && licensed) print name; name = substr($0, 5, length($0) - 8); licensed = 0; next }
		/^--- (LICEN[CS]E|COPYING|UNLICENSE)/ || /^SPDX-License-Identifier: / { licensed = 1 }
		END { if (name != "" && licensed) print name }' "$1" | sort
}

lines_missing_from() { # LIST1 LIST2: lines of LIST1 that LIST2 lacks
	printf '%s\n' "$1" | while IFS= read -r line; do
		printf '%s\n' "$2" | grep -qxF -- "$line" || echo "$line"
	done
}

verify() {
	[ -f "$2" ] || fail "$2 does not exist"
	want=$( { modules "$1"; printf 'go-stdlib %s\n' "$(go_version_of "$1")"; } | sort)
	have=$(licensed_sections "$2")
	missing=$(lines_missing_from "$want" "$have" | tr '\n' ',')
	extra=$(lines_missing_from "$have" "$want" | tr '\n' ',')
	[ -z "$missing" ] || fail "$2 has no licence text for: $missing"
	[ -z "$extra" ] || fail "$2 lists components that are not in the binary: $extra"
	expected=$(mktemp)
	trap 'rm -f "$expected"' EXIT
	render "$1" >"$expected"
	cmp -s "$expected" "$2" || fail "$2 differs from the notices generated for the binary (a licence or NOTICE text is missing or altered)"
}

generate() {
	tmp=$(mktemp)
	trap 'rm -f "$tmp"' EXIT
	render "$1" >"$tmp"
	mv "$tmp" "$2"
	trap - EXIT
}

usage() { echo "usage: notices.sh modules BINARY | generate BINARY OUT | verify BINARY NOTICES" >&2; exit 2; }

[ $# -ge 2 ] || usage
case $1 in
modules) [ $# -eq 2 ] || usage; modules "$2" ;;
generate) [ $# -eq 3 ] || usage; generate "$2" "$3" ;;
verify) [ $# -eq 3 ] || usage; verify "$2" "$3" ;;
*) usage ;;
esac
