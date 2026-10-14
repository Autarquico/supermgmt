#!/bin/sh
# SuperMgmt bootstrap installer (spec section 3.2, ADR-0019).
#
# Usage: install.sh [mode] [sm-install-args...]     (mode defaults to $SUPERMGMT_MODE, then auto)
# Env:   SUPERMGMT_VERSION=vX.Y.Z|latest  SUPERMGMT_CHANNEL=stable|beta  SUPERMGMT_MODE
#        SUPERMGMT_RELEASE_BASE_URL  mirror/test override of the release download base; never skips verification
# Exit:  2 invalid arguments, 3 unsupported platform, 4 prerequisite failure, 5 download/checksum/signature failure
#
# It verifies a signed checksum list, then the archive, and only then executes the unpacked `sm`.
# Trust root of `curl | bash`: this file on the main branch (spec 3.2). Review-first users verify it with install.sh.sig.
set -eu

DEFAULT_BASE_URL='https://github.com/autarquico/supermgmt/releases/download'
NAMESPACE='supermgmt-release'
PRINCIPAL='release@supermgmt'

log() { printf 'install.sh: %s\n' "$*" >&2; }
die() { code=$1; shift; log "error: $*"; exit "$code"; }

write_trust_roots() {
	cat >"$WORK/allowed_signers" <<'EOF'
# BEGIN allowed_signers
release@supermgmt valid-after="20261014",namespaces="supermgmt-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBDaUxtppvnxho0KAF62G5IJVRMII+v1e7zJNy1f0F3T
# END allowed_signers
EOF
	cat >"$WORK/revoked_keys" <<'EOF'
# BEGIN revoked_keys
# END revoked_keys
EOF
	cat >"$WORK/selftest_signers" <<'EOF'
selftest@supermgmt valid-after="20200101",namespaces="supermgmt-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/0rZjuLbOAYMUDGUQxdU6VZp13y6BXawIDIRfDnJPc
EOF
	cat >"$WORK/selftest.sig" <<'EOF'
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgL/StmO4ts4BgxQMZRDF1TpVmnX
fLoFdrAgMhF8Ock9wAAAARc3VwZXJtZ210LXJlbGVhc2UAAAAAAAAABnNoYTUxMgAAAFMA
AAALc3NoLWVkMjU1MTkAAABAcwRofHb6eTVNPGpLA1vHPvOGOByz0YwzlMxPBTIV6T3MiO
J5MdRm2h6kVwgscGBqGDu6ZzQc7qanik2v5D0xDg==
-----END SSH SIGNATURE-----
EOF
	printf 'supermgmt-installer-selftest\n' >"$WORK/selftest.msg"
}

have() { command -v "$1" >/dev/null 2>&1; }

detect_platform() {
	case $(uname -s) in
		Linux) OS=linux ;;
		Darwin) OS=darwin ;;
		*) die 3 "unsupported OS: $(uname -s)" ;;
	esac
	case $(uname -m) in
		x86_64 | amd64) ARCH=amd64 ;;
		aarch64 | arm64) ARCH=arm64 ;;
		*) die 3 "unsupported architecture: $(uname -m)" ;;
	esac
	ROOT=no; [ "$(id -u)" -eq 0 ] && ROOT=yes
	SYSTEMD=no; [ -d /run/systemd/system ] && SYSTEMD=yes
	TTY=no; [ -t 0 ] && TTY=yes
	PVE=no; have pveversion && pveversion >/dev/null 2>&1 && PVE=yes
	log "detected: os=$OS arch=$ARCH root=$ROOT systemd=$SYSTEMD tty=$TTY proxmox=$PVE"
}

require_commands() {
	for c in curl tar awk sed grep mktemp ssh-keygen; do
		have "$c" || die 4 "required command not found: $c (install it, or verify the release manually on another machine)"
	done
	have sha256sum || have shasum || die 4 'required command not found: sha256sum or shasum'
}

verify_signature() { # file signature
	ssh-keygen -Y verify -f "$WORK/allowed_signers" -r "$WORK/revoked_keys" \
		-I "$PRINCIPAL" -n "$NAMESPACE" -s "$2" <"$1" >/dev/null 2>&1
}

verify_the_verifier() {
	ssh-keygen -Y verify -f "$WORK/selftest_signers" -I selftest@supermgmt -n "$NAMESPACE" \
		-s "$WORK/selftest.sig" <"$WORK/selftest.msg" >/dev/null 2>&1 ||
		die 4 'ssh-keygen cannot verify OpenSSH signatures (OpenSSH 8.2 or newer is required); install a newer OpenSSH client or verify manually on another machine'
}

fetch() { # url destination
	if [ -n "${SUPERMGMT_RELEASE_BASE_URL:-}" ]; then
		curl -fsSL --retry 2 -o "$2" "$1" || die 5 "download failed: $1"
	else
		curl -fsSL --proto '=https' --tlsv1.2 --retry 2 -o "$2" "$1" || die 5 "download failed: $1"
	fi
}

fetch_verified() { # remote-path destination
	fetch "$BASE_URL/$1" "$2"
	fetch "$BASE_URL/$1.sig" "$2.sig"
	verify_signature "$2" "$2.sig" || die 5 "signature verification failed: $1"
}

is_version() { printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; }

sha256_of() {
	if have sha256sum; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

json_field() { sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n 1; }

# Seconds since the epoch for YYYY-MM-DDTHH:MM:SSZ, in portable shell arithmetic.
epoch() {
	case $1 in
		[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
		*) die 5 "malformed timestamp: $1" ;;
	esac
	y=${1%%-*}; r=${1#*-}; mo=${r%%-*}; r=${r#*-}; d=${r%%T*}; r=${r#*T}
	h=${r%%:*}; r=${r#*:}; mi=${r%%:*}; s=${r#*:}; s=${s%Z}
	mo=$((1$mo - 100)); d=$((1$d - 100)); h=$((1$h - 100)); mi=$((1$mi - 100)); s=$((1$s - 100))
	[ "$mo" -le 2 ] && y=$((y - 1))
	era=$((y / 400)); yoe=$((y - era * 400))
	doy=$(((153 * (mo > 2 ? mo - 3 : mo + 9) + 2) / 5 + d - 1))
	days=$((era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468))
	echo $((days * 86400 + h * 3600 + mi * 60 + s))
}

resolve_channel_version() { # channel
	fetch_verified "channels/$1.json" "$WORK/channel.json"
	[ "$(json_field "$WORK/channel.json" channel)" = "$1" ] || die 5 'channel file is for another channel'
	issued=$(epoch "$(json_field "$WORK/channel.json" issued_at)")
	valid_until=$(epoch "$(json_field "$WORK/channel.json" valid_until)")
	now=$(epoch "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
	[ "$issued" -le $((now + 300)) ] || die 5 'channel file is issued in the future'
	[ "$now" -le "$valid_until" ] || die 5 'channel file has expired'
	[ $((valid_until - issued)) -le 2592000 ] || die 5 'channel file validity exceeds 30 days'
	VERSION=$(json_field "$WORK/channel.json" version)
	is_version "$VERSION" || die 5 'channel file holds an invalid version'
}

resolve_version() {
	requested=${SUPERMGMT_VERSION:-latest}
	if [ "$requested" = latest ]; then
		CHANNEL=${SUPERMGMT_CHANNEL:-stable}
		case $CHANNEL in stable | beta) ;; *) die 2 "invalid SUPERMGMT_CHANNEL: $CHANNEL (stable|beta)" ;; esac
		resolve_channel_version "$CHANNEL"
	else
		is_version "$requested" || die 2 "invalid SUPERMGMT_VERSION: $requested (vX.Y.Z or latest)"
		VERSION=$requested
		CHANNEL=
	fi
	log "installing $VERSION"
}

check_header() {
	[ "$(sed -n 1p "$WORK/checksums.txt")" = "version: $VERSION" ] || die 5 'signed checksums are for another version'
	header_channel=$(sed -n 's/^channel: //p;2q' "$WORK/checksums.txt")
	case $header_channel in stable | beta) ;; *) die 5 'signed checksums carry no valid channel' ;; esac
	[ -z "$CHANNEL" ] || [ "$header_channel" = "$CHANNEL" ] || die 5 'signed checksums are for another channel'
}

download_archive() {
	name="sm_${VERSION#v}_${OS}_${ARCH}.tar.gz"
	fetch_verified "$VERSION/checksums.txt" "$WORK/checksums.txt"
	check_header
	expected=$(awk -v n="$name" 'NR > 2 && $2 == n { print $1; c++ } END { exit c != 1 }' "$WORK/checksums.txt") ||
		die 5 "$name is not listed exactly once in the signed checksums"
	fetch "$BASE_URL/$VERSION/$name" "$WORK/$name"
	[ "$(sha256_of "$WORK/$name")" = "$expected" ] || die 5 "checksum mismatch for $name"
	tar -xzf "$WORK/$name" -C "$BIN" sm || die 5 "$name does not contain sm"
}

parse_mode() {
	MODE=${SUPERMGMT_MODE:-auto}
	if [ $# -gt 0 ]; then case $1 in -*) ;; *) MODE=$1 ;; esac; fi
	case $MODE in
		auto | local | server | client | proxmox-lxc | upgrade | uninstall | restore) ;;
		*) die 2 "invalid mode: $MODE" ;;
	esac
}

main() {
	parse_mode "$@"
	[ $# -gt 0 ] && case $1 in -*) ;; *) shift ;; esac
	BASE_URL=${SUPERMGMT_RELEASE_BASE_URL:-$DEFAULT_BASE_URL}
	BASE_URL=${BASE_URL%/}
	WORK=$(mktemp -d)
	BIN=$(mktemp -d)
	trap 'rm -rf "$WORK"' EXIT
	detect_platform
	require_commands
	write_trust_roots
	verify_the_verifier
	resolve_version
	download_archive
	trap - EXIT
	rm -rf "$WORK"
	log "verified; starting sm install $MODE"
	if [ ! -t 0 ] && [ -z "${SUPERMGMT_NONINTERACTIVE:-}" ] && { : </dev/tty; } 2>/dev/null; then
		exec "$BIN/sm" install "$MODE" "$@" </dev/tty
	fi
	exec "$BIN/sm" install "$MODE" "$@"
}

main "$@"
