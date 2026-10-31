#!/bin/sh
# SuperMgmt node join (spec section 13, ADR-0022).
#
# Usage: join.sh --server URL [--token-stdin | --token-file FILE] [--ca-file FILE] [--hostname NAME] [--ssh-port N]
#        Without a token option the token is asked for on the terminal, without echo. It is never an argument.
#        join.sh --tunnel --instance ID --authorized-key KEY [--token-stdin]
#        Prepares a node that only a Cloudflare Tunnel will reach; no server is contacted. `sm join --tunnel`
#        asks for the connector token on the terminal, without echo, unless --token-stdin is given.
# Env:   SUPERMGMT_VERSION=vX.Y.Z|latest  SUPERMGMT_CHANNEL=stable|beta
#        SUPERMGMT_RELEASE_BASE_URL  mirror/test override of the release download base; never skips verification
# Exit:  2 invalid arguments, 3 unsupported platform, 4 prerequisite failure, 5 download/checksum/signature failure;
#        otherwise the exit status of `sm join`.
#
# It verifies the signed `sm` exactly as install.sh does, then runs `sm join` as root.
# The verification functions below are the same text as in install.sh; a test keeps them identical.
set -eu

DEFAULT_BASE_URL='https://github.com/autarquico/supermgmt/releases/download'
NAMESPACE='supermgmt-release'
PRINCIPAL='release@supermgmt'

log() { printf 'join.sh: %s\n' "$*" >&2; }
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

# ---- what is specific to join --------------------------------------------------

usage_error() { die 2 "$1 (see the usage at the top of join.sh)"; }

parse_args() {
	SERVER=; TOKEN_FILE=; TOKEN_STDIN=no; CA_FILE=; NODE_NAME=; SSH_PORT=
	TUNNEL=no; INSTANCE=; AUTHORIZED_KEY=
	while [ $# -gt 0 ]; do
		case $1 in
			--server | --token-file | --ca-file | --hostname | --ssh-port | --instance | --authorized-key)
				[ $# -ge 2 ] || usage_error "$1 needs a value"
				case $1 in
					--server) SERVER=$2 ;;
					--token-file) TOKEN_FILE=$2 ;;
					--ca-file) CA_FILE=$2 ;;
					--hostname) NODE_NAME=$2 ;;
					--ssh-port) SSH_PORT=$2 ;;
					--instance) INSTANCE=$2 ;;
					--authorized-key) AUTHORIZED_KEY=$2 ;;
				esac
				shift 2 ;;
			--tunnel) TUNNEL=yes; shift ;;
			--token-stdin) TOKEN_STDIN=yes; shift ;;
			*) usage_error 'unknown or unsupported argument (the token is never an argument)' ;;
		esac
	done
	if [ "$TUNNEL" = yes ]; then
		[ -n "$INSTANCE" ] || usage_error '--tunnel needs --instance'
		[ -n "$AUTHORIZED_KEY" ] || usage_error '--tunnel needs --authorized-key'
		[ -z "$SERVER$TOKEN_FILE$CA_FILE$NODE_NAME$SSH_PORT" ] || usage_error '--tunnel takes no --server, --token-file, --ca-file, --hostname or --ssh-port'
		return
	fi
	[ -z "$INSTANCE$AUTHORIZED_KEY" ] || usage_error '--instance and --authorized-key are only for --tunnel'
	[ -n "$SERVER" ] || usage_error '--server is required'
	[ -z "$TOKEN_FILE" ] || [ "$TOKEN_STDIN" = no ] || usage_error '--token-file and --token-stdin are mutually exclusive'
}

detect_platform() {
	[ "$(uname -s)" = Linux ] || die 3 "unsupported OS: $(uname -s) (sm join supports Linux nodes)"
	OS=linux
	case $(uname -m) in
		x86_64 | amd64) ARCH=amd64 ;;
		aarch64 | arm64) ARCH=arm64 ;;
		*) die 3 "unsupported architecture: $(uname -m)" ;;
	esac
}

require_commands() {
	[ "$(id -u)" -eq 0 ] || die 4 'join.sh must run as root (use sudo)'
	for c in curl tar awk sed grep mktemp ssh-keygen; do
		have "$c" || die 4 "required command not found: $c (install it, or verify the release manually on another machine)"
	done
	have sha256sum || have shasum || die 4 'required command not found: sha256sum or shasum'
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
	log "using sm $VERSION"
}

# Without --token-file or --token-stdin the token is asked for on the terminal
# (stdin may be the script itself under `curl | sudo bash`) and kept in a file
# only root can read, removed on exit.
prompt_for_token() {
	{ : </dev/tty; } 2>/dev/null || die 2 'no join token: pass --token-stdin or --token-file (there is no terminal to ask on)'
	SAVED_STTY=$(stty -g </dev/tty)
	printf 'Join token: ' >/dev/tty
	stty -echo </dev/tty
	IFS= read -r token </dev/tty || token=
	stty "$SAVED_STTY" </dev/tty
	SAVED_STTY=
	printf '\n' >/dev/tty
	[ -n "$token" ] || die 2 'the join token is empty'
	(umask 077; printf '%s' "$token" >"$WORK/token")
	TOKEN_FILE=$WORK/token
}

cleanup() {
	[ -z "${SAVED_STTY:-}" ] || stty "$SAVED_STTY" </dev/tty 2>/dev/null || true
	rm -rf "${WORK:-}" "${BIN:-}"
}

main() {
	parse_args "$@"
	BASE_URL=${SUPERMGMT_RELEASE_BASE_URL:-$DEFAULT_BASE_URL}
	BASE_URL=${BASE_URL%/}
	SAVED_STTY=
	WORK=$(mktemp -d)
	BIN=$(mktemp -d)
	trap cleanup EXIT
	detect_platform
	require_commands
	write_trust_roots
	verify_the_verifier
	resolve_version
	download_archive
	if [ "$TUNNEL" = yes ]; then
		# sm asks for the connector token itself, on /dev/tty, without echo.
		log "verified; starting sm join --tunnel"
		set -- --tunnel --instance "$INSTANCE" --authorized-key "$AUTHORIZED_KEY"
		[ "$TOKEN_STDIN" = no ] || set -- "$@" --token-stdin
		"$BIN/sm" join "$@"
		return
	fi
	[ -n "$TOKEN_FILE" ] || [ "$TOKEN_STDIN" = yes ] || prompt_for_token
	log "verified; starting sm join"
	set -- --server "$SERVER"
	[ -z "$TOKEN_FILE" ] || set -- "$@" --token-file "$TOKEN_FILE"
	[ "$TOKEN_STDIN" = no ] || set -- "$@" --token-stdin
	[ -z "$CA_FILE" ] || set -- "$@" --ca-file "$CA_FILE"
	[ -z "$NODE_NAME" ] || set -- "$@" --hostname "$NODE_NAME"
	[ -z "$SSH_PORT" ] || set -- "$@" --ssh-port "$SSH_PORT"
	"$BIN/sm" join "$@"
}

main "$@"
