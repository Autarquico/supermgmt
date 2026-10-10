#!/bin/sh
# Write and sign a channel pointer: OUTDIR/<channel>.json and .json.sig (spec 3.2).
# Usage: channel.sh CHANNEL VERSION ISSUED_AT VALID_UNTIL OUTDIR     Env: SM_SIGNING_KEY_FILE
# Timestamps are UTC, YYYY-MM-DDTHH:MM:SSZ. The signer refuses a validity window over 30 days.
set -eu

[ $# -eq 5 ] || { echo "usage: channel.sh CHANNEL VERSION ISSUED_AT VALID_UNTIL OUTDIR" >&2; exit 2; }
channel=$1 version=$2 issued_at=$3 valid_until=$4 outdir=$5
here=$(cd "$(dirname "$0")" && pwd)

case $channel in stable | beta) ;; *) echo "invalid channel: $channel" >&2; exit 2 ;; esac
printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo "invalid version: $version" >&2; exit 2; }
for t in "$issued_at" "$valid_until"; do
	printf '%s\n' "$t" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || { echo "invalid timestamp: $t" >&2; exit 2; }
done

epoch() { date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s; }
window=$(($(epoch "$valid_until") - $(epoch "$issued_at")))
[ "$window" -gt 0 ] && [ "$window" -le 2592000 ] || { echo "validity window must be within (0, 30 days]" >&2; exit 2; }

mkdir -p "$outdir"
printf '{"channel":"%s","version":"%s","issued_at":"%s","valid_until":"%s"}\n' \
	"$channel" "$version" "$issued_at" "$valid_until" >"$outdir/$channel.json"
"$here/sign.sh" "$outdir/$channel.json"
