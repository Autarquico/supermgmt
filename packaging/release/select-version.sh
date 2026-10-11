#!/bin/sh
# Print the newest release a channel may point at. Release tags arrive on stdin, newest first.
# stable takes the newest vX.Y.Z; beta takes the newest vX.Y.Z-pre. This is the rule finalize.sh uses to
# write the signed `channel:` header of checksums.txt, so a pointer never names another channel's release.
# Usage: select-version.sh CHANNEL < tags     Prints nothing when no tag fits.
set -eu

[ $# -eq 1 ] || { echo "usage: select-version.sh CHANNEL" >&2; exit 2; }
case $1 in
stable) pattern='^v[0-9]+\.[0-9]+\.[0-9]+$' ;;
beta) pattern='^v[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z.-]+$' ;;
*) echo "invalid channel: $1" >&2; exit 2 ;;
esac
grep -E "$pattern" | head -n 1 || true
