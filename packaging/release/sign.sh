#!/bin/sh
# Sign a file with the release key: ssh-keygen -Y sign, namespace supermgmt-release. Writes <file>.sig.
# Env: SM_SIGNING_KEY_FILE  path of the private key (never printed).
set -eu

[ $# -eq 1 ] || { echo "usage: sign.sh FILE" >&2; exit 2; }
: "${SM_SIGNING_KEY_FILE:?SM_SIGNING_KEY_FILE is required}"

rm -f "$1.sig"
ssh-keygen -q -Y sign -f "$SM_SIGNING_KEY_FILE" -n supermgmt-release "$1"
