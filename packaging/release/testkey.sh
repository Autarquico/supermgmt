#!/bin/sh
# Generate a throwaway release key and the matching allowed_signers file in DIR (CI and tests only).
# Usage: testkey.sh DIR [PRINCIPAL_OPTIONS]    e.g. 'valid-before="20200101"' to mint an expired key.
set -eu

[ $# -ge 1 ] || { echo "usage: testkey.sh DIR [OPTIONS]" >&2; exit 2; }
mkdir -p "$1"
ssh-keygen -q -t ed25519 -N '' -C release@supermgmt -f "$1/key"
printf 'release@supermgmt %snamespaces="supermgmt-release" %s\n' "${2:+$2,}" "$(cut -d' ' -f1,2 "$1/key.pub")" >"$1/allowed_signers"
