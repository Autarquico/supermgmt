#!/bin/sh
# Build a snapshot release into dist/ and sign it with a throwaway test key (make snapshot).
# Requires goreleaser v2 and syft on PATH. Never uses the production key.
set -eu

cd "$(dirname "$0")/../.."
goreleaser release --snapshot --clean
version="v$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' dist/metadata.json | head -n 1)"
rm -rf dist/test-trust
packaging/release/testkey.sh dist/test-trust
SM_SIGNING_KEY_FILE=dist/test-trust/key packaging/release/finalize.sh dist "$version"
