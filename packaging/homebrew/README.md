# Homebrew distribution plan

Decision: ADR-0036 (Q4). SuperMgmt ships through its own tap, `autarquico/homebrew-tap`, as the
formula **`supermgmt`**, which installs the `sm` binary. The formula name differs from the binary
name to avoid a clash with other `sm` tools.

## The formula is a derived artifact

`supermgmt.rb.tmpl` has no hand-written versions or digests. `packaging/release/brew-formula.sh`
renders it from the **signed** `checksums.txt` of a stable release:

```sh
packaging/release/brew-formula.sh dist/checksums.txt dist/allowed_signers > supermgmt.rb
```

- With the second argument (TRUST, as in `verify-asset.sh`) the signature of `checksums.txt` is
  verified before anything is read. Always pass it when rendering a real release.
- Beta releases are refused: only `channel: stable` and a plain `vX.Y.Z` version render.
- Each of the four archives (`darwin`/`linux` x `arm64`/`amd64`) must be listed exactly once with a
  64-hex sha256, otherwise rendering fails.
- `SM_RELEASE_BASE_URL` overrides the download base (default: GitHub releases of this repository).

## Publishing (human step)

CI holds no tap token. After a stable tag is released and verified:

1. Render the formula as above.
2. Commit it as `Formula/supermgmt.rb` in `autarquico/homebrew-tap`.
3. `brew audit --strict --online autarquico/tap/supermgmt` and `brew install` / `brew test` locally.

Creating the tap repository and the first publish are owner tasks (M6 plan, human checks).

## Verification in this repository

- `go test ./test/install -run BrewFormula` renders a fixture and compares it with an inline golden.
- `ruby -c` on the rendered output runs in the same test when `ruby` is present.
- `brew audit --strict` against a snapshot runs in the nightly `brew-audit` job (macOS).

## Out of scope

homebrew-core (needs notability) and Linux `.deb`/`.rpm` packages (ADR-0036: they would bypass the
ADR-0027 upgrade protocol).
