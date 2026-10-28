# ADR-0034: Release hardening gates

- Status: Proposed
- Spec: §31 M6, §32, §36, §41; ADR-0019, ADR-0035, ADR-0036

## Context

§32 requires formatting, vet, lint, unit/integration tests, race tests where practical, govulncheck, dependency review, static analysis and secret scanning, and states that a release requires every gate green. §31 M6 adds fuzz tests for parsers and inputs. Before M6 the repository has gosec (golangci), govulncheck, CodeQL and dependency review, but no secret scanning, no licence notices in the archives, ten fuzz targets for a much larger parser surface, race tests on Ubuntu only, and a release workflow that runs on any `v*` tag without looking at CI.

## Decision

### Fuzzing

- Every function that parses untrusted or persisted input is mapped to a reachable `Fuzz*` target, or exempted with a reason, in `scripts/fuzz-inventory.txt`. One line per function: `<import path>.<Func>  <FuzzTarget>` or `<import path>.<Func>  exempt: <reason>`.
- **Discovery, not names.** `test/fuzzinv` walks the AST of every non-test `.go` file under `internal/` and lists each function that (a) is named `parse*`, `decode*`, `read*`, `load*` or `unmarshal*` (any case), or (b) calls `json.Unmarshal`, `(*json.Decoder).Decode`, `yaml.Unmarshal`, `yamlstrict.Decode`, `tar.NewReader`, `zstd.NewReader`, or a go-jose/go-oidc parse function. Each listed function must be in the inventory, and each inventory row must name an existing function and target. `test/fuzzinv` imports the standard library only (depguard).
- **Reachability.** `scripts/fuzz.sh reach` runs every target over its seeds with `-coverpkg` and fails when a mapped function has zero coverage.
- Seeds are `f.Add` calls built from existing fixtures and fakes, so every `go test` runs them. Crasher regression inputs live in `testdata/fuzz/<Target>/`.
- **Pull requests** run the seeds (inside `make test`) and the `fuzz-inventory` job (discovery and reachability). No mutation on pull requests.
- **Nightly** runs every target for `-fuzztime=5m`, in 8 shards (`scripts/fuzz.sh shard <i> 8`, inventory order) of at most 60 minutes. A crasher fails its shard and is uploaded as an artifact.
- `scripts/fuzz.sh count` is the authoritative target count. M6 plans 45 new targets on top of the 10 that exist at its start.

### Race and stress

- `-race` runs on unit tests on Ubuntu and macOS.
- A `stress` build-tag suite (`test/stress/`) hammers the concurrency seams with `-race -count=N`: job claim, lease and fencing; the SSE broker; the SSH pool; Proxmox single-flight sync; deployment locks; concurrent MCP token issuance, the `oauth_access_tokens` upsert of one token, and a JWKS refresh on an unknown `kid`. MCP is stateless streamable HTTP (ADR-0031), so there are no server sessions to stress.
- `test/stress` runs in process: depguard forbids the installer, the TUI, the Docker fixtures and the e2e harness there.

### Flake policy

- No retries in pull-request gates.
- Each flake is classified as a **test synchronization defect** or a **production defect**.
- A fix needs failing-before/passing-after proof: a deterministic reproduction, or at least 200 runs under `-cpu 1,2,4` with load, before and after.
- A flake without a proven fix may be quarantined to nightly only with an issue, an owner, an expiry date and replacement pull-request coverage of the behaviour it guards. It stays reported as **unresolved**.

### Scans

- **Secret scanning.** gitleaks over the full history in CI, run as `go run github.com/zricethezav/gitleaks/v8@v8.30.1` (MIT; the module path the tool declares). `.gitleaks.toml` allowlists named test fixtures only, each with a reason; no blanket regex. GitHub secret scanning and push protection are owner settings.
- **Licence gate.** `go run github.com/google/go-licenses/v2@v2.0.1` checks the compiled module set against the dependency-review allowlist. The W0 dry run on `./cmd/sm` (Go 1.27.2) classified every module except three whose module zip carries no licence file the classifier recognizes: `github.com/in-toto/attestation` v1.2.0, `github.com/in-toto/in-toto-golang` v0.11.0 and `github.com/cyberphone/json-canonicalization`. These are resolved by a reviewed override list (module, version, licence, upstream file), never by skipping them.
- Pinned `go run` tools follow `Makefile` practice: exact versions at least two weeks old, verified by sum.golang.org, listed in `docs/dependencies.md`.

### Release gate

- `release.yml` gains a `gates` job, and `build` needs it. `gates` reads the check runs of the **exact tag SHA** and requires `conclusion: success` for every name in `packaging/release/required-checks.txt`. Pending, missing, skipped, neutral, cancelled or failed stops the release before any build or signature.
- A successful `nightly` run on that exact SHA is also required (the owner dispatches it on the candidate commit before tagging).
- A policy test keeps `required-checks.txt` equal to the set of `ci.yml` jobs (matrix legs expanded) plus `nightly`.

### Supply chain

- **Notices.** `THIRD_PARTY_LICENSES` lists every module in the compiled binary's build info (`go version -m`), with its full licence text and any `NOTICE` file. It ships in every archive; `release-check` compares it with each archive's binary.
- **SBOM completeness.** Every module in the build info appears in the SPDX document with the same version.
- **Reproducibility.** The real GoReleaser config (`goreleaser build --snapshot`) runs twice from two independent `git archive` extractions with separate `GOCACHE`, `GOMODCACHE`, `GOPATH` and `TMPDIR`. The four `sm` binaries and the four archives must be byte-identical.
- **Provenance.** After attestation, `verify-provenance.sh` checks the statement before `publish`: the subject digests equal the published archives and `checksums.txt`, the source digest equals the tag SHA, and the builder is `release.yml` at that ref.

## Consequences

- A release cannot be built from a commit whose CI or nightly gates did not pass.
- Fuzzing finds defects late; each crasher becomes a bounded fix task with a regression input.
- Unresolved flakes and tooling gaps stay visible in the release checklist instead of disappearing behind retries.
