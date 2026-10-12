# ADR-0006: Pinned compose-go and CLI equivalence

- Status: Proposed
- Spec: §20.3 steps 1–6 and 10, §35; ADR-0007, ADR-0010

## Context

§20.3 loads every Compose file with a pinned `compose-spec/compose-go` and requires the node's `docker compose config` output to equal the model that loader produced, except for fields in a fixture-tested normalization table. Two facts shape the mechanism. The loader rewrites source forms before any SuperMgmt check can see them: compose-go v2.15.0 validates the schema, then deletes `version` and canonicalizes ports (short syntax and ranges become long entries) (`loader/loader.go:525-540`, `transform/ports.go:27-65`). And the CLI on the node is a different program whose defaults drift between releases.

## Decision

### Versions

- Loader: `github.com/compose-spec/compose-go/v2` **v2.15.0** (2026-09-03).
- Node CLI: Docker Compose **v5.5.1** (2026-09-03), the release built on the same compose-go, so loader and CLI share their parsing code.
- Supported CLI matrix: v5.5.1 only, verified in the node fixture. Preflight refuses any other `docker compose version --short` with `PREFLIGHT_FAILED` (`details.cause = COMPOSE_UNSUPPORTED`); §35 forbids claiming unverified versions. Adding a CLI version is a new fixture row plus a review of the normalization table.

### Loader options

One in-memory `types.ConfigFile{Filename: "compose.yaml", Content}`; `SkipInterpolation` (SuperMgmt has interpolated already, §20.3 step 2), `SkipInclude`, `SkipExtends`, `ResolvePaths = false`, `SkipResolveEnvironment`, an empty `Environment`, no `ResourceLoaders`; the project name is set by the caller. The loader never reads a file, the process environment or a `.env` file.

### Two closed-schema passes

1. **Raw pass, before the loader** (`rawschema.go`). The raw YAML is parsed as a `yaml.Node` tree; aliases are expanded and `<<` merge keys resolved by our own walker, with depth and size bounds. The merged tree is checked against the closed schemas of §20.3 steps 4–6 and their syntax rules: allowed top-level keys only (so `version` is rejected, not deleted), ports in long syntax only and without ranges, `command`/`entrypoint` in list form only, `environment` in map form only, every nested object closed. This is the only pass that sees the forms the loader rewrites.
2. **Model pass, after the loader** (`schema.go`). The typed model is checked against the same allowlist, which catches anything the loader introduced.

Both passes run again after the image rewrite (step 8). A key listed as exemptible (step 7) passes only with the exact values of the app's exceptions.

### Equivalence (step 10)

- `internal/deployments/compose/normalize.go` lists the only CLI-default fields step 10 ignores. Each row names the field and the fixture that proves CLI v5.5.1 emits it.
- A golden corpus, `internal/deployments/compose/testdata/equivalence/{basic,ports_long,healthcheck,volumes_networks,secrets_envfile}.yaml`, goes through both the loader and the real CLI in CI (`compose-equivalence` job).
- CI test: interpolating the frozen file with an empty environment is the identity.
- Environment values are compared through their hashes only (ADR-0010).

### Confinement

compose-go is imported only by `internal/deployments/compose` (depguard). That package imports only the standard library, compose-go, `go.yaml.in/yaml/v3`, `domain`, `errors` and `audit`.

### CLI pin (T0s spike, measured)

Measured on the node fixture (Debian trixie, docker 26.1.5, aarch64 host): `docker compose version` reports v5.5.1 and `jq-1.7`. `docker compose version --short` was not pinned down (`5.5.1` versus `v5.5.1`; the fixture test accepts both), so the matrix check must be settled against the real output before it matches on it.

- The fixture installs the static binary as a CLI plugin at `/usr/local/lib/docker/cli-plugins/docker-compose` through BuildKit `ADD --checksum=sha256:...` (`test/fixtures/node/Dockerfile`):
  - linux-x86_64: `db1889184726840f75c4f9c001048430d4f25b3be3cb084d3ddd762bc0aed576`
  - linux-aarch64: `732e3a84c1a0f67256ce80bc2598a24546b10ca05f9faa97efceb1171ece2ef7`
- `jq` comes from apt (1.7) and is not hash-pinned.
- `config --format json` is usable for the step-10 comparison with environment resolution on. It **escapes `$` as `$$` in every string** (`a$b${C}$$` prints as `a$$b$${C}$$$$`). The environment hashing undoes this only for `environment` values (ADR-0010); other fields (command, labels) stay escaped, so a whole-model comparison must put both sides in the same form.
- The matrix row is fixture-verified for the env-file and environment-hash behaviour. Not verified: the full normalization table against the golden corpus (CI job `compose-equivalence`).

## Consequences

- The Compose CLI is the largest drift risk in M4. A CLI outside the matrix fails preflight instead of deploying a model nobody compared.
- Source forms the loader would silently rewrite (`version`, short ports, ranges, string commands, list environments) are rejected with their YAML path.
- Upgrading compose-go or the CLI is an ADR change, a fixture change and a normalization-table review, never a version bump alone.
