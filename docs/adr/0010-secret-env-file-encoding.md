# ADR-0010: Secret env-file encoding and the node-side resolved check

- Status: Proposed
- Spec: §10, §11.2 (`secret.write`), §20.3 steps 9–10, §46; ADR-0006, ADR-0008

## Context

§20.3 step 9 writes secret values to `secrets/<service>.env` on the node, and §46 requires every value of a test corpus to reach the container byte for byte. Values with NUL or newline must be rejected at `secret.write` unless a pinned Compose version proves support. Step 10 requires the node to compare **resolved** values privately (hash-only output), so the control plane learns whether Compose would hand each container exactly the bound values, without the values ever leaving the node.

## Decision

### Encoding

- The materialized `compose.yaml` wires each service with secrets as `env_file: [{path: secrets/<service>.env, format: raw, required: true}]`. Only the pipeline emits `env_file` (§20.3 step 1 rejects it in sources).
- `secrets/<service>.env` holds one `NAME=value` line per binding, value bytes verbatim; `format: raw` means Compose applies no quoting, escaping or interpolation.
- Secrets referenced by apps live under `apps/…`. `secret.write` on `apps/…` rejects NUL, `\n`, `\r` and invalid UTF-8 with `INVALID_ARGUMENT`; every other byte sequence is allowed.

### Resolved-environment check (step 10)

- Template `compose.verify` runs `docker compose -f <file> -p <project> --project-directory <dir> config --format json` **with** environment resolution, under `env -i` with a fixed `PATH`, and pipes the output through a fixed `jq` program (`jq` is a required node tool, ADR-0030) and `sha256sum`. It prints two things only:
  1. the effective model with every `environment` value replaced by `sha256:<hex>` of the resolved value — the masked model used for the step-10 whole-model comparison (ADR-0006);
  2. the set `{service, env_name, sha256}`.
- The control plane computes the expected hashes in memory from the decrypted secret versions and the plan's variables. Values never leave the node and are never persisted.
- Any mismatch (a missing name, an extra name, a different hash) is `STAGING_FAILED` (`details.cause = ENV_HASH_MISMATCH`).
- **No file-hash fallback.** `config --no-env-resolution` plus `sha256sum` of the env files proves file bytes, not what Compose resolves, so it is not equivalent and is not used.

### Tests

Through the real generated files and the real CLI v5.5.1 in the node fixture: variable versus `env_file` precedence, empty values, spaces, `$`, tampered `env_file` wiring, a stray extra env file, a modified `secrets/<service>.env`. Corpus: `$`, single and double quotes, `#`, inner, leading and trailing spaces, `=`, backslashes, unicode, the empty value.

### CLI behaviour (T0s spike, measured on Compose v5.5.1 and jq 1.7)

Tests: `test/integration/fixtures_envfile_test.go`, `test/integration/fixtures_envhash_spike_test.go`.

- **`format: raw`.** All 20 corpus values resolve verbatim in `config` and inside the container (`printenv`): `$`, `${C}`, `$$`, quotes, `#`, leading, trailing and only spaces, `=`, backslashes (`\n` stays literal), unicode and emoji, tab, backticks, `%`, empty. A missing `required: true` env file makes `config` fail (fail closed).
- **`$` escaping.** `config --format json` doubles every `$`; the program un-doubles it (`$$` to `$`, lossless) for `environment` values only.
- **Precedence.** `environment:` beats `env_file`; an empty string stays `""`; a name-only `NAME:` with no host value under `env -i` resolves to JSON `null` (emitted as sha256 `null`). The control plane never produces such a name, so a `null` in the node set counts as a mismatch.
- **jq has no sha256.** The template therefore uses jq, a bash loop and `sha256sum`: node tools required are `jq`, `bash`, `base64`, `sha256sum`, `cut`. Command shape: `env -i PATH=... bash script <dir>`; inside, `docker compose -f $dir/compose.yaml -p P --project-directory $dir config --format json` (no `--no-env-resolution`), with stderr kept out of stdout.
  1. ROWS, `jq -r`: `.services | to_entries[] | .key as $s | (.value.environment // {}) | to_entries[] | [$s, .key, (if .value == null then "n" else "s" end), ((.value // "") | gsub("\\$\\$"; "$") | @base64)] | @tsv`. Bash decodes the base64 column and hashes it (`base64 -d | sha256sum | cut`), producing `service<TAB>name<TAB>sha|null` lines.
  2. SET, `jq -Rn -c`: `[inputs | select(length > 0) | split("\t") | {service: .[0], env_name: .[1], sha256: (if .[2] == "null" then null else .[2] end)}]`
  3. MASK, `jq -c --argjson h SET`: `($h | map({key: (.service + "/" + .env_name), value: .sha256}) | from_entries) as $m | .services |= with_entries(.key as $s | if .value.environment then .value.environment |= with_entries(.value = (if .value == null then null else "sha256:" + $m[$s + "/" + .key] end)) else . end)`
  - Output: one line `{"model": <masked model>, "set": [{service, env_name, sha256}]}`. Services without `environment` yield no rows and no invented key. The programs are the constants in `fixtures_envhash_spike_test.go`, which is authoritative.
- **Proven.** The expected set equals the node set (precedence, empty, spaces, `$`, `=`, quotes); the masked model carries `"NAME":"sha256:<hex>"` for every name and no plaintext value; tampering is detected for a changed value, an extra name, a missing name, an env file swapped between services and a dropped `environment` override.

### Image size (ADR-0029 input)

- `docker manifest inspect --verbose <ref>@<digest>` prints one JSON object for a single image manifest (`Descriptor.platform`, `SchemaV2Manifest{config, layers[]}`) and a JSON array of such entries for an index. Without `--verbose` no platform is printed.
- Program: normalize to an array, select exactly one entry whose `.Descriptor.platform.os/.architecture` equal `docker version --format '{{.Server.Os}}'` / `'{{.Server.Arch}}'` (not `docker info` Architecture, which says `aarch64`), size = `config.size + sum(layers[].size)` (`.SchemaV2Manifest // .OCIManifest`). Variant is ignored on purpose. busybox arm64: 477 + 1977510 = 1977987 bytes. An unknown digest exits nonzero (fail closed, `IMAGE_SIZE_UNKNOWN`).
- `--insecure` is needed only for a plain-HTTP registry (the fixture's local registry:2); real registries do not need it.
- **Not verified:** OCI manifests/indexes (`OCIManifest` key), nested indexes, registry auth and rate limits. To be checked against a real registry digest in an e2e before ADR-0029 is final.
- The node fixture has neither curl nor wget; bash `/dev/tcp` works for readiness polling.

## Consequences

- A secret value can contain any byte except NUL, CR and LF; multi-line values (PEM blocks) must be stored encoded and decoded by the application.
- Docker shows container environment to anyone with Docker access, which is already root-equivalent (§17); this is documented, not mitigated.
- Every managed node that deploys needs `jq`.
