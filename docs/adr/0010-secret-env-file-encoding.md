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

### Pending T0s spike

> **Pending T0s spike (W0).** `format: raw` and the resolved check are CLI behaviour, so they are proven on the pinned CLI before this ADR is final: T0s round-trips the corpus through Compose v5.5.1 (`test/integration/fixtures_envfile_test.go`) and shows that the resolved hash set equals the expected one for precedence, empty, spaces and `$`, and differs for tampered wiring (`test/integration/fixtures_envhash_spike_test.go`). If the resolved check cannot be made to work on v5.5.1, the architect escalates to the user before W1; the ADR is not finalized on a weaker mechanism.

## Consequences

- A secret value can contain any byte except NUL, CR and LF; multi-line values (PEM blocks) must be stored encoded and decoded by the application.
- Docker shows container environment to anyone with Docker access, which is already root-equivalent (§17); this is documented, not mitigated.
- Every managed node that deploys needs `jq`.
