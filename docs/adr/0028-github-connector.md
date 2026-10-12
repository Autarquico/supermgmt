# ADR-0028: GitHub connector

- Status: Proposed
- Spec: §8.3, §11.1, §18, §21.1, §23; ADR-0011, ADR-0012, ADR-0018

## Context

§18 makes GitHub the source of truth for CI results, the issuer of automation credentials (Actions OIDC) and of build provenance (artifact attestations). §21.1 step 6 limits GitHub redirects to "the configured GitHub API hosts". No real GitHub, GHCR or Sigstore is reachable from CI, so every assumption is checked against fakes, and the fakes need a contract.

## Decision

### Provider and credential

- Provider `type: github` with `name`, `api_url` (default `https://api.github.com`; GitHub Enterprise Server sets its own, e.g. `https://ghe.example.com/api/v3`), `credential_ref: secret://providers/<name>/token`, optional `webhook_secret_ref` (secret://) and `ca_file`.
- The token is a fine-grained **read-only** personal access token with Contents, Checks, Actions, Attestations and Metadata: read. GitHub App authentication is post-V1.
- Registration: static configuration, or `POST /api/v1/providers` with `type: github` (`provider.write`, high risk, approval path). Proxmox `POST /providers` stays deferred.

### Outbound requests and redirects

- Every request goes through netguard with the provider allowlist (§21.1 step 5: private ranges allowed, so GHES on a private address works).
- Redirects: at most 3, each re-filtered by netguard, and only to the **exact origin of `api_url`** (scheme, host, effective port). The client wraps netguard's redirect check with an origin check, because netguard's host match ignores the port when the allowlist entry has none (`internal/netguard/transport.go:90-102`).
- No content host (`*.githubusercontent.com`): files are read through the JSON contents API, `GET /repos/{owner}/{repo}/contents/{path}?ref=<sha>` (base64, ≤ 1 MiB upstream; our cap 256 KiB), which needs no blob redirect.
- `Authorization` is attached by a per-request `RoundTripper` only when the request's origin equals `api_url`'s, so a refused or foreign redirect never carries the token. Tokens never appear in errors or logs.
- Response bodies are capped per endpoint.
- Real GitHub redirect behaviour is unverified (manual checklist row).

### Check verification

Exactly §18: for the exact commit, every required check has a completed run from the named `app_id`, with the named name and conclusion `success`, using the latest attempt; for Actions checks the suite resolves to a workflow run whose `path`, `head_branch`, `head_sha` and `event` match. Evidence goes to `artifact_checks`, one row per check. Verdict: `passed`, `pending`, or `failed` with `CHECK_FAILED` / `CHECK_MISSING`.

### Actions OIDC

- JWKS from the fixed issuer `https://token.actions.githubusercontent.com`, cached, refreshed on an unknown `kid`; every claim rule of §18; `jti` recorded in `oidc_replay` (replay → `OIDC_REPLAY`). HTTPS only.
- Automation identity: `actor_type = automation`, `issuer = https://token.actions.githubusercontent.com`, `subject = repository_id:<id>:workflow:<deploy_workflow>`. `app.write` creates or links it with **no role**; an admin grants `deployer` (or a narrower rule) explicitly. Unlinking revokes its open OIDC credentials.
- Credential kind `github_oidc`, implicit scopes `["deployment.create", "deployment.read"]`.

### OIDC credential status

- A successful verification inserts a `github_oidc_credentials` row, in the same transaction as the provisional deployment: `id = sha256(issuer|jti)` (the job's and deployment's `credential_id`), `identity_id`, the §18 non-secret claims (`repository_id`, `workflow_ref`, `job_workflow_ref`, `sha`, `ref`, `event_name`, `environment`, `run_id`, `run_attempt`), `issued_at`, `expires_at`, `revoked_at`. The raw token is never stored.
- `CredentialStatus` for `github_oidc`:
  - **revoked** if `revoked_at` is set, the identity is disabled (`identities.disabled_at`), or the automation identity is no longer linked to the app;
  - **expired** if `now ≥ expires_at`; natural expiry does not fail a submitted job (§11.1);
  - a missing row fails closed as revoked.
- `oidc_claims` binding at finalization reads the stored claims, so a CI wait longer than the token's lifetime is safe.

### Attestations

- `GET /repos/{owner}/{repo}/attestations/sha256:<digest>`, verified with `github.com/sigstore/sigstore-go` **v1.3.0** (2026-07-30): SLSA v1 provenance predicate; subject digest; certificate SAN = `https://github.com/<owner>/<repo>/<workflow_path>@refs/heads/<branch>`; issuer = the Actions issuer; source repository ID and commit SHA from the Fulcio extensions.
- Trusted roots: Sigstore public-good and GitHub's instance, embedded at build, refreshed through TUF over netguard, last good root cached on disk. A stale or unverifiable root fails closed with an actionable error; verification never falls back to "unverified".
- `require_provenance: true` environments accept only attestation binding (§18 (a)).

### Webhooks

Server mode only: `POST /api/v1/github/webhook` (`exempt:webhook`). HMAC-SHA256 over the raw body (`X-Hub-Signature-256`, constant-time compare), `delivery_id` dedupe in `webhook_deliveries`, body ≤ 1 MiB, rate-limited. `check_run`, `check_suite` and `workflow_run` nudge the CI watcher; nothing else acts on webhook content. Server mode also polls as a backstop at `github.ci_poll_max`; local mode polls only.

### Fake fidelity

- `ghfake` serves only the endpoints and fields M4 uses, recorded from the GitHub REST documentation (version, URL and date in `test/fixtures/github/PROVENANCE.md`). It rejects unknown paths and parameters, enforces the token, and models check-run attempts, suite → run mapping, pagination, redirects and rate-limit headers.
- Attestations in tests are signed by sigstore-go's virtual Sigstore (`pkg/testing/ca`).
- A test-only build tag `ghsim` lets the e2e binary override the OIDC issuer and the trusted root; a release-build test proves the tag is absent (the M3 `crashpoints` pattern).
- Anything a fake cannot prove is a manual checklist row (`docs/manual-checks/m4-real-github.md`), never a claim.

### Dependencies and confinement

- sigstore-go and go-jose (already in the module graph through go-oidc, now direct) are imported only by `internal/providers/github`; `pkg/testing/ca` and `ghfake` only by tests (depguard).
- sigstore-go brings a large transitive tree (rekor, TUF, go-openapi, protobuf, gRPC). Indirect modules raised for govulncheck in W0: `golang.org/x/net` v0.58.0 → v0.60.0 (GO-2026-6603, -6610, -6611, -6612, -6617) and `google.golang.org/grpc` v1.82.1 → v1.83.2 (GO-2026-6348, GO-2026-6443).
- **Release binary size** (`CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`, linux/amd64, measured in W0 by linking the pinned packages into `sm`): 21,229,728 bytes before M4; 22,261,920 with compose-go (+1,032,192, +4.9 %); 33,505,440 with compose-go and sigstore-go (+12,275,712, +57.8 %). Recorded so later changes are compared against it.

## Consequences

- SuperMgmt never needs write access to GitHub.
- Real attestations, GHCR pulls, real Actions OIDC and real redirect behaviour are fake-verified only until the manual checklist runs.
- The binary grows by about half for attestation verification; `require_provenance` is the reason it exists.
