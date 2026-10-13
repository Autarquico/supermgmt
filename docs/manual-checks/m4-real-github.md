# M4 manual checks: real GitHub, GHCR and Sigstore

**Status: DEFERRED. Nothing on this page has been run.** Every GitHub interaction in M4 was verified against a hand-written fake (`internal/providers/github/ghfake`, served to the end-to-end tests by `test/e2e/ghsim`), attestations against a virtual Sigstore (`sigstore-go` `pkg/testing/ca`), and images against a local TLS registry. The fake was written from the GitHub documentation, not recorded from the live API ([test/fixtures/github/PROVENANCE.md](../../test/fixtures/github/PROVENANCE.md)). "Deploys exactly the CI-passed commit and attested digest" (SPEC Appendix E, M4) therefore stays **fake-verified, not real-verified** until sections 1 to 8 pass. Run it before a release; a skipped row stays "not verified" in the README and ROADMAP.

Use two throwaway repositories you own, one **public** and one **private**, each with a workflow modeled on [`examples/github-actions.yml`](../../examples/github-actions.yml) (test, build with `actions/attest-build-provenance`, deploy), and a lab node set up with `docker_access=true` and Docker Compose 5.5.1. Use a lab SuperMgmt server reachable by GitHub Actions over HTTPS (a tunnel is fine). Record the date, the `sm version` commit and what GitHub reported for each check. Where a row says **the fake needs fixing**, change the fake and its documentation, not the expectation.

Conventions: `$OWNER/$REPO` is the repository, `$SHA` a commit on `main` that passed CI, `$DIGEST` the image digest the build job pushed to GHCR, `$TOKEN` the provider token.

## 1. Provider token and the REST API

Create a fine-grained read-only token limited to the two repositories (Contents, Checks, Actions, Attestations, Metadata: read) and import it with `sm secrets import --name providers/github/token`.

| # | Check | Expected by the code |
|---|---|---|
| 1.1 | `curl -H "Authorization: Bearer $TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/repositories/<id>` for both repositories | 200 with `id`, `owner.id`, `owner.login`, `name`, `html_url`, `default_branch`, `private`. The connector resolves a repository by numeric ID. |
| 1.2 | `GET /user/repos?per_page=100` with the token | Lists exactly the two repositories (the repository listing of the provider reads this endpoint and follows `Link: rel="next"`). A fine-grained token that sees repositories through this endpoint is an assumption. |
| 1.3 | Remove one permission at a time (Checks, Actions, Attestations, Contents) and run `sm apps create` / a deployment | The failure names the missing capability instead of a generic error. Record which permission each call actually needs; correct the list in [deployments.md](../deployments.md#register-github) if the set listed there is wider or narrower than necessary. |
| 1.4 | Rate-limit headers (`X-RateLimit-*`) and a 403/429 answer with `Retry-After` | The connector reports a provider error and retries later; it does not hammer. (The fake models the headers; the real wording is unchecked.) |
| 1.5 | The same flow against **GitHub Enterprise Server** `api_url`, if you have one | Works with `ca_file` for a private CA; otherwise record as not tested. |

## 2. Check runs, suites and workflow runs

These are the assumptions listed as unverified in PROVENANCE.md.

| # | Check | Expected |
|---|---|---|
| 2.1 | `GET /repos/$OWNER/$REPO/commits/$SHA/check-runs?filter=all` | Returns the check runs of every attempt with `id`, `name`, `status`, `conclusion`, `completed_at`, `app.id`, `check_suite.id`. The connector calls it with `filter=all` and takes the highest check-run `id` per (name, app) as the latest attempt. |
| 2.2 | Re-run a workflow ("Re-run all jobs") and list check runs again | The re-run adds a **new check run with a higher id to the same check suite**, and the workflow run's `run_attempt` increases. If it does not, **the fake needs fixing** and the latest-attempt rule in `internal/providers/github/checks.go` must be reconsidered. |
| 2.3 | `GET /repos/$OWNER/$REPO/actions/runs?check_suite_id=<id>` | Returns the single run owning the suite, with `path`, `head_branch`, `head_sha`, `event`, `run_attempt`. |
| 2.4 | The `path` field of a workflow run | A bare path like `.github/workflows/ci.yml`, without an `@ref` suffix. For a workflow called by another (reusable), record what `path` holds. |
| 2.5 | The GitHub App id (`app.id`) of checks reported by Actions | The docs use 15368 as an example value; read the real `app.id` of your Actions checks and confirm a required check configured with it is accepted. |
| 2.6 | A required check that is skipped, neutral, cancelled or timed out | Not `success`: the deployment fails or waits as documented. Record `conclusion` values seen. |
| 2.7 | Deploy a commit whose required check is still running; then let it finish | The deployment waits in `waiting_ci`, then finalizes. In server mode, confirm a webhook (section 6) triggers the re-check sooner than the poll. |
| 2.8 | Two checks of the same name from different apps | Only the configured app's check counts. |
| 2.9 | Pagination: a commit with more check runs than one page (`per_page` of the connector) | All pages are read. |

## 3. File contents and redirects

The connector reads the manifest and Compose file from the exact commit through the JSON contents API and follows redirects only to the exact origin of `api_url`, at most three hops, never carrying the token elsewhere.

| # | Check | Expected |
|---|---|---|
| 3.1 | `GET /repos/$OWNER/$REPO/contents/.supermgmt.yaml?ref=$SHA` | 200 JSON, `type: file`, `encoding: base64`, `sha` equal to the git blob id of the content, `size`. The connector rejects anything else. |
| 3.2 | Same for a file larger than 1 MiB and one between 256 KiB and 1 MiB | Record what GitHub returns above 1 MiB (the code assumes no inline content). Both cases must fail with a clear error: the connector's own cap is 256 KiB. |
| 3.3 | **Redirects.** Rename the repository (or transfer it), then read the old name with `curl -i` | GitHub answers 301 to `https://api.github.com/repositories/<id>/...`. Confirm the redirect target origin equals `api_url`'s, and that SuperMgmt follows it. If any redirect leaves `api.github.com` (for example to a content host), the connector refuses it: record the host. This is the main unknown behind the origin-pinned redirect rule. |
| 3.4 | Request a file path that is a symlink, a directory and a submodule | Refused (not a regular file). |
| 3.5 | Capture the `Authorization` header sent to any non-`api_url` host with a network trace during sections 1 to 3 | None. |
| 3.6 | Commit moved after CI: push a new commit to `main` after CI passed and before finalization | The deployment still reads the CI-passed commit, not the branch head. |

## 4. GitHub Actions OIDC

| # | Check | Expected |
|---|---|---|
| 4.1 | Request an OIDC token in the deploy job (`ACTIONS_ID_TOKEN_REQUEST_URL&audience=<github.oidc_audience>`), decode it | Issuer `https://token.actions.githubusercontent.com`, RS256, `kid` present, claims `repository_id`, `repository_owner_id`, `run_id`, `run_attempt` as **strings of digits**, plus `sub`, `jti`, `repository`, `ref`, `sha`, `event_name`, `workflow_ref`, `job_workflow_ref`, `environment` (when the job uses one). |
| 4.2 | `GET https://token.actions.githubusercontent.com/.well-known/openid-configuration` and the `jwks_uri` | `jwks_uri` is on the issuer's origin (the verifier refuses otherwise); keys have `kid`. |
| 4.3 | Token lifetime and `iat` | The token is accepted within 5 minutes of `iat`; record the real `exp - iat`. |
| 4.4 | A real deploy from `push` to `main` | The deployment is created, bound by claims or attestation, and finalized. |
| 4.5 | Use the same token twice | The second request is refused (`OIDC_REPLAY`). |
| 4.6 | A job in a **pull request** from a fork and from the same repository, and a `workflow_dispatch` from another branch | Never accepted (event, ref or workflow_ref mismatch). Record the claims GitHub puts in each. |
| 4.7 | A deploy workflow that calls a **reusable** workflow | `job_workflow_ref` names the reusable workflow; with `deploy_reusable_workflow` configured it is accepted, without it refused. Record the real `workflow_ref` and `job_workflow_ref` values. |
| 4.8 | The job runs with `environment: production` | Claim `environment` is `production`. SuperMgmt does not require it in V1 (documented limitation); confirm only that the claim is present. |
| 4.9 | Wrong audience | Refused. |
| 4.10 | Revoke: unlink the automation identity (`app.write` with `automation_identity: false`) between request and finalization | The deployment fails with `CREDENTIAL_REVOKED`. |

## 5. Artifact attestations and Sigstore

| # | Check | Expected |
|---|---|---|
| 5.1 | `GET /repos/$OWNER/$REPO/attestations/sha256:<hex>` with the token, **public repository** | 200 with `attestations[].bundle` (Sigstore bundle JSON). |
| 5.2 | Same for the **private repository** | The code assumes private repositories sign with GitHub's own Sigstore instance (not public-good), which is why it embeds a second trust source. 200 with a bundle, or record the real answer. |
| 5.3 | Decode the certificate in the bundle | SAN is `https://github.com/$OWNER/$REPO/<workflow path>@refs/heads/<branch>`; issuer `https://token.actions.githubusercontent.com`; the source repository ID and commit SHA extensions equal the repository ID and `$SHA`. SuperMgmt builds the expected SAN from `ci_policy.deploy_workflow`, so the attesting workflow must be that file. |
| 5.4 | Attest from a workflow file that is **not** `deploy_workflow`, then deploy | Not bound by attestation (documented consequence); confirm. |
| 5.5 | Deploy with `require_provenance: true` on a public repository and on a private one | Accepted with a valid attestation, refused (`DIGEST_UNBOUND`) without one or with a different digest. |
| 5.6 | Verify with the real `gh attestation verify oci://ghcr.io/... --owner $OWNER` on the same digest | Agrees with SuperMgmt's verdict. |
| 5.7 | Predicate type | `https://slsa.dev/provenance/v1` (the only type accepted). |
| 5.8 | An attestation of another digest or another commit | Refused. |

## 6. Webhooks (server mode)

| # | Check | Expected |
|---|---|---|
| 6.1 | Create a repository webhook to `https://<server>/api/v1/github/webhook`, content type JSON, a secret equal to the one behind `webhook_secret_ref`, events Check runs, Check suites, Workflow runs | Deliveries show 200 and the acknowledgement status `nudged`; a deployment in `waiting_ci` re-checks promptly. |
| 6.2 | Headers: `X-Hub-Signature-256: sha256=<hmac>`, `X-GitHub-Delivery`, `X-GitHub-Event` | Present as the code reads them. |
| 6.3 | Redeliver a delivery from the GitHub UI | Answered `duplicate`; nothing re-evaluated. |
| 6.4 | Change the secret on one side | 401; nothing happens. |
| 6.5 | The `ping` event and an unsupported event | Acknowledged and ignored. |
| 6.6 | Payload size of a large `workflow_run` | Under the 1 MiB cap. |
| 6.7 | Behind Cloudflare or another proxy | The signature still verifies (the body is not altered). |

## 7. Trust roots and TUF

| # | Check | Expected |
|---|---|---|
| 7.1 | Compare the embedded GitHub TUF anchor (`githubTUFAnchor`, `internal/providers/github/trustroot.go`) with `https://tuf-repo.github.com/1.root.json` obtained through an independent channel, and with the root GitHub documents | **The anchor was fetched once by hand on 2026-10-12 (sha256 `b73aa59b16d2c4989de18e402e168183d0e58f8cf9249d7cb4dd0d1774830c6e`) and never independently verified.** Verify it before any release; a mismatch makes this a release blocker. |
| 7.2 | Start a server with an empty trust-root cache and verify an attestation | The TUF refresh walks the root chain forward from the anchor through the outbound filter and caches `trusted_root.json`; the real TUF walk (go-tuf over the outbound filter) has **no test**: the unit tests replace the fetch with a stub that returns a trusted-root document (`internal/providers/github/trustroot_test.go`), and the only networked test checks that a private address is refused. |
| 7.3 | Block the TUF host and wait past the stale age (7 days is the code's limit; shorten it in a lab build, or age the cache file) | Verification fails closed with an actionable error, never as "unverified". |
| 7.4 | Public-good Sigstore trusted root | Refreshes from the embedded public-good anchor. |
| 7.5 | Rotation: when GitHub or Sigstore publishes a new root version | The refresh follows it without a rebuild. |

## 8. GHCR and the node

| # | Check | Expected |
|---|---|---|
| 8.1 | The node pulls `ghcr.io/<owner>/<image>@$DIGEST` from a **public** package | Succeeds; the deployment reaches `succeeded`. |
| 8.2 | A **private** package | Requires registry credentials on the node, which SuperMgmt does not manage in M4. Record how you logged the node's Docker in and that the deployment works; the setup is a manual step. |
| 8.3 | Disk preflight: `docker manifest inspect --verbose ghcr.io/...@$DIGEST` on the node | Reports per-platform layer and config sizes the preflight sums; with a multi-arch image the platform match is unique (`compose.image_size` errors on no unique match). |
| 8.4 | Compose 5.5.1 on a real distribution (the fixture is Debian) | `docker compose version --short` prints `5.5.1` (no `v`), and the equivalence behavior holds. Other versions are refused. |
| 8.5 | A full deploy, a failing health check with automatic rollback enabled, and a manual `sm rollback`, end to end against the real repository | As described in [deployments.md](../deployments.md#lifecycle). |
| 8.6 | Interrupt a deployment (kill the daemon during `deploy`) and restart | Held or recovered from evidence; no blind re-run. |

## Results

| Check | Result (pass / fail / skipped) | Date | `sm version` | Notes |
|---|---|---|---|---|
| 1.1 to 1.5 | | | | |
| 2.1 to 2.9 | | | | |
| 3.1 to 3.6 | | | | |
| 4.1 to 4.10 | | | | |
| 5.1 to 5.8 | | | | |
| 6.1 to 6.7 | | | | |
| 7.1 to 7.5 | | | | |
| 8.1 to 8.6 | | | | |

When a check changes an assumption, update in the same change: the fake, [PROVENANCE.md](../../test/fixtures/github/PROVENANCE.md), the matching row in [compatibility.md](../compatibility.md), and the README and ROADMAP status.
