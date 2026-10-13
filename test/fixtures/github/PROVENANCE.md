# ghfake provenance (ADR-0028, fake fidelity)

`internal/providers/github/ghfake` is hand-written from the GitHub REST
documentation. **Nothing here was recorded from, or verified against, the live
API.** Anything the fake cannot prove belongs in
`docs/manual-checks/m4-real-github.md`.

- REST API version: `2022-11-28` (sent as `X-GitHub-Api-Version` by the client).
- Documentation read: 2026-10-12.

## Endpoints and fields modelled (checks, T5b)

| Endpoint | Documentation | Fields the fake serves | Behaviour modelled |
|---|---|---|---|
| `GET /repos/{owner}/{repo}/commits/{ref}/check-runs` | https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference | `total_count`, `check_runs[]`: `id`, `name`, `status`, `conclusion` (null until completed), `head_sha`, `started_at`, `completed_at` (null until completed), `app.id`, `check_suite.id` | Query `filter` (`latest` default, `all`), `per_page`, `page`, `Link` pagination. `latest` keeps the highest-id run per (name, app); `all` keeps every attempt. Other parameters answer 422. |
| `GET /repos/{owner}/{repo}/actions/runs` | https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-repository | `total_count`, `workflow_runs[]`: `id`, `run_attempt`, `path`, `head_branch`, `head_sha`, `event`, `status`, `conclusion` | Query `check_suite_id` only; a suite without a run answers an empty list. |

Webhook payloads (`check_run`, `check_suite`, `workflow_run`) are reduced by
`VerifyWebhook` to `repository.id` and the nested `head_sha`; the signature
scheme (`X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of the raw body>`) is
from https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries.

## Unverified assumptions (manual checklist candidates)

- A re-run of a workflow adds a **new check run (higher id) to the same check
  suite** and bumps the workflow run's `run_attempt`; the verifier takes the
  highest check-run id as "latest attempt".
- `filter=all` returns the check runs of every attempt.
- `GET /actions/runs?check_suite_id=` returns the single run owning the suite.
- A workflow run's `path` is the bare workflow file path
  (`.github/workflows/ci.yml`), without a `@ref` suffix.
