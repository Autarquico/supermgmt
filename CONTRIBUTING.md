# Contributing to SuperMgmt

SuperMgmt is pre-alpha. The master specification ([`docs/spec/SUPERMGMT-SPEC.md`](docs/spec/SUPERMGMT-SPEC.md)) is the source of truth; work follows its milestones (see [ROADMAP.md](ROADMAP.md)). Read the milestone spec under [`docs/specs/`](docs/specs/) before starting.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Issue first

Open an issue before starting anything non-trivial: a new feature, a behavior change, a new dependency, or anything that touches a security control. Small fixes (typos, obvious bugs, test gaps) can go straight to a pull request. Work scheduled for a later milestone is not accepted early (SPEC §0); say which milestone your change belongs to.

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## Setup

Requirements: Go 1.27 (see `go.mod`), `make`, and `golangci-lint` v2 for `make lint`.

```bash
git clone https://github.com/autarquico/supermgmt.git
cd supermgmt
go mod download
make test
make build        # writes dist/sm
```

Common targets (`make help` lists all):

| Target | Purpose |
|---|---|
| `make test` | unit tests (`-shuffle=on`) |
| `make test-race` | unit tests with the race detector |
| `make lint` | golangci-lint and format check |
| `make generate` | regenerate generated files and fail on drift |
| `make vuln` | govulncheck |
| `make integration` | integration tests (build tag `integration`) |
| `make cross-build` | linux/darwin x amd64/arm64 with `CGO_ENABLED=0` |

`make api-check`, `make e2e`, `make snapshot` and `make release-check` are placeholders until M2.

## Architecture boundaries

The layout is fixed by SPEC §5. The rules that matter most:

- **No business logic in `cmd/`, HTTP handlers, TUI models or MCP handlers.** They adapt requests to application services and nothing else.
- **Layering is enforced by `depguard`** in `.golangci.yml`, and a violation fails CI:
  - `internal/domain` is pure: standard library, `github.com/google/uuid`, `internal/errors` only.
  - `internal/policy` does not import `internal/database` or `internal/jobs`.
  - `database/sql` and the SQLite driver are imported only by `internal/database`, `internal/jobs` and `migrations`.
  - `cmd/` imports only `internal/cli`.
- Time comes from an injected `domain.Clock`; `time.Now` is forbidden by lint outside the clock.
- Errors are typed (`internal/errors`, imported as `smerr`) and wrapped with context.
- Dependencies are limited by SPEC §41. Do not edit `go.mod` or `go.sum` in a feature PR; propose the dependency in the issue.

Prefer boring, auditable code. Let abstractions emerge from two or three real uses; a new interface needs a real second implementation or a declared seam.

## Tests

- Tests describe behavior, are table-driven where natural, and use only the standard `testing` package.
- Every exported behavior has a test, and every error path that matters has a negative test.
- Tests must pass with `-race` and `-shuffle=on`.
- Security-relevant code (policy, approvals, plan hashing, redaction) needs negative tests: what must be refused.

## Generated files

Generated files carry a header or markers and CI fails on drift. Run `make generate` and commit the result. Example: the environment table in [`docs/configuration.md`](docs/configuration.md) is generated from the config schema; edit the prose outside the `GENERATED` markers, never the table.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/) in English: `feat(policy): ...`, `fix(database): ...`, `docs: ...`.
- **DCO sign-off is required.** Every commit must carry `Signed-off-by:`, which certifies the [Developer Certificate of Origin](https://developercertificate.org/). Use `git commit -s`. There is no CLA.
- Keep pull requests focused. Describe the spec sections touched and map each acceptance criterion to a test.
- Fill in the [pull request template](.github/PULL_REQUEST_TEMPLATE.md). Its checklist is the review bar:
  - summary, spec sections touched, acceptance-criterion-to-test table;
  - security-sensitive changes declared (see below);
  - `make test test-race lint` pass locally;
  - commits signed off.

## Security-sensitive changes

A change is security-sensitive if it touches authentication, secrets, policy, approvals, plan hashing, audit or redaction, SSH host keys, command execution, the installer, or dependencies. For these:

1. Say so in the issue and the PR, and name the threat considered (SPEC §30).
2. Add negative tests.
3. Show that no secret reaches logs, events or error messages.
4. Never weaken a control to make a test pass; changing a security constraint requires a spec change, not an ADR (see [`docs/adr/README.md`](docs/adr/README.md)).

## Decisions

Decisions the spec leaves open are recorded as ADRs in [`docs/adr/`](docs/adr/). Open one as `Proposed` in the PR that needs it. See [GOVERNANCE.md](GOVERNANCE.md).

## Documentation honesty

Documentation must never describe planned work as shipped. Mark anything not yet implemented with its milestone ("planned, M3").
