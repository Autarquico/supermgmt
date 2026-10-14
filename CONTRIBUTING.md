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
| `make integration` | integration tests in `test/integration` |
| `make integration-fixtures` | Docker node fixtures (`-tags fixtures`); needs a local Docker daemon |
| `make test-pty` | terminal handoff tests under a pseudo-terminal |
| `make cross-build` | linux/darwin x amd64/arm64 with `CGO_ENABLED=0` |
| `make fuzz-inventory` | every parser of untrusted input is mapped to a fuzz target, and the seeds reach it |
| `make fuzz` | mutate the fuzz targets (`FUZZTIME`, `FUZZ_SHARD`, `FUZZ_SHARDS`); slow, runs nightly in CI |
| `make race-stress` | the concurrency suite under `-race` (build tag `stress`, `STRESS_COUNT` runs) |
| `make secrets-scan`, `make licenses` | gitleaks over the full history; licence allowlist over the compiled modules |
| `make migration-test` | migrate and restore the committed M1 to M5 fixtures (needs the full history) |
| `make docs-check` | docs cite existing tests and jobs, links resolve, the platform matrix and the human checklist follow their rules |

`make api-check` checks `api/openapi.yaml` against the route table, `make snapshot` builds a signed snapshot release into `dist/`, and `make release-check` verifies it.

## Architecture boundaries

The layout is fixed by SPEC §5. The rules that matter most:

- **No business logic in `cmd/`, HTTP handlers, TUI models or MCP handlers.** They adapt requests to application services and nothing else.
- **Layering is enforced by `depguard`** in `.golangci.yml`, and a violation fails CI:
  - `internal/domain` is pure: standard library, `github.com/google/uuid`, `internal/errors` only.
  - `internal/policy` does not import `internal/database` or `internal/jobs`.
  - `database/sql` and the SQLite driver are imported only by `internal/database`, `internal/jobs` and `migrations`.
  - `cmd/` imports only `internal/cli`.
  - `internal/tui` and `internal/client` talk to the daemon through the API only (they never import `app`, `jobs`, `database`, `daemon`, `transport`, `runtimes` or `providers`); `internal/api` reaches nodes only through `app`; `internal/cli` does not import `app`, `jobs` or `transport`; `internal/api/wire` is pure.
- Time comes from an injected `domain.Clock`; `time.Now` is forbidden by lint outside the clock.
- Errors are typed (`internal/errors`, imported as `smerr`) and wrapped with context.
- Dependencies are limited by SPEC §41. Do not edit `go.mod` or `go.sum` in a feature PR; propose the dependency in the issue.

Prefer boring, auditable code. Let abstractions emerge from two or three real uses; a new interface needs a real second implementation or a declared seam.

## Tests

- Tests describe behavior, are table-driven where natural, and use only the standard `testing` package.
- Every exported behavior has a test, and every error path that matters has a negative test.
- Tests must pass with `-race` and `-shuffle=on`.
- Security-relevant code (policy, approvals, plan hashing, redaction, host keys, command templates) needs negative tests: what must be refused.
- Behaviour that only real software can confirm (Proxmox, GitHub, MCP clients, signing keys) is covered by a fake in the tests and by a row in [`docs/manual-checks/`](docs/manual-checks/m6-release.md). Add the row in the same change, state the assumption, and never describe the fake-verified behaviour as verified.
- Anything that touches the terminal handoff (`internal/tui/handoff.go`, `internal/client/interactive.go`) also needs a run of [`docs/manual-checks/m1-handoff.md`](docs/manual-checks/m1-handoff.md) on a real terminal; the PTY tests do not replace it.

## Fuzzing

Every function that parses untrusted or persisted input (node output, API answers, files, archives, tokens, request bodies) has a fuzz target, or an exemption with a reason, in `scripts/fuzz-inventory.txt`.

- `test/fuzzinv` finds parser candidates in the syntax tree of `internal/` (names such as `parse*`, `decode*`, `read*`, `load*`, or a call to a JSON, YAML, tar or zstd decoder). A new candidate that is not in the inventory fails `make fuzz-inventory`, and so does a row that names no function or no target.
- Seed every target with `f.Add` from existing fixtures. The seeds run in every `go test`, so a pull request never mutates; mutation runs in the nightly workflow, 5 minutes per target.
- A crasher is a bug. Do not skip it: keep the failing input under `testdata/fuzz/<Target>/`, fix the parser in the same change, and say what the input was.
- A row marked `exempt: gap:` is a parser with no target yet. Replacing it with a target is welcome; adding a new one needs a reason in the pull request.

## Race and stress tests

- `make test-race` runs the unit tests under `-race` on Ubuntu and macOS.
- Concurrency seams (job claim and lease, the SSE broker, the SSH pool, Proxmox sync, deployment locks, MCP token issuance) have tests under `test/stress`, behind the build tag `stress`, repeated many times under `-race` by `make race-stress`. A race is a production defect until proven otherwise: fix it in a separate change and keep the reproduction.
- Tests that change the machine they run on (`hostlifecycle` tag) refuse to start unless `SM_E2E_VM=1` and the runner is a disposable CI machine. Never run them on a development machine.

## Flaky tests

There are no automatic retries in the pull-request gates, and a flake is never fixed by adding one.

1. Classify it: a **test synchronization defect** (the test races the code under test: a sleep, an unordered map, a shared port) or a **production defect** (the code is wrong under timing).
2. Fix the cause. A fix needs a proof that it failed before and passes after: a deterministic reproduction, or at least 200 runs under `-cpu 1,2,4` with load, before and after.
3. A flake you cannot fix may be moved to the nightly workflow only with an issue, an owner, an expiry date, and pull-request coverage of the behaviour it guarded. It stays reported as **unresolved** in the [release checklist](docs/release-checklist.md#unresolved-items-and-stated-limitations); moving it never counts as fixing it.

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

A change is security-sensitive if it touches authentication, secrets (including the KEK files and the instance SSH identity), policy, approvals, plan hashing, audit or redaction, SSH host keys, the command catalog or `node.setup`, command execution, the installer, or dependencies. For these:

1. Say so in the issue and the PR, and name the threat considered (SPEC §30).
2. Add negative tests.
3. Show that no secret reaches logs, events or error messages.
4. Never weaken a control to make a test pass; changing a security constraint requires a spec change, not an ADR (see [`docs/adr/README.md`](docs/adr/README.md)).

## Decisions

Decisions the spec leaves open are recorded as ADRs in [`docs/adr/`](docs/adr/). Open one as `Proposed` in the PR that needs it. See [GOVERNANCE.md](GOVERNANCE.md).

## Documentation honesty

Documentation must never describe planned work as shipped. Mark anything not yet implemented with its milestone ("planned, M3").
