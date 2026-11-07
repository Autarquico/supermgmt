---
codename: supermgmt
title: "Retire deployments, apps and the GitHub connector"
type: task
status: draft
priority: P1
size: XL
issue: null
prs: []
related_issues: []
depends_on: [retire-app-move, node-routes]
supersedes: [m4-apps-deployments]
related_specs: [retire-app-move, node-routes]
created: 2026-11-07
updated: 2026-11-07
---

# Retire deployments, apps and the GitHub connector

## Contexto / problema

ADR-0043 removes the deployment engine (ADR-0011, ADR-0029), the GitHub connector as a deployment input (ADR-0028) and app targets as deployment units. Once moves are gone and routes belong to nodes, nothing outside this set depends on it:

- Packages: `internal/deployments/**`, `internal/providers/github/**` (with `ghfake`), `internal/health/**`, the M4 app concept in `internal/app` (`apps.go`, `deploy_*`, `deployments*`, `ci_watch*`, `binding*`, `finalize*`, `snapshots*`, `repositories*`, `automation*`, `webhook_audit*`), `auth/github*.go`, `config/github*.go`.
- Tables from 000005 and 000010: `repositories`, `apps`, `app_targets`, `artifacts`, `artifact_checks`, `github_oidc_credentials`, `deployments`, `deployment_steps`, `health_checks`, `webhook_deliveries`, `execution_snapshots`.
- Restore neutralizes `deployments` after migrating (`backup/neutralize.go:114-133`), so dropping the table breaks restore unless both change together.
- Surfaces: `sm deploy`, `sm rollback`, `sm deployments`, `sm apps list|get|create|target add`, the GitHub webhook, MCP `infra_list_apps`, `infra_list_deployments`, `infra_get_deployment`, `infra_create_deployment`, `infra_rollback_deployment`, TUI apps and deployments views.
- Build: `go.mod` modules used only here (compose-go, sigstore-go, go-tuf, in-toto, rekor, go-digest), Makefile and CI jobs `compose-equivalence` and `e2e-deploy`.

## Scope

**Entra:**
- Delete the packages, code, surfaces, policy actions (`deployment.*`, `app.*`, `app_target.*`), MCP tools, TUI views, config keys (`github:`, provider type `github`), SSH templates only deployments use, error reasons only they use, examples, tests, fuzz targets and inventory rows, Makefile targets, CI jobs and unused modules.
- The `deployer` role and automation identities seeded for CI are removed; their audit events stay.
- Migration 000014: refuse to run while a deployment is not terminal; close leftover deployment jobs, intents and locks; delete provider rows of type `github` and the secrets only they reference; drop the tables in foreign-key order. `events`, `jobs` and `observations` keep their resource-type checks so the audit and old jobs stay readable.
- Restore: neutralize only what still exists, so restoring a backup taken before 000014 works.
- Config: a config file with a `github:` block or a `github` provider loads with a warning that it is retired and is otherwise ignored.
- Docs: ADR-0011, 0028, 0029 "Superseded by ADR-0043", ADR-0043 "Accepted"; `docs/deployments.md` and `docs/manual-checks/m4-real-github.md` retired; the spec (`docs/spec/SUPERMGMT-SPEC.md` §18-§20.3, §28, M4) and guides updated; generated docs regenerated.

**No entra:**
- The CI/CD hooks of ADR-0043 (deploy account provisioning) and discovery of apps: their own specs.

## Criterios de aceptación

### Scenario: the deployment surfaces are gone
- **Given** a daemon built from this change
- **When** the operator runs `sm deploy`, `sm deployments list` or `sm apps create`, or an MCP client calls `infra_create_deployment`
- **Then** they do not exist; help, `docs/cli.md`, `docs/mcp.md` and the TUI show none of them

### Scenario: an instance with an open deployment does not migrate
- **Given** a database at 000013 with a deployment that is not terminal
- **When** the daemon migrates
- **Then** 000014 fails without changing anything and says to let it finish or cancel it with the previous version

### Scenario: a finished M4 instance migrates and keeps its audit
- **Given** the M4 and M5 migration fixtures brought to 000013
- **When** 000014 runs
- **Then** the M4 tables are gone, no deployment job, intent or lock is open, no GitHub provider or its secret remains, and the `deployment.*` and `webhook.received` events are still listed by `sm audit`

### Scenario: a backup from before the retirement restores
- **Given** a backup taken at 000011 with deployments in progress
- **When** it is restored with this version
- **Then** the restore migrates it, refuses or neutralizes as the scenarios above say, and never fails on a dropped table

### Scenario: an old config and policy still load
- **Given** a config with a `github:` block and a policy granting `deployment.create` to `deployer`
- **When** the daemon starts
- **Then** it starts with one warning per retired key and action

### Scenario: the build is smaller
- **Given** `go mod tidy`
- **When** the modules are listed
- **Then** compose-go, sigstore-go and go-tuf are not required; `make generate`, `make lint` and CI pass without `compose-equivalence` and `e2e-deploy`

## Notas técnicas

- Keep `domain.ResourceApp`, `ResourceAppTarget`, `ResourceDeployment` and `CredentialGitHubOIDC` so old events and jobs decode; resolve an unknown app target in an old plan or job as gone, not as an error.
- `test/docs` cites deleted tests (about 109) and checks commands shown in the guides; both must be updated in the same change.
- Compose templates useful for discovery (`ps`, project containers) may stay if discovery uses them; otherwise they go.
