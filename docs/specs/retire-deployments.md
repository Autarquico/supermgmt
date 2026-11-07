---
codename: supermgmt
title: Retire deployments, apps and the GitHub connector
type: task
status: active
priority: P1
size: XL
issue: 77
prs: []
related_issues: [77]
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
- The `deployer` role is removed (its bindings first); `node.backup_template.run`, which only its rule granted, moves to the admin rule. Automation identities created for CI are disabled and lose their role bindings, never deleted (jobs, plans and events reference them); their audit events stay. Jobs whose stored credential kind is `github_oidc` are no longer resumable: the credential reads as revoked.
- Migration 000014: refuse, changing nothing, while a deployment is not in a terminal state (`succeeded`, `failed`, `rolled_back`, `rollback_failed`, `cancelled`), or a job of type `deployment.create` or `deployment.rollback`, or a `control_plane.apply` job whose plan is `app.write`, `app_target.write` or a GitHub `provider.write`, is not terminal or has an intent not completed. Otherwise delete the locks of those terminal jobs by job id, disable the automation identities, remove the deployer role, delete provider rows of type `github` (their secrets stay, unused; the upgrade guide says to revoke the tokens in GitHub), and drop the tables children first. `events`, `jobs`, `plans` and `observations` keep their CHECKs so the audit and old jobs stay readable.
- Restore: the deployment neutralisation goes (the table no longer exists after migrating). A backup taken before 000014 with only terminal deployments restores; one with an open deployment is refused with guidance to restore it with the previous release, let the deployment finish, and take a new backup.
- Config: the `github:` and `health:` blocks (the latter only served deployment health checks) and providers of type `github` are retired: a config file that has them loads with one warning per block or provider, which `sm config validate` also prints, and they are otherwise ignored. A misspelt key is still an error.
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
- **Given** a database at 000013 with terminal deployments and their jobs, locks and events, a GitHub provider, an automation identity with role bindings and a deployer binding (and, separately, the M4 and M5 migration fixtures)
- **When** 000014 runs
- **Then** the M4 tables are gone, no lock of those jobs remains, no GitHub provider remains, the automation identity is disabled without bindings, the deployer role is gone, `foreign_key_check` passes, and the `deployment.*`, `app.write` and `app_target.write` events are still listed by `sm audit`

### Scenario: a backup from before the retirement restores
- **Given** a backup taken at 000011 with deployments in progress
- **When** it is restored with this version
- **Then** a backup with only terminal deployments restores; one with an open deployment is refused, changing nothing, with the guidance to restore it with the previous release, let it finish and back up again; neither fails on a dropped table

### Scenario: an old config and policy still load
- **Given** a config with a `github:` block and a policy granting `deployment.create` to `deployer`
- **When** the daemon starts
- **Then** it starts with one warning per retired block, provider and action, and admin still has `node.backup_template.run`

### Scenario: old GitHub-authenticated jobs do not resume
- **Given** an interrupted job whose credential kind is `github_oidc`, from before the upgrade
- **When** recovery looks at it
- **Then** its credential reads as revoked and it is not resumed

### Scenario: the build is smaller
- **Given** `go mod tidy`
- **When** the modules are listed
- **Then** compose-go, sigstore-go, go-tuf, go-containerregistry and their indirects are not required (go-oidc stays for MCP OAuth); `make generate`, `make lint` and CI pass without `compose-equivalence` and `e2e-deploy`

## Notas técnicas

- Keep `domain.ResourceApp`, `ResourceAppTarget`, `ResourceDeployment` and `CredentialGitHubOIDC` so old events and jobs decode; resolve an unknown app target in an old plan or job as gone, not as an error.
- `test/docs` cites deleted tests (about 109) and checks commands shown in the guides; both must be updated in the same change.
- Compose templates useful for discovery (`ps`, project containers) may stay if discovery uses them; otherwise they go.
