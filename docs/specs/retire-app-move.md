---
codename: supermgmt
title: Retire app move
type: task
status: active
priority: P1
size: L
issue: null
prs: []
related_issues: [75]
depends_on: []
supersedes: [app-move, app-move-routes]
related_specs: [node-routes, retire-deployments]
created: 2026-11-07
updated: 2026-11-07
---

# Retire app move

## Contexto / problema

ADR-0043 takes building, deploying and moving applications out of SuperMgmt's scope. App move (ADR-0041) and app move with routes (ADR-0042) are its leaf: nothing else depends on them, but they reach into routes, locks and tunnel plans:

- `internal/app/app_move*.go` (21 files), `database/repo_app_moves*.go`, `repo_app_move_routes*.go`, migrations 000010 and 000011 (`app_moves`, `app_move_volumes`, `app_move_routes`).
- `requireNoRoutedMove*` and `requireNoOpenMove` are defined in move files and called from `plans.go:104-139`, `locks.go:113-140` and `app_routes.go:102,237,253`; `IncomingMoveRoutes` from `app_routes_job_ingress.go:43`; `activateRoutes` from `app_move_job_routes.go:306`.
- Surfaces: `sm apps move|moves` (`cli/apps_moves*.go`), `api/routes_app_moves.go`, `wire/app_moves.go`, `client/api_app_moves.go`, MCP `infra_move_app` and `infra_list_app_moves`, TUI `moves*.go`, policy actions `app_target.move`, `app_target.cleanup_source`, `app_target.abandon_move`.
- `policy/validate.go:131` rejects an unknown action, so a policy file that names a removed action would stop the daemon from starting.

## Scope

**Entra:**
- Delete app move end to end: code, surfaces, policy actions, MCP tools, TUI views, SSH templates only moves use (`parse_move`), tests, fuzz targets and inventory rows.
- A retired-action list in the policy catalog: a policy file naming a retired action (or a pattern matching only retired ones) loads with one warning per action and grants nothing. Reused by the next two specs.
- Migration 000012: refuse to run while a move is not terminal; then drop `app_move_routes`, `app_move_volumes`, `app_moves`, restoring `app_routes_ids_once` to its 000009 form (node, tunnel and generation fixed again). Jobs, intents and locks of move actions left over are closed so recovery does not look for them.
- Docs: ADR-0041 and ADR-0042 "Superseded by ADR-0043"; `docs/manual-checks/app-move.md`, `docs/specs/app-move*.md` archived; mentions in the guides removed; generated CLI docs regenerated.

**No entra:**
- Routes, deployments, apps, app targets and GitHub (next two specs).

## Criterios de aceptación

### Scenario: the move commands are gone
- **Given** a daemon built from this change
- **When** the operator runs `sm apps move`, calls `infra_move_app` or `POST` the moves API
- **Then** the CLI reports an unknown command, MCP an unknown tool and the API 404; `sm --help`, `docs/cli.md` and the TUI show no move

### Scenario: an old policy file still loads
- **Given** a policy file that grants `app_target.move` and `app_target.*`
- **When** the daemon starts
- **Then** it starts, logs one warning naming `app_target.move` as retired by ADR-0043, and no action is granted by the retired rule

### Scenario: an instance with an open move does not migrate
- **Given** a database at 000011 with a move in a non-terminal phase
- **When** the daemon migrates
- **Then** migration 000012 fails without changing anything and the error says to finish or abandon the move with the previous version

### Scenario: an instance with finished moves migrates and keeps its audit
- **Given** a database at 000011 with terminal moves, their jobs and audit events
- **When** migration 000012 runs
- **Then** the move tables are gone, no move job, intent or lock is left open, `app_routes` keeps its rows and the 000009 trigger, and `sm audit` still lists the `app_move.*` events

### Scenario: tunnel and route plans no longer ask about moves
- **Given** a node with routes
- **When** the operator rotates the Access token, disables the tunnel or exposes a route
- **Then** the plans build without any move guard and behave as before otherwise

## Notas técnicas

- `errors/reason.go`: drop reasons only moves use; keep any shared one.
- `test/docs` cites tests by name: remove the citations of deleted tests.
- Restore (`backup/neutralize.go`) only touches `deployments` today; it stays until retire-deployments.
