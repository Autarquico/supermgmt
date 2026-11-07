---
codename: supermgmt
title: Retire app move
type: task
status: shipped
priority: P1
size: L
issue: 75
prs: [78]
related_issues: [75]
depends_on: []
supersedes: [app-move, app-move-routes]
related_specs: [node-routes, retire-deployments]
created: 2026-11-07
updated: 2026-11-07
---

# Retire app move

## Contexto / problema

ADR-0043 takes building, deploying and moving applications out of SuperMgmt's scope. App move (ADR-0041) and app move with routes (ADR-0042) are its leaf: they can be removed once their hooks into routes, locks, tunnel plans and the TUI are untangled:

- `internal/app/app_move*.go` (21 files), `database/repo_app_moves*.go`, `repo_app_move_routes*.go`, migrations 000010 and 000011 (`app_moves`, `app_move_volumes`, `app_move_routes`).
- `requireNoRoutedMove*` and `requireNoOpenMove` are defined in move files and called from `plans.go:104-139`, `locks.go:113-140` and `app_routes.go:102,237,253`; `IncomingMoveRoutes` from `app_routes_job_ingress.go:43`; `IncomingReservationsExcept` from the route capacity check (`app_routes.go:296`); `routedMoveOf` from route activation (`app_routes_activate.go:18`); `moveStartMsg` from the TUI update loop (`tui/model.go:248`).
- Surfaces: `sm apps move|moves` (`cli/apps_moves*.go`), `api/routes_app_moves.go`, `wire/app_moves.go`, `client/api_app_moves.go`, MCP `infra_move_app` and `infra_list_app_moves`, TUI `moves*.go`, policy actions `app_target.move`, `app_target.cleanup_source`, `app_target.abandon_move`.
- `policy/validate.go:131` rejects an unknown action, so a policy file that names a removed action would stop the daemon from starting.

## Scope

**Entra:**
- Delete app move end to end: code, surfaces, policy actions, MCP tools, TUI views, SSH templates only moves use (`parse_move`), tests, fuzz targets and inventory rows.
- A retired-action list in the policy catalog. A rule naming a retired action, or a wildcard matching only retired actions, loads with a warning and that entry grants or denies nothing; a wildcard that also matches live actions keeps exactly its live matches, on allow and deny rules alike. A name that is neither live nor retired (a typo) is still an error. Warnings are reported once per retired action and file, in the daemon log at start and by `sm config validate`. Reused by the next two specs.
- Migration 000012, in its own transaction: refuse to run while a move is not `done` or `rolled_back`, or while any job of a move action (move, cleanup, abandon) is not terminal or has an intent not completed; otherwise delete the locks still held by terminal move jobs (selected by job id), drop `app_routes_ids_once`, drop `app_move_routes`, `app_move_volumes`, `app_moves`, and recreate the trigger in its 000009 form. Jobs, plans, events and deployments of kind `move` stay as history.
- Docs: ADR-0041 and ADR-0042 "Superseded by ADR-0043"; `docs/manual-checks/app-move.md`, `docs/specs/app-move*.md` archived; mentions in the guides removed; generated CLI docs regenerated.

**No entra:**
- Routes, deployments, apps, app targets and GitHub (next two specs).

## Criterios de aceptación

### Scenario: the move commands are gone
- **Given** a daemon built from this change
- **When** the operator runs `sm apps move`, calls `infra_move_app` or `POST` the moves API
- **Then** the CLI reports an unknown command, MCP an unknown tool and the API 404; `sm --help`, `docs/cli.md` and the TUI show no move

### Scenario: an old policy file still loads without widening anything
- **Given** a policy file with an allow rule for `app_target.move`, an allow rule for `app_target.*` and a deny rule for `app_target.cleanup_source` and `app_target.write`
- **When** the daemon starts and `sm config validate` runs
- **Then** both start or pass with a warning per retired action naming ADR-0043; the first rule grants nothing; the wildcard still grants `app_target.read` and `app_target.write`; the deny rule still denies `app_target.write`; every live action decides as before

### Scenario: a typo is still an error
- **Given** a policy file naming `app_target.moev`
- **When** the daemon starts
- **Then** it refuses the policy as it does today

### Scenario: an instance with an open move does not migrate
- **Given** a database at 000011 with a move in a non-terminal phase
- **When** the daemon migrates
- **Then** migration 000012 fails, the schema version, rows, locks, intents and triggers are unchanged, and the error says to let the move finish (or abandon it where it is halted) with the previous version
- **And** the same holds for a terminal move whose cleanup job is still running or interrupted

### Scenario: an instance with finished moves migrates and keeps its audit
- **Given** a database at 000011 with terminal moves, their jobs and audit events
- **When** migration 000012 runs
- **Then** the move tables are gone, no lock of a move job remains, startup recovery runs clean, `app_routes` keeps its rows and the 000009 trigger (node, tunnel and generation fixed again), `foreign_key_check` passes, `sm audit` still shows the `app_move.*` events with their payloads, and deployments, including those of kind `move`, are unchanged

### Scenario: tunnel and route plans no longer ask about moves
- **Given** a node with routes
- **When** the operator rotates the Access token, disables the tunnel or exposes a route
- **Then** the plans build without any move guard and behave as before otherwise
- **And** route activation after a deployment and route removal on unexpose work as before

## Notas técnicas

- `errors/reason.go`: drop reasons only moves use; keep any shared one.
- `test/docs` cites tests by name: remove the citations of deleted tests.
- Restore migrates before neutralizing (`backup/restore.go:160-186`): a backup with a terminal move restores; one with an open move fails at 000012 with the same guidance. The deployment neutralization stays until retire-deployments.
- `finalize.go`'s `errAppMoved` means the app or target changed during finalization, not a move: it stays.
