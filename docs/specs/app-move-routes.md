---
codename: supermgmt
title: Move an app target's Cloudflare routes with it
type: epic
status: active
priority: P1
size: L
issue: 56
prs: []
related_issues: [56]
depends_on: []
supersedes: []
related_specs: [app-move, app-expose-tunnel]
created: 2026-11-01
updated: 2026-11-01
---

# Move an app target's Cloudflare routes with it

## Contexto / problema

`sm apps move` (ADR-0041, `docs/specs/app-move.md`) refuses a target that has a route that is not `removed` (`internal/app/app_move_plan.go:171`). The user must unexpose, move, and expose again. That removes the hostname from DNS for the whole move and recreates the Access app.

A route's identity is frozen: node, tunnel ID and tunnel generation (`internal/app/app_routes.go:251-278`). The `app_routes_ids_once` trigger forbids changing it (`migrations/000009_app_routes.up.sql:50-59`). The Cloudflare client cannot update a DNS record. It only creates, finds and deletes (`internal/providers/cloudflare/dns.go:45,70,84`).

This spec covers the part of feature 4 that the 2026-11-01 split set aside: items 2, 5, 11 and 12 of `.claude/loop/app-move/codex-critique.md`.

## Scope

**Entra:**

1. **Admission.** `app_target.move` accepts a target with routes under these conditions:
   - **Route phases.** Every route that is not `removed` is `active` or `waiting` and has no open job. Any other phase refuses the move and names the route: `provisioning`, `ingress_ready`, `access_ready`, the removal phases, `failed` or `conflict`.
   - **Destination tunnel.** B has a committed tunnel, which means `transport: cloudflare` (`internal/app/app_routes_job_ingress.go:87`).
   - **Capacity.** B's live routes plus the target's routes plus the incoming routes of other open moves to B fit the 98-route limit (`internal/app/app_routes.go:20`).
   - **Re-checks.** Both checks run again under the claim locks, before `staged` and again before the routes switch.
   - **During the move.** While the move is open, `app_route.expose` is already refused (ADR-0041), and `app_route.unexpose` of the target is refused as well.
2. **The plan freezes each route.**
   - It freezes the route ID, hostname, phase, access mode and the recorded DNS record and Access app IDs.
   - It also freezes the identity at A: account, zone, instance, tunnel ID and generation. The identity at B is the same account, zone and instance with B's committed tunnel ID and generation.
   - Revalidation fails the move when any of these changed.
3. **`app_move_routes`.** Migration `000011` adds one row per frozen route, holding:
   - the move;
   - the route;
   - the from and to node, tunnel ID and tunnel generation;
   - a state with these values: `pending`, `dest_ingress`, `dns_switched`, `committed`, `source_cleaned`, `dns_restored` and `dest_withdrawn`.

   The intended DNS content is persisted before each repoint is dispatched. The same migration rebuilds `app_moves` to add the phases `routes_dest_ingress`, `routes_switched`, `routes_source_cleaned`, `compensating_routes_restored` and `compensating_routes_withdrawn`. The rebuild keeps every index, trigger and row.
4. **Order.** Every Cloudflare write holds the instance Cloudflare lock (`internal/app/locks.go:44`). The move job takes that lock when the target has routes.
   1. **After `verified`**, B's tunnel ingress gains the rules. The ingress builder (`internal/app/app_routes_job_ingress.go:33`) includes, for B, the incoming routes of a move whose row is in `dest_ingress`, `dns_switched` or `committed` and that `servesIngress` would serve (`:19`). A `waiting` route is never published. The move then advances to `routes_dest_ingress`.
   2. **Each `active` route is switched in turn:**
      - for an `owners` route, the recorded Access app is revalidated first, the same check expose runs before DNS (`internal/app/app_routes_job_expose.go:198`). A missing app halts the move. A drifted one is repaired;
      - the record is then checked: it must carry the route's marker, be a proxied CNAME, and point at A's tunnel or B's tunnel. Anything else halts the move. A foreign record is never touched;
      - the CNAME is repointed to B's tunnel with a new `UpdateDNSRecord` (PATCH), keeping the record ID. The row moves to `dns_switched`.

      A `waiting` route has no DNS and is not switched. The move then advances to `routes_switched`.
   3. **Commit.** The commit transaction of ADR-0041 also does two things:
      - It updates each route's `node_id`, `tunnel_id` and `tunnel_generation` to the row's to-values. Each update requires the route's current values to equal the row's from-values.
      - It moves each row to `committed`.

      Every row count is asserted. The trigger is relaxed for exactly this case: the three columns may change together only to the to-values of a `dns_switched` or `pending` (`waiting`) row of the target's open move, and only from that row's from-values. Every other identity rule stays.
   4. **After the commit**, A's ingress loses the rules: A's builder no longer counts the routes, because they now name B. The rows move to `source_cleaned` and the move to `routes_source_cleaned`. Then come `source_parked` and `done`, as before.
5. **Resume of a repoint whose outcome is unknown.** A PATCH whose answer was lost is reconciled by reading the exact record ID:
   - content pointing at B's tunnel means the repoint happened;
   - content pointing at A's tunnel means it did not;
   - anything else halts the move.
6. **Compensation before the commit** first undoes the routes, in this order, and then continues as ADR-0041:
   1. Every `dns_switched` row is repointed back to A's tunnel, after the same ownership check. The row moves to `dns_restored`.
   2. B's ingress is rewritten without the incoming routes. The rows move to `dest_withdrawn`.
   3. B is stopped only after both steps, so no record ever points at a stopped B.

   A failed restore halts the move with B still running. The halt message names the hostnames whose records point at B.
7. **Unchanged.** The Access app and its policies stay the same objects, with the same hostname. A's ingress keeps its rules until after the commit, so a client with cached DNS reaches A until A is parked.
8. **Surfaces.**
   - `sm apps moves` and `infra_list_app_moves` list each route's state.
   - The plan output lists the hostnames that will be repointed.
   - Audit `app_move.route_switched` and `app_move.route_restored`.
9. **Docs.**
   - `docs/deployments.md` and `docs/cloudflare.md` get a "Moving a target with routes" section.
   - The `docs/manual-checks/app-move.md` checklist gets a routes section.
   - `docs/project-status.md` is updated.

**No entra:**

- Moving a route whose operation is unfinished. The route must first be completed, removed or resumed.
- Changing hostname, access or port during a move.
- Verifying public reachability through Cloudflare after the switch: an `owners` route answers with Access, and B's health is already proven on the node.
- Moving between Cloudflare accounts, zones or instances.

## Criterios de aceptación

### Scenario: a public route follows the app
- **Given** a target on A with an `active` public route `shop.example.com`, and B with a committed tunnel
- **When** it moves to B
- **Then** B's ingress serves the rule before the CNAME is repointed, the CNAME keeps its record ID and marker and points at B's tunnel, the route row names B, B's tunnel and its generation, and A's ingress has no rule for it after the commit

### Scenario: an owners route keeps its Access application
- **Given** an `active` owners route
- **When** it moves
- **Then** the Access app is the same object with the same policies, it was revalidated before the repoint, and a missing Access app halts the move before any record changes

### Scenario: a waiting route moves without Cloudflare
- **Given** a `waiting` route
- **When** the target moves
- **Then** no DNS or ingress call is made for it, the route row names B after the commit, and a later deployment on B activates it there

### Scenario: unfinished routes refuse the move
- **Given** a route in `provisioning`, a removal phase, `failed` or `conflict`, or with an open job, or a B without a committed tunnel, or a B whose capacity would exceed 98 routes counting incoming moves
- **When** the user requests the move
- **Then** it is refused naming the route or the reason, and no plan is created

### Scenario: a partial switch is undone before B stops
- **Given** two routes, where the second repoint fails
- **When** compensation runs
- **Then** the first record is repointed back to A's tunnel, B's ingress no longer has either rule, and only then is B stopped. Routes and `node_id` still name A

### Scenario: a lost repoint answer is reconciled
- **Given** a PATCH whose response was lost
- **When** the job resumes
- **Then** the record is read by ID. If it points at B the row becomes `dns_switched`, if it points at A the repoint is retried, and if it points elsewhere the move halts

### Scenario: a foreign record halts the switch
- **Given** a route whose record no longer carries the route's marker
- **When** the switch reaches it
- **Then** the move halts, the record is untouched, earlier switched records are restored by compensation, and A keeps serving

### Scenario: the trigger accepts only the move's exact identities
- **Given** an open move with a `dns_switched` row
- **When** an update writes any other node, tunnel or generation, or writes them for a route of another target, or for a row not in `dns_switched` or `pending`
- **Then** the database refuses it

### Scenario: unexpose waits for the move
- **Given** an open move of a target with routes
- **When** the user unexposes one of its routes
- **Then** it is refused with a message naming the move

### Scenario: other ingress writers keep the incoming rules
- **Given** a move in `routes_dest_ingress`
- **When** another route of B is exposed, or B's tunnel setup reruns
- **Then** B's ingress still contains the incoming rules

## Notas técnicas / riesgos

- `UpdateDNSRecord` needs `cffake` support and chaos hooks.
- The relaxed trigger is the riskiest database change. Negative tests cover every column, other targets and rows in other states.
- The feature is experimental and tested against `cffake` and fixture daemons only, until the manual checklist passes.

## Referencias

- ADR-0042 (this feature), ADR-0041 (app-move), ADR-0040 (routes).
- Critique: `.claude/loop/app-move/codex-critique.md` items 2, 5, 11, 12.
