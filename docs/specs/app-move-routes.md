---
codename: supermgmt
title: Move an app target's Cloudflare routes with it
type: epic
status: active
priority: P1
size: XL
issue: 56
prs: [57]
related_issues: [56]
depends_on: []
supersedes: []
related_specs: [app-move, app-expose-tunnel]
created: 2026-11-01
updated: 2026-11-02
---

# Move an app target's Cloudflare routes with it

## Contexto / problema

`sm apps move` (ADR-0041, `docs/specs/app-move.md`) refuses a target that has a route that is not `removed` (`internal/app/app_move_plan.go:171`). The user must unexpose, move and expose again. That drops the hostname from DNS for the whole move and recreates the Access app.

Three things stand in the way:

- **A route's identity is frozen.** Its node, tunnel ID and tunnel generation are fixed at admission (`internal/app/app_routes.go:251-278`), and the `app_routes_ids_once` trigger forbids changing them (`migrations/000009_app_routes.up.sql:50-59`).
- **DNS records cannot be updated.** The Cloudflare client only creates, finds and deletes them (`internal/providers/cloudflare/dns.go:45,70,84`).
- **The move's phase logic assumes no routes.** `pastCommit` recognises only `committed`, `source_parked` and `done` (`internal/app/app_move_plan.go:486-493`), and the commit requires `verified` (`internal/database/repo_app_moves.go:365-370`).

This spec covers the part of feature 4 that the 2026-11-01 split set aside, which is items 2, 5, 11 and 12 of `.claude/loop/app-move/codex-critique.md`. It also integrates the plan critique in `.claude/loop/app-move-routes/codex-critique.md`.

## Terms

- **A** is the source node and **B** the destination.
- **Routed move:** a move of a target that has at least one route that is not `removed`.
- **Reservation:** an open routed move holds a reservation on B's route capacity and on the tunnel identity of both A and B. The reservation lasts until the move is `done` or `rolled_back`. A halted move still holds it.

## Scope

**Entra:**

1. **Admission.**
   - **Route phases.** `app_target.move` accepts a target only when every route that is not `removed` is `active` or `waiting` and has no open job (`queued`, `running` or `awaiting_approval`). Any other phase refuses the move and names the route: `provisioning`, `ingress_ready`, `access_ready`, the removal phases, `failed` or `conflict`.
   - **Tunnel on B.** B must have a committed tunnel, that is `transport: cloudflare` (`internal/app/app_routes_job_ingress.go:87`).
   - **Capacity.** There is one transactional capacity function, used both by move admission and by ordinary expose admission (`internal/app/app_routes.go:266-272`). It counts:
     - B's live routes;
     - the routes of uncommitted moves into B, halted moves included;
     - the routes of this request.

     Committed rows are not counted twice. The limit is 98.
   - **Owners routes.** For each owners route, its recorded Access app must exist, guard the hostname and carry only the Owners policy. The check is the one in `requireAccessApp` (`internal/app/app_routes_job_expose.go:198`). A missing or unrepairable app refuses the move.
   - **Re-checks.** All of these run again under the claim locks, before `staged` and before `routes_dest_included`.
2. **While a routed move is open**, the following are refused at request time and again at claim time:
   - `app_route.expose` and `app_route.unexpose` of the target, including the existing-route path of `assess` (`internal/app/app_routes.go:234-248`), system activation and queued expose jobs;
   - any tunnel operation on A or B that changes the generation or writes ingress outside the shared builder: setup and enable with `--tunnel`, rotation and disable (`internal/app/tunnel_disable.go:86`, `internal/app/tunnel_rotate.go`). The message names the move.

   A queued job that predates the move fails its claim-time check.
3. **The plan freezes each route.**
   - Per route it freezes the route ID, hostname, phase (`active` or `waiting`), access mode, and the recorded DNS record and Access app IDs.
   - It freezes the identity at A: account, zone, instance, tunnel ID and generation.
   - It freezes the identity at B: the same account, zone and instance, plus B's committed tunnel ID and generation at plan time.
   - Revalidation fails the move when any frozen value differs. After the commit, revalidation uses the move record (ADR-0041). Compensation never depends on forward revalidation passing.
4. **`app_move_routes`** is a new table added by migration `000011`. It has one row per frozen route.
   - **Columns:**
     - the move and the route, with the frozen route phase;
     - the from and to node, tunnel ID and tunnel generation;
     - the DNS record ID.
   - **States:**
     - `pending`;
     - `dest_included`, the intent to be in B's ingress;
     - `dest_published`, meaning B's PUT was reconciled;
     - `dns_switching`, a forward PATCH intent;
     - `dns_switched`;
     - `committed`;
     - `source_cleaned`;
     - `dns_restoring`, a reverse PATCH intent;
     - `dns_restored`;
     - `dest_excluded`, the intent to leave B's ingress;
     - `dest_withdrawn`.
   - **Immutability.** Every column except the state and its timestamps is immutable, enforced by a trigger.
   - **DNS intents.** Each PATCH, forward or reverse, is recorded before dispatch through the intent ledger. The record holds the direction, the attempt, the intended content and a not-before time for reconciliation.
   - **`app_moves` rebuild.** The same migration rebuilds `app_moves` and keeps every index, trigger and row. The rebuild adds:
     - forward phases `routes_dest_included`, `routes_switched` and `routes_source_cleaned`;
     - compensation phases `compensating_routes_restored` and `compensating_routes_withdrawn`.

     The `halted_phase` CHECK gets the same phases.
5. **Phase contract.** It is written as code: one ordered table of phases with a pre-commit or post-commit class, used by `pastCommit`, by resume validation, by claim rebuilding and by compensation.
   - **Routed order:**
     1. `verified`
     2. `routes_dest_included`
     3. `routes_switched`
     4. `committed`
     5. `routes_source_cleaned`
     6. `source_parked`
     7. `done`
   - **Unrouted order:** the ADR-0041 order, unchanged.
   - **Commit precondition:** the commit runs from `routes_switched` for a routed move and from `verified` for an unrouted one.
   - **After commit:** a post-commit phase never compensates, whether halted or not. Its only way is forward. When a forward step cannot pass, it halts and the operator resumes it.
6. **Ingress membership is durable and comes before every PUT.**
   - **Builder.** The ingress builder (`internal/app/app_routes_job_ingress.go:33`) counts, for B, the routes of rows in `dest_included`, `dest_published`, `dns_switching`, `dns_switched` and `dns_restoring`. A route that `servesIngress` would serve (`:19`) is counted once. After the commit the route row names B, so the builder counts it by that row and ignores the move row. A row in `dest_excluded` or `dest_withdrawn` is not counted.
   - **Publish.** The rows move to `dest_included` first. Then B's ingress is built and PUT, holding the instance Cloudflare lock (`internal/app/locks.go:44`). The PUT is reconciled by reading B's tunnel configuration, and only then do the rows move to `dest_published`.
   - **Withdraw.** The rows move to `dest_excluded` first. Then B's ingress is built and PUT, and reconciled the same way. Only then do the rows move to `dest_withdrawn`.
   - **Other writers.** Every other writer of B's ingress takes the same lock and uses the same builder, so it keeps or drops the incoming rules according to the rows.
7. **Switch.** It runs per `active` route, holding the instance Cloudflare lock. A `waiting` route has no DNS and skips this step.
   1. **Access first.** For an owners route, the Access app is revalidated. If it is missing or cannot be repaired, the **route** is halted with the existing route halt (`internal/app/app_routes_job.go:368-388`), and the move rolls back (§11). The same applies when the worker's re-checks before `staged` and before `started` find it missing. A halted route is not served by any builder (`servesIngress`), so its rule leaves both A's and B's ingress on their next PUT. The move then PUTs both. This is fail-closed: a missing Access app is never served. A read can't stop someone else from deleting the app later. `docs/security.md` says so.
   2. **One move-aware DNS validator.** It is used for the forward switch, for reconciliation and for restore. It requires:
      - exactly one record for the hostname, with the frozen ID;
      - the route's marker;
      - type CNAME;
      - proxied;
      - content pointing at A's frozen tunnel or B's frozen tunnel.

      A sibling record or a foreign marker halts the move. Ownership is never inferred from content alone. The PATCH sends only `content` and never rewrites the comment.
   3. **Forward PATCH.** The row moves to `dns_switching`. The intent is recorded with direction forward. The CNAME is PATCHed to B's tunnel with a new `UpdateDNSRecord`, which keeps the record ID. On success the row moves to `dns_switched`.
8. **Unknown DNS outcomes.** An intent whose answer was lost is unknown. It is reconciled only after its not-before time, set to dispatch time plus 2 minutes. Until then, nothing issues the opposite PATCH, withdraws B or stops B.

   Once the not-before time has passed, the record is read by ID and run through the validator:
   - content at the intent's target means the PATCH applied;
   - content at the other tunnel means it did not;
   - anything else halts the move with B running.

   If the read itself fails, the outcome stays unknown and the move stays open with B running. Every unknown intent is reconciled before compensation takes any step.
9. **Commit.**
   - The ADR-0041 commit transaction runs from `routes_switched`. It also updates each route's `node_id`, `tunnel_id` and `tunnel_generation` to the row's to-values, as one tuple per route.
   - The update requires that:
     - the route's current values equal the row's from-values;
     - the current phase equals the frozen phase;
     - the row is `dns_switched` for an `active` route, or `pending` for a `waiting` route.
   - The rows move to `committed`, and every row count is asserted.
   - **The relaxed trigger** allows the three columns to change only as that exact tuple, and only when all of these hold:
     - the move is in `routes_switched`;
     - the move's source and destination equal the row's from and to nodes;
     - the row's route is `OLD.id` and its target is the route's target;
     - the row's state and frozen phase are those above;
     - `OLD` equals the from-values and `NEW` equals the to-values.

     Every other identity and write-once rule stays as it is.
10. **After the commit.**
    - **Source clean.** A's ingress is PUT and reconciled. The routes now name B, so A's builder no longer counts them. The rows move to `source_cleaned` and the move to `routes_source_cleaned`. Then come `source_parked` and `done`.
    - **Waiting routes.** In the transaction that advances the move to `done`, the move closes and `waiting` routes are scheduled for activation on B through the existing activation (`internal/app/app_routes_activate.go:12-62`), with its deduplication. The move runs no activation before `done`.
    - **Ingress during the switch.** A proxied CNAME is resolved at the Cloudflare edge, so the switch moves traffic without depending on client DNS caches. Between the repoint and the source clean, A's ingress still has the rules. For a stateless move, A still serves them until it is parked.
11. **Compensation before the commit** undoes the routes before ADR-0041's steps.
    1. Every unknown DNS intent is reconciled (§8).
    2. Every row that applied a forward PATCH (`dns_switched`, or `dns_switching` reconciled as applied) is moved to `dns_restoring`. The record is then PATCHed back to A's tunnel after the validator, and the row moves to `dns_restored`. Phase `compensating_routes_restored`.
    3. B's rules are withdrawn (§6). Phase `compensating_routes_withdrawn`.
    4. ADR-0041 compensation follows. It stops B, then starts and verifies A when A was stopped, and so on.

    **Availability during rollback:**
    - **Stateless:** A is running throughout, so traffic returns to a running A.
    - **Stateful:** A is stopped until step 4. The single-writer rule forbids starting A while B can still write, so the hostnames serve errors from the repoint back until A passes its health check. Writes made on B after the switch stay in B's volumes, which are never deleted after B's first start (ADR-0041). The rollback lists the hostnames and the window, and `docs/deployments.md` describes it.

    A failed restore, or an unknown outcome that cannot be settled, halts the move with B running and names the hostnames that point at B.
12. **Abandon** (`sm apps move --abandon`) does not apply to a routed move while any row is in `dns_switching`, `dns_switched`, `dns_restoring`, `dest_included`, `dest_published` or `dest_excluded`. The refusal names the rows. An operator resumes such a move. Abandon never leaves a record that points at B without a running B.
13. **Cloudflare client.**
    - `UpdateDNSRecord(ctx, zoneID, id, content)` sends a PATCH of `content` only.
    - `GetDNSRecord(ctx, zoneID, id)` reads one record.
    - `GetTunnelConfig` already exists (`internal/providers/cloudflare/tunnels.go:103`) and reconciles ingress PUTs.
    - `cffake` gains both calls and chaos hooks that:
      - fail a call;
      - apply the change but lose the response;
      - delay the change after the response or the cancellation.
14. **Surfaces.**
    - `sm apps moves` and `infra_list_app_moves` show each route's state.
    - The plan output lists the hostnames that will be repointed and the rollback window for a stateful move.
    - Audit events: `app_move.route_switched`, `app_move.route_restored` and `app_move.route_halted`.
15. **Docs.**
    - `docs/deployments.md` and `docs/cloudflare.md`: "Moving a target with routes", covering the order, the guarantees, the rollback window and what is refused.
    - `docs/security.md`: the boundary of the Access check.
    - `docs/manual-checks/app-move.md`: a routes section.
    - `docs/project-status.md`.

**No entra:**

- Moving a route whose operation is unfinished. Finish it, remove it or resume it first.
- Changing the hostname, access mode or port during a move.
- Tunnel setup, rotation or disable on A or B during a routed move.
- Verifying public reachability through Cloudflare after the switch.
- Moving between Cloudflare accounts, zones or instances.
- Draining connections on A before removing its rules.

## Criterios de aceptación

### Scenario: a public route follows the app
- **Given** a target on A with an `active` public route `shop.example.com`, and B with a committed tunnel
- **When** it moves to B
- **Then** B's ingress serves the rule before the CNAME is repointed, the CNAME keeps its record ID, marker and comment and points at B's tunnel, the route row names B, B's tunnel and its generation, and A's ingress has no rule for it after `routes_source_cleaned`

### Scenario: an owners route keeps its Access application, or stops being served
- **Given** an `active` owners route
- **When** it moves
- **Then** the Access app is the same object, revalidated before B's ingress is published and before the repoint
- **And** if the app is missing at either point, the route halts, neither A's nor B's ingress serves it, the move rolls back, and no record was repointed by that step (amended 2026-11-03 after the external review)

### Scenario: a waiting route moves without Cloudflare and activates on B
- **Given** a `waiting` route whose port the known-good deployment publishes
- **When** the target moves
- **Then** no DNS call is made for it before `done`, the route row names B after the commit, and an expose job for B is scheduled when the move reaches `done`

### Scenario: unfinished routes and missing capacity refuse the move
- **Given** a route in `provisioning`, a removal phase, `failed` or `conflict`, or with an open job; or a B without a committed tunnel; or a B whose live routes plus incoming reservations plus these routes exceed 98
- **When** the user requests the move
- **Then** it is refused naming the route or the reason, and no plan is created

### Scenario: an ordinary expose respects a reservation
- **Given** an open routed move into B that reserves the last free slots
- **When** another target exposes a route on B
- **Then** the expose is refused for capacity, and after the move is `rolled_back` the same expose is admitted

### Scenario: a partial switch is undone before B stops
- **Given** two `active` routes, where the second repoint fails definitively
- **When** compensation runs
- **Then** the first record is repointed back to A's tunnel, B's ingress no longer has either rule, only then is B stopped, and routes and `node_id` still name A

### Scenario: a PATCH that applied before its checkpoint is restored
- **Given** a forward PATCH that applied but whose response was lost, with the row still `dns_switching`
- **When** compensation starts
- **Then** nothing is withdrawn or stopped before the not-before time, then the record is read, found at B, restored to A, and only then is B withdrawn and stopped

### Scenario: a late forward request does not undo a restore
- **Given** a forward PATCH whose application the fake delays past its cancellation
- **When** compensation runs
- **Then** the reverse PATCH is not sent before the forward intent's not-before time, and the final record points at A

### Scenario: a lost answer during the forward switch is reconciled
- **Given** a PATCH whose response was lost
- **When** the job resumes after the not-before time
- **Then** the record is read by ID and checked by the validator. At B, the row becomes `dns_switched`. At A, the repoint is retried. With a sibling, a foreign marker or other content, the move halts with B running

### Scenario: the trigger accepts only the move's exact identities
- **Given** an open move with a `dns_switched` row
- **When** an update changes any other column together with the identity, writes other to-values, targets a route of another target, uses a row in another state or with another frozen phase, runs while the move is halted, compensating or before `routes_switched`, or edits the move-route row's identity columns
- **Then** the database refuses it

### Scenario: tunnel operations, exposes and unexposes wait for the move
- **Given** an open routed move, including a halted one
- **When** a tunnel setup, rotation or disable of A or B, or an expose or unexpose of the target, is requested, or such a job queued before the move is claimed
- **Then** each is refused with a message naming the move

### Scenario: another ingress writer keeps the incoming rules
- **Given** a move whose rows are `dest_published`
- **When** another target's route on B is exposed
- **Then** B's ingress contains the incoming rules and the new rule, and a later withdrawal by the move removes only the incoming ones

### Scenario: a post-commit halt only goes forward
- **Given** a move halted in `routes_source_cleaned` because A's ingress PUT failed
- **When** the operator resumes it
- **Then** it continues to `source_parked` and `done`, and no compensation step runs

### Scenario: stateful rollback window
- **Given** a stateful routed move whose second repoint fails
- **When** compensation runs
- **Then** the first record points at A again before B stops, B stops before A starts, the hostnames' error window and B's kept volumes are reported, and A serves after its health check

## Notas técnicas / riesgos

- The relaxed trigger and the `app_moves` rebuild are the riskiest database changes. Negative tests cover every column, every state and phase, other targets, and edits to move-route rows. The migration test runs on populated tables.
- A state-machine test matrix asserts DNS content, ingress membership on A and B, Access protection, running nodes and reservation ownership, not only phase names. It covers:
  - forward and reverse PATCH uncertainty;
  - PUT uncertainty;
  - lease takeover;
  - Access failure;
  - commit rollback;
  - halted moves;
  - interleaving with other exposes;
  - waiting activation;
  - abandon refusals.
- The feature is experimental and tested against `cffake` and fixture daemons only, until the manual checklist passes.

## Referencias

- ADR-0042 (this feature), ADR-0041 (app-move), ADR-0040 (routes).
- Critiques: `.claude/loop/app-move/codex-critique.md` items 2, 5, 11 and 12; `.claude/loop/app-move-routes/codex-critique.md`.
