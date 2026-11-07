# ADR-0042: Moving an app target's routes with it

- Status: Superseded by ADR-0043
- Spec: spec `docs/specs/archive/2026-11-07-app-move-routes.md`; ADR-0040, ADR-0041

## Context

ADR-0041 moves an app target between nodes but refuses targets with routes. A route's Cloudflare identity (node, tunnel, generation) is frozen by a trigger, and its CNAME points at the source tunnel. Unexposing and exposing again drops the hostname and recreates the Access app.

## Decision

### A routed move reserves what it will touch

- Only `active` or `waiting` routes with no open job can move. The move reserves B's route capacity in the same calculation ordinary exposes use, and freezes both tunnel identities.
- While it is open, exposes, unexposes and tunnel setup/rotation/disable on either node are refused at request and claim time, so the frozen identities cannot drift and recovery never depends on forward revalidation.

### Every Cloudflare change is an intent before it is a call

- `app_move_routes` holds each route's from/to identity and a state for every ingress inclusion, PUT, repoint and restore. Membership is persisted before each ingress PUT; PUTs are reconciled by reading the tunnel configuration.
- Each PATCH is a ledger intent with direction and a not-before time. A lost answer is settled only after that time, by reading the record by ID through one validator (exact ID, no siblings, marker, CNAME, proxied, A or B content). Nothing opposite is sent, withdrawn or stopped while an outcome is unknown.

### Serve, repoint, commit, clean — and never compensate after commit

- After B is healthy: B's ingress gains the rules; each owners route's Access app is revalidated; each CNAME is repointed in place, keeping its ID and comment.
- A missing Access app halts the route itself, which takes it out of every ingress: fail closed.
- The commit writes the routes' new identity with the target's node. The trigger allows exactly the recorded from→to tuple, for that move, in `routes_switched`, and nothing else.
- Afterwards A's ingress loses the rules; waiting routes are scheduled for activation when the move is `done`. A post-commit move only goes forward.

### Undo DNS before stopping B

- Compensation settles every unknown intent, repoints switched records back to A, withdraws B's rules, and only then runs ADR-0041's compensation. A stateful rollback has an error window from the repoint back until A is healthy again, because A may not start while B can write.

## Consequences

- The hostname never leaves DNS during a move.
- Tunnel maintenance on A or B waits for routed moves to finish.
- A record or Access app edited by someone else during a move halts it; nothing foreign is overwritten, and an unprotected owners route is not served.
- The relaxed trigger widens what the database accepts only to values the move recorded beforehand.
