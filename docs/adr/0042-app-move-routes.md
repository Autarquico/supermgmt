# ADR-0042: Moving an app target's routes with it

- Status: Proposed
- Spec: spec `docs/specs/app-move-routes.md`; ADR-0040, ADR-0041

## Context

ADR-0041 moves an app target between nodes but refuses targets with routes. A route's Cloudflare identity (node, tunnel, generation) is frozen by a trigger, and its CNAME points at the source tunnel. Unexposing and exposing again drops the hostname and recreates the Access app.

## Decision

### Routes are switched inside the move, per route, with a record of each

- A move accepts routes that are `active` or `waiting` with no open job; anything unfinished refuses it.
- `app_move_routes` holds each route's from- and to-identity and its switch state. The intended DNS content is persisted before each repoint, and a lost answer is reconciled by reading the record by ID.

### Serve first, repoint, commit, then clean

- After the destination is healthy, its ingress gains the incoming rules: the ingress builder counts them for the destination node.
- Each CNAME is repointed in place (a new `UpdateDNSRecord`) after the expose ownership check and, for owners routes, after revalidating the Access app. The Access app is kept.
- The commit writes the routes' new identity in the same fenced transaction as the target's node. The identity trigger allows exactly the move's recorded from→to change and nothing else.
- Only then does the source ingress lose the rules, so cached clients reach the source until it is parked.

### Undo routes before stopping the destination

- Compensation repoints every switched record back to the source tunnel and withdraws the destination rules before the destination is stopped, so no record points at a stopped node. A failed restore halts the move with the destination still running.

## Consequences

- A stateful move with routes has the same downtime as without them; the hostname never leaves DNS.
- A record edited by someone else during a move halts it; nothing foreign is overwritten.
- The relaxed trigger widens what the database accepts, but only to values the move recorded beforehand.
