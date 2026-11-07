---
codename: supermgmt
title: "Routes publish a node port"
type: task
status: draft
priority: P1
size: L
issue: null
prs: []
related_issues: []
depends_on: [retire-app-move]
supersedes: []
related_specs: [app-expose-tunnel, retire-deployments]
created: 2026-11-07
updated: 2026-11-07
---

# Routes publish a node port

## Contexto / problema

ADR-0043 amends ADR-0040: a route publishes a port of a node, not a service of a deployment (`hostname → node, port, access`). Today a route belongs to an app target and waits for its deployment:

- `app_routes.app_target_id` references `app_targets`, `service` is required, and the phase `waiting` holds a route until the deployed version publishes the port (`migrations/000009_app_routes.up.sql`).
- Admission calls `requireKnownGoodServes` (`app_routes.go:275`), the expose job `newestKnownGoodServes` (`app_routes_job_expose.go:22-27`), and a finished deployment activates waiting routes (`deploy_handler.go:342`).
- The actions `app_route.expose` and `app_route.unexpose` are keyed on `ResourceAppTarget`; authorisation goes through `app_target.read` (`app_routes.go:57-166`).
- Surfaces take `<app> <environment> --service`: `sm apps expose|unexpose|routes` (`cli/apps_routes.go:26,69,113`), `wire/app_routes.go`, MCP `infra_expose_app`, `infra_unexpose_app`, `infra_list_app_routes`, TUI `routes.go`.

## Scope

**Entra:**
- Model: a route is `node, hostname, port, access`. Migration 000013 rebuilds the table as `node_routes` without `app_target_id` and `service`, keeping ids, phases, Cloudflare object ids and errors; a `waiting` route (it created nothing in Cloudflare) becomes `removed` with a note that it waited for a deployment.
- Lifecycle: expose runs ingress, Access (owners), then DNS, as ADR-0040 fixes, and the route is `active` when they exist. No deployment is consulted. Unexpose and conflict handling unchanged.
- Admission: the node is managed, has a connector (`transport: cloudflare`) and a committed tunnel; the port is 1-65535 and not already routed on that node; the hostname is in the zone and free. Exposing a port nothing listens on is allowed; `sm nodes routes` shows whether the node answers on it at read time (best effort, no history).
- Policy: actions `node_route.expose`, `node_route.unexpose`, `node_route.read` on `ResourceNode`; `app_route.*` join the retired-action list (retire-app-move).
- Surfaces: `sm nodes expose <node> --hostname <fqdn> --port <n> [--access public|owners]`, `sm nodes unexpose <node> --hostname <fqdn>`, `sm nodes routes [<node>]`; API, client and wire under the node; MCP `infra_expose_port`, `infra_unexpose_port`, `infra_list_routes`; the TUI routes view lists by node.
- Docs: ADR-0040 "Amended by ADR-0043"; `docs/specs/app-expose-tunnel.md` and `docs/manual-checks/app-expose-tunnel.md` rewritten as node routes; guides and generated docs updated.

**No entra:**
- Removing apps, app targets or deployments (retire-deployments), beyond cutting the route's dependency on them.
- Discovering which container publishes a port.

## Criterios de aceptación

### Scenario: a node port is published without a deployment
- **Given** a node with a committed tunnel and no app or deployment
- **When** the operator runs `sm nodes expose vps1 --hostname web.example.com --port 8080` and approves the plan
- **Then** the ingress gains `web.example.com → http://127.0.0.1:8080` before the catch-all, then the DNS record is created, and the route is `active`

### Scenario: owners-only routes get Access before DNS
- **Given** the same node
- **When** the operator exposes with `--access owners`
- **Then** the Access application with the owners' Allow policy exists before the DNS record, as in ADR-0040

### Scenario: admission refuses what cannot work
- **Given** a node without a connector, a port already routed on the node, or a hostname outside the zone or already live
- **When** the operator exposes it
- **Then** the plan is refused with the reason; for a node without a connector the message proposes `sm nodes setup <node> --tunnel`

### Scenario: unexpose removes in reverse order
- **Given** an active route
- **When** the operator unexposes it
- **Then** the objects are removed in the order ADR-0040 fixes, DNS record first (phases `dns_removed`, `ingress_removed`), and the row stays `removed` as the record

### Scenario: existing routes survive the migration
- **Given** a database at 000012 with active, halted, removed and waiting routes
- **When** migration 000013 runs
- **Then** the active, halted and removed rows keep their ids, phases and Cloudflare object ids under `node_routes`; the waiting row is `removed` with its note; tunnel setup still writes the same ingress for the node

### Scenario: an old policy file still loads
- **Given** a policy file granting `app_route.expose`
- **When** the daemon starts
- **Then** it starts with a warning that the action is retired and points to `node_route.expose`

### Scenario: MCP lists and exposes by node
- **Given** an MCP client with `node_route.read`
- **When** it calls `infra_list_routes`
- **Then** it receives node, hostname, port, access and phase per route; `infra_expose_port` creates a plan under the same approval as the CLI

## Notas técnicas

- `desiredIngress` (`app_routes_job_ingress.go:35`) stays shared with tunnel setup (`tunnel_steps.go:105`); its message citing `sm apps unexpose` changes.
- Keep a read path for old plans and jobs whose resource is an app target.
