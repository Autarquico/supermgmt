---
codename: supermgmt
title: Expose an app through its node's Cloudflare Tunnel
type: epic
status: active
priority: P1
size: XL
issue: 50
prs: []
related_issues: [50]
depends_on: []
supersedes: []
related_specs:
  - cloudflare-tunnel-transport
  - node-enroll-tunnel
  - m4-apps-deployments
created: 2026-10-31
updated: 2026-10-31
---

# Expose an app through its node's Cloudflare Tunnel

## Contexto / problema

A node with a Cloudflare connector (`transport: cloudflare`, ADR-0037 and ADR-0039) routes only SSH:
- the tunnel ingress is exactly `SSHIngress(hostname)`, one SSH rule plus the 404 catch-all (`internal/providers/cloudflare/types.go:40`);
- `ensureIngress` overwrites any other content on each setup or enable (`internal/app/tunnel_steps.go:95-111`);
- teardown replaces the whole list with `ClosedIngress()` (`internal/app/tunnel_teardown.go:227-248`).

A deployed app publishes host ports from its frozen Compose model (`internal/deployments/compose/types.go:83,116`), but nothing makes them reachable through the tunnel. To publish an app today the user has to edit the tunnel, Access and DNS by hand in the Cloudflare dashboard, and the next `sm nodes setup --tunnel` wipes those edits.

Maintainer goal (2026-10-29): apps are exposed through the tunnel without configuring anything by hand.

## Scope

**Entra:**

1. **`sm apps expose <app> <env> --hostname <fqdn> --service <svc> --port <n> [--access public|owners]`**
   - **Access.** An omitted `--access` is normalised to `public` before policy evaluation, in the CLI, the API and the MCP plan alike. The command prints that a public route is reachable from the internet with no authentication.
   - **Policy.** The request is a new policy action `app_route.expose` on the app target. Its baseline risk is medium. Its param `access` raises the risk by value: public is high, owners stays medium (`internal/policy/catalog.go:131-135`).
   - **Approval.** It follows the `applyOrSubmit` contract (`internal/app/apps.go:822-831`): when policy needs no approval, the row and its job are written in the request transaction; otherwise a plan is submitted, and its approved apply does the same.
   - **The hostname is canonicalised before policy and storage**: lowercased, without a trailing dot. It must sit under the configured zone on a label boundary: `a.example.com` is accepted, `evil-example.com` is not.
   - **It refuses before touching Cloudflare** when:
     - Cloudflare is not configured;
     - the target's node has no connector: its `Endpoint.Transport` is not `cloudflare` (`internal/domain/transport.go:18`), or a tunnel disable is in progress. The message suggests `sm nodes setup <node> --tunnel`;
     - the hostname is invalid, is outside the zone, or is in the SSH namespace. Any first label starting `ssh-` is reserved, because node SSH hostnames are `ssh-<node>.<zone>` (`internal/providers/cloudflare/names.go:39`) and future nodes need theirs;
     - another live route of any app already uses the hostname;
     - the node already has 98 live routes. With the SSH rule and the catch-all, that is the 100-rule limit (`internal/providers/cloudflare/tunnels.go:123`). The count and the insert run in one transaction;
     - the target's newest known-good deployment (`internal/database/repo_deployments.go:246`) has no `HostPort` with that service and port, over TCP, bound to `127.0.0.1` or `0.0.0.0`. IPv6-only bindings are refused, because `cloudflared` dials `127.0.0.1`. A target with no known-good deployment yet is accepted, and its route stays `waiting` (item 4).
2. **The route record.**
   - A new table `app_routes`, added by migration `000009`, holds:
     - the route ID, the app target, the node, the canonical hostname, the service, the port and the access mode. The hostname is unique among routes that are not `removed`;
     - **the Cloudflare identity frozen at admission**: account ID, zone, instance ID, tunnel ID and the generation of the node's committed tunnel operation (`migrations/000007_cloudflare_tunnels.up.sql:7-47`). Before every mutation the job checks the identity against the current config and the node's newest committed enable. On a mismatch it halts with "the node's tunnel changed; unexpose and expose again";
     - the phase, with the halted/conflict semantics of `tunnel_operations` (`internal/database/repo_tunnel.go:180,205,226`):
       - expose: `waiting` → `provisioning` → `ingress_ready` → `access_ready` → `active`;
       - removal: `removing` → `dns_removed` → `ingress_removed` → `removed`;
     - `phase_started_at`, preserved across halt and resume;
     - the Cloudflare object IDs (DNS record and Access app), written once by a trigger, as in `migrations/000007_cloudflare_tunnels.up.sql:53`.
   - `waiting` means that nothing has happened in Cloudflare.
   - Admission and activation leave the route `waiting` and enqueue its job. Only the route's own job, holding the ingress lock and after its DNS preflight has passed, persists `provisioning`, immediately before the first PUT. From then on the route counts in the desired ingress, so a crash between the PUT and the advance leaves a rule that every builder keeps and that removal cleans up, and no other writer ever publishes a rule whose DNS was not checked (amended 2026-10-31 after the internal security review).
   - The node is fixed by its target: app targets cannot move between nodes today (`internal/api/wire/m4.go:173-177`).
3. **The tunnel ingress becomes a managed list.**
   - One function builds it from the node's state: the SSH rule, then one `http://127.0.0.1:<port>` rule per route of the node in `provisioning`, `ingress_ready`, `access_ready`, `active`, `removing` or `dns_removed`, ordered by hostname, then the 404 catch-all. A route halted while exposing does not serve, and neither does its later removal unless it had served before the halt.
   - `ensureIngress` in setup and enable compares against it instead of `SSHIngress` (`internal/app/tunnel_steps.go:95-111`), so a `sm nodes setup --tunnel` rerun keeps the app rules. Expose and unexpose use the same function.
   - **One ingress lock.** Every path that writes a node tunnel's ingress takes the instance Cloudflare lock (`internal/app/locks.go:50`) and recomputes the list after acquiring it. Those paths are setup/enable, rotation, disable, expose and unexpose. Disable takes it too; today it holds only its node lock (`internal/app/locks.go:34-35`).
   - Enrollment teardown writes only the ingress of an enrollment's own tunnel. That tunnel has no routes, because routes need a committed node. Its lock release (`internal/app/tunnel_teardown.go:244`) is unchanged.
   - Cloudflare replaces the whole list on each write (`internal/providers/cloudflare/tunnels.go:86`).
4. **Order of activation.**
   - Expose runs as a resumable job. First a DNS preflight, then ingress rule → Access app (only `owners`) → proxied CNAME to `<tunnel>.cfargotunnel.com` last. That is the ADR-0037 order (`internal/app/tunnel_steps.go:38-65`).
   - An `owners` route has no DNS until its Access app exists, the same guard as `ensureDNS` (`tunnel_steps.go:162-164`).
   - **DNS ownership is checked on every run, including resumes and recorded IDs.** Every record for the hostname must carry this route's marker, be a proxied CNAME and point at the frozen tunnel. A record that does not (a foreign one, or a sibling that appeared between the preflight and the create) halts the route. A foreign record is never adopted, replaced or deleted. `ensureNamed` (`internal/app/tunnel_ensure.go:88-92`) returns a recorded ID without this check, so routes do not reuse it as is.
   - **Adoption.** A route-specific fenced helper, extracted next to `ensureNamed` (`tunnel_ensure.go:32-35,80`), adopts only objects with the route's name or marker that were created after `phase_started_at` minus five minutes.
   - **Only after health.** A route activates only while its target's newest known-good deployment publishes the port. A route accepted before any known-good deployment stays `waiting`. When a deployment of that target settles as succeeded (`internal/app/deploy_health.go:200-213`), the same transaction enqueues one expose job per `waiting` route of the target whose port the new version publishes; the job re-checks the known-good port under the target lock before its first mutation. A route that already has an open job gets no second one. Today nothing runs after success (`internal/app/deploy_handler.go:343-346`).
   - The expose job takes the app target's lock as well as the ingress lock, so activation is serialised with that target's deployments (`internal/app/locks.go:161-175`).
   - **Objects and markers.**
     - Access app: name `supermgmt <instance> route <route-id>`, domain the hostname, policies `[OwnersPolicyID]` only. The service-token policy guards SSH for the daemon and does not belong on an app.
     - DNS comment: `supermgmt:<instance>:route:<route-id>`.
5. **`sm apps unexpose <app> <env> --hostname <fqdn>`.**
   - Approval-gated as `app_route.unexpose` (risk medium).
   - Persists `removing`, then runs in this order: DNS → ingress rule removed → Access app.
   - The Access app is removed last. Cached DNS can still reach the hostname after its record is gone, and the rule must stop serving before the protection goes. This is the teardown order of `internal/app/tunnel_teardown.go:181-195,250`.
   - Before removing anything it reconciles objects created but never recorded, the way disable does (`internal/app/tunnel_disable.go:193-208`).
   - The route ends `removed`, and its hostname can be reused.
   - A `waiting` route is removed with no Cloudflare call. A `provisioning` route goes through the full removal.
6. **`sm apps routes [<app> [<env>]]`** lists routes with hostname, target, service:port, access and phase. `sm apps get` shows the target's routes.
7. **Guards on other paths.**
   - **Deployment.** The deploy handler checks under the target's execution lock before forward steps start (`internal/app/deploy_handler.go:143-168`). It fails a deployment whose frozen model, or whose frozen automatic-rollback model, no longer publishes the service and port of a route that is not `removed`. The deployment ends `failed` before touching the node, and the message names the route and `sm apps unexpose`.
   - **Rollback.** An explicit rollback (`internal/app/deployments_rollback.go`) is refused at request time on the same condition, and checked again at execution.
   - **Early warning.** Finalization (`internal/app/finalize.go:309`) also refuses the plan early.
   - **Tunnel disable.** `sm nodes tunnel disable` is refused while the node has routes that are not `removed`. The check is repeated after the ingress lock is acquired, and the message lists the routes. Disable keeps replacing the whole ingress with `ClosedIngress()`.
8. **Surfaces.**
   - The API gains `GET/POST /app-targets/{id}/routes` and `DELETE /app-targets/{id}/routes/{hostname}` (following `PathAppTarget`, `internal/api/wire/paths.go:93`) and `GET /app-routes`, with wire types and OpenAPI.
   - Client, CLI and TUI palette entries (`expose`, `unexpose`).
   - Audit events `app_route.exposed`, `app_route.removed` and `app_route.halted`.
   - **MCP.**
     - Read tool `infra_list_app_routes`, filtered by app and environment. Apps and environments are given by name or id.
     - Write tools `infra_expose_app` and `infra_unexpose_app`, following `infra_create_deployment` (`internal/mcp/tools_write.go:40`). They exist only when write tools are enabled, and they always go through policy and approval. A `public` route is high risk, and an omitted access is normalised to `public` before evaluation.
     - Both actions declare `hostname`, `service`, `port` and `access` in the catalog (`internal/policy/catalog.go`), so `infra_plan_action` (`internal/mcp/tools_plan.go:44`) can plan them too.
     - The tool goldens (`internal/mcp/testdata/tools.{read,all}.golden.json`, `testdata/wire/tools_list.golden.json`) and the MCP route matrix (`test/integration/testdata/mcp_route_matrix.json`) are updated.
9. **Docs.**
   - `docs/cloudflare.md` gains an "Expose an app" section.
   - `docs/cli.md`.
   - `docs/security.md`: a public route is unauthenticated, and the operator owns the app's own auth.
   - `docs/project-status.md`.
   - Manual checklist `docs/manual-checks/app-expose-tunnel.md`.

**No entra:**

- Moving a route between nodes, which is `app-move`, feature 4.
- Changing a route in place (access mode, port). That is unexpose followed by expose.
- Hostnames outside the configured zone, multiple zones and wildcard hostnames.
- Non-HTTP origins (`tcp://`, `ssh://` for apps), HTTPS origins and `originRequest` options.
- Health-driven withdrawal of an active route when a later deployment fails. The previous known-good version keeps serving through rollback (ADR-0029).
- A per-app Allow policy or e-mail lists other than `owner_emails`.
- Drift reconciliation of route objects. `sm nodes tunnel status` keeps checking only the SSH objects (`internal/app/tunnel_reconcile.go:122-147`).

## Criterios de aceptación

### Scenario: an app on a tunnel node is exposed with one command
- **Given** a node with `transport: cloudflare` and an app target on it whose known-good deployment publishes `web` on `127.0.0.1:8080`
- **When** the user runs `sm apps expose shop prod --hostname shop.example.com --service web --port 8080` and approves the plan
- **Then** the tunnel ingress is `[ssh rule, {shop.example.com → http://127.0.0.1:8080}, 404]`, a proxied CNAME `shop.example.com → <tunnel>.cfargotunnel.com` exists with the route marker, no Access app is created, and the route is `active`

### Scenario: an owners route is guarded before it has DNS
- **Given** the same target
- **When** the user exposes it with `--access owners`
- **Then** the Access app for the hostname exists with only the Owners Allow policy before the CNAME is created, and an injected failure after the ingress step leaves no DNS record

### Scenario: a route waits for a healthy deployment
- **Given** a target with no known-good deployment
- **When** the user exposes it
- **Then** the route is `waiting` and Cloudflare is not called
- **When** a deployment of that target settles as succeeded and publishes the port
- **Then** the route becomes `active` with no further user action
- **And** a deployment that fails its health check leaves the route `waiting`

### Scenario: refusals happen before Cloudflare is touched
- **Given** a target on a node without a connector, or a hostname outside the zone (including a suffix spoof such as `evil-example.com`), in the `ssh-` namespace, already routed under another letter case, or a port the deployment publishes only on IPv6 or on another interface, or a node already at 98 routes
- **When** the user runs `sm apps expose`
- **Then** it fails with a message naming the cause, no Cloudflare call is made, and no route row is written

### Scenario: a foreign DNS record is never taken over
- **Given** the zone already has a record for the hostname without the route marker
- **When** the expose job runs its DNS preflight, or such a record appears between the preflight and the create
- **Then** the route halts naming the record, no ingress rule or DNS record of the route remains serving, and the foreign record is untouched

### Scenario: node setup keeps the app rules
- **Given** an active route on a tunnel node
- **When** the user reruns `sm nodes setup <node> --tunnel`
- **Then** the ingress still contains the route's rule

### Scenario: concurrent ingress writers do not lose rules
- **Given** two routes on the same node exposed by two jobs at once, or an expose racing `sm nodes setup --tunnel` or a token rotation
- **When** both jobs run
- **Then** the final ingress contains the SSH rule and both routes' rules

### Scenario: the job resumes after the daemon dies
- **Given** an expose or unexpose job interrupted after each Cloudflare mutation in turn
- **When** the daemon restarts
- **Then** the job finishes with exactly one ingress rule, at most one Access app and one DNS record for the route (none after unexpose), adopted by marker and never duplicated

### Scenario: unexpose removes in reverse order
- **Given** an active `owners` route
- **When** the user runs `sm apps unexpose` and approves
- **Then** the DNS record is deleted first, then the ingress rule, and the Access app last, so the hostname is never served without its Access app; the SSH rule and other routes stay; the route is `removed`; and the hostname can be exposed again

### Scenario: a deployment cannot silently break a route
- **Given** an active route on port 8080
- **When** a deployment or rollback whose model no longer publishes 8080 is requested, including one finalized before the route was admitted and executed after
- **Then** it is refused, or fails before touching the node, and names the route

### Scenario: a crash after the ingress write is cleaned up by unexpose
- **Given** an expose job that died after its ingress PUT and before recording `ingress_ready`
- **When** another writer rebuilds the ingress, and the user later unexposes the route
- **Then** the rule survives the rebuild, unexpose removes it, and the hostname is released only after no rule, Access app or DNS record of the route remains

### Scenario: a changed tunnel halts the route
- **Given** a route whose node's tunnel was recreated, or whose zone or account changed in the config
- **When** its job runs
- **Then** it halts before any mutation and tells the user to unexpose and expose again

### Scenario: tunnel disable does not orphan routes
- **Given** a node with an active route, or an expose admitted while a disable waits for the lock
- **When** the user runs `sm nodes tunnel disable <node>`
- **Then** it is refused and lists the route, and no route ever points at a closed tunnel

### Scenario: public exposure is approval-gated and visible
- **Given** a policy that requires approval for high-risk actions
- **When** a public expose is planned
- **Then** the plan has risk high, waits for approval, and the CLI states that the route is unauthenticated; the audit log records `app_route.exposed` with hostname and access

### Scenario: an MCP client exposes an app and a public route waits for approval
- **Given** an MCP client with write tools enabled and a policy that requires approval for high-risk actions
- **When** it calls `infra_expose_app` with no access, and then `infra_list_app_routes`
- **Then** the access is `public`, the plan has risk high and waits for approval, no route row or Cloudflare object exists until it is approved, and once approved the route is listed with its phase

## Notas técnicas / riesgos

- **Files:**
  - Cloudflare: `internal/providers/cloudflare/types.go` (the ingress builder), `names.go` (route names and markers).
  - Tunnel: `internal/app/tunnel_steps.go` (`ensureIngress`), `tunnel_disable.go` (the refusal).
  - New `internal/app/app_routes*.go` for the service, job, phases and resume.
  - Deploy: `deploy_health.go`/`deploy_handler.go` for the schedule on success, and the deployment planner for the port guard.
  - Policy: `internal/policy/catalog.go`, plus `internal/app/handlers.go` and `locks.go`.
  - Migration `000009_app_routes`, `internal/database/repo_app_routes.go`.
  - API `routes_m4.go`, `wire/m4.go`, `api/openapi.yaml`, client, CLI `apps.go`, TUI palette.
  - `pendingSchema = 9` (`test/e2e/milestones_test.go:42`, `test/fixtures/migrations/gen/provenance.go:45`) and the doctor goldens.
- **Testing:**
  - `cffake` with fault injection after each mutation (`chaosAPI`).
  - Compose fixtures for `HostPort`.
  - The deploy handler with the fake executor to cover activation on success.
  - Fuzz the hostname/zone check and the route-row scan.
- **Risks:**
  - A public route exposes the app as is. SuperMgmt does not add authentication, and the CLI and docs say so.
  - The whole-list ingress PUT makes any writer outside SuperMgmt (the dashboard) lose its edits on the next write. This is documented, and it is the ADR-0037 behaviour.
  - `cloudflared` reaches the origin on `127.0.0.1`. A port published only on another interface is refused instead of rewritten.

## Tasks (no autoritativo — el board manda)

- [ ] ADR-0040
- [ ] Migration and repository for `app_routes`
- [ ] Managed ingress builder; `ensureIngress` and teardown use it
- [ ] Expose/unexpose jobs with resume, adoption and the lock
- [ ] Activation on deployment success; the port guard on deploy and rollback plans; the disable refusal
- [ ] Policy actions, API, client, CLI, TUI
- [ ] Tests per scenario, fuzz, docs, manual checklist

## Referencias

- ADR-0037 (Cloudflare Tunnel transport), ADR-0039 (node enroll through the tunnel), ADR-0029 (deployment engine).
- Cloudflare: remotely managed tunnel ingress, Access self-hosted applications, proxied CNAME to `cfargotunnel.com`.
