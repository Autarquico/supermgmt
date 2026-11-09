---
codename: supermgmt
title: App panels: see what runs on each node, as apps
type: feature
status: draft
priority: P1
size: L
issue:
prs: []
related_issues: []
depends_on: []
supersedes: []
related_specs: [retire-deployments, mcp-tool-coverage, assistant-tui]
created: 2026-11-09
updated: 2026-11-09
---

# App panels: see what runs on each node, as apps

## Contexto / problema

ADR-0043 makes SuperMgmt the place to see and maintain what runs on every node, and names two panels and their MCP equivalents. Today discovery stores containers with a Compose project name in their metadata (`internal/runtimes/docker/discover.go:121`) and nothing groups them. Volumes and the restart count are not read (`internal/runtimes/docker/container.go:40-62`), there is no CPU or memory read, logs are the last N lines only (`internal/api/wire/query.go:64-66`), and service status comes from the refresher rather than from the node at the moment of asking (`internal/app/refresher.go:149-151`).

This is the first of three slices: reads, panels and their MCP tools. External checks (healthchecks.io) and interactive exec and database connection are separate specs.

## Scope

- An app is a Compose project on a node. Its components are the project's containers. It is a projection of discovery with no table and no lifecycle of its own.
- Containers outside a project and systemd units appear on the node as other services, ungrouped.
- Overview panel: machines, the apps on each, and per app its state, restarts, current resource use and recent error count.
- App panel in the spirit of lazydocker: components, logs (recent, follow, search), stats, configuration, volumes and published ports, with start, stop and restart through the existing governed actions.
- MCP read tools for all of the above; existing `infra_*_service` tools cover the actions.
- Add the Compose project fixture needed to test this.

### Out of scope

- Time series or any stored statistic. A trend exists only in memory while a panel is open.
- healthchecks.io and other external checks; exec; database connection.
- Non-Compose workloads as apps.
- Showing a Compose file's secrets: configuration is what the runtime reports, redacted.

## Decisions

- **Reads are live.** App detail, stats and restart counts come from the node when asked, through named, allowlisted templates. A panel states the time of its data and, when the node cannot be reached, shows the last discovery marked as stale.
- **No new `app.*` action.** `app.read` and `app.write` are retired names (`internal/policy/retired.go:27-30`). Reading an app requires `service.read`, its logs `service.logs`. Actions stay per service.
- **Docker access is granted by a person.** Reads need the session user to reach Docker (`internal/app/probe.go:101`) and MCP cannot plan a setup that grants it (`docs/mcp.md:66`). The panel says so and names the command; it never enables it on its own.
- **Log output keeps the existing boundaries:** `Inventory.redacted` (`internal/app/inventory.go:818-828`), the MCP cap (`internal/mcp/api.go:79`) and the untrusted-content marking (`docs/mcp.md:292`) apply to follow and search too. Search runs on a bounded window of lines and says what window it covered.
- **ADR-0043 is amended:** "resource use over time" becomes the current sample, with an in-memory trend while a panel is open; interactive exec and database connection are for people only, stated in the MCP coverage map.

## Scenarios

### Scenario 1: A Compose project is an app
- **Given** a node running a Compose project `shop` with containers `web` and `db`, plus a plain container and a systemd unit
- **When** the user opens the overview
- **Then** the node lists the app `shop` with two components, and the plain container and the unit as other services

### Scenario 2: Health of an app at a glance
- **Given** `shop` has one container restarted 3 times and another unhealthy
- **When** the overview loads
- **Then** `shop` shows as degraded, with its restart count and current CPU and memory, and the time of the reading

### Scenario 3: Inside an app
- **Given** the app `shop`
- **When** the user opens its panel
- **Then** it shows each component's state and image, the volumes and published ports, and the configuration reported by the runtime with secret values redacted

### Scenario 4: Follow and search logs
- **Given** the panel of `shop`, on component `web`
- **When** the user follows the logs, then searches for `timeout`
- **Then** new lines arrive live, matches are highlighted, the search states the window of lines it covered, and following stops when the user leaves

### Scenario 5: Governed restart from the panel
- **Given** a user whose policy requires approval to restart in production
- **When** they restart component `web` from the panel
- **Then** the usual plan and approval apply, the action is audited, and no action is available for a whole app

### Scenario 6: Node unreachable
- **Given** a node that stops answering
- **When** the user opens its apps
- **Then** the last discovery is shown marked stale with its time, and live reads and actions say the node cannot be reached

### Scenario 7: Docker not accessible
- **Given** a node whose session user cannot reach Docker
- **When** the user opens the overview
- **Then** the node shows that apps cannot be read and names the command a person runs to allow it, and nothing is changed on the node

### Scenario 8: The same through MCP
- **Given** an MCP client with the default read grant
- **When** it asks for the apps of a node, an app's detail, stats and a log search
- **Then** it gets the same data as the panels, within the MCP log cap, with node content marked untrusted, and the coverage guard (`test/integration/mcp_coverage_test.go:21`) passes

### Scenario 9: Nothing is stored
- **Given** panels and MCP clients reading stats repeatedly
- **When** the database is inspected
- **Then** no statistic or sample was written

### Scenario 10: Log secrets stay redacted
- **Given** a log line containing a value that matches the redaction patterns
- **When** it is shown by follow, search or an MCP tool
- **Then** the value is redacted in each

## Verification limits

Tested against fake nodes, the fixture node with a real Compose project and the TUI harness. A real host with real workloads is a manual check.
