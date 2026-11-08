---
codename: supermgmt
title: "MCP adds and sets up nodes, a person checks the host key"
type: task
status: draft
priority: P1
size: M
issue: null
prs: []
related_issues: []
depends_on: [mcp-tool-coverage]
supersedes: []
related_specs: []
created: 2026-11-08
updated: 2026-11-08
---

# MCP adds and sets up nodes, a person checks the host key

## Contexto / problema

Part of #63, with the decision of 2026-11-08: adding and setting up nodes are in, secrets are out, and root-equivalent choices stay with a person.

- `node.add` and `node.update` are direct actions with no MCP tool. `sm nodes add` scans the host key, a person confirms the fingerprint, then the node is stored (`internal/cli/nodes.go:275-283`).
- `node.setup` is plannable, and through `infra_plan_action` a model supplies any parameter, including `docker_access` (root-equivalent, `internal/policy/catalog.go:87`) and service `grants` that become sudoers rules.
- `mcp_coverage.json` lists these as pending.

## Scope

**Entra:**
- `infra_add_node`: scans the host key of an SSH endpoint and requests `node.add` pinned to that key. An MCP client's request always waits for a person, and the plan the person approves shows the host, user and SHA-256 fingerprint, so the person is the one trusting the key. The model cannot supply a key or a fingerprint.
- `infra_setup_node`: plans `node.setup` with only safe parameters (the node, and `tunnel`). It takes no `docker_access`, `grants`, `proxmox` or sudoers parameters.
- MCP identities cannot set those parameters on `node.setup` by any path: `Plans.Create` refuses them for an `mcp` actor, before storing a plan.
- `node.add` and `node.setup` remain outside `builtin-mcp-operate`: they need an explicit `type:mcp` rule, and the tools say so.
- Coverage guard: pending entries become tools; `nodes repin` and tunnel enrollment confirmation are exclusions, with the reason (a person re-trusts a host key; the connector token is a credential).
- Docs: `docs/mcp.md`, spec tool list.

**No entra:**
- Repin by MCP. Enrollment without inbound ports by MCP (the connector token is a credential route). Secrets.

## Criterios de aceptación

### Scenario: adding a node waits for a person who sees the key
- **Given** writes on and a rule granting `node.add` to `type:mcp`
- **When** an MCP client calls `infra_add_node` for a reachable host
- **Then** the result is `approval_required`, no node exists yet, and the plan shown to the approver has the host, the user and the host key's SHA-256 fingerprint

### Scenario: the model cannot choose the key
- **Given** the same client
- **When** it passes a host key or fingerprint in the arguments
- **Then** the tool has no such argument, and the pinned key is the one the daemon scanned

### Scenario: a changed key after approval does not connect
- **Given** an approved add whose host now presents another key
- **When** the node is first dialled
- **Then** the connection fails on the host key mismatch, as for a node added by a person

### Scenario: setup cannot grant root by MCP
- **Given** a rule granting `node.setup` to `type:mcp`
- **When** an MCP client plans `node.setup` with `docker_access`, `grants` or `proxmox`, through `infra_plan_action` or the raw API
- **Then** it is refused before a plan is stored, and a person planning the same parameters is unaffected

### Scenario: safe setup waits for a person
- **Given** the same rule
- **When** the client calls `infra_setup_node` for a node, with or without `tunnel`
- **Then** the job is `approval_required`

### Scenario: not granted by default
- **Given** the default policy and writes on
- **When** an MCP client calls `infra_add_node` or `infra_setup_node`
- **Then** the result is denied, naming the policy reason

### Scenario: the guard knows the decision
- **Given** the coverage test
- **Then** `nodes add` and `nodes setup` map to tools, `nodes repin` and enrollment confirmation are excluded with reasons, and no entry stays pending

## Notas técnicas

- Direct actions become a `control_plane.apply` job when approval is required (`internal/app/direct.go:22-24`). Check the plan document carries the fingerprint for the approval views (`sm approvals`, TUI).
- A credential reference for the node comes from the instance default; the tool takes no secret.
