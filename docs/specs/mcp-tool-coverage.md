---
codename: supermgmt
title: "MCP drives what sm operates: reads, jobs and default grants"
type: task
status: active
priority: P1
size: L
issue: 83
prs: [84]
related_issues: [83]
depends_on: []
supersedes: []
related_specs: [mcp-https-token, mcp-node-tools, assistant-claude-cli, m5-mcp]
created: 2026-11-08
updated: 2026-11-08
---

# MCP drives what sm operates: reads, jobs and default grants

## Contexto / problema

Part of #63. ADR-0043 makes MCP coverage the top priority, but today (`internal/mcp/tools_read.go:21-96`, `tools_plan.go:44`, `tools_write.go:16-48`) a client has 9 read/plan tools and 5 write tools:

- After `approval_required` the model is blind: `job.read` is granted, but `mcp.API` has no job or approval method (`internal/mcp/api.go:22-35`).
- No tool lists the actions `infra_plan_action` accepts or their parameters, so the model guesses names.
- `infra_get_service_logs` is denied by default (`service.logs` is not `*.read`, `internal/policy/default.yaml:24-26`), although ADR-0043 requires it for owners' own clients.
- With `mcp.write_tools_enabled: true` a default install still cannot write: no rule grants `type:mcp` anything but reads and plans.
- Instance-targeted actions (`cloudflare.access_token.rotate`, `backup.create`) cannot be planned: `infra_plan_action` demands a valid id that no tool reveals (`internal/mcp/tools_plan.go:93-95`).
- `proxmox.snapshot.delete` is plannable, against "no default MCP tools for resource deletion" (`docs/spec/SUPERMGMT-SPEC.md:1826`).

## Scope

**Entra:**
- Read tools: `infra_list_jobs`, `infra_get_job`, `infra_list_approvals`, `infra_get_plan`, `infra_list_providers`, `infra_get_provider`, `infra_list_backups`, `infra_get_status`, `infra_list_tunnel_enrollments`, `infra_get_ssh_key` (public key only), and `infra_list_actions` (the catalog entries an MCP client may plan, with parameters, risk and whether they need write tools).
- Write tools: `infra_start_service`, `infra_stop_service`, `infra_shutdown_node`, `infra_probe_node`, `infra_power_guest`, `infra_snapshot_guest`, `infra_cancel_job`, `infra_refresh_provider`, `infra_create_backup`, `infra_rotate_cloudflare_access_token`, `infra_disable_tunnel`. All registered only with `mcp.write_tools_enabled`, all through the plan → approval → job flow, none returning a model-supplied hash.
- Instance-targeted planning works without the model knowing an instance id.
- Default policy: a `builtin-mcp-operate` rule for `type:mcp` grants `service.logs` and what `builtin-operator` holds (`service.start|stop|restart`, `node.probe`, `node.reboot`, `proxmox.vm.power`, `proxmox.snapshot.create`, `proxmox.backup.create`, `job.cancel`). `mcp.write_tools_enabled` still decides whether writes exist, and the approval floor still holds every operational-or-higher action for a person. Admin-class actions (`node.shutdown`, `backup.create`, `node.tunnel.disable`, `cloudflare.access_token.rotate`, `node_route.*`) have tools but need an explicit `type:mcp` rule, because they change reachability or instance state.
- `proxmox.snapshot.delete` is refused to MCP identities before any plan is stored (`Plans.Create` rejects an MCP-forbidden action instead of storing a denied plan).
- A coverage test in `test/integration`: every `sm` command and every `/api/v1` route is either served by a named MCP tool or listed in an explicit exclusion with its reason.
- Docs: `docs/mcp.md` tool tables and the logs redaction limit; spec tool list.

**No entra:**
- Secrets (`secrets import`, key rotation, `ssh-key rotate`): their value would cross the model's transcript. Listed as exclusions.
- `node.add`, repin, `node.setup` (mcp-node-tools). HTTPS reach and the profile-aware bridge (mcp-https-token). The ADR-0043 app panels (their own epic).

## Criterios de aceptación

### Scenario: the model can follow what it submitted
- **Given** an MCP client whose write ended `approval_required`
- **When** it calls `infra_get_job` and `infra_list_approvals`
- **Then** it sees the job's state and the pending approval, with control-plane fields only, and no way to approve

### Scenario: the model can discover what it may plan
- **Given** an MCP client
- **When** it calls `infra_list_actions`
- **Then** it receives the job actions an MCP identity can plan, with parameters and risk, served by a new `GET /api/v1/actions` using the same predicate as the MCP gate: no direct, credential, governance, destructive, forbidden or setup sub-actions, and `node.setup` not until mcp-node-tools. The list does not say whether policy grants them on a given target

### Scenario: a default install can read logs, redacted
- **Given** a default policy and an MCP client
- **When** it calls `infra_get_service_logs`
- **Then** it gets the lines through the same scrub as today, and `docs/mcp.md` states what the scrub cannot catch

### Scenario: writes work by default only when turned on, and always wait
- **Given** a default policy and `mcp.write_tools_enabled: true`
- **When** an MCP client calls `infra_restart_service`
- **Then** the job is `approval_required` until a person approves that plan hash
- **And** with `write_tools_enabled: false` the same tool is unknown

### Scenario: read-risk probes run without approval
- **Given** writes on
- **When** an MCP client calls `infra_probe_node`
- **Then** the probe runs without approval, as for a person

### Scenario: an instance-level job can be planned
- **Given** writes on and a policy granting `cloudflare.access_token.rotate` to `type:mcp`
- **When** an MCP client calls `infra_rotate_cloudflare_access_token`
- **Then** the plan targets the instance without the client naming an id, and waits for approval

### Scenario: no deletion by MCP
- **Given** a policy granting `proxmox.snapshot.delete` to `type:mcp`
- **When** an MCP client plans it
- **Then** it is refused before any plan is stored

### Scenario: an agent can withdraw its own job
- **Given** a job submitted by the MCP client, not yet running
- **When** it calls `infra_cancel_job`
- **Then** the job is cancelled, the client supplying no hash; a job of another identity is refused by `Governance.Cancel`

### Scenario: coverage cannot silently regress
- **Given** a new `sm` command or `/api/v1` route with no tool and no exclusion
- **When** the tests run
- **Then** the coverage test fails naming it

## Notas técnicas

- New tools over existing routes need no matrix row; new routes do (`test/integration/mcp_route_matrix_test.go:171`).
- Remote text goes through `untrustedText`/`remoteMap`; views are the only scrub (`docs/mcp.md:261`).
- `job.cancel` is `ModeGovernance` and has no approval gate; ownership lives in `Governance.Cancel`, and the floor still refuses approve, reject and resolve.
- `infra_get_job` omits intents' evidence and pre-state; job errors, provider errors and enrollment errors are untrusted text; enrollments omit the join line.
- `infra_refresh_provider` is a query, but it dials a provider, so it stays behind the write flag.
