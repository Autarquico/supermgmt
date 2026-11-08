---
codename: supermgmt
title: "sm mcp reaches a server: MCP client tokens over HTTPS"
type: task
status: active
priority: P1
size: M
issue: 85
prs: [86]
related_issues: [85]
depends_on: [mcp-tool-coverage]
supersedes: []
related_specs: [mcp-tool-coverage, assistant-claude-cli, m5-mcp]
created: 2026-11-08
updated: 2026-11-08
---

# sm mcp reaches a server: MCP client tokens over HTTPS

## Contexto / problema

Part of #63. An agent on a workstation cannot drive a server or a Proxmox appliance without an external OAuth authorization server:

- `sm mcp` always connects to the local daemon (`internal/cli/mcp_bridge.go:79`).
- `RunServer` binds only HTTPS and the admin socket (`internal/daemon/server.go:57-69`), and `smm_` tokens are refused on HTTPS (`internal/api/server.go:524-526`, ADR-0032). A token registered on a server is usable nowhere, yet `sm mcp clients add` issues it (`internal/cli/mcp.go:101`).
- The bridge reads `mcp.enabled` and `write_tools_enabled` from the local configuration (`internal/cli/mcp_bridge.go:111-124`), which says nothing about a remote server.

Decision (user, 2026-11-08): MCP client tokens may travel over HTTPS, opt-in. MCP stays off the network as a protocol: the bridge runs on the workstation and calls `/api/v1`, so ADR-0033 stands. Recorded in ADR-0044, amending ADR-0032.

## Scope

**Entra:**
- Config `mcp.token_over_https` (default `false`), server mode only.
- A client registered with `--https` carries a marker (`mcp_clients.over_https`, migration 000015), set at registration so the approved plan covers it. With the flag off, HTTPS refuses `smm_` tokens on the prefix alone, with no lookup. With the flag on, the lookup is restricted to marked clients, so an unmarked token gets the same answer as an unknown one and builds no caller.
- The server owns the refusals at registration, before any plan: `over_https` with the flag off; a local client without `over_https` on a server (it would be usable nowhere); `over_https` on a local instance (no HTTPS to reach); `over_https` on an OAuth client.
- Marked clients default to a 30-day expiry and the server caps them at 90 days (`--expires`).
- The audit `Source` says which path was used (`mcp_socket` or `mcp_https`).
- The per-identity write bucket applies; reads are charged as for any bearer on `/api/v1`.
- Bridge: `sm mcp --profile NAME` targets that profile with only the MCP token (never the human's credential, no daemon autostart); without the flag, the active profile; a local target behaves as today.
- `write_tools_enabled` reaches the bridge in `wire.Me`, only for MCP callers, so the tool list matches the target; the bridge no longer reads a local configuration for that. With MCP disabled on the target the token does not resolve, and the bridge says so.
- `--keychain` reads a namespace of its own, so it can never pick up a stored human credential.
- `sm mcp clients add`: on a server without `--https`, or with the flag off, says where the token will work instead of issuing a useless one silently; prints a host config snippet with `--profile`.
- Docs: ADR-0044, ADR-0032 amendment, `docs/mcp.md` (a remote agent without OAuth, the leak trade-off), security guide, spec §23-24.

**No entra:**
- MCP protocol on the network with a static token (`/mcp` keeps OAuth, ADR-0033). Embedded authorization server. New tools.

## Criterios de aceptación

### Scenario: a marked client drives a server from a workstation
- **Given** a server with `mcp.token_over_https: true` and a client registered with `--https`
- **When** `sm mcp --profile lab --token-file F` starts
- **Then** the bridge calls the server's `/api/v1` with only that token, lists the server's tools, and a restart waits for a person's approval on that server

### Scenario: the flag is off by default
- **Given** a server with the default configuration and a marked client
- **When** its token is presented over HTTPS
- **Then** it is refused on its prefix, with no database lookup

### Scenario: an unmarked token stays local
- **Given** `mcp.token_over_https: true` and a client registered without `--https`
- **When** its token is presented over HTTPS
- **Then** the answer is identical to an unknown token and no caller is built

### Scenario: the floor does not depend on the transport
- **Given** a marked client over HTTPS
- **When** it tries to approve a job, issue a credential or open a session
- **Then** it is refused exactly as on the socket, and every route of the MCP matrix gives the same result on both transports

### Scenario: the audit tells the paths apart
- **Given** the same client over each path
- **When** it acts
- **Then** the events carry `mcp_https` or `mcp_socket`

### Scenario: the human's credential never travels with the bridge
- **Given** a remote profile with a stored human token
- **When** the bridge runs with an MCP token
- **Then** the bridge never reads the human's credential store, `--keychain` cannot resolve to a human credential, and a non-MCP token placed in the token file is refused after the identity check

### Scenario: the tool list follows the server
- **Given** a local configuration with writes on and a server with writes off (or the reverse)
- **When** the bridge lists tools
- **Then** it lists what the server allows

### Scenario: registration says where the token works
- **Given** an active server profile with the flag off
- **When** the operator runs `sm mcp clients add --https`
- **Then** the server refuses, naming the flag, before storing a plan; without `--https` on a server it refuses, explaining that a local token cannot be used there

### Scenario: a revoked or expired token stops at once
- **Given** a marked client
- **When** it is removed or expires
- **Then** the next HTTPS request is `UNAUTHENTICATED`, uncached

## Notas técnicas

- `internal/auth/mcptoken.go:13` hardcodes the source label. `mcpGate` keys on the actor type, not the transport.
- The route matrix runs socket and in-process only (`test/integration/mcp_route_matrix_test.go:20-24`): add HTTPS.
- `backup` restore revokes MCP tokens already; the marker needs nothing more.
