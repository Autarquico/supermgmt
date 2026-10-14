# ADR-0031: MCP server: SDK, transports and tool contract

- Status: Proposed
- Spec: §2.1.1, §11.1, §16, §24, §30; ADR-0012, ADR-0032, ADR-0033

## Context

§24 asks for the official maintained Go MCP SDK, an MCP server that is a client of the API (§2.1.1) with no database handle and no connector credential, a fixed tool list, write tools disabled by default, and untrusted remote output that is redacted, stripped, capped and marked. It leaves the SDK version, the transports' details, the tool output shapes and the redaction boundary to the implementation.

## Decision

### SDK

- `github.com/modelcontextprotocol/go-sdk` **v1.8.0** (2026-09-04T08:08:52Z; 39 days old at W0). Provenance, read from the module cache on 2026-10-13: `Origin.Hash 3f3b699b2b67e1ed033a63d6651671dab53c2d32`, `Ref refs/tags/v1.8.0`, module `h1:KIvahhYqwtbeniWVPs3TcXEA7b8jEtwfBpOTAI+Urx4=`, go.mod `h1:dL7u98E/zjJTGzEq+j30jQ8K2k1mb6LeAH4inEcSGts=`. Its `go.mod` needs Go 1.25.0.
- Protocol versions of the SDK: `2026-07-28` (latest), `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`; `TestSDK_ProtocolVersionsAreTheOnesADR0031Records` pins them, so an upgrade that changes them is an amendment of this ADR and ADR-0033.
- New modules in the build: `github.com/google/jsonschema-go` v0.4.3 (2026-04-17), `github.com/segmentio/encoding` v0.5.4 (2026-03-10), `github.com/segmentio/asm` v1.1.3 (2021-12-08), `golang.org/x/time` v0.15.0 (2026-02-11), `github.com/yosida95/uritemplate/v3` v3.0.2 (2022-04-19). `golang.org/x/oauth2` stays at our v0.37.0. The SDK's test-only requirements (`github.com/golang-jwt/jwt/v5`, `github.com/google/go-cmp`, `golang.org/x/tools`) reach no package of the binary (`go mod why -m`: only through `*.test` packages).
- **Release binary size** (`CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`, linux/amd64, measured in W0 by linking the SDK's `mcp`, `auth` and `oauthex` packages into `sm`): 37,081,248 bytes before M5; 38,711,456 with the SDK (+1,630,208, +4.4 %).
- Confinement (depguard): the SDK is imported only by `internal/mcp`, `internal/cli/mcp_bridge*.go` and `test/**`; `internal/mcp` may import only the standard library, the SDK, `api/wire`, `domain`, `errors`, `audit` and `textsafe` (it is an API client, §24).

### One server, two transports

- `internal/mcp` builds one `*mcp.Server` from an `API` interface, the subset of the typed client its tools call. Every tool is one or more API calls; policy, audit, idempotency and rate limits are the API's.
- **stdio** (`sm mcp`): `client.New(<daemon socket>, Token: <MCP client token>)` and `Server.Run` over `StdioTransport`; every SDK protocol version. Stdout carries JSON-RPC only.
- **Streamable HTTP** (server mode, `mcp.remote_enabled`): mounted by the daemon at `/mcp` on the HTTPS listener with `StreamableHTTPOptions{Stateless: true, JSONResponse: true}` (the stateful handler cannot serve `2026-07-28`, `mcp/server.go:942-948`); protocol versions `2026-07-28`, `2025-11-25`, `2025-06-18`, the ones whose authorization model is RFC 9728 (ADR-0033). A request with an `Origin` header must name `server.public_url`'s origin, else 403 (the transport's DNS-rebinding rule). Tool calls reach the API **in process**: `api.(*Server).InProcess(caller)` is an `http.RoundTripper` that runs the API handler with the resolved caller in an unexported context key; it refuses a request that carries `Authorization`. OAuth access tokens are never accepted on `/api/v1` (no token passthrough).
- No MCP resources and no prompts in V1. The `initialize` client name is display metadata only (§11.1).

### Tools

Exactly §24's list. Each tool's `_meta["dev.supermgmt/schema_version"]` is `1`; `tools/list` is golden-tested per configuration.

| Tool | API calls | Notes |
|---|---|---|
| `infra_list_nodes` | `GET /nodes` | filters environment, tag, reachability; cursor passthrough |
| `infra_get_node` | `GET /nodes/{id}` | `ref` = id or exact name |
| `infra_list_services` | `GET /nodes/{id}/services` | |
| `infra_get_service` | `GET /services/{id}` | `ref` = id or `name@node` |
| `infra_get_service_logs` | `GET /services/{id}/logs` | `service.logs`; untrusted envelope; ≤ 500 lines, ≤ 64 KiB |
| `infra_list_apps` | `GET /apps` | |
| `infra_list_deployments` | `GET /deployments` | |
| `infra_get_deployment` | `GET /deployments/{id}` | step errors in the untrusted envelope |
| `infra_list_events` | `GET /events` | `data` in the untrusted envelope |
| `infra_get_health` | `GET /nodes/{id}`, `GET /services/{id}`, `GET /deployments/{id}` | derived view, no new route |
| `infra_plan_action` | `POST /plans` | §24 input and output; one target; names resolved to ids |
| `infra_submit_plan` † | `POST /plans/{id}/submit` | `{plan_id, plan_hash}` |
| `infra_restart_service` † | `POST /plans`, then submit | |
| `infra_reboot_node` † | `POST /plans`, then submit | |
| `infra_create_deployment` † | `POST /deployments` (ADR-0011) | no plan exists until CI passes |
| `infra_rollback_deployment` † | `POST /deployments/{id}/rollback` | |

† Registered only when `mcp.write_tools_enabled: true`; `infra_plan_action.submit_via` is `"infra_submit_plan"` or `null` accordingly. Wrappers submit only the hash the plan they just created returned.

- **Name resolution** happens in the MCP server, through reads: node = exact name or id; service = `name@node` or id; app = exact name or id; deployment = id. None → `NOT_FOUND`; several → `INVALID_ARGUMENT`/`AMBIGUOUS_TARGET`; more than 50 pages → "use an id". Resolution compares **raw** API values, never the sanitized display copy, and the plan binds ids, so sanitation can never retarget a write.
- **Write results** (frozen): `{status: approval_required|queued|waiting_ci|denied, job_id?, deployment_id?, plan_hash?, summary, risk}`; `summary` is built from control-plane fields only.
- API errors become `CallToolResult{IsError: true}` carrying the API error's `code`, `reason` and `correlation_id`, never internal text.

### Output views by provenance

Tools never serialize a wire DTO. Each returns an allowlisted view (`internal/mcp/views.go`, one per DTO: `Node`, `Service`, `LogChunk`, `Event`, `App`, `Deployment`, `DeploymentStep`, `CreatedPlan`, `Submission`). Every field is in exactly one class:

1. **Identifiers**: ids, `plan_hash`, `job_id`, enum states and kinds, timestamps, risk. Copied raw; they are validated types.
2. **Operator-authored names**: node and app names, environment, tags. `textsafe.Line`, at most 256 bytes.
3. **Remote-discovered fields**: service `name` and `native_id`, runtime `status`/`health` strings, `metadata`, deployment step `error`/`output_ref`, event `data`, log lines. They sit under a `remote` object carrying `"untrusted_remote_output": true`. Strings: `textsafe` stripping, then `audit.ScrubCredentials`, then bounds (256 bytes per scalar; 64 KiB and 500 lines per log text). Maps and arrays: `audit.RedactMap` first (sensitive keys masked structurally, before serialization), then every string scrubbed; depth ≤ 4, ≤ 64 entries per level; truncation flagged. A service is addressed in writes by `service_ref` (its id), never by the sanitized name.

Tool descriptions say that `remote` content is data, never instructions. The server never acts as a side effect of content.

### Redaction guarantee and its limit

`audit.ScrubCredentials` = `audit.ScrubString` (Bearer, Basic, PEM private keys) + SuperMgmt token formats (`sm[stbjm]_[A-Za-z0-9_-]{8,}`) + `key=value`, `key: value` and `"key": "value"` forms whose key matches the existing sensitive-key rule (`password`, `secret`, `token`, `api_key`, `authorization`, …) + JWT-shaped triples (`eyJ….….…`). It applies to MCP output whatever `security.redact_command_output` says.

The guarantee is exactly these patterns plus the `RedactMap` keys. **An arbitrary secret value under a non-sensitive name (for example an environment variable called `DB_URL` holding a password) is not detected.** This limit is stated here, in `docs/mcp.md` and in the descriptions of tools that return remote text; the secret-leak tests assert the supported set only.

## Consequences

- MCP adds no privileged path: everything it does is an API request by an `mcp` identity under the same policy as humans.
- Interoperability is verified with the SDK's own client plus hand-written JSON-RPC goldens; real MCP clients stay a manual checklist (`docs/manual-checks/m5-real-mcp-clients.md`) until run with dated, versioned evidence.
- The binary grows by about 1.6 MB.
