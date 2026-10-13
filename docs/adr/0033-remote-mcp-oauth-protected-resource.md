# ADR-0033: Remote MCP as an OAuth 2.0 protected resource

- Status: Accepted
- Spec: §8.2, §21.1, §23, §24; RFC 6750, RFC 7662, RFC 8707, RFC 9068, RFC 9728; ADR-0031, ADR-0032

## Context

§24 makes remote MCP (server mode, streamable HTTP) an OAuth 2.0 protected resource only: an external authorization server issues the tokens, SuperMgmt serves Protected Resource Metadata, answers 401 with a challenge, validates tokens as JWTs or by introspection, maps `(iss, sub, client_id)` to a pre-registered `mcp` identity, and records any deviation from the MCP authorization specification checked at implementation time.

## MCP authorization specification checked

Read on 2026-10-13 from modelcontextprotocol.io:

- **`2026-07-28`** (the SDK's latest protocol): *Authorization* and *Authorization Server Discovery*.
- **`2025-06-18`**: *Authorization*.
- **`2025-11-25`** is served (ADR-0031) but its authorization text was **not read** in W0. The rows below come from `2026-07-28`; `2025-06-18` states the same metadata, audience, passthrough and status-code rules, makes the challenge mandatory, and has no scope-challenge guidance.

Resource-server requirements in those texts and how SuperMgmt meets them:

| Requirement | SuperMgmt |
|---|---|
| Implement RFC 9728 Protected Resource Metadata with at least one `authorization_servers` entry | metadata document naming `mcp.oauth.issuer` |
| 401 carries `WWW-Authenticate` with `resource_metadata` (MUST in `2025-06-18`; one of two discovery mechanisms in `2026-07-28`) | every 401 from `/mcp` |
| `scope` in the challenge (SHOULD) | `mcp.oauth.required_scopes` |
| Validate tokens per OAuth 2.1 §5.2; audience bound to this server (RFC 8707 §2); invalid or expired → 401 | below; 401 |
| Insufficient scope → 403 with `error="insufficient_scope"`, `scope`, `resource_metadata` (SHOULD) | yes |
| Accept only tokens for this resource; never accept or pass through other tokens | OAuth tokens are refused on `/api/v1`; tool calls reach the API in process (ADR-0031) |
| Tokens never in the query string | only the `Authorization` header is read (`bearer_methods_supported: ["header"]`) |
| `offline_access` not in the challenge or `scopes_supported` (SHOULD NOT) | documented: do not list it in `required_scopes` |

Client registration (Client ID Metadata Documents, Dynamic Client Registration) is a client and authorization-server concern: SuperMgmt supports neither and needs neither, because an admin pre-registers each remote client's OAuth identity (ADR-0032).

**Deviations**

1. **Root metadata identifier.** The root `/.well-known/oauth-protected-resource` (named by §24 and allowed by both MCP revisions) serves the same document as the path-suffixed one, whose `resource` is `<origin>/mcp`. A client that discovers through the root and applies RFC 9728 §3.3 strictly will reject it, because the identifier derived from the root URL is the bare origin. Discovery through the 401 challenge, which names the path-suffixed URL, is the supported path.
2. **Case of the resource.** `2026-07-28` says implementations SHOULD accept uppercase scheme and host in the canonical URI. SuperMgmt compares `aud` byte-for-byte with `mcp.oauth.resource` (RFC 9068 §4); an authorization server must echo the resource exactly as configured.
3. **Scope hierarchies.** `2026-07-28` says servers MUST account for scope hierarchies. SuperMgmt knows none: a token must carry every `required_scopes` string exactly. An authorization server with hierarchical scopes must issue the exact scope.

## Decision

### Resource identity (validated at config load)

- `mcp.remote_enabled` requires `instance.mode: server`.
- `server.public_url` must be an absolute `https` URL with an empty path (or `/`), no query, no fragment, no userinfo. Prefix-mounted reverse proxies are not supported in V1.
- `mcp.oauth.resource` must be **byte-equal** to `<public_url origin>/mcp`: no trailing slash, no query, no fragment (RFC 8707 §2, RFC 9728 §3.3).
- Derived, never configured: the metadata URL `<origin>/.well-known/oauth-protected-resource/mcp` (RFC 9728 §3.1, path-suffixed), used in every challenge. Tokens must have `aud` containing exactly the resource.
- `issuer`, `jwks_url` and `introspection_url` must be `https` URLs; `introspection_url` requires `introspection_client_id` and `introspection_client_secret_ref` (`secret://`). Incomplete or invalid `mcp.oauth` refuses to start remote MCP (§24); local stdio is unaffected.

### Endpoints (`exempt:mcp`)

`/mcp`, `/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource` are served on the HTTPS listener only when `remote_enabled`, outside `/api/v1` and outside the OpenAPI document (like the admin-socket routes), and listed in the ADR-0012 route table as `exempt:mcp`.

- Metadata: `{resource, authorization_servers: [mcp.oauth.issuer], scopes_supported: required_scopes, bearer_methods_supported: ["header"]}`.
- `/mcp` without a token, or with an invalid one → `401` + `WWW-Authenticate: Bearer resource_metadata="<derived metadata URL>", scope="<required scopes>"`.
- Missing scope → `403` with `error="insufficient_scope"`, `scope` and `resource_metadata`.
- A valid token whose `(iss, sub, client_id)` maps to no live `mcp` identity → `403` (`POLICY_DENIED`/`MCP_CLIENT_UNREGISTERED`).

### JWT access tokens (`jwks_url`, RFC 9068 profile)

- Header `typ` must be `at+jwt` or `application/at+jwt` (case-insensitive). Absent, `JWT` or ID-token shapes are refused: `typ` is the only in-band discriminator RFC 9068 §4 defines, and the absence of `nonce` does not prove an access token. Issuers that cannot emit `at+jwt` use introspection; V1 has no legacy JWT mode.
- Signature through `go-oidc`'s `RemoteKeySet` (refresh on an unknown `kid`; RS256/384/512, PS256, ES256/384, EdDSA; `none` and HMAC refused). go-oidc is imported only by `internal/auth/oidc` and `internal/auth/oauth*.go` (depguard).
- `iss` equals `mcp.oauth.issuer` exactly; `aud` contains `mcp.oauth.resource`; `exp` and `iat` required, `nbf` honoured, 60 s skew; `client_id` required, and `azp`, when present, must equal it; tokens carrying `nonce` are refused (defence in depth); every required scope present in `scope` or `scp`.

### Introspection (`introspection_url`, RFC 7662)

POST authenticated with `introspection_client_id` and the secret behind `introspection_client_secret_ref`; requires `active: true` and the same `iss`, `aud`, `exp`, `iat`, `client_id` and scope rules; `token_type`, when present, must be `access_token` or `Bearer`. A response without `iat` is refused (ADR-0032's re-registration floor needs it). Results are never cached beyond the request.

Every JWKS and introspection call goes through `netguard` as a provider endpoint (§21.1): https only, no redirects.

### Token rows

Each accepted token gets an `oauth_access_tokens` row keyed by its SHA-256 (the credential id), so revocation, expiry at claim (§11.1) and audit work as for other credentials. A presented token whose row is revoked or belongs to another client is refused before any verification work. OAuth scopes are an admission check only; they do not become action scopes in V1.

### Rate limits on `/mcp` (in this order)

1. The per-address admission bucket (the login bucket) on every `/mcp` and metadata request, before any header parsing, hash lookup, JWKS or introspection call; invalid-token floods are bounded by it.
2. Token resolution.
3. A per-identity MCP request bucket (same rate as the write bucket) per accepted request.
4. Inside a tool, each effective API write through `InProcess` is charged once to the per-identity write bucket; the outer `/mcp` request is not a write.

Rejections are `429` with `Retry-After`. Socket MCP gets only (4) (ADR-0032).

### Fake fidelity

`internal/auth/oauthfake` (tests only, depguard) serves JWKS with key rotation and RFC 7662 introspection that requires client authentication, mints RFC 9068 access tokens and ID-token-shaped JWTs with any claim or header mutation, and counts every JWKS and introspection call. Its fields and errors are recorded from the RFCs (versions and URLs in `internal/auth/oauthfake/PROVENANCE.md`). A real authorization server, including RFC 8707 `resource` at authorization and at token exchange, is a manual checklist row that stays **deferred** until run with dated, versioned evidence.

## Consequences

- Tokens minted for another resource on the same host never work at `/mcp`, and MCP tokens never work on `/api/v1`.
- Some authorization servers need configuration (an `at+jwt` access-token profile, or introspection) before they can be used.
- Root-only discovery clients may fail; the challenge path is documented as the supported one.
