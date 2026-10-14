# ADR-0032: MCP clients, tokens and the MCP identity

- Status: Proposed
- Spec: §9, §11.1, §11.2, §11.3, §20.4, §23, §29.2; ADR-0012, ADR-0017, ADR-0031, ADR-0033

## Context

§11.1 defines the `mcp` actor: a local client registered by a human and given a token once, or a remote client identified by `(issuer, subject, client_id)` and pre-registered by an admin, never inheriting its registrar's roles. §11.2 catalogs `mcp_client.register` (high), `mcp_client.issue_token` (credential) and `mcp_client.delete`. §24 adds write tools disabled by default. The spec leaves the client state, the token lifecycle, re-registration, socket admission and the meaning of "write tools disabled" open.

## Decision

### State (migration 000006)

- Table `mcp_clients`: `pending_token → active`, `* → deleted` (forward-only trigger); for local clients, the SHA-256 of its single token, set once (trigger). **At most one live (non-deleted) client per identity and per name** (partial unique indexes). Deleted rows, their revocations and their OAuth token rows are kept as history.
- Table `oauth_access_tokens` (ADR-0033): one row per accepted OAuth access token, keyed by the SHA-256 of the token; a row never changes client and never un-revokes (trigger).
- `credential_kind` and `actor_type` already admit the MCP values (`000001`); no existing table changes.

### Register

`POST /api/v1/mcp/clients` (`mcp_client.register`, high risk, keyed). Body `{name, origin: local}` or `{name, origin: remote, subject, client_id}`; the issuer of a remote client is `mcp.oauth.issuer`, and remote registration needs server mode with remote MCP enabled. Ids are generated at request time, so the approved plan names what it creates. The high-risk floor makes it a `control_plane.apply` job awaiting approval (the `secret.write` shape: 202 with the pending job).

Apply creates the identity with **no role bindings**: local → always a new identity, `issuer = "supermgmt:mcp-local"`, `subject = <mcp_clients.id>`, `client_id = ''`, client row `pending_token`; remote → the OAuth triple, client row `active`. `approved_at` is the time of the last counted approval, or the apply time when policy required none.

**Re-registering a deleted remote triple** reuses its identity row (UNIQUE on the triple, `000001`), clears `disabled_at`, still grants no role, and creates a **new** client row; the old row stays `deleted`. Old credentials stay refused: every OAuth token row of the old client is revoked and a revoked hash is never re-attached, and an access token whose `iat` is earlier than the live client's `created_at − 60 s` is refused (`OAUTH_TOKEN_INVALID`). `iat` is therefore required (ADR-0033).

### Issue the token (local clients)

`POST /api/v1/mcp/clients/{id}/token` (`mcp_client.issue_token`, credential route: unkeyed, never stored as an idempotent answer). Allowed once, only to the registration's requester, only while `pending_token`, only within 24 hours of `approved_at`. It returns `smm_…` (token kind `m`, 32 random bytes, SHA-256 stored) once and moves the client to `active` in the same transaction.

- Wrong caller → `POLICY_DENIED`/`NOT_PLAN_ACTOR`; not pending → `CONFLICT`/`INVALID_TRANSITION`; late → `CONFLICT`/`ISSUANCE_WINDOW_EXPIRED`.
- `expires_at` is mandatory and at most 365 days ahead; the CLI default is 90 days (like API tokens).
- A token that was issued but never delivered is recovered only by delete and re-register. `sm mcp clients add` preflights the destination (an `O_EXCL|O_NOFOLLOW` 0600 file, or the native OS keychain with no file fallback) before issuing, and prints exact recovery commands when storage fails afterwards; it never prints the token.

### Delete and list

- `DELETE /api/v1/mcp/clients/{id}` (`mcp_client.delete`, keyed): state `deleted`, token revoked, every OAuth token row of the client revoked, identity `disabled_at` set, its role bindings removed (audited). Rows are kept.
- `GET /api/v1/mcp/clients` (`identity.read`): never returns a token or a hash.

### Socket admission

- On the local socket, `Authorization: Bearer smm_…` makes the request the `mcp` caller of that client (`credential_kind = mcp_token`, `credential_id = mcp_clients.id`, expiry from the row). Any other token kind on the socket is still refused; no token is still `local:<uid>`.
- `mcp.enabled: false` → MCP tokens are refused (`UNAUTHENTICATED`). `smm_` tokens are refused on HTTPS: they are a stdio-only credential.
- Socket `mcp` callers are charged to the per-identity write bucket on every effective write (the socket path had no limiter).

### Credential status

`mcp_token` from `mcp_clients` (revoked, deleted or expired); `oauth_access_token` from `oauth_access_tokens` (expiry from the token; revoked by client deletion or restore). An expired MCP or OAuth token fails a queued job at claim (§11.1). Restore revokes both (§29.2). The auth sweep keeps OAuth token rows referenced by a non-terminal job or a provisional deployment.

### MCP-forbidden actions

For an `mcp` actor, `core.authorize` denies **before policy**, whatever `write_tools_enabled` or a custom grant says, every catalog action of mode `credential` (`token.create`, `mcp_client.issue_token`, `enrollment.create`, and any later one) plus `mcp_client.register`, `mcp_client.delete`, `identity.write` and `role_binding.write`: `POLICY_DENIED`/`MCP_ACTION_FORBIDDEN`. An MCP bearer can never mint a credential whose lifecycle is independent of its client.

### Writes gate

With `mcp.write_tools_enabled: false` (the default), for an `mcp` actor:

- `core.authorize` denies every non-`query` action with `MCP_WRITES_DISABLED`. By path: `POST /plans` still answers 201 and stores a plan whose verdict is that denial (plans are created even when denied); `POST /plans/{id}/submit` fails 403 and enqueues nothing; direct actions fail before any `control_plane.apply` job.
- `authorizeGovernance` returns the same denial, on top of the never-approve floor.
- Deployment admission: `Deployments.Create`, `Rollback` and `Cancel` authorize `deployment.create`, `deployment.rollback` and `job.cancel` before persisting a row, starting a CI watch or calling a provider, for every actor. (W0 re-check of the merged M4 tree: `Create` and `Rollback` already authorize through `core.authorize` before their insert, `internal/app/deployments.go:189,247` and `internal/app/deployments_rollback.go:57-64`; `Cancel` calls `Policy.EvaluateGovernance` directly, `internal/app/deployments.go:399`, and must be routed through the gate.) Finalization keeps its own policy check (ADR-0011) and the MCP approval floor.

With writes on: normal policy, plus the floors (approval for risk ≥ operational, never approve) and the forbidden set.

## Consequences

- An MCP identity starts with no role binding: the built-in policy gives every `type:mcp` subject `*.read` and `plan.create` (`builtin-mcp-read`), and anything more is granted explicitly.
- Losing an issued token costs a delete and a re-registration, which needs approval again; that is the price of never showing a token twice.
- `write_tools_enabled` is enforced at the application layer, so a token used outside the MCP server gains nothing by skipping the tool list.
