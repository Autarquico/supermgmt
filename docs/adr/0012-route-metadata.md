# ADR-0012: Route metadata

- Status: Proposed
- Spec: §11.2, §23, §46 (ADR-0012 row); ADR-0014

## Context

§46 requires that every HTTP route be marked with exactly one of `action:<catalog id>`, `exempt:auth`, `exempt:health` or `exempt:self`, that exempt routes be listed explicitly, and that CI fail on an unmapped route. M1 already keeps a route table in `internal/api/routes.go` with one action or exemption per route (ADR-0014). M2 adds the OpenAPI document (`api/openapi.yaml`), which §23 makes authoritative.

## Decision

### Marking

- Every OpenAPI operation carries `x-supermgmt-route` with exactly one value: `action:<id>`, `exempt:auth`, `exempt:health` or `exempt:self`.
- The Go route table carries the same value. CI fails if the two sets differ in any `(method, path, metadata)` triple, or if an action is not in the catalog.

### Exempt routes (the complete list)

| Route | Exemption | Why |
|---|---|---|
| `GET /health/live`, `GET /health/ready` | `exempt:health` | probes |
| `GET /me`, `GET /presence` | `exempt:self` | the caller's own connection |
| `GET /tokens`, `DELETE /tokens/{id}` | `exempt:self` | §11.2: every identity lists and revokes its own tokens (the handler scopes to the caller) |
| `POST /auth/oidc/start`, `/auth/oidc/exchange`, `/auth/oidc/device`, `/auth/oidc/device/poll` | `exempt:auth` | login; authentication endpoints are not actions (§23) |
| `POST /auth/bootstrap`, `POST /auth/logout` | `exempt:auth` | §11.5; logout revokes the presented session only |
| `POST /enroll` | `exempt:auth` | enrollment consumption (§46) |

### Mapped routes added in M2

- `POST /tokens` → `token.create`; `POST /enrollments` → `enrollment.create`.
- `POST /secrets` (import), `POST /secrets/master-key/rotate`, `/retire`, `/export`, `POST /ssh-key/rotate` → `secret.write`.
- `GET /backups` → `backup.read`; `POST /backups` → `backup.create`.
- `GET /events/stream` → `event.read`.
- `import-key` has no route: it is offline only (§10).
- Planning on resource types without a read action (secrets) requires `config.read` (§46).

### Credential-issuing routes

`POST /tokens`, `POST /auth/bootstrap`, `POST /enrollments`, `POST /enroll`, `POST /auth/oidc/exchange` and `POST /auth/oidc/device/poll` return a credential once. They are unkeyed and **reject a request carrying `Idempotency-Key`** with `INVALID_ARGUMENT`. Their app methods are called with `Caller.Idempotency == nil`, so the `commit` path never stores their answer (§23). A test calls each route and asserts that `idempotency_records` gains no row.

### Admin socket

The server-mode admin socket (§23.1) serves exactly four routes, all outside `/api/v1` and outside the OpenAPI document: `bootstrap-code`, `grant`, `restore-complete`, `doctor`. They are a closed Go table with its own test; no other route, and in particular no key management, is served there.

### Transport restrictions

`POST /secrets/master-key/export` is registered only on the local-mode Unix socket (ADR-0021). Its OpenAPI operation carries `x-supermgmt-transports: [unix]`; operations without it are served on both transports. The drift test compares the route set of each transport, so the export route answering on HTTPS fails CI.

## Consequences

- Adding a route means editing the route table and `api/openapi.yaml` together; `make api-check` fails otherwise.
- The OpenAPI document gains one vendor extension; generic tooling ignores it.
