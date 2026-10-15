# cffake provenance (ADR-0028 fake fidelity, ADR-0037)

`internal/providers/cloudflare/cffake` is hand-written from the public
Cloudflare API documentation (developers.cloudflare.com/api, v4) and from the
`cloudflared` source read in the spike (`.claude/loop/cloudflare-tunnel-transport/spike.md`).
**Nothing here was recorded from, or verified against, a real Cloudflare
account.** What it proves is that the client and the state machine hold their
contracts against a server that follows the documentation and misbehaves on
command; it proves nothing about Cloudflare. Everything under "Unverified
assumptions" belongs in `docs/manual-checks/cloudflare-tunnel.md`.

- API: `https://api.cloudflare.com/client/v4`, documentation read 2026-10-15.
- The fake answers on `https://104.16.0.1/client/v4` (a public address, so the
  netguard filter lets a default client through; clients reach it through
  `netguard.WithTestDialer`) with a throwaway CA.

## Endpoints and fields modelled

| Endpoint | Fields served | Behaviour modelled |
|---|---|---|
| `GET /user/tokens/verify`, `GET /accounts/{a}/tokens/verify` | `id`, `status`, `not_before`, `expires_on` | Always `active`; `WithUserOwnedToken` makes the account variant refuse. |
| `GET /zones` | `id`, `name`, `status`, `account.id` | Filters `name`, `account.id`; one zone. |
| `POST /accounts/{a}/cfd_tunnel` | `id`, `name`, `created_at`, `deleted_at`, `status`, `config_src`, `remote_config`, `connections[]` | Body `name`, `config_src`, `tunnel_secret`. Live tunnels have unique names (409, code 1013). |
| `GET /accounts/{a}/cfd_tunnel` | same | Filters `name` (exact), `is_deleted`; pagination. |
| `GET`/`DELETE /accounts/{a}/cfd_tunnel/{id}` | same | Delete is a soft delete (`deleted_at`); refused (400, code 1022) while connectors are attached; a deleted tunnel is still readable by ID. |
| `DELETE …/cfd_tunnel/{id}/connections` | `null` | Detaches connectors. |
| `PUT`/`GET …/cfd_tunnel/{id}/configurations` | `tunnel_id`, `version`, `config.ingress[]`, `source`, `created_at` | The last rule must be a hostname-less catch-all; version counts PUTs; an unconfigured tunnel reads `config: null`. |
| `GET …/cfd_tunnel/{id}/token` | base64 string | Deterministic fake token. |
| `POST`/`GET /zones/{z}/dns_records`, `DELETE …/{id}` | `id`, `zone_id`, `zone_name`, `name`, `type`, `content`, `proxied`, `ttl`, `comment`, `created_on` | CNAME only; names must be inside the zone; a second record at a name is refused (400, code 81057); filters `name`, `type`. |
| `POST`/`PUT`/`GET`/`DELETE /accounts/{a}/access/policies` | `id`, `name`, `decision`, `include[]` (`email`, `service_token`), `exclude`, `require`, `reusable`, `created_at` | `non_identity` takes only service-token rules, `allow` only email rules; token IDs must exist; no name filter; a policy attached to an application cannot be deleted (409). |
| `POST`/`GET`/`DELETE /accounts/{a}/access/apps` | `id`, `aud`, `name`, `domain`, `type`, `policies[]` (`id`, `precedence`), `allowed_idps`, `session_duration`, `created_at` | `self_hosted` only; policies must exist; a domain is unique among applications (409); filters `name` and `exact` (without `exact`, a substring search). |
| `POST`/`GET`/`DELETE /accounts/{a}/access/service_tokens` | `id`, `name`, `client_id`, `client_secret` (creation only), `created_at`, `updated_at`, `expires_at`, `duration` | Duplicate names allowed; filter `name` is a substring search; the secret is never listed. |

Common behaviour: bearer token checked before routing (401 in the v4 envelope);
another account in the path answers 403; an undeclared query parameter or
request field answers 400 and is listed by `Rejected()`; every list reports
`result_info` and honours `page`/`per_page` up to `WithPageSize`.

## Fault injection

- `Inject(op, fault, times)` and `Plan(func(Mutation) Fault)` apply to every
  endpoint (`Op*` constants). Faults: `FailBefore` (500, nothing applied),
  `LostResponse` (applied, connection dropped), `Forbidden` (403),
  `RateLimited` (429, `Retry-After: 1`).
- `Mutations()` logs every mutating request with its sequence number, fault,
  status and whether it committed, so a matrix test can inject at the k-th.
- `WithPropagationDelay(n)` hides a created object from lists for the next n
  requests (reads by ID see it at once).
- `WithEchoedCredentials()` makes error messages repeat the bearer token and a
  control sequence, to test that clients sanitize.
- `RoutableWithoutAccess()` / `EverRoutableWithoutAccess()` check, after every
  committed mutation, that no proxied CNAME to `*.cfargotunnel.com` exists
  without an Access application on that exact domain with an existing policy.

## Unverified assumptions (manual checklist candidates)

- Tunnel names are unique among live tunnels and the conflict is `409` with code
  `1013`. A DNS conflict is `400` with code `81057` (the client also treats
  `81053`, `81058` and any `409` as conflicts).
- Deleting a tunnel with connectors answers `400`/`1022`; connectors disappear
  after `DELETE …/connections` (or a few seconds after cloudflared stops).
- The `name` filter of the tunnel list is exact; those of Access applications
  (with `exact=true`) and service tokens are treated as substring searches by the
  fake, and the client filters exactly on top of whatever the server returns.
- Reusable policies have no name filter; the account-level list is paginated.
- A reusable policy attached to an application cannot be deleted; an
  application domain is unique per account; service token names are not.
- Restricting identity providers is an application property (`allowed_idps`), not
  a policy one.
- `GET …/configurations` on a never-configured tunnel returns `config: null`.
- A service token's `client_secret` appears only in the creation answer.
- Time stamps are RFC 3339 with optional fractional seconds.
- Requests are accepted with `Authorization: Bearer <token>` for both user-owned
  and account-owned tokens, the latter verified at `/accounts/{a}/tokens/verify`.
- Rate limiting answers `429` with `Retry-After` in seconds.
