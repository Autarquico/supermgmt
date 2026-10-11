# Cloudflare (optional guide)

This is a **guide only**. SuperMgmt has no Cloudflare connector in M2, never needs Cloudflare, and nothing on this page has been run against a real Cloudflare account (verification status: **not verified**). Core operation works with localhost, a LAN, a VPN or any reverse proxy (SPEC §25). Cloudflare product behaviour changes: check the current Cloudflare documentation before relying on any statement about it here.

## Topology

```text
sm client / TUI  --HTTPS-->  Cloudflare (Tunnel, optionally Access)  --->  cloudflared  --http-->  127.0.0.1:8787  sm server
```

- `cloudflared` runs on the SuperMgmt host and makes an outbound connection to Cloudflare, so no inbound port has to be opened for SuperMgmt (SPEC §25).
- SuperMgmt runs in **proxy mode**: `server.tls.mode: proxy`, `server.listen: 127.0.0.1:8787`, plain HTTP on loopback, TLS terminated by Cloudflare.
- Install it that way: `install.sh server --tls proxy --public-url https://mgmt.example.com` (the default), where the public URL is the hostname the tunnel serves. See [installation.md](installation.md).

Sketch of the tunnel's ingress rule (the file layout and keys are Cloudflare's; verify them in their documentation):

```yaml
ingress:
  - hostname: mgmt.example.com
    service: http://127.0.0.1:8787
  - service: http_status:404
```

## What SuperMgmt requires from the proxy

These come from SuperMgmt's own proxy rules ([ADR-0017](adr/0017-server-transport-credentials-sessions.md), SPEC §23.1), not from Cloudflare:

- The TCP peer must be inside `server.trusted_proxies`. With `cloudflared` on the same host the default `127.0.0.1/32` is what you want. Only requests from a trusted peer may carry forwarding headers that SuperMgmt believes.
- From a trusted peer, `X-Forwarded-Proto` **must** be `https`. Anything else, including a missing header, is answered with `400`. Whether `cloudflared` forwards that header to the origin is **not verified**; if every request gets a 400, this is the first thing to check, and the fix belongs in the proxy, not in SuperMgmt.
- The client address is taken from `X-Forwarded-For` (rightmost entry that is not itself a trusted proxy). `CF-Connecting-IP` is not read. The address feeds rate limiting and the `source_cidrs` check of join tokens; how Cloudflare composes `X-Forwarded-For` for the client address is **not verified**, so test a join with `--source-cidr` before depending on it.
- A request from loopback gets no special trust or privilege. Running `cloudflared` on the same host does not make Cloudflare traffic "local".

## Trust boundary

State it precisely, because it is easy to assume otherwise:

- **SuperMgmt consumes no Cloudflare identity assertion.** The `Cf-Access-Jwt-Assertion`, `Cf-Access-Authenticated-User-Email` and every other `Cf-Access-*` header are ignored; no code reads them (a search of `internal/` finds none). SPEC §25 (1.4.3) says the same: validation applies only if a later version consumes such assertions.
- **Every request is authenticated by SuperMgmt itself**: an OIDC-issued session or an API token, checked against SuperMgmt's own tables, then authorized by its policy. A request that reaches SuperMgmt through the tunnel without a valid bearer credential is `401`, whatever Cloudflare let through.
- Therefore **Cloudflare Access is an extra gate in front, not an identity source.** It can decide who may reach the hostname at all; it cannot grant anything inside SuperMgmt, and a misconfigured Access policy cannot give anyone SuperMgmt privileges.
- If a future version validates Access assertions, it must verify the JWT signature against the team's JWKS, the team domain and the application audience (AUD) according to current Cloudflare documentation. None of that exists today.
- What does cross the trust boundary: bearer tokens (visible to Cloudflare, which terminates TLS), the client address from forwarding headers, and the plain-HTTP hop on loopback. Cloudflare can read and alter traffic; use it only if you accept that.

## Access and the `sm` client

`sm` is not a browser. It sends `Authorization: Bearer ...` and has **no way to add other headers** (such as Access service-token headers) or to follow an Access login page; nothing in `internal/client` does either (a search finds no such code). Consequences, none of them verified against real Access:

- An Access application in front of the whole hostname with a login-page policy will block `sm`, `sm join` and the `join.sh` enrollment from nodes.
- Options: leave the API hostname outside Access and rely on SuperMgmt's authentication, OIDC and rate limits (there is no browser UI in M2); or use an Access policy that lets these paths through. Either way the decision is yours, and the first option is simply "Tunnel without Access".
- Event streams (`GET /events/stream`) send a heartbeat comment every 15 seconds; whether Cloudflare keeps the connection open for that pattern is not verified.

## Hardening checklist

- Bind SuperMgmt to loopback (the installer default); do not add a public listener next to the tunnel.
- Keep `server.trusted_proxies` as narrow as the proxy's address.
- Use OIDC with `auth.oidc.allowed_domains`; bearer tokens leave the machine in clear to Cloudflare's edge.
- Restrict `join` tokens with `--source-cidr` only after confirming the client address SuperMgmt sees ([operations.md](operations.md)).
- Treat the Cloudflare account and the tunnel credentials as part of your trust base; SuperMgmt cannot protect against their compromise.
