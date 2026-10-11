# ADR-0017: Server transport, credentials and sessions

- Status: Proposed
- Spec: §2.2, §9, §11.1, §11.5, §23, §23.1, §29.2, §30, Appendix A; ADR-0014

## Context

M1 serves `/api/v1` on a Unix socket authenticated by peer credentials, and refuses any `Authorization` header (ADR-0014). M2 adds server mode: the same handlers over HTTPS with bearer credentials, an admin socket, and a server-sent event stream. Two M1 facts constrain the design. The daemon creates `local:<uid>` and binds it to `admin` on every start (`internal/daemon/identity.go`), which would make the §11.5 bootstrap impossible on a server. The only credential store is `LocalSocketCredentials`, which refuses every token kind.

## Decision

### Process and listeners

- `sm server` runs the daemon in server mode (Appendix A `ExecStart`); `sm daemon` stays the local-mode entry point.
- `server.tls.mode: direct`: TLS ≥ 1.2 with `cert_file`/`key_file`, served through `tls.Config.GetCertificate` so SIGHUP swaps the pair atomically. A failed reload keeps the old pair and logs an error.
- `server.tls.mode: proxy`: `server.listen` is loopback or `unix:`. `X-Forwarded-For` and `X-Forwarded-Proto` are read only when the TCP peer is inside `trusted_proxies`; otherwise they are ignored. A forwarded proto other than `https` is rejected with 400. A loopback peer gets no trust of any kind.
- Plain HTTP on a non-loopback address is refused at start (config validation, already in M0).

### Bearer credentials

- Format `sm<k>_<base64url(32 random bytes)>`, where `k` is `s` (session), `t` (API token), `b` (bootstrap code) or `j` (join token). A token of the wrong kind for an endpoint is refused before lookup.
- Only `SHA-256(token)` is stored, in a `UNIQUE` column, and looked up by it. Nothing is cached, so a revocation takes effect on the next request (§23).
- The HTTPS listener accepts `Authorization: Bearer` only. The Unix socket keeps refusing it (ADR-0014). There are no cookies, so CSRF does not apply (§23.1).
- `auth.CredentialStatus` replaces `LocalSocketCredentials` for both the request path and the claim-time check (§11.1). `local_socket` is always active; `session` and `api_token` are read from their tables (revoked or expired); every other kind is refused until its milestone.
- API tokens: mandatory expiry ≤ 365 days, scopes may only narrow the creator's permissions (§11.3 step 7), unique name per identity.
- Sessions: TTL `security.session_ttl`; origin `oidc` or `bootstrap`; `POST /auth/logout` revokes the presented session.

### Identities by mode

- Local mode: unchanged, `local:<uid>` is created and bound to `admin`.
- Server mode: the daemon ensures only the instance and the `system` identity. It never creates `local:<uid>`. The first admin comes from the bootstrap exchange (§11.5), which is refused once an `admin` binding exists, except during restore hold (§29.2).
- OIDC humans are identities keyed by `(human, issuer, subject, '')`; display name and email are metadata refreshed at each login.

### Admin socket

`server.admin_socket`, mode 0660, owned by the service user. The peer UID must be 0 or the service user (fail closed on lookup errors). It serves exactly `bootstrap-code`, `grant`, `restore-complete` and read-only `doctor` (§23.1, ADR-0012). It never serves key management.

### Limits and headers

- Token bucket per remote address on `/auth/*` and `/enroll` (10/min, burst 5) and per identity on writes (60/min, burst 20). An exceeded limit is 429 with `Retry-After`.
- Every response: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`; no CORS headers, so browsers refuse cross-origin calls.

### Event stream

- `GET /events/stream` (`event.read`), `text/event-stream`. Each frame is one event as JSON with `id: <seq>`. `Last-Event-ID` resumes after that sequence number.
- Heartbeat comment every 15 s; write deadline 10 s; at most 4 open streams per identity (the fifth is 429).
- The credential and `event.read` are re-evaluated every 30 s and whenever a `token.revoked`, `session.revoked` or `role_binding.*` event passes through the stream. If either fails, the stream ends.

### Startup order and restore hold

Server and local daemon start in the order fixed by ADR-0020: lock → restore-journal recovery → open and migrate → load `restore_hold` (an unreadable value refuses the start) → assemble → workers. During hold the engine claims nothing (the existing `jobs.Store.SetRestoreHold` gate) and the backup scheduler is off.

## Consequences

- One handler set serves two transports; the transport decides only how the `Caller` is authenticated.
- A restart of the server invalidates OIDC logins in progress (ADR-0018), never established sessions.
- The rate limits are fixed constants in M2; configurable limits would need new config keys (spec change).
