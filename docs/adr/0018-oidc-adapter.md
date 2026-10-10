# ADR-0018: OIDC adapter

- Status: Proposed
- Spec: §8.2, §11.5, §21.1, §23, §23.1 (1.4.3: discovery trust), §30, §32

## Context

In server mode the daemon is the OIDC client and holds the client secret (§23.1). The CLI logs in with PKCE through a loopback redirect, or with the device grant where the IdP refuses variable loopback ports. "Never invent cryptography" (§10) and the review of the M2 plan favour an established JWS verifier over hand-written parsing.

## Decision

### Libraries

- `github.com/coreos/go-oidc/v3` (Apache-2.0) verifies ID tokens and fetches the key set; it brings `github.com/go-jose/go-jose/v4` (Apache-2.0).
- `golang.org/x/oauth2` (BSD-3-Clause) builds authorization URLs with PKCE S256 and runs the token and device endpoints.
- Only `internal/auth/oidc` imports them (depguard).
- At the token endpoint the confidential client authenticates with `client_secret_basic` (`oauth2.AuthStyleInHeader`), never auto-detected.

### Discovery trust

- Fetched once at start (a restart picks up a changed document; key rotation is covered by the key set refetching `jwks_uri` on an unknown `kid`) through the `netguard` client for provider endpoints: private ranges allowed, loopback and metadata never, redirects disabled, body capped at 64 KiB.
- The document's `issuer` must equal `auth.oidc.issuer` byte for byte.
- `authorization_endpoint`, `token_endpoint`, `device_authorization_endpoint` and `jwks_uri` must be `https` and on the issuer's origin or on an origin listed in `auth.oidc.allowed_endpoint_origins`. Anything else refuses the start.
- `userinfo_endpoint` is never called; claims come only from the verified ID token.

### ID token verification

- Signature by a key from `jwks_uri`, algorithms RS256, ES256 or EdDSA only.
- `iss` equals the issuer, `aud` contains the client id, `azp` equals the client id when `aud` has several values, `exp` and `iat` with 60 s skew.
- `email_verified == true` and the email's domain is in `auth.oidc.allowed_domains` when that list is non-empty.
- A `jti`, when present, is inserted into `oidc_replay(issuer, jti, expires_at)`; a duplicate is `OIDC_REPLAY`. Expired rows are swept.

### Authorization code with PKCE (loopback)

- `POST /auth/oidc/start` accepts only `redirect_uri = http://127.0.0.1:<port>/callback` (RFC 8252) and an S256 challenge.
- The server stores `{state, nonce, redirect_uri, code_challenge, expires_at = now + 10 min}` in memory and returns the authorization URL with `nonce`.
- IdPs that match redirect URIs exactly (a Dex confidential client does, W0 spike) are served by `sm login --callback-port <n>`, which pins the loopback port to one registered value; the device grant remains the fallback.
- `POST /auth/oidc/exchange` consumes `state` exactly once, redeems the code with `code_verifier` and the same `redirect_uri`, verifies the ID token and requires `nonce` to match.

### Device authorization grant (RFC 8628)

- `POST /auth/oidc/device` starts a device authorization at the IdP. The server keeps a transaction `{txn_id (random 128 bits), device_code, interval, expires_at = IdP expires_in}`; the IdP device code never leaves the server. The client receives `txn_id`, `user_code` and the verification URIs.
- `POST /auth/oidc/device/poll` takes `txn_id`. Polls of one transaction are serialized. A poll sooner than `interval` answers `slow_down` and adds 5 s to the interval (as the IdP would). The server polls the IdP at most once per client poll.
- Completion is single use: the first successful poll returns the session and deletes the transaction; any later poll is `CONFLICT`. An expired transaction is `UNAUTHENTICATED`/`OIDC_INVALID`.
- `client_id` and `client_secret` are sent as form fields at the device endpoint (Dex ignores HTTP Basic there). Dex then echoes the secret in the browser verification URL; `docs/configuration.md` states this, and production use of the device flow with Dex needs a dedicated client.
- IdPs may return tokens for the same device code more than once (Dex does); single use is enforced by the server, not assumed from the IdP.
- RFC 8628 has no nonce parameter; the device flow therefore does not require one and relies on the single-use, server-held device code plus `iss`, `aud` and `exp`.

### State and restarts

Login state and device transactions live in memory, bounded (1,000 entries, oldest evicted). A restart invalidates logins in progress; the user retries. Sessions are unaffected.

### Bootstrap

With OIDC configured, `POST /auth/bootstrap` is called with the session of a completed login and binds that identity to `admin` (§11.5).

## Consequences

- Three new modules, all under licenses in the dependency-review allowlist (`x/oauth2` added to the `x/` entry).
- Dex is the test IdP; `docs/configuration.md` lists only IdPs actually tested.
- An IdP that serves keys or tokens from another origin needs `allowed_endpoint_origins`.
