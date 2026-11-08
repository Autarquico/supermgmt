# ADR-0044: MCP client tokens over HTTPS, opt-in and per client

- Status: Accepted
- Amends: ADR-0032
- Spec: `docs/specs/mcp-https-token.md`; ADR-0033, ADR-0043

## Context

ADR-0043 makes reaching any instance through MCP the top priority. ADR-0032 made `smm_` tokens a stdio-only credential, accepted only on the local socket. A server has no API socket, so a token registered on a server or an appliance is usable nowhere, and the only remote path is OAuth with an external authorization server, which a single-operator lab does not have.

## Decision

The stdio bridge stays on the workstation and calls the server's `/api/v1` with an `smm_` token. MCP as a protocol stays off the network, so ADR-0033 is unchanged: `/mcp` still requires OAuth.

A token works over HTTPS only if **both** hold:

- the server sets `mcp.token_over_https: true` (default `false`, server mode only);
- the client was registered for it (`over_https`, set at registration and covered by the approved plan).

With the flag off, the server has no resolver for these tokens and refuses them on their prefix, with no database lookup. With the flag on, the lookup is restricted to marked clients, so an unmarked token is answered exactly like an unknown one. Registration refuses what could not work: a marked client with the flag off, an unmarked local client on a server, a marked client on a local instance, or a marked OAuth client.

Marked clients expire by default after 30 days, and the server caps them at 90. The audit source says which path was used (`mcp_socket` or `mcp_https`).

The bridge sends only the MCP token. It never reads a stored human credential, and MCP keychain entries live in their own namespace (`mcp/<name>`) so that `--keychain` cannot resolve to one.

## Consequences

- A leaked marked token is usable from the network until it expires or is revoked. It cannot approve, issue credentials or open sessions, because the floor keys on the identity type, not the transport; it can read the inventory and logs and request what policy grants.
- Failed bearer attempts on `/api/v1` are not rate limited per address, as for API tokens today; a token carries 32 random bytes.
- A registration approved before the flag was turned off still yields a marked client, and the resolver refuses it at use.
- Tokens stored in a keychain under the old bare name are no longer read: remove the client and add it again.
