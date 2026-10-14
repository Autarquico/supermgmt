# ADR-0022: Join and enrollment (minimal)

- Status: Accepted
- Spec: §9 (`join_tokens`), §11.2 (`enrollment.create`), §13, §46; ADR-0009, ADR-0016

## Context

§13 offers `join.sh` for managed enrollment without a permanent agent. ADR-0009 already defines how the dedicated `supermgmt` user and its `restrict`ed key line are created, but over SSH from the server with an `admin_user`. Join reverses the direction: the node runs as root and reaches the server over HTTPS with a single-use token.

## Decision

### Issuing

- `POST /enrollments` (`enrollment.create`, credential-issuing, never approval-gated) returns a join token `smj_…` once; only its hash is stored.
- Constraints in `constraints_json`: `tags` applied to enrolled nodes, `max_nodes` (default 1), `source_cidrs` (empty: any), and expiry ≤ 24 h.

### Joining

`scripts/join.sh` verifies and unpacks `sm` exactly like `install.sh` (ADR-0019), then runs `sm join --server <url> --token-stdin`. The token comes from stdin or a prompt, never an argument (§13).

1. `sm join` reads the node's host public key (`/etc/ssh/ssh_host_ed25519_key.pub`, else ECDSA, else RSA), hostname and addresses.
2. `POST /enroll` (`exempt:auth`) with the token and that data. Server TLS is verified with the system roots or a `--ca-file`.
3. The server consumes the token in one transaction: it checks expiry, `uses < max_nodes` and `source_cidrs` against the request's client address (after the proxy rules of ADR-0017), creates the node (`management_state = managed`, pinned host key, `user = supermgmt`, tags), and records the token id and the request digest in the node's `metadata_json`.
4. The response carries the node id, the instance id and **the instance SSH public key `ssh/default` at its current version** with its fingerprint (ADR-0016).
5. On the node, `sm join` runs the ADR-0009 (d) user steps locally as root: create or adopt-only-if-ours the `supermgmt` user, home and modes, `markers/`, and `.ssh/authorized_keys` with the single line `restrict <key> supermgmt@<instance_id>`. Nothing else.

### No privilege grant

Join writes no sudoers and joins no `docker` or journal group. Those stay `node.setup`, an approval-gated job run with an `admin_user` (ADR-0009), so join cannot bypass `sudoers.write`. A joined node advertises read capabilities only until setup runs.

### Lost response and retries

- `request_digest = SHA-256(host_public_key ‖ 0x00 ‖ hostname)`.
- Before `expires_at`, a request whose token and digest match a node already enrolled with that token returns that node's result (same node, same key line) without using another slot; `sm join` is therefore safe to re-run after a lost response.
- A new digest on an exhausted token (`uses = max_nodes`) is `CONFLICT`.
- Enrollment never mutates an existing node. Any other request whose digest matches a node already enrolled (a fresh token, an exhausted token, a different token) is `CONFLICT`: no slot is used, tags are untouched, and the refusal is audited as `enrollment.denied` with the reason. The digest inputs (host public key, hostname) are public, so possession of a token cannot be allowed to change a node; changing tags is an authenticated `node.update`.
- Only the exact replay above (token id recorded on the node and same digest, token not expired or invalidated) is answered from the stored node.

### Out of scope

Overlay networks, outbound tunnels and any resident agent.

## Consequences

- A stolen join token is single-use, short-lived, source-restricted and yields only an unprivileged, read-only node entry pinned to the thief's host key; it never grants access to other nodes.
- `node.setup` after join still needs an `admin_user` credential.
