# ADR-0038: Reaching the Proxmox API through the host's SSH connection

- Status: Proposed
- Spec: §15.1, §21.1; spec `docs/specs/proxmox-via-node.md`; ADR-0009, ADR-0024, ADR-0025, ADR-0034, ADR-0037

## Context

The Proxmox provider dials `endpoint` over HTTPS through netguard, so a PVE host is manageable only from a network that routes to port 8006. A PVE 9 host is a Debian 13 machine with `sshd`, so it can be an SSH node, reached directly or through Cloudflare Tunnel (ADR-0037). The API then sits at `127.0.0.1:8006` on the far side of a connection whose host key SuperMgmt already pins.

## Decision

### A relay session, not port forwarding

- The dedicated key stays `restrict`, as ADR-0009 requires. No form of SSH forwarding (local, remote, stream-local) is enabled, and this ADR amends nothing in ADR-0009.
- The provider reaches the API through an SSH **session** as the dedicated account that runs one argument-free catalog template, `proxmox.api.relay`: `<socat> STDIO TCP:127.0.0.1:8006`. The session's stdio is the connection, under the carrier contract of ADR-0037: bounded open, cancellation, deadlines, idempotent close, sanitized stderr and one release of the pooled lease.
- The destination is in the template body. No API, configuration or plan can name another one. The only parameter is the `socat` path setup recorded, which must be in `/usr/bin`, `/bin` or `/usr/local/bin`.
- Port forwarding with `permitopen` was rejected. Restricting it fully needs `permitlisten` and stream-local controls whose behaviour depends on the OpenSSH build, and it would amend ADR-0009 for a capability the relay provides without forwarding.

### Setup detects; it never assumes

`sm nodes setup <node> --proxmox` adds one step between the tunnel step and `authorized_keys`. On every run, everything it relies on is detected or proved on the host:

- The PVE major version comes from `pveversion`. Anything other than 9 fails before any change.
- `socat` is installed from the host's own Debian repositories when it is absent, then resolved again.
- The TLS server name comes from the leaf certificate's SANs, read through the relay, as the first of `localhost`, `127.0.0.1` and the hostname. If none of them is present, the step fails and lists the SANs it found.
- The step finishes with an authenticated `GET /version` through the relay before the metadata is written.

### Identities and the token

- PVE identities are instance-owned and shared with the appliance installer (`internal/pveid`): user and roles carry the instance ID and an owner comment. A foreign identity with the same name is refused, never adopted.
- The token is privilege-separated, with explicit token ACLs. It is created by a setup command whose **stdout** is secret (`SecretOutput`): the executor, the stepper and every error path drop that output. The token is stored at `secret://proxmox/<node>` as soon as it is created.
- PVE shows a token secret once, so a lost secret is never recovered: the owned token is deleted and created again. The token ID (`user@realm!name`) is public metadata; audit records it, and never the secret.

### Trust

- The CA (`/etc/pve/pve-root-ca.pem`) is read through the pinned SSH connection and recorded in `SetupMeta.Proxmox` (setup version 4). It is not a secret.
- Every handshake verifies the chain to that CA and the recorded server name. `verify_tls: false` stays invalid.
- Cloudflare, when the node is tunnelled, carries only SSH, whose host key it cannot forge (ADR-0037). TLS to PVE runs inside that session.

### Configuration and resolution

- A provider names exactly one of `endpoint` and `via_node`. `credential_ref`, `ca_file` and `tls_server_name` override what setup recorded.
- Validation checks only the shape, because nodes also come from the API. The node is resolved at every sync, and a missing node, a node that is not SSH, or a node with no Proxmox metadata makes the provider unavailable with the fix named.
- One resolver feeds both the sync and the power path.
- The client cache key covers the node, its spec revision, its host key, the setup metadata and the server name. A replaced client closes its idle relays.
- The relayed HTTP client applies netguard's request rules and body cap (`netguard.Guard`), but does not use netguard's dialer, because its connection is already bound to a single destination.

## Consequences

- A remote PVE host needs no open port 8006 and no hand-made token.
- With a tunnelled PVE host, Proxmox management depends on Cloudflare's availability.
- The dedicated account can run one more command, which reaches only the API, whose authority is already the token's.
- The power role lets SuperMgmt start and stop every guest, the same scope the appliance has.
- Tested against fakes only. The feature is experimental until `docs/manual-checks/proxmox-via-node.md` has passed on a real PVE 9 host, both directly and through a tunnel.
