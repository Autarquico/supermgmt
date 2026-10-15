# ADR-0037: Reaching SSH nodes through Cloudflare Tunnel

- Status: Proposed
- Spec: §8.4, §12, §16, §25; spec `docs/specs/cloudflare-tunnel-transport.md`; ADR-0009, ADR-0015, ADR-0030, ADR-0034, ADR-0035, ADR-0036

## Context

SSH nodes are dialled directly (`internal/transport/ssh/pool.go`, `hostkey.go`), so a node is reachable only while the control plane can route to it. The maintainer chose Cloudflare Tunnel with Zero Trust Access, provisioned entirely by SuperMgmt through the Cloudflare API, with `cloudflared` installed on the node by setup. Evidence from `cloudflared` 2026.10.1 and the API documentation is in the spike (`.claude/loop/cloudflare-tunnel-transport/spike.md`, summarised below). Cloudflare stays optional (§25).

## Decision

### Transport seam

- A node endpoint carries `transport` (`direct` or `cloudflare`; absent means `direct`; anything else is rejected) and `tunnel_hostname`. Both live in the endpoint JSON (no column change) and are owned by the tunnel jobs. **Amendment to ADR-0009:** static-configuration reconciliation never writes these two fields; setup still never rewrites configured fields.
- `ssh.Target` carries the transport. A `Dialer` returns a `net.Conn`; the pool and `ScanHostKey` use it. Host-key pinning, credentials, handshake classification and every template are unchanged.

### Carrier: a `cloudflared access ssh` subprocess

- The `cloudflare` dialer runs the absolute path of `cloudflared` with argv `access ssh --hostname <h>`, and uses its stdio as the connection. A native Go implementation of the Access websocket carrier and a local TCP listener (`access tcp --url`) were considered: the first maintains an undocumented protocol, the second owns a port and its readiness. Both stay options.
- The environment is exactly `TUNNEL_SERVICE_TOKEN_ID`, `TUNNEL_SERVICE_TOKEN_SECRET` and `HOME` (a private empty directory): no `PATH`, so cloudflared's browser fallback (`token/shell.go`) cannot find `open` or `xdg-open`; no log variables, no `--logfile`, never debug, because debug logging dumps the request headers including the secret (`carrier/websocket.go:57-60`); no proxy variables.
- Before spawning, the daemon sends its own HTTPS request with the service-token headers to `https://<hostname>` through netguard; an Access login redirect means the token is not admitted, and the dial fails without spawning.
- Lifetime contract: the child lives as long as the connection, not the dial context; startup and handshake are bounded; deadlines unblock reads and writes; `Close` is idempotent and concurrent-safe; stderr is drained with a bound and sanitized before it reaches an error; `Wait` runs exactly once; termination escalates from SIGTERM to SIGKILL; cleanup runs on handshake failure, eviction and daemon shutdown.

### Credentials, split by purpose

- **Provisioning:** a Cloudflare API token at `secret://cloudflare/api-token`, with account *Cloudflare Tunnel: Edit*, *Access: Apps and Policies: Edit*, *Access: Service Tokens: Edit* and zone *DNS: Edit* (labels to confirm on a real account). Only tunnel jobs read it; it can be removed after provisioning. Blast radius: whoever holds it can open tunnels and Access applications in the account; this is documented.
- **Runtime:** one Access service token per instance at `secret://cloudflare/access-service-token` (`client_id:client_secret`). The dialler reads only this. Rotation overlaps: create, add to every owned policy, switch, remove from policies, delete.
- **Node:** the tunnel token, fetched inside the job and streamed over SSH stdin into `/etc/supermgmt/cloudflared/token` (root, 0600). `cloudflared service install <token>` is not used because it takes the token as an argument; setup writes its own unit with `tunnel run --token-file`.
- None of the three appear in plans, payloads, events, logs, views, errors, child argv, units, journals or backup plaintext.

### Ownership and the operation record

- Cloudflare offers no settable marker on tunnels (`metadata` is read-only), so names are the marker: tunnel `sm-<instance-id>-<node-id>`, Access application `supermgmt <instance-id> <node-id>`, policies `supermgmt service|owners <instance-id>`, service token `supermgmt-<instance-id>`; DNS records also carry the comment `supermgmt:<instance-id>:<node-id>`.
- Migration `000007` adds the operation record: node, generation, account, zone, instance ID, phase, phase start time and every object ID. After an ambiguous response the job looks up by exact name (paginated) and adopts an object only if the record shows that phase started and the object was created no earlier than the phase start; otherwise it is a conflict and the job stops.
- Order of creation: tunnel, ingress, Access application and policies, then DNS. Order of removal: DNS and ingress, then Access, then the tunnel. The hostname is never routable without its Access application.

### Concurrency

- Enable and disable hold the node's resource lock; service-token initialisation and rotation hold an instance-wide lock. The lease is checked before every external mutation and the job cancels on lease loss. A fence cannot stop a request Cloudflare already accepted, so a takeover first reconciles the record against Cloudflare.
- The switch is a conditional endpoint update against the expected revision, made after a fresh connection through the candidate transport passed the pinned host key and the dedicated-account verification. Pooled connections of the old transport are retired.

### Trust boundary

Cloudflare routes the connection and carries the outer stream. It sees connection metadata and can deny service; it cannot impersonate a node without the node's SSH host key, because the pin is enforced over the tunnel. No step repins automatically. Access admission for an owner grants neither an SSH login nor any SuperMgmt privilege.

### Restore

Backups keep the record and object IDs; secrets stay the existing encrypted records. A restored instance mutates nothing in Cloudflare before `sm admin restore-complete`, then reconciles.

### Claims

The feature is **experimental** and **fake-verified** (ADR-0036 vocabulary) until the real-account checklist passes. Cloudflare's API and `cloudflared` join the egress inventory in `docs/dependencies.md`.

## Consequences

- The daemon host needs `cloudflared` for tunnelled nodes; `sm doctor` reports it.
- Setup gains privileged steps (apt source, keyring with a pinned fingerprint, package, token file, unit); `SetupVersion` becomes 3.
- A node whose direct path is closed depends on Cloudflare's availability.
