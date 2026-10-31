# ADR-0039: Adding a node that is reachable only through Cloudflare Tunnel

- Status: Proposed
- Spec: spec `docs/specs/node-enroll-tunnel.md`; ADR-0009, ADR-0019, ADR-0022, ADR-0037

## Context

ADR-0037 turns a node that is already reachable directly into a tunnel node: the host key is scanned over a direct dial, and `cloudflared` is installed through the admin's SSH session. ADR-0022's join flow does not need inbound SSH, but the node calls the server back over HTTPS, which an instance on a laptop cannot answer. A host behind NAT, or a VPS with every inbound port closed, cannot be added at all.

## Decision

### An enrollment record, no pending node

- `sm nodes add --name <n> --tunnel` creates a `tunnel_enrollments` row and allocates the node ID up front. The ID has to exist this early because the Cloudflare object names embed it.
- No node row exists until the commit. A pending management state would need a new enum value, filters in every listing and probe path, and guards on every mutation. A `discovered` row would be listed and probed.
- The enrollment keeps:
  - the phase;
  - the Cloudflare object IDs, written once;
  - the adoption timestamp;
  - the SSH identity snapshot: the public key, its fingerprint and the versioned secret reference;
  - the scanned host key, and the confirmation bound to it.
- Provisioning reads and advances its record through one interface, implemented by both `tunnel_operations` and `tunnel_enrollments`. Creation order, names and adoption are those of ADR-0037.
- The name is reserved across providers and open enrollments by every path that creates a node, and the commit checks it again.

### No node-to-server channel

- The operator runs one line on the node:
  ```
  join.sh --tunnel --instance <id> --authorized-key <key>
  ```
  The line carries only public values. join.sh verifies the signed `sm` (ADR-0019) and runs `sm join --tunnel`.
- **Before changing anything**, `sm join --tunnel` checks the distribution, systemd, root, the host key and the ownership of the `supermgmt` account.
- **The token.** It reads the connector token from `/dev/tty` without echo, or from stdin, and refuses it in argv.
- **Installation.** It installs `cloudflared` with exactly the keyring, source, unit and token path that node setup uses: shared Go content, run as root locally. It then provisions the dedicated account, with one `restrict` line (ADR-0009).
- **Fingerprint.** It prints the host key fingerprint.
- **Where the token lives on the instance.** It is held in the secret store for the enrollment's lifetime, shown only on the operator's terminal to an authorized caller, and deleted at the commit, at expiry and at cancellation.
- **Why not fetch the token from Cloudflare on demand.** That would require keeping the provisioning API access, which ADR-0037 allows removing.

### The human binds the host key

- The daemon scans the host key over the tunnel, after the Access preflight, and persists it.
- The operator confirms that exact key, either with `--fingerprint` or interactively. The confirmation is a compare-and-swap against cancellation and expiry.
- The proof probes an in-memory node as the dedicated account over the tunnel. It uses the confirmed key, pinned with its exact bytes, and the snapshotted identity.
- The commit writes everything in one fenced transaction:
  - the provider and node rows, with `transport: cloudflare`;
  - durable `tunnel_only` provenance;
  - a committed `tunnel_operations` row;
  - the audit event.

### Lifecycle

- The enrollment runs as short jobs (provision, scan, commit, cleanup); the row holds the state between them. A scheduler re-arms the scan with backoff until the expiry: 1 h by default, 24 h at most.
- **Expiry or cancellation** removes the enrollment's own objects in the disable order: DNS, then the ingress closed, then the Access application, then the tunnel.
  - The instance's shared policies and service token are kept.
  - Objects created but never recorded are reconciled first.
  - Progress is persisted, and the name is released only when nothing is left.
- **Disabling the tunnel** on a `tunnel_only` node is refused, because it has no direct path to fall back to.

## Consequences

- Any Debian 13 or Ubuntu 24.04 host with outbound HTTPS can be managed from a laptop, with no inbound port.
- The fingerprint comparison is the only binding between the host the line ran on and the key that gets pinned. It is the same trust `sm nodes add` asks for today.
- A tunnel-only node depends on Cloudflare entirely. If its tunnel breaks, it is recovered with a new enrollment.
- The node has only the dedicated account until an operator adds an admin, so setup steps that need root are not available at first.
- Tested against fakes only. The feature is experimental until `docs/manual-checks/node-enroll-tunnel.md` has passed with a real account and a host with no inbound port.
