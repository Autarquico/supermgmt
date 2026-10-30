---
codename: supermgmt
title: Reach the Proxmox API through the host's SSH connection
type: epic
status: active
priority: P1
size: L
issue: 45
prs: [46]
related_issues: [45]
depends_on: []
supersedes: []
related_specs: [cloudflare-tunnel-transport]
created: 2026-10-29
updated: 2026-10-30
---

# Reach the Proxmox API through the host's SSH connection

## Contexto / problema

The Proxmox provider reaches the PVE API over a direct HTTPS dial to `endpoint` (`internal/providers/proxmox/client.go:84-111`). The dial goes through netguard, which always refuses loopback (`internal/netguard/filter.go:9-14`), and the client takes no other dialer (`client.go:38-55`). So a Proxmox host is manageable only from a network that routes to its port 8006. A laptop away from home loses it, and exposing 8006 to the internet is not acceptable.

SSH nodes no longer have that limit: a node can be reached through Cloudflare Tunnel (`docs/cloudflare.md`, ADR-0037), with the host key pinned over the tunnel. A Proxmox VE 9 host is a Debian 13 machine with `sshd`, so it can be an SSH node like any other, direct or tunnelled. Once it is one, the PVE API is one hop away: `127.0.0.1:8006` on the far side of an SSH connection SuperMgmt already authenticates.

Maintainer goal (2026-10-29): from their own machine, SuperMgmt manages the Proxmox host and its guests wherever the host is, and the user provides only the Cloudflare credentials. No manual tunnel, no open port, no PVE token created by hand.

## Scope

**Entra:**

1. **Provider over a node.**
   - A Proxmox provider can name `via_node: <node>` instead of an `endpoint`; exactly one of the two is set (validation error otherwise).
   - With `via_node`, `credential_ref` and `ca_file` are optional and default to what node setup recorded (item 4).
   - The node must be an SSH node whose `node.setup` capability carries the Proxmox metadata. Until it does, the provider is `unavailable`, with a message naming `sm nodes setup <node> --proxmox`.
2. **Dial seam in the Proxmox client.**
   - `proxmox.WithDialer(func(ctx) (net.Conn, error))` replaces the network dial and netguard for that client only. The HTTP request host and the TLS server name are fixed by the client, never by the API's answers, and redirects stay off.
   - The Proxmox client options are the only way in; netguard is unchanged for every other caller.
3. **A relay session, not port forwarding.** ADR-0009 keeps the dedicated key `restrict` (no forwarding of any kind), and this spec does not amend that.
   - `Pool.OpenRelay(ctx, target, templates.ProxmoxAPIRelay)` opens an SSH **session** as the dedicated account running one fixed catalog command, `socat STDIO TCP:127.0.0.1:8006` (the path setup recorded, item 4). The session's stdin/stdout is the returned `net.Conn`, the same carrier contract as the cloudflared child in ADR-0037: bounded open, context-cancelled with late results cleaned up, deadlines, idempotent `Close`, stderr drained and sanitized, exactly one release of the pooled lease.
   - Relays count against the pool's per-connection session limit (`pool.go:43-51`); the provider client keeps at most 2 idle relays and closes them after 30 s idle.
   - The destination is part of the template, not a parameter any API, config or plan can set. The template takes no arguments.
   - Works over both transports (`direct`, `cloudflare`), because it rides on the SSH connection.
4. **`sm nodes setup <node> --proxmox`** (palette: `setup <node> proxmox`), approval-gated like every setup, with the admin bootstrap and the lease checks it already does before every node mutation. One step after the tunnel step and before `authorized_keys`:
   1. detects, never assumes: the node is a PVE 9 host (`pveversion`, parser `internal/installer/pve.go:51`, major `supportedPVEMajor`), else `CAPABILITY_UNAVAILABLE` before any change; `socat` is resolved from fixed directories, and when absent it is installed with `apt-get install socat` from the host's own Debian repositories (the same apt path the tunnel step uses), then resolved again; its path is recorded;
   2. creates or verifies the **instance-owned** identities exactly as the appliance installer does (`internal/installer/proxmox_steps.go:371-411`, shared code, not copied): user and roles named with the instance ID, owner comment checked, a foreign identity of the same name refused, never adopted;
   3. creates a **privilege-separated** token with the installer's explicit token ACLs (`pve.go:674`, `proxmox_steps.go:445-460`), as a sensitive-output command whose JSON is parsed strictly (an unexpected shape fails the step without echoing the output), and stores it immediately as `secret://proxmox/<node>`. If the token exists but the store has no secret (lost after an ambiguous outcome), the job deletes that token, which is ours by the owner check, and creates it again; it never reads or rotates a token it does not own;
   4. reads `/etc/pve/pve-root-ca.pem` and the node's hostname;
   5. **discovers and proves TLS**: through a relay as the dedicated account, a handshake that verifies the chain to the CA and reads the leaf's SANs; the server name is the first of `localhost`, `127.0.0.1`, the node's hostname that the leaf names, and none matching is `CAPABILITY_UNAVAILABLE` naming the SANs found; then one authenticated `GET /version` with the stored token;
   6. records `SetupMeta.Proxmox{CAPEM, TokenRef, TokenID, TLSServerName, RelayPath, InstalledAt}` in setup's fenced capability write. The CA and the token ID are public metadata; the CA is pinned through the SSH host key.
   - `SetupVersion` becomes 4; versions 1–3 read as "no Proxmox".
   - Re-running with `--proxmox` is idempotent. A setup without it keeps the existing Proxmox state, like `--tunnel` (`internal/api/wire/setup.go:152`).
5. **Sensitive-output setup commands.** The template catalog gains an explicit kind for a setup command whose **stdout** is secret (today `Sensitive` means stdin and is refused on non-mutating or setup templates, `catalog.go:188-191`). Its sensitivity survives rendering and the stepper (`internal/runtimes/systemd/setup.go:158`), and stdout/stderr are dropped from every error path.
6. **TLS over the relay.** The certificate must chain to the recorded CA and match the recorded `TLSServerName`; a provider may override the name as `tls_server_name` (strict DNS name or IP literal). `verify_tls: false` stays a validation error. Without a proven handshake no request carries the token.
7. **Daemon wiring.**
   - Configuration validation checks only the shape (exactly one of `endpoint`, `via_node`; names well formed), because nodes also come from the API, not just the file. The node is resolved at every sync: missing, not SSH or without Proxmox metadata makes the provider `unavailable` with a message naming the fix. Reconcile order does not matter.
   - One resolver returns the effective credential, token identity, CA, server name and node target together; `clientFor` and the power path's token-identity read (`proxmox_evidence.go:206`) both use it.
   - The client cache key includes the node ID, its spec revision, the host key fingerprint, the setup metadata hash and the effective server name. Replacing a client closes its idle relays, so a repin or transport switch takes effect at the next sync.
   - `sm providers check <name>` works online for `via_node` providers through the daemon; `--offline` keeps its endpoint-only behaviour.
8. **Policy and audit.** New setup parameter `proxmox` in the policy catalog, like `ParamTunnel` (`internal/policy/catalog.go:84`). Audit records token creation and deletion with the public token ID (`user@realm!name`), never the secret.
9. **Docs.**
   - `docs/providers.md`: Proxmox through a node, which becomes the recommended remote layout.
   - `docs/cloudflare.md`: a Proxmox host as a tunnel node.
   - Updates to `docs/security.md` (the relay command and the token's scope), `docs/configuration.md`, `docs/project-status.md` (experimental, fakes only) and `docs/manual-checks/proxmox-via-node.md` (a real PVE 9 host, direct and tunnelled).

**No entra:**
- Adding a node that was never directly reachable (spec `node-enroll-tunnel`). Until then the PVE host is first added directly, and then optionally switched with `--tunnel`.
- Writing the provider block into the config file. The user adds three lines (`type`, `name`, `via_node`) and the setup job prints them.
- Clusters with several PVE hosts reached through different nodes. One provider has one `via_node`; a cluster answers for all its members through that node.
- Snapshots, backups, consoles, or any provider operation beyond what exists today (`docs/providers.md:139`).
- The `proxmox-lxc` appliance: unchanged.

## Criterios de aceptación

### Scenario: the provider reaches PVE through the node, wherever it is
- **Given** a node `pve1` set up with `--proxmox`, reachable only through its SSH connection (direct or `cloudflare`), and a provider `{type: proxmox, name: pve, via_node: pve1}`
- **When** the daemon syncs the provider
- **Then** it discovers the cluster's nodes and guests over relay sessions to `127.0.0.1:8006`, opens no network connection to port 8006, and the guests' power actions work through the same path

### Scenario: one host, one destination, no forwarding
- **Given** the dedicated account's key on a Proxmox node
- **When** anything asks that connection for local TCP, remote TCP or stream-local forwarding
- **Then** sshd refuses it (`restrict`, unchanged), and the only path to the API is the argument-free relay template, whose destination no API, config or plan can change

### Scenario: TLS is verified against the CA the host gave over the pinned connection
- **Given** a provider through `pve1`
- **When** the service on 8006 presents a certificate that does not chain to the recorded CA, or a name that does not match `tls_server_name`
- **Then** the sync fails with a TLS error naming the provider, and no request carrying the token is sent

### Scenario: setup creates the PVE identity and token without the user
- **Given** a PVE 9 host added as a node with an admin user, and no SuperMgmt identity on it
- **When** `sm nodes setup pve1 --proxmox` is approved and runs
- **Then**
  - the instance-owned user, roles, ACLs and privilege-separated token exist on the host;
  - a TLS handshake and an authenticated `GET /version` succeeded through a relay before the metadata was written;
  - the token is only in the secret store, under `secret://proxmox/pve1`;
  - the CA is in the setup metadata;
  - the job prints the three-line provider block;
  - neither the token nor anything derived from it appears in argv, logs, the audit trail, job output or the plan.

### Scenario: re-running repairs and never leaks
- **Given** a node already set up with `--proxmox` whose stored token was deleted
- **When** setup runs again with `--proxmox`
- **Then** the owned token is deleted and recreated under the same ID and stored again; a token or user of the same name that is not owned by this instance is refused, never replaced

### Scenario: not a Proxmox host
- **Given** a Debian node without `pveversion`, or a PVE 8 host
- **When** setup runs with `--proxmox`
- **Then** setup fails before changing anything Proxmox-related with `CAPABILITY_UNAVAILABLE` naming the reason, and no PVE identity is created

### Scenario: configuration mistakes are refused
- **Given** a provider with both `endpoint` and `via_node`, or neither; or one whose `via_node` names an unknown node, a non-SSH node, or a node without Proxmox metadata
- **When** the configuration loads, or the provider syncs
- **Then** the shape errors fail validation naming the field, whatever the order of the entries; the reference errors make the provider `unavailable` with a message naming the fix (`sm nodes add`, `sm nodes setup <node> --proxmox`)

### Scenario: the endpoint case is unchanged
- **Given** an existing provider with `endpoint: https://pve.lan:8006`
- **When** it syncs after this change
- **Then** it behaves exactly as before: netguard filtering, no node dependency, and the same configuration and errors

### Scenario: node changes invalidate the client
- **Given** a cached client for a provider through `pve1`
- **When** `pve1` is repinned, its transport switches, its setup metadata changes, or it is removed
- **Then** the old client's relays are closed, the next sync builds a new client over the new connection, or reports the provider `unavailable` when the node is gone; the power path resolves the same credential as the sync

## Notas técnicas / riesgos

- **No assumptions about the host.** Everything setup relies on (PVE version, relay tool, certificate names, `pveum` output) is detected or proved by the step itself on each run and recorded in the metadata; nothing is taken from documentation. The manual checklist runs the same step against a real PVE 9 host.
- **Files:**
  - Proxmox client: `internal/providers/proxmox/client.go` (options and HTTP client construction).
  - Pool and relay: `internal/transport/ssh/pool.go`, a new `relay.go` (session carrier, reference on the live connection), modelled on `dial_cloudflare_conn.go`.
  - Setup: `internal/runtimes/systemd/setup.go:85-108`.
  - PVE tooling: share `internal/installer/pve.go` through a runner backed by the setup's root executor. That needs new templates in the fixed catalog `internal/transport/ssh/templates/` (pveversion, pveum user/role/acl/token, reading the CA, hostname, the relay), each with validated arguments, plus the sensitive-output kind (`catalog.go`).
  - Metadata: `internal/runtimes/runtime.go:90-132`.
  - Config: `internal/config/provider.go:49`, `validate.go:355`.
  - Static reconcile: `internal/app/staticconfig.go:317-330`.
  - Sync: `internal/app/proxmox_sync.go:448`.
  - CLI: `internal/cli/providers.go:269-299`, `internal/cli/nodes_setup.go`.
  - Policy: `internal/policy/catalog.go`.
- **Testing:**
  - The node fixture runs `socat` to the existing PVE fake (`internal/providers/proxmox/pvefake`) served with TLS from a test CA.
  - The fake `pveum` and `pveversion` live in the node fixture image for the setup step.
  - Fuzz the new parsers (pveum token JSON, CA PEM read).
  - Secret scans cover the token through the sensitive-output path.
- **Risks:**
  - The power role lets SuperMgmt start and stop every guest; the scope is the same as the appliance's.
  - The relay template is the one new command the dedicated account runs; it reaches only the API, whose authority is already the token's.
  - A PVE host reached only through Cloudflare depends on Cloudflare's availability (as in ADR-0037).
- **ADR-0038:**
  - the provider over a node and the fixed-destination channel;
  - the relay session instead of forwarding, keeping ADR-0009's `restrict`;
  - the CA pinned through the SSH host key;
  - instance-owned identities and the token recreated, never read or adopted.

## Tasks (no autoritativo — el board manda)

- [ ] ADR-0038
- [ ] `proxmox.WithDialer`; `Pool.OpenRelay` and the relay template
- [ ] Config `via_node` / `tls_server_name`, validation, static reconcile
- [ ] Setup step `--proxmox`: sensitive-output kind, catalog templates, shared PVE runner, TLS proof, metadata v4
- [ ] Daemon wiring: sync, power actions, client cache invalidation, `providers check`
- [ ] Fixtures: relay to `pvefake` over TLS; fake PVE tools; a host without `socat`; leaves with each SAN layout
- [ ] Policy, audit, docs, manual checklist

## Referencias

- ADR-0037 (Cloudflare Tunnel transport), ADR-0009 (node setup), ADR-0024 and ADR-0025 (Proxmox provider), ADR-0015 (handoff isolation).
- OpenSSH `authorized_keys(5)` (`restrict`); `socat(1)`.
- Proxmox VE: `pveum user token add`, `/etc/pve/pve-root-ca.pem`, `pve-ssl.pem`.
