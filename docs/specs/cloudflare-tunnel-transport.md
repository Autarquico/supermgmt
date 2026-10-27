---
codename: supermgmt
title: Reach SSH nodes through Cloudflare Tunnel
type: epic
status: active
priority: P1
size: XL
issue: null
prs: [36]
related_issues: [31]
depends_on: []
supersedes: []
related_specs: []
created: 2026-10-15
updated: 2026-10-27
---

# Reach SSH nodes through Cloudflare Tunnel

## Contexto / problema

SSH nodes are reached by a direct TCP dial to `host:port` (`internal/transport/ssh/pool.go:400`, `hostkey.go:55`). That works only while the control plane can route to the node: a laptop that leaves the home network loses its home nodes, nodes behind NAT need an open port 22, and a public VPS exposes SSH to the internet.

Cloudflare Tunnel solves reachability: `cloudflared` on the node keeps an outbound connection to Cloudflare, a hostname routes to the node's `ssh://localhost:22`, and a Cloudflare Access application in front of that hostname admits only SuperMgmt's service token (automation) and the owners' own identities (interactive sessions). No inbound port, no public IP, any network.

Maintainer decisions (2026-10-15): Cloudflare Zero Trust with Access; `sm nodes setup` installs `cloudflared`; **SuperMgmt provisions every Cloudflare object through the API** (a flow that needs manual dashboard steps per node is not exportable to other users). Spec §25 still holds: Cloudflare is optional and nothing in the core requires it.

The feature ships as **experimental** until the real-account checklist has passed (see Testing).

## Scope

**Entra:**

1. **Go/no-go spike (gate before any other task).** With the pinned `cloudflared` version and the current API, record evidence for: (a) installing and running the node service with the tunnel token never in argv, the systemd unit, the journal or failure output (stdin or a root-only credential file read by a supported mechanism); (b) the inputs `cloudflared access ssh` accepts for a service token without argv (environment), its stdio behaviour, and how to disable its browser fallback; (c) the ownership markers each object type supports (tunnel, tunnel configuration, DNS record, Access application, Access policy, service token) and how to look each one up by name or marker with pagination; (d) the exact permission identifiers needed and what can be introspected without mutating. If (a) or (b) cannot be met, implementation stops and the spec is revised.
2. **Cloudflare connection** in the configuration: `account_id`, `zone` (node hostnames are `ssh-<node>.<zone>`), `api_token_ref` (`secret://` only), `owner_emails` (non-empty, no wildcards), `access_identity_providers` (the Access IdP IDs owners may log in with; empty means Cloudflare's one-time PIN). Absent block: the feature is off and nothing else changes.
3. **Two credentials, split by purpose.**
   - *Provisioning*: the API token (tunnel edit, Access apps and policies edit, Access service tokens edit, DNS edit on the zone). Used only by tunnel jobs. It can be removed from the store after provisioning; dialling never needs it.
   - *Runtime*: one Access service token per instance (`secret://cloudflare/access-service-token`, packed `client_id:client_secret`), the only Cloudflare credential the dialler reads.
   `sm doctor` reports what it can prove about the provisioning token (valid, which reads succeed) and says "not verifiable" for edit rights rather than claiming them; it warns 30 days before the service token expires.
4. **Instance service token lifecycle**, serialized by an instance-wide lock: created on first use with a deterministic name `supermgmt-<instance-id>`; its ID is recorded before the secret is stored, and an ambiguous outcome (created, secret lost) deletes the recorded or name-matched orphan and creates a new one. `sm cloudflare rotate-access-token` rotates with overlap: create the new token, add it to every owned Access policy, switch the dialler, remove the old one from the policies, delete it. It is never revoked while a node depends on it.
5. **Durable operation record** (new table, migration `000007`): per node and generation, the account, zone, instance ID, phase, and every object ID created (tunnel, configuration, DNS record, Access application and policies). Every Cloudflare object carries an ownership marker (instance ID and node ID, using what the spike shows each type supports, else a deterministic name). After an ambiguous response the job looks the object up by marker or name before creating; an object with the expected name but another owner is a conflict, never adopted.
6. **`sm nodes setup <node> --tunnel`** (palette: `setup <node> tunnel`), approval-gated, holding the node's resource lock, checking the lease before every external mutation and cancelling on lease loss; a takeover reconciles the operation record before acting. While the node is still directly reachable it:
   1. ensures the instance service token;
   2. creates or finds, in order, the tunnel, its ingress `ssh-<node>.<zone> → ssh://localhost:22`, the Access application with a Service Auth policy (the instance token) and an Allow policy (`owner_emails` through `access_identity_providers`), and only then the proxied DNS record, so the hostname is never routable without its Access application;
   3. installs `cloudflared` from Cloudflare's signed package repository (pinned key fingerprint; Debian 13, Ubuntu 24.04) and the tunnel credential by the mechanism the spike proved;
   4. verifies over a **fresh** connection through the candidate transport, not a pooled one, with the existing pinned host key, and runs the dedicated-account verification setup already performs;
   5. commits `transport: cloudflare` and `tunnel_hostname` against the expected endpoint revision, and retires pooled direct connections.
   Re-running is idempotent and repairs a missing or invalid node credential. A failure at any step leaves the transport `direct` and the operation record resumable.
7. **Endpoint state ownership.** `transport` (`direct | cloudflare`, absent means `direct`, unknown values rejected) and `tunnel_hostname` live in the node endpoint (JSON column) and are owned by the tunnel jobs: static configuration reconciliation never changes them (an amendment to ADR-0009's "setup never rewrites configured state", recorded in the ADR). Old endpoint JSON and setup metadata keep working (compatibility tests).
8. **Dial seam.** A `Dialer` chosen by the target's transport, used by the pool and `ScanHostKey`. `cloudflare` runs `cloudflared access ssh --hostname <h>` as an explicit argv subprocess with a minimal environment holding the service token and the browser fallback disabled; its stdio is the `net.Conn`. Contract: the child lives as long as the connection, not the dial context; a bounded startup and handshake phase; deadlines that unblock reads and writes; idempotent concurrent `Close`; bounded stderr draining, sanitized before it reaches any error; exactly one `Wait`; termination escalation; cleanup on handshake failure, eviction and daemon shutdown. A missing `cloudflared` on the daemon host is `CAPABILITY_UNAVAILABLE` naming it.
9. **Interactive sessions** (`sm ssh`, TUI `s`) through the owner's Access login: the handoff sets a `ProxyCommand` built from the client's own resolved `cloudflared` path and a hostname validated as strict DNS labels on both daemon and client, with shell quoting and OpenSSH `%` expansion handled; unknown transports are rejected; every other isolation option stays. Access admission grants neither an SSH login (the owner still needs an authorized key) nor any SuperMgmt privilege.
10. **`sm nodes tunnel disable <node>`**, approval-gated and resumable through the operation record: verify the direct path for both the admin and the dedicated account; commit `direct`; stop and remove the `cloudflared` service and only the files setup installed; remove the DNS record and ingress (close the route), then the Access application and policies, then the tunnel. The instance service token stays.
11. **Trust boundary, documented and tested.** Cloudflare controls routing and the outer carrier: it sees connection metadata and can deny service, but cannot impersonate the node without its SSH host key, because the pin is enforced over the tunnel. No step ever repins a host key automatically; a tunnel that reaches a different SSH key fails.
12. **Backup and restore.** Backups keep the operation records and object IDs and keep secrets as the existing encrypted records (no plaintext). A restore leaves tunnelled nodes in a reconcile state: until `sm admin restore-complete`, no tunnel job mutates Cloudflare, and reconciliation then finds missing, deleted or recreated objects.
13. CLI, TUI and views show the transport; the audit timeline records every Cloudflare mutation with object IDs (never secrets). Docs: a rewritten `docs/cloudflare.md` (node tunnels, plus the existing server guide as its own section), providers, security (the trust boundary and credential split), configuration, troubleshooting, project status (experimental, tested against fakes), and `docs/manual-checks/cloudflare-tunnel.md`.

**No entra:**
- Adding a node that was never directly reachable (`sm nodes add --tunnel-hostname`, a follow-up).
- ProxyJump / bastion; WARP or private-network routing; HTTP ingress for applications; tunnelling the SuperMgmt server itself.
- A native Go Access carrier or a persistent local TCP listener (recorded as options in the ADR).
- Multiple Cloudflare accounts or zones, per-node service tokens, nodes other than Debian 13 and Ubuntu 24.04.

## Criterios de aceptación

### Scenario: the spike decides
- **Given** the pinned `cloudflared` and the current Cloudflare API
- **When** the spike runs
- **Then** its evidence file shows the tunnel credential absent from argv, unit, journal and failure output, the service-token inputs of `cloudflared access ssh`, the ownership marker per object type and the permission identifiers; otherwise no other task starts

### Scenario: a node becomes reachable from any network
- **Given** a set-up SSH node reachable directly and a Cloudflare connection whose token can provision
- **When** the operator runs `sm nodes setup web1 --tunnel` and approves it
- **Then** the tunnel, ingress, Access application and policies and DNS record exist and carry the instance's ownership marker, `cloudflared` runs on the node, a fresh connection through the tunnel matched the pinned host key and passed the dedicated-account verification, and the transport reads `cloudflare`
- **And** with the direct route blocked, probes, service actions, logs and deployments on web1 keep working

### Scenario: the switch happens only after the tunnel is proven
- **Given** a tunnel whose verification fails (Access denies the token, wrong ingress, a different host key, the dedicated account fails verification)
- **When** the job finishes
- **Then** the job fails naming the step, the transport stays `direct`, and a pooled direct connection could not have satisfied the verification

### Scenario: crashes and lost responses never duplicate or orphan objects
- **Given** a fault injected after every Cloudflare mutation (crash, lost response, lease loss) during setup with `--tunnel`, during disable and during service-token creation
- **When** the job is retried or taken over
- **Then** each object exists at most once, every created object is in the operation record, an object with the expected name but another owner is refused as a conflict, and the run converges

### Scenario: the hostname is never routable without Access
- **Given** any interruption point during setup or disable
- **When** Cloudflare state is inspected
- **Then** the DNS record never exists while its Access application is missing

### Scenario: secrets never leak
- **Given** tunnel setup, dialling, rotation and disable, including failures
- **When** plans, job payloads, events, logs, API views, errors, child argv and environment of every non-cloudflared process, the node's unit and journal, and decompressed backup archives are inspected
- **Then** the API token, the service token secret and the tunnel credential appear in none of them in plaintext

### Scenario: humans use their own identity
- **Given** a tunnelled node and an operator whose email is in `owner_emails`
- **When** the operator runs `sm ssh web1`
- **Then** the ssh client connects through the operator's Access login with the pinned host key enforced and no SuperMgmt credential handed over; a non-owner is denied by Access; the service token alone is admitted only for automation

### Scenario: hostile hostnames and paths are refused
- **Given** a tunnel hostname or `cloudflared` path containing shell syntax, `%` sequences, whitespace or option-like text
- **When** it reaches the daemon or the client handoff
- **Then** it is rejected before any process starts

### Scenario: rotation without downtime
- **Given** several tunnelled nodes and a service token near expiry
- **When** `sm cloudflare rotate-access-token` runs
- **Then** probes keep succeeding throughout, every owned Access policy ends with only the new token, and the old token is deleted last

### Scenario: disabling returns the node to a direct path
- **Given** a tunnelled node that is again directly reachable
- **When** `sm nodes tunnel disable web1` runs, including after an interruption at any step
- **Then** the direct path was verified for both accounts first, the transport reads `direct`, only setup's files and service are removed from the node, the route is closed before Access is removed, the tunnel is deleted last, and the instance service token remains

### Scenario: restore does not fight the original
- **Given** a backup restored while tunnels exist
- **When** the restored instance starts
- **Then** no tunnel job mutates Cloudflare before `sm admin restore-complete`, and reconciliation afterwards reports and repairs missing, deleted or recreated objects

### Scenario: Cloudflare stays optional
- **Given** a configuration without a Cloudflare connection
- **When** SuperMgmt runs every existing feature
- **Then** nothing changes: no Cloudflare call, no `cloudflared` requirement, and `--tunnel` is refused saying the connection is not configured

## Notas técnicas / riesgos

- **Testing.** Offline CI: a hand-written Cloudflare API fake (`cffake`, provenance documented, fault injection after every mutation, pagination, propagation delays) and a fake `cloudflared` that forwards to the fixture sshd. These prove the seams, the state machine and secret handling, not Cloudflare's behaviour. The real-account checklist (provisioning, service-token and owner admission, non-owner denial, teardown, rotation) is required before the feature leaves experimental. Secret scans observe child processes deterministically (a recording wrapper), not by sampling `ps`.
- **Files.** Dial: `internal/transport/ssh/{pool.go,hostkey.go}`, `internal/providers/ssh/node.go`. Endpoint: `internal/domain/entity.go`, `internal/database/repo_inventory.go:124` (struct conversion: both structs change together), `internal/api/wire/dto.go`. Handoff: `internal/client/interactive.go:136`. Setup: `internal/app/setup.go`, `internal/runtimes/systemd/setup.go`, `internal/transport/ssh/templates/setup.go`. Backup: `internal/backup/restore.go`. Config: `internal/config/*`. Policy catalog for the new actions.
- **Setup version.** `SetupMeta` gains the tunnel state; `SetupVersion` becomes 3 so older metadata is told apart.
- **Risks.** Cloudflare API and `cloudflared` CLI drift (pinned version, spike evidence, checklist); a node whose direct path is closed depends on Cloudflare's availability (documented); `cloudflared` updates through apt; the provisioning token has account-wide tunnel and Access edit rights (documented blast radius; removable after provisioning).
- **ADR-0037**: transport seam and the subprocess carrier, the credential split, ownership markers and the operation record, the endpoint-state amendment to ADR-0009, the trust boundary.

## Tasks (no autoritativo — el board manda)

- [ ] Spike and evidence (go/no-go)
- [ ] ADR-0037
- [ ] Config block, secrets, doctor diagnostics
- [ ] Cloudflare API client, `cffake` with fault injection, fuzz targets for its decoders
- [ ] Migration 000007 and the operation record
- [ ] Dial seam and the subprocess carrier contract
- [ ] Endpoint transport fields and compatibility
- [ ] Setup steps for cloudflared; the `--tunnel` job
- [ ] Disable job; service-token lifecycle and rotation
- [ ] Handoff ProxyCommand
- [ ] Backup and restore reconciliation
- [ ] CLI, TUI, docs, manual checklist

## Referencias

- Cloudflare: remotely managed tunnels (`/accounts/{account_id}/cfd_tunnel`, `/configurations`, tunnel token), Access self-hosted applications, Service Auth and Allow policies, service tokens (`CF-Access-Client-Id`, `CF-Access-Client-Secret`), `cloudflared access ssh` as ProxyCommand.
- Spec §25 (Cloudflare optional), §8.4 and ADR-0015 (handoff isolation), ADR-0009 and ADR-0030 (node setup), ADR-0034 (fuzz inventory), ADR-0035 (migrations and fixtures).
- Critique: `.claude/loop/cloudflare-tunnel-transport/plan.md` round 1 (codex), integrated here.
