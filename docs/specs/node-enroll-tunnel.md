---
codename: supermgmt
title: Add a node that is reachable only through Cloudflare Tunnel
type: epic
status: active
priority: P1
size: XL
issue: 48
prs: []
related_issues: [48]
depends_on: []
supersedes: []
related_specs: [cloudflare-tunnel-transport, proxmox-via-node]
created: 2026-10-30
updated: 2026-10-30
---

# Add a node that is reachable only through Cloudflare Tunnel

## Contexto / problema

Today a node can switch to Cloudflare Tunnel only if it was first reachable directly. `sm nodes add` scans the host key over a direct TCP dial (`internal/app/inventory.go:94`, `internal/transport/ssh/hostkey.go:39-44`), and `sm nodes setup --tunnel` installs `cloudflared` over the admin's SSH session (`internal/app/setup.go:144-176`). The docs say this outright: a node that was never reachable directly cannot become a tunnel node, and `sm nodes add` has no tunnel option (`docs/cloudflare.md:24,219`).

The join flow (ADR-0022) does not help. `sm join` calls the server back over HTTPS (`internal/join/client.go:60`), and a SuperMgmt instance on the maintainer's laptop cannot be reached from a VPS or a home host behind NAT.

Maintainer goal (2026-10-29): SuperMgmt, running on their machine, manages every node wherever it is, and the user brings only the Cloudflare credentials. One command on the laptop, one line on the node, nothing configured by hand.

## Scope

**Entra:**

1. **`sm nodes add --name <name> --tunnel`** (palette: `add node <name> tunnel`), approval-gated as `node.add` with a new policy parameter `tunnel`.
   - `--tunnel` excludes `--host`, `--port`, `--admin-user` and `--admin-credential-ref`. `--environment`, `--tag`, `--fingerprint` and `--expires-in` stay; `--expires-in` defaults to 1h, and the maximum is 24h.
   - It refuses before touching Cloudflare when:
     - Cloudflare is not configured (the message names the settings, as `--tunnel` setup does);
     - the name is taken by a node or by another enrollment;
     - the name does not yield a valid hostname `ssh-<name>.<zone>` (`internal/app/tunnel_enable.go:119`).
   - **Approval.** Policy evaluates `node.add` with `tunnel`, the environment and the tags (`internal/app/direct.go:192-204`) before any Cloudflare mutation. An approved plan starts the enrollment. Today an approved `node.add` inserts the node immediately (`internal/app/apply.go:237-245`); that path is not used for `--tunnel`.
   - **Name reservation.** The name is reserved in one transaction against providers (whose names are globally unique, `migrations/000001_initial.up.sql:59-63`) and open enrollments. Every node-creating path checks both: `requireFreeName` (`internal/app/inventory.go:237-245`) and the join enrollment's name choice (`internal/app/enrollments.go:371-387`). The reservation is checked again at commit.
2. **An enrollment record before a node exists.**
   - The node ID is allocated when the enrollment starts, because every Cloudflare object name embeds it (`internal/app/tunnel_steps.go:68,114,165`).
   - A new table `tunnel_enrollments` keeps the enrollment state, with one active enrollment per name:
     - the pre-allocated node ID, name, environment, tags and expiry;
     - the phase, with halted/conflict semantics like `tunnel_operations`;
     - the Cloudflare object IDs, written once (the same trigger rule as `tunnel_operations`);
     - `phase_started_at`;
     - the SSH identity snapshot taken at start: the public key, its fingerprint and the versioned secret reference. Existing join keeps the original identity the same way (`internal/app/enrollments.go:36-40,338-355`). Every proof and the commit use this snapshot, even after an identity rotation;
     - the scanned host key and the confirmation bound to that exact key (item 5).
   - The node is not written early in a pending state:
     - `pending` is not an allowed management state (`migrations/000001_initial.up.sql:81`, `internal/domain/enum.go:95-108`);
     - `discovered` rows are listed and probed (`internal/database/repo_inventory.go:224-237`, `internal/app/refresher.go:123-136`).
     Nothing appears in the node inventory until the commit.
   - **The tunnel record as a seam.** Provisioning reads and advances its record: the phase, the object IDs, the fenced advance and halt, and the timestamps used for adoption (`internal/app/tunnel_steps.go:50-80,125-130,162-163`, `tunnel_enable.go:349-378,420-443`, `tunnel_ensure.go:155-158`). These move behind an interface that both tables implement.
   - Creation order, naming and adoption rules stay exactly as ADR-0037 sets them (tunnel → ingress → Access → DNS last; adoption back to 5 minutes before `phase_started_at`).
   - The `setup --tunnel` behaviour does not change.
   - **Policy repair.** Repairing the instance's Access policies also enumerates the Access applications of open enrollments, which it does not today (`internal/app/tunnel_token.go:332-346,373-385`).
3. **The line for the node.** After provisioning, the command prints one line and the hostname:
   ```
   curl -fsSL https://raw.githubusercontent.com/autarquico/supermgmt/main/scripts/join.sh | sudo sh -s -- --tunnel --instance <id> --authorized-key '<daemon public key>'
   ```
   - On a non-stable channel the line sets `SUPERMGMT_CHANNEL` (`scripts/join.sh:172-177`).
   - The line carries no secret: the instance ID and the authorized key are public. The instance ID is what renders the managed key comment (`internal/join/account.go:53-60`).
   - **The connector token.**
     - It is stored in the secret store under the enrollment and shown separately, once, on the operator's terminal, with the instruction to paste it at the node's prompt.
     - `sm nodes add --tunnel <name> --show-token` prints it again while the enrollment is open.
     - Reading it requires authenticated authorization for the enrollment.
     - It is never in the enrollment row, in a job or view serialization, in audit or in logs.
     - It is deleted at the commit, at expiry and at cancellation.
4. **`join.sh --tunnel` and `sm join --tunnel` on the node.** join.sh verifies the signed `sm` as it does today (`scripts/join.sh:22-126`) and hands off to `sm join --tunnel --authorized-key <key>`. Nothing calls the server.
   1. **Checks before any change**, all of them before anything is installed:
      - Linux amd64/arm64, Debian trixie or Ubuntu noble (`internal/runtimes/systemd/tunnel.go:44-54`);
      - root, systemd, `apt-get` and `useradd`;
      - a well-formed authorized key and instance ID;
      - a readable host key;
      - a `supermgmt` account that is absent or ours. Today's `Preflight` checks only root and `useradd` (`internal/join/system.go:47-58`).
   2. **Reads the connector token** from `/dev/tty` without echo, or from `--token-stdin`.
      - The input is bounded and the terminal is restored on every exit.
      - The token never appears in argv or the environment, and a token given on the command line is refused.
      - It must have the alphabet and length of a connector token (`internal/runtimes/systemd/tunnel.go:23-39`), otherwise the command stops before writing anything. That is a shape check, not authentication.
   3. **Installs `cloudflared`** locally as root, without SSH or sudo.
      - The pinned Cloudflare keyring, apt source, token path (0600), unit and restart-pending marker are exactly the bytes `systemd.ensureTunnel` uses, exported from `internal/runtimes/systemd` (which `join` already imports, `internal/join/account.go:11`). They are run through a small local root executor, not copied into shell.
      - The apt commands are the same as the setup templates' (`internal/transport/ssh/templates/setup.go:153-158,231-242`): update only `cloudflared.list`, non-interactive install with `--no-install-recommends` and the 60 s dpkg lock wait.
      - A foreign source file is handled as `ensureTunnel` handles it (`tunnel.go:151-183`): when `cloudflared` is installed it is used as is; when it is not installed, the foreign source makes the command stop.
   4. **Creates the dedicated account** with `internal/join.Provision`: the `supermgmt` user, its directories and one `restrict` authorized_keys line with the given key. An existing account is adopted only if it is ours (`internal/join/account.go:83-104`).
   5. **Prints the host key fingerprint** (`SHA256:…`, the ed25519 key, or ecdsa then rsa, as `join` reads it today, `internal/join/join.go:39-43,76`) and the instruction to compare it on the operator's side.
   - Re-running is idempotent. A token different from the installed one replaces it and restarts the connector.
5. **Confirmation and commit (daemon).**
   - **Jobs.** The enrollment runs as short jobs: provision, scan, commit, cleanup. The instance lock is taken only where ADR-0037 requires it. Between jobs, the enrollment row holds the state, and a scheduler re-arms the scan with backoff until the expiry; restart resumes it. Exhausted job attempts leave the enrollment `halted`, not silently terminal (`internal/jobs/lease.go:44-58`).
   - **Scan.** The host key is scanned over the tunnel with a target built from the enrollment: `Host` and `TunnelHostname` set to the hostname, port 22, `Transport: cloudflare` (`internal/transport/ssh/dial.go:71-82`). The Access preflight runs before the carrier (`dial_cloudflare.go:173-204`). The scanned key is persisted on the enrollment.
   - **Confirmation.** The persisted key is compared with `--fingerprint` when given. Otherwise the CLI shows its fingerprint and asks, the same way `confirmHostKey` does (`internal/cli/nodes.go:268-277`).
     - The confirmation names the enrollment ID and the exact key, and is a compare-and-swap that cancellation and expiry can win.
     - A mismatch ends the enrollment with `SSH_HOST_KEY_MISMATCH`, and its Cloudflare objects are cleaned up.
     - Without a terminal, `--fingerprint` is required.
   - **Proof.** The job builds an in-memory node: the allocated node ID, the dedicated user, the confirmed key pinned with exact bytes, and the snapshot's credential. It probes it with `Connector.Dedicated` and the discovery probe (`internal/app/connector.go:69-75`, `internal/providers/ssh/node.go:55-65`). It does not use `Prober.Probe`, which loads a database node (`internal/app/probe.go:57-80`).
   - **Commit, in one fenced transaction:**
     - the provider row and the node row: SSH, `transport: cloudflare`, endpoint host = tunnel hostname, the pinned host key, no `admin_user`, and the snapshot's versioned credential, as enrolled nodes are (`internal/app/enrollments.go:328-355`);
     - the node's durable provenance `tunnel_only`, kept through any later setup;
     - a `tunnel_operations` row in phase `committed` carrying the object IDs. This uses a dedicated import, since `CreateTunnelOperation` always inserts `started` (`internal/database/repo_tunnel.go:101-116`);
     - the enrollment marked `committed`;
     - an audit `node.add` with `transport: cloudflare` and the host key fingerprint.
   - **Waiting.** The CLI waits for the commit and prints progress. Interrupting it leaves the job running, and `sm nodes add --tunnel <name>` again reattaches to it.
6. **Expiry, cancel, resume.**
   - **Expiry or cancellation.** When an enrollment expires, or `sm nodes add --tunnel <name> --cancel` cancels it, its Cloudflare objects are removed in the order the disable path uses: DNS, then the ingress closed, then the Access application, then the tunnel (`internal/app/tunnel_disable.go:447-461`).
     - The instance's shared policies and service token are kept (`tunnel_disable.go:516-517`, ADR-0037).
     - The removal is the cloud-only part of disable, extracted. It does not need a node or a direct path.
     - Before deleting, it reconciles objects created but not recorded, ambiguous ownership included (`tunnel_disable.go:164-196,231-247`).
     - Progress is persisted at each step. The enrollment becomes `expired` or `cancelled`, and its name is released, only when nothing is left; a failed removal retries.
     - No node row is ever written.
   - **Resume.** A daemon restart resumes the job from its phase, without duplicating objects.
   - **Pending enrollments.** `sm nodes list` shows them in a separate section with their expiry.
7. **After the commit.**
   - The node is managed like a joined node: probe, inventory and units through the dedicated account (`internal/providers/ssh/node.go:40-47`).
   - `sm nodes setup` still needs an `admin_user`. That path is documented, not built here.
   - `sm nodes tunnel disable` on a `tunnel_only` node is refused before planning or mutating anything, because there is no direct path to fall back to, and the message says so. The refusal comes from the provenance, never from a missing `admin_user`, which is normal for joined nodes.
   - Recovery after the commit is a new enrollment after `sm nodes remove`. The connector token is no longer stored.
8. **Docs.**
   - `docs/cloudflare.md`: replace "never reachable directly cannot…" with the enroll flow.
   - `docs/cli.md`.
   - `docs/security.md`: what the node line installs, the token's path, the fingerprint check.
   - `docs/project-status.md`: experimental, fakes only.
   - `docs/manual-checks/node-enroll-tunnel.md`: a real account and a VPS without any inbound port.
   - ADR-0039.

**No entra:**
- Serving `join.sh` from the daemon or any other callback channel from node to server.
- An admin account or `sm nodes setup` steps over the enrollment. The node has only the dedicated account until the operator adds one.
- Enrolling non-Debian/Ubuntu nodes, or nodes without systemd.
- Exposing apps (spec `app-expose-tunnel`) and moving apps (spec `app-move`).
- Changing the existing `sm nodes setup --tunnel` and disable flows, except moving `provisionCloudflare` behind the recorder.

## Criterios de aceptación

### Scenario: a node with no inbound port is added from the laptop
- **Given** Cloudflare configured on the instance and a Debian 13 host whose SSH port is unreachable from the instance
- **When** the operator runs `sm nodes add --name vps1 --tunnel`, runs the printed line on the host, pastes the token at its prompt, and confirms the fingerprint the host printed
- **Then** the node `vps1` is saved with `transport: cloudflare` and the scanned host key pinned, a probe through the tunnel succeeds, and at no point did the instance open a TCP connection to the host's address

### Scenario: Cloudflare objects come before any node and never leave an open route
- **Given** an enrollment in progress
- **When** each Cloudflare call is made
- **Then** the order is tunnel → ingress → Access application → DNS, the hostname is never routable without the Access application, and no node row exists until the commit

### Scenario: the token never leaks
- **Given** the node line and the token
- **When** the operator runs the enrollment end to end
- **Then** the token appears in no argv, environment variable, shell history, audit event, log line, enrollment row or error message on either side; `sm join --tunnel` refuses a token passed as an argument

### Scenario: a different host key is refused
- **Given** an enrollment waiting for its node
- **When** the key scanned over the tunnel does not match `--fingerprint`, or the operator answers no
- **Then** the enrollment ends with `SSH_HOST_KEY_MISMATCH`, nothing is pinned, no node row is written, and the enrollment's Cloudflare objects are removed

### Scenario: the daemon dies mid-enrollment
- **Given** an enrollment interrupted after any phase, including between a Cloudflare call and its record
- **When** the daemon restarts
- **Then** the job resumes from its phase, adopts the objects it created and creates no duplicates, and the result is the same as an uninterrupted run

### Scenario: an enrollment nobody completes expires clean
- **Given** an enrollment whose node never answered
- **When** its expiry passes, or the operator cancels it
- **Then** its DNS record is removed, the ingress closed, then its Access application and tunnel removed, in that order; the instance's shared policies and service token remain; the enrollment is `expired` or `cancelled` only once nothing is left, and no node row exists

### Scenario: the node side stops before changing anything it cannot finish
- **Given** a host that is not Debian trixie or Ubuntu noble, has no systemd, has a `supermgmt` account that is not ours, or has a foreign Cloudflare apt source and no `cloudflared` installed
- **When** `join.sh --tunnel` runs
- **Then** it exits non-zero naming the reason, before installing anything, writing the token or creating the account

### Scenario: the node line can be run again
- **Given** a host that already ran the line, with the same or a new connector token
- **When** the line runs again
- **Then** the account, key line and cloudflared install are unchanged, a new token replaces the old one and restarts the connector, and the fingerprint printed is the same

### Scenario: mistakes are refused before Cloudflare is touched
- **Given** an instance without Cloudflare settings, or a name already used by a node or an open enrollment, or `--tunnel` with `--host`
- **When** `sm nodes add --tunnel` runs
- **Then** it fails with a message naming the fix, and no Cloudflare call is made

### Scenario: the confirmation binds the key the human saw
- **Given** an enrollment whose scanned key was shown and confirmed
- **When** the daemon restarts, the instance's SSH identity is rotated, the node presents a different key afterwards, or a cancel races the confirmation
- **Then** the proof and the commit use exactly the confirmed key and the identity snapshotted at start; a different key at proof fails with `SSH_HOST_KEY_MISMATCH`; a cancelled or expired enrollment cannot be committed

### Scenario: the name stays reserved
- **Given** an open enrollment for `vps1`
- **When** a direct `sm nodes add --name vps1` or a join enrollment would create a node named `vps1`
- **Then** it is refused, and the enrollment's commit still checks the name inside its transaction

### Scenario: a tunnel-only node cannot fall back to direct
- **Given** a node committed by enrollment, with or without an `admin_user` added later
- **When** `sm nodes tunnel disable` runs on it
- **Then** it is refused before any change, saying the node has no direct path, while a direct joined node without `admin_user` keeps today's behaviour

## Notas técnicas / riesgos

- **Files:**
  - CLI: `internal/cli/nodes.go:190-280`.
  - Inventory and scan: `internal/app/inventory.go:94,123-211`.
  - Tunnel: `internal/app/tunnel_steps.go`, `tunnel_enable.go`, `tunnel_disable.go`.
  - New migration `000008_tunnel_enrollments`.
  - Join: `internal/join/*`, `internal/cli/join.go`, `scripts/join.sh`.
  - Shared cloudflared content: `internal/runtimes/systemd/tunnel.go` and `cloudflare_pin.go`, plus the template paths in `internal/transport/ssh/templates/setup.go:25-37`. Move what `join` needs into a package both can import, without changing its bytes.
  - Policy: `internal/policy/catalog.go`.
  - API wire and OpenAPI.
  - TUI palette.
- **Testing:**
  - `cffake` with fault injection after each mutation (`internal/app/tunnel_helpers_test.go` `chaosAPI`).
  - The cloudflared fake (`test/fixtures/cloudflared-fake`) pointing at an in-process SSH server that is never dialled directly.
  - `internal/join` with a recording Host for the tunnel steps.
  - The signed join.sh rendering in `test/e2e/harness/release.go`.
  - Fuzz the connector-token shape check.
- **Risks:**
  - The operator's fingerprint comparison is the only binding between the line run on the host and the host key the instance pins, the same trust as `sm nodes add` today.
  - The connector token gives whoever holds it the right to serve that hostname, but Access still requires the instance's service token to reach SSH.
  - A node enrolled this way is lost if the tunnel breaks: there is no direct fallback, and repair is a new enrollment.
  - Alternative considered for the token: fetching it on demand from the recorded tunnel ID (`internal/app/tunnel_steps.go:60-64`). Rejected because it needs the provisioning API access that ADR-0037 allows removing (`docs/adr/0037-cloudflare-tunnel-transport.md:26`).

## Tasks (no autoritativo — el board manda)

- [ ] ADR-0039
- [ ] Migration and repository for `tunnel_enrollments`; recorder seam in `provisionCloudflare`
- [ ] Enrollment job: provision, wait/scan, confirm, prove, commit, expire/cancel, resume
- [ ] CLI/API/policy/TUI for `nodes add --tunnel`, `--show-token`, `--cancel`, the pending section in `nodes list`
- [ ] `sm join --tunnel` and `join.sh --tunnel` with the shared cloudflared install
- [ ] Disable refusal for enrolled nodes
- [ ] Tests per scenario, fuzz, docs, manual checklist

## Referencias

- ADR-0037 (Cloudflare Tunnel transport), ADR-0022 (join and enrollment), ADR-0019 (installer signatures), ADR-0009 (node provisioning).
- Cloudflare: `cloudflared tunnel run --token`, Access service tokens.
