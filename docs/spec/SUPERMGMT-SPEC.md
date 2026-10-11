# SuperMgmt — Master Implementation Specification

> **Purpose:** this document is the single source of truth for implementing SuperMgmt from an empty repository to a releasable open-source product. It is intentionally prescriptive so an implementation agent can build the project without inventing product behavior, architecture, file formats, security rules, or UX along the way.
>
> **Working name:** SuperMgmt · **CLI:** `sm` · **Status:** implementation specification · **Spec version:** 1.4.4-draft (changes in Appendix F)

---

## 0. Instructions to the implementation agent

Implement this specification as a production-quality open-source repository. Do not silently simplify security controls, replace typed contracts with ad-hoc maps, introduce a mandatory SaaS dependency, or make Proxmox/Cloudflare required for core operation. When a third-party API differs from this specification, preserve the product semantics and isolate the vendor-specific behavior behind an adapter. Pin dependencies and document any necessary deviation in an ADR.

The implementation order MUST follow the milestones in §31. Each milestone must compile, have tests, and leave the repository usable. Do not implement future milestone behavior as hidden, untested code. Prefer boring, auditable code over clever abstractions.

Before release, verify current upstream documentation for Go, MCP, Proxmox VE, GitHub Actions/OIDC, Cloudflare Access/Tunnel, Docker/Compose and any optional overlay networking. Do not hard-code assumptions about vendor versions that can be discovered at runtime.

The final repository MUST include every file listed in §27 unless marked generated/optional. Examples in this document are contracts; keep sample files synchronized with actual schemas through tests.

---

# 1. Product definition

## 1.1 One-line pitch

**SuperMgmt is a local-first, terminal-first control plane that connects developer infrastructure, services, repositories and deployments, and exposes the same safe operational model to humans through a TUI/CLI and to AI agents through MCP.**

## 1.2 Problem

Developers commonly manage infrastructure through disconnected tools: SSH, Proxmox, Docker, systemd, GitHub Actions, Cloudflare, Vercel, VPS provider dashboards, logs and custom scripts. AI agents make this fragmentation worse because each integration requires separate credentials, schemas and safety policies.

SuperMgmt creates a normalized graph and action layer over those resources. It does not replace the underlying platforms. It discovers them, relates them, exposes safe actions, records what happened, and provides one human and one machine interface.

## 1.3 Target users

- Individual developers with a laptop, GitHub, Docker, Vercel and one or more VPSs.
- Homelab operators using Proxmox, VMs/LXCs, NAS devices and external VPSs.
- Small engineering teams that want lightweight infrastructure management without Kubernetes.
- AI-assisted operators that need a constrained MCP interface instead of unrestricted shell credentials.

## 1.4 Foundational principles

1. **Local-first.** `sm` can run on a laptop with no server dependency.
2. **Agentless-first.** Linux nodes are managed over SSH by default; no daemon is required on every machine.
3. **Provider-independent.** Proxmox is a first-class integration, never a core dependency.
4. **MCP-native, not MCP-controlled.** MCP uses the same policy/audit core as humans and receives no privileged bypass.
5. **Terminal-first.** TUI and CLI are primary product surfaces.
6. **Safe by default.** Read operations are easy; writes are scoped; destructive actions are denied or approval-gated.
7. **Workloads survive control-plane failure.** SuperMgmt is not in the serving path of managed applications.
8. **Capability-based.** Features appear because a resource advertises capabilities, not because of hard-coded provider menus.
9. **Observable and auditable.** Every state-changing operation has actor, target, plan, result and correlation ID.
10. **No Kubernetes requirement.** Docker Compose/systemd are first-class deployment targets.

## 1.5 Non-goals for V1

- Kubernetes orchestration.
- Terraform replacement or arbitrary cloud resource provisioning.
- Full CM system comparable to Ansible/Salt.
- Full secrets-vault product.
- Long-term high-cardinality metrics warehouse.
- Windows administration.
- HA multi-control-plane clustering.
- Browser-first dashboard.
- Generic unrestricted root shell exposed through MCP.

---

# 2. Product modes and installation topology

SuperMgmt supports three equal deployment modes.

## 2.1 Local mode

Runs directly on macOS or Linux laptop/workstation. Ideal for one developer.

```text
Laptop
├── sm daemon (single owner of state)
│   ├── local API (Unix socket, mode 0600; same API as §23)
│   ├── SQLite
│   ├── job workers, sync loops, scheduler
│   ├── MCP (optional, stdio bridge or loopback)
│   └── connectors -> SSH / GitHub / Proxmox / etc.
└── sm TUI / CLI  (always API clients of the daemon)
```

### 2.1.1 Process model (all modes)

Exactly one process — the **daemon** — owns the database, job workers, sync loops and connectors. TUI, CLI and MCP are always clients of the API (§23); there is no in-process TUI backend. This gives one code path for local and remote use.

**Offline commands** do not need a daemon and never open the database while one runs: `sm version`, `sm completion`, `sm config validate`, `sm doctor --offline`, `sm install …` (installer phase, before the service starts), `sm secrets import --offline` (§3.5), `sm secrets import-key --offline` (§10) and `sm backup restore --offline` (§29.2). These take the database lock themselves and refuse while a daemon holds it; `import-key --offline` also works when no database exists yet. Everything else is an API client.

**Locking.** Two independent locks, both `flock`, both held for the daemon's lifetime:

1. **Database lock** on `<canonical db path>.lock`. The canonical path is computed before the database exists: create the parent directory (mode 0700) if missing, take `realpath(parent)`, then append the basename. A second daemon for the same database exits with code 2 and names the PID recorded in the lock file.
2. **Socket lock** on `<socket path>.lock`. If it is held, another daemon — possibly for a different database — owns that socket, and this daemon exits with code 2 ("socket in use"). The socket file is unlinked only while holding the socket lock.

**Socket location (local mode).** `daemon.socket` if set; otherwise `$XDG_RUNTIME_DIR/supermgmt/sm.sock`; if `XDG_RUNTIME_DIR` is unset (or on macOS), `<state dir>/run/sm.sock` (§8.1). If the resulting path exceeds the platform `sun_path` limit (104 bytes macOS, 108 Linux) the daemon fails with an explicit message; it never silently shortens to `/tmp`.

**Socket directory rules.** The daemon creates the directory with mode 0700, then verifies with `lstat` that it is a real directory (not a symlink), owned by the daemon UID, mode exactly 0700; otherwise it refuses to start. The socket is bound with umask 0177 (mode 0600).

**Startup and stale sockets.** Order: acquire the database lock → acquire the socket lock → if a socket file exists, unlink it (holding the socket lock proves no live daemon owns it) → bind → write the PID to both lock files → serve. Clients that auto-start the daemon spawn it and then poll for the socket for up to 5 s; concurrent auto-starts are safe because only one process wins the lock and the losers exit quietly.

**Mutual verification.** The daemon accepts a connection only if the peer UID (`SO_PEERCRED` on Linux, `getpeereid` on macOS) equals its own UID. The client likewise verifies the daemon's peer UID equals its own before sending credentials.

**Local-mode trust boundary.** Peer credentials prove the OS user, not which program is speaking. Any process running as the same OS user can already read that user's SSH keys and agent, so local mode does **not** defend against malicious code running as the same user; `SECURITY.md` states this. Within that boundary, SuperMgmt still separates human and MCP authority (§11.1): MCP bridges must present a daemon-issued MCP client token, so a well-behaved but prompt-injected model cannot act as the human. Users who need isolation from a compromised MCP client run it under a different OS user (socket access is then refused) or use server mode with per-client OAuth (§24).

**Residency.** When the last client exits, a local daemon stays alive only while it has active work: non-terminal jobs or deployments in `waiting_ci`/`awaiting_approval`. Otherwise it exits after `daemon.idle_exit` (default 10m). Schedules (backups, periodic sync) do not keep a local daemon resident unless `daemon.resident: true`, which `sm daemon install-user-unit` sets up via a launchd agent or systemd user unit. Server mode is always resident.

**Webhooks.** Local mode cannot receive inbound webhooks. CI-gated deployments in local mode poll the GitHub API (§18). Webhooks require server mode.

Server mode (§2.2) is the same daemon listening on HTTPS (§23.1); its local administrative socket lives at `/run/supermgmt/admin.sock` (root and the service user only) and is used for bootstrap and offline-safe admin commands (§11.5).

## 2.2 Server mode

Runs `sm server` (the daemon of §2.1.1 bound to TCP) on a Linux VM/VPS. Clients run the TUI locally and connect over HTTPS. Authentication can be native local tokens for bootstrap and OIDC for normal remote access.

## 2.3 Proxmox appliance mode

The universal installer detects a Proxmox VE host and, by default, creates a dedicated **unprivileged Debian LXC**, installs SuperMgmt inside it, configures systemd, creates restricted Proxmox credentials, and registers the current cluster as the first provider.

The Proxmox host MUST NOT need Docker, Node.js, Go, or a cloned repository.

Default LXC sizing:

```yaml
cores: 2
memory_mib: 2048
swap_mib: 512
disk_gib: 16
network: dhcp
unprivileged: true
nesting: false
keyctl: false
```

All values are configurable.

---

# 3. Universal installation UX

## 3.1 Zero-clone requirement

A normal user MUST NOT need to clone the repository or manually download scripts.

Canonical installation UX after project publication:

```bash
curl -fsSL https://raw.githubusercontent.com/<ORG>/supermgmt/main/install.sh | bash
```

The repository owner MUST replace `<ORG>` before release. Documentation MUST also offer a review-first alternative that verifies the bootstrap with a key obtained out-of-band (§3.2), using the copy attached to a specific release:

```bash
V=v1.2.3
curl -fLO https://github.com/<ORG>/supermgmt/releases/download/$V/install.sh
curl -fLO https://github.com/<ORG>/supermgmt/releases/download/$V/install.sh.sig
# allowed_signers obtained out-of-band (SECURITY.md at a signed tag / project website)
ssh-keygen -Y verify -f allowed_signers -I release@supermgmt -n supermgmt-release \
  -s install.sh.sig < install.sh \
  && less install.sh \
  && SUPERMGMT_VERSION=$V bash install.sh
```

## 3.2 Bootstrap trust model

`install.sh` is a small bootstrapper (target: under 300 lines of POSIX shell). It MUST NOT install arbitrary files from the moving `main` branch beyond itself. It does only this:

1. Detect platform and prerequisites (§3.3), including the verifier: it runs `ssh-keygen -Y verify` against an embedded known-good test signature **before downloading anything**. OpenSSH 8.2 or newer is required (`-Y` is 8.1, but the `valid-after`/`valid-before` options of `allowed_signers`, which the self-test uses, are 8.2); hosts without a capable `ssh-keygen` (or without the OpenSSH client at all) fail with exit code 4 and instructions to install the client or verify manually on another machine. Verification is never skipped.
2. Resolve the version.
   - Precedence: `SUPERMGMT_VERSION=vX.Y.Z` (pinned) > `SUPERMGMT_VERSION=latest` / `SUPERMGMT_CHANNEL` > default channel `stable`.
   - A channel is resolved by downloading `channels/<channel>.json` and `.sig` from the release host. The signed file contains `{channel, version, issued_at, valid_until}`, and the bootstrap rejects it if signature verification fails, `now > valid_until`, `issued_at > now + 5m`, or `valid_until − issued_at > 30 days`. Channel files are re-signed at least every 14 days, so a replayed channel file is at most 30 days stale.
   - A pinned version gets integrity only, no freshness, which is intended.

   Then download `checksums.txt`, `checksums.txt.sig` and the platform archive.
3. Verify the signature (namespace `supermgmt-release`, principal `release@supermgmt`) against the embedded `allowed_signers` block, then verify the archive SHA-256 from `checksums.txt`.
4. Check that the signed `checksums.txt` header (`version: vX.Y.Z`, `channel: stable|beta`) matches what was requested; this binds the signature to a version and prevents serving an old signed release for a new request.
5. Unpack `sm` to a private temp directory and `exec sm install <mode>` with the environment preserved.

All installer logic — Proxmox LXC creation, rollback journal, service setup, upgrade, uninstall, restore — lives in Go (`internal/installer`) and is unit-tested against fakes.

**Trust roots, stated honestly.** The `curl … | bash` path trusts the repository's `main` branch: whoever can change `install.sh` there can replace both the verifier and the embedded key, so repository compromise defeats that path. `SECURITY.md` says so. An independent path exists for users who need it: every release also attaches `install.sh` and `install.sh.sig`, and the release key fingerprint is published out-of-band (`SECURITY.md` at a signed tag, the project website, release notes). The review-first flow (§3.1) verifies `install.sh` itself with `ssh-keygen -Y verify` using a key obtained from those sources before running it.

**Key lifecycle.**
- `allowed_signers` entries carry `valid-after`/`valid-before`.
- Rotation: the new key is announced in a release signed by the old key; during the overlap `install.sh` embeds both keys.
- Revocation: `install.sh` embeds a `revoked_keys` list, which is passed to `ssh-keygen -Y verify -r`.
- The private key lives only in the protected release environment (§36).

**Downgrade protection.** `sm install upgrade` refuses a version lower than the installed one unless `--allow-downgrade` is given, which is audited.

Releases additionally carry Sigstore/SLSA provenance (§36) for auditors; the bootstrap does not depend on it.

## 3.3 Environment detection

The bootstrap MUST detect:

- OS: Linux/macOS.
- Architecture: amd64/arm64 initially.
- root/non-root.
- Proxmox host: presence and successful execution of `pveversion`, plus expected PVE filesystem/API tools.
- systemd availability.
- interactive TTY.
- required commands (`curl`, checksum utility, tar); install only minimal missing prerequisites after approval when possible.

Detection result MUST be printed before changes.

## 3.4 Installer modes

```text
auto              default; Proxmox -> proxmox-lxc, desktop -> local, generic Linux server -> server prompt
local             install local CLI/control plane
server            install server directly on current Linux host
client            install CLI/TUI only
proxmox-lxc       create dedicated LXC and install server there
upgrade           upgrade existing installation
uninstall         remove SuperMgmt software; data removal separately confirmed
restore           restore control-plane backup
```

Environment variable: `SUPERMGMT_MODE`.

## 3.5 Proxmox LXC install contract

On a detected Proxmox host in `auto`, interactive install defaults to `proxmox-lxc`. Before modifying anything it displays a plan:

```text
SuperMgmt installation plan

Environment: Proxmox VE <detected-version>
Mode:        dedicated unprivileged LXC
VMID:        <auto-selected-free-id>
Hostname:    supermgmt
Template:    Debian <supported-version>
Storage:     <selected-storage>
Bridge:      vmbr0
Network:     DHCP
CPU:         2 cores
Memory:      2048 MiB
Disk:        16 GiB

Will create:
- LXC <vmid>
- SuperMgmt service inside LXC
- restricted Proxmox API identity/token
- provider registration for this cluster

Will NOT:
- open router ports
- install Docker on the Proxmox host
- mount the host filesystem into the LXC
- create a privileged container

Proceed? [y/N]
```

Steps:

1. Acquire installer lock.
2. Validate PVE version against compatibility matrix.
3. Choose free VMID (default search starting at configurable 900).
4. Discover storages supporting `vztmpl` and rootdir; choose interactively or via env.
5. Discover bridge; default `vmbr0` only if present.
6. Ensure supported Debian LXC template exists; download through official Proxmox tooling if missing.
7. Create unprivileged LXC with no unnecessary features.
8. Configure DHCP or requested static network.
9. Start LXC and wait for network/readiness with timeout.
10. Copy/download verified SuperMgmt release into LXC.
11. Install binary, config directories, system user and systemd service.
12. Create restricted Proxmox API identity/token according to §15. Do not print secret after initial secure transfer.
13. Store credential encrypted in SuperMgmt secret store.
14. Register Proxmox endpoint using the host/cluster API address reachable from LXC.
15. Run discovery and connectivity test.
16. Print access instructions and backup recommendation.

Steps 1–16 are executed by `sm install proxmox-lxc` (Go), invoking `pct`, `pveam`, `pvesh` and `pveum` through fixed argument vectors (never shell strings). Every PVE CLI interaction is behind an interface with a fake used in tests.

Secure credential transfer (steps 12–13):

1. The installer runs `pveum user token add … --output-format json` with stdout captured in memory by Go; it is never echoed, logged or journaled. `--privsep 1` is always used.
2. The installer writes the token to a host temp file inside a fresh `mktemp -d` directory (mode 0700, file mode 0600, created with `O_EXCL|O_NOFOLLOW`).
3. Inside the container it runs `pct exec <vmid> -- install -d -m 0700 -o supermgmt -g supermgmt /run/supermgmt-bootstrap` (tmpfs) **before** pushing. It then pushes the file to `/run/supermgmt-bootstrap/pve-token` in the container (a tmpfs path) with owner `supermgmt` and mode 0600 via `pct push` (the ownership/permission flags must be verified per PVE version in the compatibility matrix; if unsupported, follow up with `pct exec … chown/chmod` before any other step).
4. It deletes the host file and directory immediately, and again in the rollback journal's cleanup.
5. Inside the container: `pct exec <vmid> -- sm secrets import --offline --name providers/<name>/token --from-file /run/supermgmt-bootstrap/pve-token --delete-source`. This runs before the service starts (an offline command, §2.1.1): it takes the database lock, encrypts the secret, and unlinks the source file.
6. On **any** failure after step 1 — push, chown, or import — the installer runs `pct exec <vmid> -- rm -rf /run/supermgmt-bootstrap` (ignoring a stopped container: `/run` is tmpfs and is cleared on stop), revokes the token (`pveum user token remove`), deletes the host temp directory, and continues the rollback journal. On success it removes the directory as well.

The token value never appears in process arguments, environment, logs or the journal.

Failure behavior: if creation fails before SuperMgmt becomes usable, installer prints exact failure and offers/executes safe rollback of resources it created. It MUST NOT delete pre-existing resources. Rollback operations are tracked in a local transaction journal under `/var/tmp/supermgmt-installer-*` and cleaned after success.

Non-interactive example:

```bash
curl -fsSL <INSTALL_URL> | \
  SUPERMGMT_MODE=proxmox-lxc \
  SUPERMGMT_VMID=900 \
  SUPERMGMT_STORAGE=local-lvm \
  SUPERMGMT_TEMPLATE_STORAGE=local \
  SUPERMGMT_BRIDGE=vmbr0 \
  SUPERMGMT_MEMORY=2048 \
  SUPERMGMT_CORES=2 \
  SUPERMGMT_DISK_GIB=16 \
  SUPERMGMT_NETWORK=dhcp \
  SUPERMGMT_NONINTERACTIVE=1 \
  bash
```

Non-interactive mode MUST fail rather than guess an ambiguous storage/bridge.

## 3.6 Installer environment variables

At minimum:

```text
SUPERMGMT_VERSION
SUPERMGMT_CHANNEL
SUPERMGMT_MODE
SUPERMGMT_INSTALL_DIR
SUPERMGMT_DATA_DIR
SUPERMGMT_CONFIG_DIR
SUPERMGMT_NONINTERACTIVE
SUPERMGMT_YES
SUPERMGMT_VMID
SUPERMGMT_HOSTNAME
SUPERMGMT_STORAGE
SUPERMGMT_TEMPLATE_STORAGE
SUPERMGMT_BRIDGE
SUPERMGMT_NETWORK
SUPERMGMT_IP
SUPERMGMT_GATEWAY
SUPERMGMT_DNS
SUPERMGMT_CORES
SUPERMGMT_MEMORY
SUPERMGMT_SWAP
SUPERMGMT_DISK_GIB
SUPERMGMT_LOG_LEVEL
```

Secrets MUST NOT be accepted as command-line flags. Sensitive bootstrap material uses stdin, temporary mode-0600 files, or environment variables only when unavoidable and immediately unset.

## 3.7 Exit codes

```text
0 success
2 invalid arguments/config
3 unsupported platform/version
4 prerequisite failure
5 download/checksum/signature failure
6 resource creation failure
7 installation/configuration failure
8 connectivity/registration failure
9 upgrade/restore failure
10 user cancelled
```

---

# 4. Executables and process model

One Go module and one user-facing binary `sm`. No separate server binary.

Commands:

```text
sm                         open TUI
sm login                   authenticate remote profile
sm logout
sm profile list|add|use|remove
sm daemon [stop|install-user-unit]   run local daemon (Unix socket); normally auto-started
sm server                  run daemon in server mode (TCP/HTTPS)
sm install <mode>          installer logic invoked by install.sh (§3.4)
sm admin bootstrap-code|grant|restore-complete   server admin socket only (§11.5, §29.2)
sm mcp                     stdio MCP bridge (§24)
sm mcp clients list|add|remove
sm ssh-key show            server-mode public key (§8.4)
sm secrets import|rotate-master-key|retire-key|export-key|import-key
sm jobs [list|get|approve|reject|resolve]
sm status
sm doctor
sm nodes [list|get|add|remove|probe]
sm ssh <node>
sm services [list|get|logs|restart]
sm docker <node>            integration menu / lazydocker handoff
sm apps [list|get|add|remove]
sm deploy [list|get|create|rollback|cancel]
sm events
sm approvals
sm providers [list|add|remove|sync]
sm backup create|list|restore --offline
sm config validate|show
sm completion <shell>
sm version
```

All commands that mutate state support `--dry-run` where meaningful and `--json` for machine-readable output. TUI, CLI and MCP reach the application services only through the API (§2.1.1); the only exceptions are the offline commands listed in §2.1.1, `sm daemon`/`sm server` themselves, and `sm admin` (admin socket).

---

# 5. Repository layout — mandatory

```text
supermgmt/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug.yml
│   │   ├── feature.yml
│   │   └── config.yml
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── release.yml
│   │   ├── codeql.yml
│   │   └── dependency-review.yml
│   ├── dependabot.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── cmd/
│   └── sm/
│       └── main.go
├── internal/
│   ├── app/                 # use cases/application services
│   ├── domain/              # pure domain types/rules
│   ├── policy/              # authorization/risk/approval
│   ├── audit/               # event creation/redaction
│   ├── config/              # typed config/loading/validation
│   ├── database/            # SQLite, migrations, repositories
│   ├── secrets/             # envelope encryption/key providers
│   ├── jobs/                # durable job engine
│   ├── api/                 # HTTP API/SSE
│   ├── auth/                # local/OIDC identities
│   ├── mcp/                 # MCP transport/tools/resources
│   ├── client/              # typed API client used by TUI/CLI/MCP
│   ├── daemon/              # process lifecycle, socket, lock, idle exit
│   ├── tui/                 # Bubble Tea UI
│   ├── cli/                 # command implementations
│   ├── transport/
│   │   └── ssh/             # SSH connections/sessions/host keys (no inventory logic)
│   ├── discovery/           # capability probing
│   ├── providers/           # inventory sources; each owns sync of its resources
│   │   ├── local/
│   │   ├── ssh/             # statically registered SSH nodes; uses transport/ssh
│   │   ├── proxmox/
│   │   ├── github/
│   │   └── cloudflare/      # optional connector (M2 guide/hooks only)
│   ├── runtimes/
│   │   ├── docker/
│   │   └── systemd/
│   ├── deployments/
│   │   └── compose/
│   ├── installer/           # sm install <mode>; PVE CLI behind interfaces
│   ├── health/
│   ├── backup/
│   └── version/
├── migrations/
│   ├── 000001_initial.up.sql
│   └── ...
├── scripts/
│   └── join.sh              # same bootstrap+verify shape as install.sh, then `sm join`
├── packaging/
│   ├── systemd/supermgmt.service
│   ├── homebrew/README.md
│   └── nfpm.yaml
├── examples/
│   ├── config.yaml
│   ├── app.supermgmt.yaml
│   ├── github-actions.yml
│   └── policies.yaml
├── docs/
│   ├── architecture.md
│   ├── installation.md
│   ├── configuration.md
│   ├── providers.md
│   ├── deployments.md
│   ├── mcp.md
│   ├── security.md
│   ├── operations.md
│   ├── troubleshooting.md
│   └── adr/
├── api/
│   └── openapi.yaml
├── test/
│   ├── integration/
│   ├── fixtures/
│   └── e2e/
├── install.sh               # tiny public bootstrap: verify + exec `sm install`
├── .editorconfig
├── .gitignore
├── .golangci.yml
├── .goreleaser.yaml
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── SECURITY.md
├── GOVERNANCE.md
├── ROADMAP.md
├── CHANGELOG.md
├── LICENSE                   # Apache-2.0 unless changed before first release
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

No business logic in `cmd/`, HTTP handlers, Bubble Tea models or MCP handlers. They adapt requests to application services.

Directories for features scheduled after the current milestone are not created (§0). Post-V1 packages (`providers/vercel`, `deployments/systemd`, `deployments/shell`) are added only when their milestone starts.

---

# 6. Domain model

## 6.1 Resource graph

Canonical relationship model:

```text
Connector/Provider
        │
        ▼
       Node ──────────────► Runtime ─────► Service
        │                                  ▲
        │                                  │
        └──── capabilities                 │
                                           │
Repository ─► Application ─► Deployment ───┘
                  │
                  └──── Environment / Target
```

## 6.2 Core entities

**Provider**: integration instance with type, endpoint, credential reference, config, status and capabilities.

**Node**: physical/virtual Linux machine or discoverable guest. Fields: UUID, provider/native ID, name, kind, management state, health state, addresses, OS, arch, tags, environment, capabilities, timestamps.

Management state (configured): `discovered`, `managed`, `retired`. Reachability (observed): `reachable`, `unreachable`, `unknown` (§6.4). Do not conflate powered-off or unreachable with unmanaged.

**Runtime**: detected service manager/container runtime on a node: `docker`, `systemd` initially.

**Service**: runtime-native process/container/unit. Stable internal ID plus native ID. Status and health are separate.

**Application**: logical deployable software. Links repository, deployment policy and one/many services.

**Artifact**: immutable release input. OCI images MUST be represented by digest. Other artifacts require checksum and immutable version URI.

**Deployment**: application + exact artifact + target + strategy + state machine + previous known-good release.

**Job**: durable asynchronous operation.

**ActionPlan**: canonical list of intended mutations, risk, preconditions, target revisions and hash. Approval binds to this hash.

**Event**: append-only audit/operational event.

**Credential**: metadata and encrypted secret reference; never exposed through normal APIs.

## 6.3 Stable IDs

Use UUIDv7 (time-ordered; generated with `github.com/google/uuid`, which supports v7). Never use mutable names as primary keys. Human resource references may use names if unambiguous but resolve to IDs before execution.

## 6.4 Revisions: desired vs observed

Every **configured** resource carries one counter, `spec_revision`, plus separate **observation** records:

- `spec_revision` increments only when desired/configured state changes. That covers user edits, tags, environment, `management_state`, management endpoint (host, port, user, admin user, pinned host-key fingerprint), credential references, app/target/environment/repository/health-check configuration, Compose content, image policy and security exceptions. It is monotonic, used for optimistic concurrency (`If-Match`), and every plan records the `spec_revision` of each configured input (Appendix C).
- Observations (power state, reachability, metrics, health, discovered addresses, versions) live in `observations`, `node_addresses` and `last_seen_at`. They NEVER bump `spec_revision`.

Configured vs observed node fields:

```text
management_state  configured: discovered | managed | retired
reachability      observed:   reachable | unreachable | unknown
endpoint          configured: host, port, user, admin_user, host_public_key
                              (OpenSSH format; fingerprint derived from it)
addresses         observed:   node_addresses (informational; never used to connect
                              unless endpoint.host = "auto", see below)
```

**Connection user (SSH nodes).** `user` (default `supermgmt`) is the dedicated account that `node.setup` creates (§12 step 7); `admin_user` (required) is the operator's own account on the node, e.g. `root` or a personal login. Automated sessions connect as `user` if and only if the node has the capability `node.setup`; otherwise they connect as `admin_user` and run read-only probes only. `node.setup` itself and interactive sessions (§8.4) always connect as `admin_user`.

`endpoint.host: auto` (allowed only for Proxmox-discovered guests) resolves the connect address from observations at **plan time**. The plan pins both the address and the host key. Execution connects to the pinned address and verifies the pinned key. A different address or key fails the job (`PLAN_STALE`) and a new plan is required. The host key, not the address, is the node's identity.

Consequence: periodic discovery does not invalidate approvals. Preconditions that depend on observations (reachable, free disk) are re-checked at execution. Failing one fails the job; nothing silently re-plans.


---

# 7. Capability system

Capabilities drive UI and authorization. Examples:

```text
node.read
node.metrics
node.ssh
node.exec.template
node.packages.read
node.packages.update
node.reboot
node.shutdown
service.read
service.logs
service.restart
service.stop
service.start
docker.read
docker.logs
docker.exec.interactive
docker.compose.deploy
proxmox.vm.power
proxmox.snapshot.create
proxmox.backup.create
proxmox.console
deployment.create
deployment.rollback
```

A capability being technically available does not grant permission. Effective ability = discovered capability ∩ policy decision (§11.3) ∩ current preconditions (checked at execution time, §6.4).

---

# 8. Configuration

## 8.1 Paths

Linux server defaults:

```text
/etc/supermgmt/config.yaml
/var/lib/supermgmt/supermgmt.db
/var/lib/supermgmt/secrets/
/var/lib/supermgmt/backups/
/var/log/supermgmt/ (only if not journald-only)
```

Local user:

```text
$XDG_CONFIG_HOME/supermgmt/config.yaml
$XDG_DATA_HOME/supermgmt/supermgmt.db
$XDG_STATE_HOME/supermgmt/
```

macOS: if `XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_STATE_HOME` are set they are honored exactly as on Linux. Otherwise:

```text
config      ~/Library/Application Support/SuperMgmt/config.yaml
database    ~/Library/Application Support/SuperMgmt/supermgmt.db
state dir   ~/Library/Application Support/SuperMgmt/state/
socket      ~/Library/Application Support/SuperMgmt/state/run/sm.sock  (§2.1.1)
```

`~/Library/Preferences` is not used (reserved for plists). Path resolution has a unit test per OS/variable combination. Linux local mode without `XDG_RUNTIME_DIR` uses `$XDG_STATE_HOME/supermgmt/run/sm.sock` (default `~/.local/state/supermgmt/run/sm.sock`).

Permissions: server config 0640, data directories 0700/0750 as appropriate, secret key 0600.

## 8.2 Master config schema

`config.yaml` example (server mode; local-mode defaults noted):

```yaml
version: 1

instance:
  name: home
  mode: server # local|server
  data_dir: /var/lib/supermgmt

server:
  listen: 127.0.0.1:8787
  public_url: https://mgmt.example.com
  tls:
    mode: proxy            # direct | proxy  (§23.1)
    cert_file: ""          # required when mode=direct
    key_file: ""           # required when mode=direct
  trusted_proxies: ["127.0.0.1/32"]   # required non-empty when tls.mode=proxy
  admin_socket: /run/supermgmt/admin.sock
  request_timeout: 30s
  shutdown_timeout: 20s

daemon:
  socket: ""            # local mode; default per §2.1.1
  idle_exit: 10m        # local mode only
  resident: false       # local mode; true keeps daemon alive for schedules

ui:
  theme: auto

refresh:
  focused_interval: 5s      # node/service currently open in a client
  inventory_interval: 60s   # status of all managed nodes
  metrics_interval: 30s     # CPU/RAM/disk samples for managed nodes
  discovery_interval: 5m    # full capability re-probe

storage:
  sqlite:
    path: /var/lib/supermgmt/supermgmt.db
    busy_timeout: 5s
    wal: true

security:
  keys_dir: /var/lib/supermgmt/secrets/keys   # master key files (§10)
  policy_file: /etc/supermgmt/policies.yaml   # optional; built-in default policy if absent
  session_ttl: 12h
  approval_ttl: 15m
  allow_self_approval: false   # default true when instance.mode=local (§11.4)
  redact_command_output: true

auth:
  bootstrap:
    code_ttl: 24h             # one-time admin bootstrap code (§11.5)
  oidc:
    enabled: false
    issuer: ""
    client_id: ""
    client_secret_ref: ""     # secret:// reference
    redirect_url: ""          # web callback; CLI uses loopback redirect (§23.1)
    allowed_domains: []
    allowed_endpoint_origins: []   # extra https origins for token/device/JWKS endpoints (§23.1)

ssh:
  connect_timeout: 8s
  command_timeout: 30s
  keepalive_interval: 30s
  max_dials_in_flight: 16          # concurrent new handshakes
  max_connections: 512             # persistent connections (one per managed node)
  max_sessions_per_connection: 4
  idle_connection_ttl: 10m
  known_hosts_file: /var/lib/supermgmt/known_hosts
  host_key_policy: strict
  logs_mode: journal-group         # journal-group | broker  (§16)

jobs:
  workers: 4
  lease: 60s
  heartbeat: 15s
  reconcile_grace: 45s             # >= ssh.connect_timeout + ssh.command_timeout + 5s
  retry_base: 2s                   # max attempts are per action (§11.2)

health:
  allowed_private_cidrs: []        # control-plane checks only (§21)

outbound:
  proxy: ""                        # optional explicit HTTPS proxy URL; ambient *_PROXY env is ignored (§21.1)

github:
  oidc_audience: ""               # default: server.public_url; required `aud` for Actions OIDC (§18)
  ci_poll_initial: 15s
  ci_poll_max: 2m
  ci_timeout: 2h

mcp:
  enabled: true
  remote_enabled: false
  oauth:                           # required when remote_enabled (§24)
    issuer: ""
    resource: ""                   # canonical MCP resource URL; token audience
    jwks_url: ""                   # or introspection_url
    introspection_url: ""
    required_scopes: ["supermgmt:mcp"]
  allow_interactive_exec: false
  write_tools_enabled: false

providers: []

backup:
  schedule: "0 3 * * *"            # server mode default; local mode: disabled unless daemon.resident
  retention: 14
  directory: /var/lib/supermgmt/backups
```

Unknown fields MUST fail validation by default to catch typos. Environment overrides use `SUPERMGMT_` prefix with documented mapping. Secrets are references, not inline values, except ephemeral development mode.

## 8.2.1 Environment schema

Environments are database entities (`environments`), created via API/TUI or declared in config under `environments:`:

```yaml
environments:
  - name: production
    risk_level: production        # development | staging | production
    require_provenance: true      # §18
    approvals_required: 1         # minimum quorum for operational+ writes (1..5)
    allow_automatic_rollback: true
```

## 8.3 Provider config examples

Proxmox:

```yaml
type: proxmox
name: home-pve
endpoint: https://pve.local:8006
credential_ref: secret://providers/home-pve/token
verify_tls: true
ca_file: /etc/supermgmt/pve-ca.pem
sync_interval: 30s
```

SSH node, local mode:

```yaml
type: ssh
name: ovh-prod-01
endpoint:
  host: 10.42.0.10
  port: 22
  user: supermgmt                         # default; the account node.setup creates
  admin_user: alex                        # required; your own account on the node
  host_public_key: "ssh-ed25519 AAAA..."
credential_ref: secret://ssh/default      # default; the instance SSH identity (§8.4)
admin_credential_ref: ssh-agent://default # default in local mode
environment: production
tags: [docker]
```

SSH node, server mode (agent not available to a service; `admin_credential_ref` has no default):

```yaml
type: ssh
name: ovh-prod-01
endpoint:
  host: 10.42.0.10
  port: 22
  user: supermgmt
  admin_user: alex
  host_public_key: "ssh-ed25519 AAAA..."
credential_ref: secret://ssh/default
environment: production
tags: [docker]
```

## 8.4 Credential references

`credential_ref` is a URI. Supported schemes (closed set; unknown schemes fail validation):

```text
secret://<path>          encrypted secret in SuperMgmt store (§10). Default for server mode.
ssh-agent://default      use $SSH_AUTH_SOCK of the daemon's user. Local mode only;
                         rejected by validation when instance.mode=server.
file://<abs-path>        key file. Opened with O_NOFOLLOW; fstat must show a regular file
                         owned by the daemon UID with no group/other bits (mode & 077 == 0);
                         the parent directory must not be group/other-writable. Discouraged;
                         supported for migration.
```

SSH identity (both modes): on first start the daemon generates an Ed25519 key pair and stores the private key as `secret://ssh/default`. It is the default `credential_ref` of SSH nodes: automated sessions as `user` sign with it, and `node.setup` authorizes its public key for `user` (§12 step 7). `sm ssh-key show` (API: `GET /api/v1/ssh-key`) prints the public key so users can authorize it on nodes. Per-node keys are optional. Proxmox, GitHub and Cloudflare tokens always use `secret://`.

`admin_credential_ref` is the credential of `admin_user` (§6.4), used for read-only probes before setup, for the `node.setup` bootstrap and, in local mode, for interactive sessions. It follows the same scheme rules; its local-mode default is `ssh-agent://default` (still local-only), and it has no default in server mode.

Interactive access in server mode never exports the server's private key. `sm ssh <node>` and `sm docker <node>` on a remote client fetch the node's endpoint and pinned host public key from the server (`GET /api/v1/nodes/{id}/connect-info`, audited). They then run the local OpenSSH client with the **user's own** credentials and a temporary `known_hosts` containing only the pinned key. Users without their own access to the node cannot open an interactive session in V1.

Providers may also be created through API/TUI and persisted in DB. Static config is reconciled as declarative read-only provider definitions; DB must track origin.

---

# 9. SQLite schema

SQLite is default. Enable WAL, foreign keys and busy timeout. Migrations are embedded in binary and also present in repository.

Driver: `modernc.org/sqlite` (pure Go). Releases are built with `CGO_ENABLED=0` so darwin/linux × amd64/arm64 cross-compile from one runner. Record the choice and its performance trade-off vs CGO drivers in ADR-0001. Only the daemon opens the database (§2.1.1).

Required tables (exact columns may evolve only via migrations):

```text
schema_migrations(version, applied_at)
instances(id, name, created_at)
identities(id, actor_type, issuer, subject, client_id, display_name, email, created_at, last_seen_at, disabled_at)
roles(id, name, description)
role_bindings(id, identity_id, role_id, created_at)
bootstrap_codes(id, code_hash, created_at, expires_at, consumed_at, consumed_by)
sessions(id, identity_id, token_hash, client, created_at, expires_at, revoked_at, last_used_at)
api_tokens(id, identity_id, name, token_hash, scopes_json, created_at, expires_at, revoked_at, last_used_at)
idempotency_records(identity_id, key, method, path, request_hash, status_code, response_json, job_id, created_at, expires_at)
oidc_replay(issuer, jti, expires_at)
providers(id, type, name, origin, endpoint, credential_ref, config_json, status, spec_revision, last_sync_at, created_at, updated_at)
environments(id, name, risk_level, config_json, spec_revision)
nodes(id, provider_id, native_id, name, kind, environment_id, management_state, reachability, endpoint_json, credential_ref, os, arch, metadata_json, spec_revision, created_at, updated_at, last_seen_at)
node_addresses(id, node_id, address, family, scope, source, preferred, last_seen_at)
node_tags(node_id, tag)
node_capabilities(node_id, capability, available, metadata_json, checked_at)
runtimes(id, node_id, type, native_id, version, status, metadata_json, last_seen_at)
services(id, runtime_id, node_id, native_id, name, kind, status, health, metadata_json, spec_revision, last_seen_at)
repositories(id, provider_id, github_repository_id, github_owner_id, owner, name, url, default_branch, metadata_json, spec_revision)
apps(id, name, repository_id, manifest_path, deployed_service, image_policy_json, compose_source, compose_content, compose_hash, compose_exceptions_json, variables_json, secret_refs_json, ci_policy_json, spec_revision, created_at, updated_at)
app_targets(id, app_id, environment_id, node_id, compose_project, deployment_policy_json, spec_revision)
artifacts(id, app_id, type, immutable_ref, digest, commit_sha, source_run_id, source_run_attempt, provenance_json, provenance_method, created_at)
artifact_checks(artifact_id, check_name, app_id, workflow_path, run_id, run_attempt, conclusion, completed_at)
plans(id, action, actor_id, credential_kind, credential_id, scopes_json, plan_json, plan_hash, finalized_at, created_at, expires_at, submitted_job_id)
deployments(id, kind, app_id, app_target_id, environment_id, node_id, artifact_id, job_id, strategy, state, state_code, state_reason, requested_by, previous_deployment_id, rollback_of_deployment_id, known_good, compose_hash, plan_hash, created_at, updated_at, finished_at)
deployment_steps(id, deployment_id, ordinal, name, state, attempt, started_at, finished_at, output_ref, error_json)
jobs(id, type, resource_type, resource_id, actor_id, credential_kind, credential_id, scopes_json, state, risk, retry_class, idempotency_key, payload_json, plan_id, plan_hash, lease_owner, lease_generation, lease_until, heartbeat_at, attempts, max_attempts, scheduled_at, created_at, started_at, finished_at, error_json)
job_approvals(id, job_id, plan_hash, approver_id, decision, reason, expires_at, renewed_at, created_at)
operation_intents(id, job_id, step, lease_generation, state, operation, target_type, target_id, marker, pre_state_json, deadline_at, dispatched_at, completed_at, outcome, evidence_json)
resource_locks(resource_type, resource_id, job_id, mode, acquired_at)
health_checks(id, resource_type, resource_id, type, scope, config_json, enabled, spec_revision, created_at)
observations(id, resource_type, resource_id, kind, value_json, observed_at, expires_at)
events(seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, timestamp, actor_type, actor_id, source, action, resource_type, resource_id, correlation_id, severity, result, data_json)
secrets(id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext, metadata_json, created_at, rotated_at)
join_tokens(id, token_hash, expires_at, consumed_at, created_by, constraints_json)
webhook_deliveries(id, provider, delivery_id, received_at, signature_valid, event_type, processed_at, result)
settings(key PRIMARY KEY, value_json, updated_at)
```

Constraints that carry semantics (not just performance):

```text
identities          UNIQUE(actor_type, issuer, subject, client_id)  -- NULLs normalized to ''
idempotency_records PRIMARY KEY(identity_id, key)
oidc_replay         PRIMARY KEY(issuer, jti)
job_approvals       UNIQUE(job_id, plan_hash, approver_id)
resource_locks      PRIMARY KEY(resource_type, resource_id, job_id); exclusive/shared rules
                    enforced in the claim transaction (§20.5)
plans               UNIQUE(submitted_job_id); submit sets it with
                    UPDATE … WHERE submitted_job_id IS NULL (one job per plan)
artifact_checks     PRIMARY KEY(artifact_id, check_name)
operation_intents   UNIQUE(marker)
webhook_deliveries  UNIQUE(provider, delivery_id)
app_targets         UNIQUE(node_id, compose_project)
providers           UNIQUE(name)
nodes               UNIQUE(provider_id, native_id)
```

Enumerations (CHECK constraints): `identities.actor_type ∈ {human, automation, mcp, system}`; `artifacts.provenance_method ∈ {attestation, oidc_claims}`; `deployments.kind ∈ {deploy, rollback}`; `operation_intents.state ∈ {recorded, completed}`; `resource_locks.mode ∈ {exclusive, shared}`; `nodes.management_state ∈ {discovered, managed, retired}`; `nodes.reachability ∈ {reachable, unreachable, unknown}`.

Indexes MUST additionally cover node/service lookup, event timeline, job queue (`state, scheduled_at`), deployments by app/environment, and token/session hash lookup.

Token and session values are stored only as SHA-256 hashes of high-entropy random tokens (≥256 bits). `idempotency_records` expire after 24h (§23).

Events are append-only through application permissions; no ordinary delete API.

---

# 10. Secret storage

V1 uses envelope encryption with AES-256-GCM from the Go standard library (`crypto/aes`, `crypto/cipher`). Never invent cryptography.

**Keys.** Master keys (KEKs) are 32 random bytes in files `security.keys_dir/<kek_id>.key` (mode 0600, owned by the service user; directory 0700). `kek_id` is a UUIDv7. The active KEK id is stored in `settings.active_kek_id`. At creation, a key-check record is stored: `settings.kek_check.<kek_id>` = `nonce(12) || AES-GCM(KEK, nonce, "supermgmt/kek-check/v1", aad_c)` with `aad_c = lp("supermgmt/kek-check/v1") || lp(kek_id)`. Startup decrypts every referenced KEK's record and fails fast if one is missing or wrong.

**Envelope (`envelope_version = 1`).** For each secret:

```text
dek          = 32 random bytes (fresh per secret and per secret update)
wrapped_dek  = nonce_w(12) || AES-GCM(KEK, nonce_w, dek, aad_w)        (ciphertext||tag)
ciphertext   = nonce_p(12) || AES-GCM(dek, nonce_p, plaintext, aad_p)  (ciphertext||tag)
aad_w        = lp("supermgmt/dek/v1") || lp(secret_id) || lp(kek_id)
aad_p        = lp("supermgmt/secret/v1") || lp(secret_id) || lp(uint32be(envelope_version))
lp(x)        = uint32be(len(x)) || x
```

Nonces are random (crypto/rand). The distinct domain-separation labels prevent swapping a wrapped DEK for a payload or between secrets.

**Rotation (`sm secrets rotate-master-key`).**
1. Generate a new KEK file and its check record.
2. In a **single SQLite transaction**, unwrap every DEK with its old KEK, rewrap it under the new KEK, update `kek_id`, and set `active_kek_id`.
3. Old KEK files are kept until an operator runs `sm secrets retire-key <kek_id>`. It refuses while any secret row or **any** archive in `backup.directory` lists the key in its manifest. Backups copied elsewhere are unknown to SuperMgmt, so retirement also requires `--external-backups-handled`, which records an audited acknowledgement that external copies were re-made or discarded.

A crash before commit leaves the old state intact; a crash after commit leaves the new state, and the old key is still present.

**Rules.**
- Logs and errors never include secret plaintext. The API never returns secret plaintext after creation.
- `sm backup` includes encrypted secrets (they are rows in the database) but never KEK files.
- Key backup is a separate, explicit `sm secrets export-key <kek_id>` that requires a passphrase (≥ 12 characters, read from a TTY or stdin, never from an argument). Export file format v1:

  ```text
  magic "SMKEY1" | u8 version=1 | lp(kek_id) | u8 log2N | u32 r | u32 p | salt(16) | nonce(12)
  | AES-256-GCM(scrypt(passphrase, salt, N, r, p, 32), nonce, KEK, aad = all preceding bytes)
  ```

  Defaults: N = 2^17, r = 8, p = 1. Import accepts 2^15 ≤ N ≤ 2^20, r = 8, p ∈ 1..4 and rejects anything else. `sm secrets import-key --offline --from <export-file>` needs no daemon and no database:
  1. It decrypts and authenticates the export with the passphrase.
  2. It writes the key to `security.keys_dir/<kek_id>.key.pending` (0600).
  3. If a database exists and references `kek_id`, it verifies the check record and renames the file to `.key`.
  4. Otherwise the key stays pending until a restore validates it against the **staged** database (§29.2).

  The daemon never loads `.pending` keys.

  `export-key` puts a wrapped master key in the response, so it is served only on the local-mode Unix socket, never over HTTPS or the admin socket. In server mode it runs offline (`sm secrets export-key --offline`, service stopped, database lock held).

  **Approval of `secret.write` (1.4.4).** Every online operation here is the `secret.write` action (high risk), so §11.3 step 8 requires approval and the request becomes a plan and a `control_plane.apply` job (§11.2). A plan never holds a secret value or a passphrase:
  - `rotate-master-key`, `retire-key` and `ssh-key rotate` carry no secret; the job performs them after approval.
  - `secret import` seals the value at request time, under the active KEK, as a **staged** secret version. It is not readable as current and takes no version number. The plan names only the staged version id and the SHA-256 of the plaintext. Approval activates that version (after checking the digest); rejection, expiry, cancellation or failure of the job deletes the staged ciphertext. A staged version counts as a reference to its KEK for `retire-key`.
  - `export-key` is two steps, as `mcp_client.register` and `mcp_client.issue_token` (§11.2): a request without a passphrase creates the approval-gated job, which exports nothing; after approval the **same identity** may execute the export once, within 24h, by supplying the passphrase. A second execution or a late one is `CONFLICT`; another identity's attempt is `POLICY_DENIED`. If policy does not require approval, the call that carries the passphrase exports directly.

Future key providers (OS keychain, age, Vault/KMS) implement a `KeyProvider` interface returning a KEK by id.


---

# 11. Authentication, RBAC, policy and approvals

## 11.1 Identities and actor types

Every request has exactly one actor. Identity is always a daemon-issued `identities.id`. Names reported by clients are display metadata only.

```text
human       local mode: the OS user of a socket connection that presents NO token
            (identity "local:<uid>", created on first daemon start). server mode: an
            OIDC subject (issuer+subject) after login.
automation  API token holder, or a verified GitHub Actions OIDC token (§18) mapped to a
            pre-registered automation identity (issuer + repository_id + workflow ref).
mcp         a registered MCP client. Local: registered by a human with `sm mcp clients add
            <name>` (registration, then one-time token issuance, §11.2), which yields an MCP client token stored by the MCP bridge config in a
            0600 file or the OS keychain; `sm mcp` presents it on every socket request.
            Remote: (issuer, subject, client_id) from OAuth (§24), pre-registered by an
            admin. The MCP `initialize` client name is never used for identity.
            An MCP identity NEVER inherits the roles of the human who registered it.
system      the daemon itself. Allowed operations, fixed in code: observation writes,
            reconciliation (§20.4), scheduled `backup.create` and backup retention pruning
            (§29.1), expiry sweeps (plans, approvals, idempotency, OIDC replay).
            Cannot hold role bindings, cannot approve.
```

On the local socket, a request carrying an MCP client token is `mcp`; a request carrying no token is `human`. This separation guards against a misbehaving model using the bridge. It does not guard against arbitrary code running as the same OS user (§2.1.1 trust boundary).

**Credential context.** Every authenticated request also carries the credential it used: `credential_kind ∈ {local_socket, session, api_token, mcp_token, oauth_access_token, github_oidc}`, `credential_id`, the token `scopes`, and the credential expiry. Plans and jobs persist this context (§9). It is re-checked at claim (§20.4):
- a revoked credential fails the job (`CREDENTIAL_REVOKED`);
- an expired API, MCP or OAuth token fails the job (`CREDENTIAL_EXPIRED`);
- a session or GitHub OIDC token that expires naturally after submission does NOT fail the job, because the submission was valid and these credentials are short-lived by design, but revocation does;
- scopes are always re-applied.

## 11.2 Roles, default policy and the action catalog

Roles are named groups of identities (`role_bindings(identity_id, role_id)`, no selectors). **The policy file is the only place where permissions are granted.** The binary ships a built-in default policy (embedded; printed by `sm config show --policy`) that gives the built-in roles their meaning. A user policy file (`security.policy_file`) replaces it entirely, and `sm config validate` shows the diff against the built-in default.

Built-in default policy:

```yaml
version: 1
rules:
  - name: builtin-read
    subjects: ["role:viewer", "role:operator", "role:deployer", "role:admin"]
    allow: ["*.read", "service.logs", "node.connect", "plan.create"]
  - name: builtin-operator
    subjects: ["role:operator", "role:admin"]
    allow: ["service.start", "service.stop", "service.restart", "node.probe",
            "node.reboot", "proxmox.vm.power", "proxmox.snapshot.create",
            "proxmox.backup.create", "job.cancel", "job.resolve"]
  - name: builtin-deployer
    subjects: ["role:deployer", "role:admin"]
    allow: ["deployment.create", "deployment.rollback", "job.cancel",
            "node.backup_template.run"]
  - name: builtin-approver
    subjects: ["role:operator", "role:deployer", "role:admin"]
    allow: ["approval.grant", "approval.reject"]
  - name: builtin-admin
    subjects: ["role:admin"]
    allow: ["config.write", "environment.write", "provider.write", "node.add",
            "node.update", "node.remove", "app.write", "app_target.write",
            "identity.write", "role_binding.write", "mcp_client.register",
            "mcp_client.issue_token", "mcp_client.delete",
            "token.create", "token.revoke", "enrollment.create", "secret.write",
            "backup.create", "node.setup", "sudoers.write", "log_broker.install"]
  - name: builtin-mcp-read
    subjects: ["type:mcp"]
    allow: ["*.read", "plan.create"]
```

`automation` identities receive nothing by default. `system` is not subject to policy; it is limited to the operations listed in §11.1. Every identity may always read itself (`/me`) and list and revoke its own tokens; these are not policy-evaluated.

**Action catalog** (`internal/policy/catalog.go`). The engine rejects any action not listed. Modes:
- `job`: the action creates a plan, then a job, and is executed by a worker.
- `direct`: a control-plane state change applied inside the request transaction. If policy requires approval, it is instead wrapped in a `job` of type `control_plane.apply` and runs after approval.
- `governance`: decisions on existing jobs (§11.4).
- `query`: reads with no state change.

```text
action                     resource     risk          mode        retry          capability               max
--------------------------------------------------------------------------------------------------------------
node.read                  node         read          query       —              —                        —
service.read               service      read          query       —              service.read             —
service.logs               service      read          query       —              service.logs             —
app.read                   app          read          query       —              —                        —
app_target.read            app_target   read          query       —              —                        —
deployment.read            deployment   read          query       —              —                        —
environment.read           environment  read          query       —              —                        —
provider.read              provider     read          query       —              —                        —
job.read / plan.read       job / plan   read          query       —              —                        —
event.read                 event        read          query       —              —                        —
config.read                instance     read          query       —              —                        —
identity.read              identity     read          query       —              —                        —
backup.read                instance     read          query       —              —                        —
node.connect               node         read          query       —              node.ssh                 —
plan.create                (targets)    read          query       —              —                        —
node.probe                 node         read          job         idempotent     node.read                3
service.start|stop|restart service      operational   job         non_retryable  service.<verb>           1
node.reboot                node         high          job         non_retryable  node.reboot              1
node.shutdown              node         high          job         non_retryable  node.shutdown            1
proxmox.vm.power           node         op./high*     job         non_retryable  proxmox.vm.power         1
proxmox.snapshot.create    node         operational   job         non_retryable  proxmox.snapshot.create  1
proxmox.snapshot.rollback  node         high          job         non_retryable  proxmox.snapshot.create  1
proxmox.snapshot.delete    node         destructive   job         non_retryable  proxmox.snapshot.create  1
proxmox.backup.create      node         operational   job         non_retryable  proxmox.backup.create    1
node.backup_template.run   node         operational   sub-action  —              node.exec.template       —
deployment.create          app_target   operational   job         resumable      docker.compose.deploy    3
deployment.rollback        app_target   operational   job         resumable      docker.compose.deploy    3
node.setup                 node         high          job         idempotent     node.ssh                 3
sudoers.write              node         high          job         non_retryable  node.ssh                 1
log_broker.install         node         high          job         non_retryable  node.ssh                 1
backup.create              instance     operational   job         idempotent     —                        3
node.add|update            node         operational   direct      —              —                        —
node.remove                node         destructive   direct      —              —                        —
provider.write             provider     high          direct      —              —                        —
provider.delete            provider     destructive   direct      —              —                        —
environment.write          environment  high          direct      —              —                        —
app.write                  app          operational   direct      —              —                        —
app_target.write           app_target   operational   direct      —              —                        —
config.write               instance     high          direct      —              —                        —
secret.write               secret       high          direct      —              —                        —
identity.write             identity     high          direct      —              —                        —
role_binding.write         identity     high          direct      —              —                        —
mcp_client.register        identity     high          direct      —              —                        —
mcp_client.issue_token     identity     operational   direct**    —              —                        —
mcp_client.delete          identity     operational   direct      —              —                        —
token.create               identity     operational   direct**    —              —                        —
token.revoke               identity     operational   direct      —              —                        —
enrollment.create          instance     operational   direct**    —              —                        —
approval.grant             plan         governance    governance  —              —                        —
approval.reject            plan         governance    governance  —              —                        —
job.cancel                 job          governance    governance  —              —                        —
job.resolve                job          governance    governance  —              —                        —
```

Notes on the catalog:
- `*` `proxmox.vm.power` is `operational` for start, shutdown and reboot, and `high` for `stop` (hard stop). The verb is a parameter and the catalog computes the risk from it; callers never supply risk.
- `**` **Credential-issuing** direct actions (`mcp_client.issue_token`, `token.create`, `enrollment.create`) return a secret exactly once and are **never approval-gated**. Two design rules make this consistent with §11.3 step 8:
  - Their risk is `operational` and their resources (identities, the instance) have no environment, so the automatic approval floors never apply to them. The only possible trigger is an explicit `require_approval: true` rule, which `sm config validate` rejects for these actions. At runtime such a request is denied (`POLICY_DENIED`, `APPROVAL_NOT_SUPPORTED`).
  - The decision that may need approval is separated from the secret: **registering** an MCP client (`mcp_client.register`, high) is approval-gated like any high-risk direct action and creates the identity in state `pending_token`. Afterwards, `mcp_client.issue_token` is allowed **once**, only to the identity that requested the registration, only while the client is `pending_token`, and within 24h of approval. It returns the token and moves the client to `active`. A lost token requires deletion and re-registration.
- `secret.write` is approval-gated by the high-risk floor (§11.3 step 8). Its operations carry no secret in the plan: an import is sealed as a staged version that approval activates, and `export-key` is requested, approved, then executed once by the requester with the passphrase (§10).
- A token can never carry scopes broader than the creator's own permissions at creation; scopes only narrow (§11.3 step 7).
- `sub-action`: never invoked directly. It is authorized as part of a composite plan (§11.3).
- Authentication operations (`/auth/*`, bootstrap exchange) are not actions. They are governed by §23.1 and §11.5.
- `backup.restore` is not an API action. It is an offline/admin-socket operation (§29.2).

**Endpoint → action mapping** is a table in `internal/api/routes.go` and in OpenAPI (`x-supermgmt-action`). CI fails if a route lacks a mapping or maps to an action not in the catalog.

Risk classes:

```text
read         no mutation
operational  restart/start/stop/deploy/update/ordinary config changes
high         reboot/shutdown/hard stop/snapshot rollback/secrets/identities/providers/
             environments/global config/node privilege changes
destructive  delete/disk/network/provider destructive actions
governance   decisions on existing plans/jobs; evaluated by §11.4, never approval-gated
```

**Administrative resource attributes:** `provider` → `provider:<name>`; `environment` → `environment:<name>`; `identity`, `instance`, `secret` → only rules with no `resources` (or `*`) match them.

## 11.3 Evaluation algorithm

**Effective resource attributes** used for matching. Tags are always control-plane-owned: `node_tags` and environments. Container labels, Compose labels and manifest content never become authorization attributes.

```text
node        node_tags; environment = nodes.environment_id; provider
service     its node's tags, environment and provider (service-level tags: none in V1)
app_target  environment of the target; app name; tags of its node
deployment  same as its app_target
provider    provider name
```

**Composite plans.** A `deployment.create`/`deployment.rollback` plan also lists the **sub-actions** its deployment policy enables:
- `proxmox.snapshot.create` on the node when `snapshot: true`;
- `node.backup_template.run` on the node when `pre_deploy_backup` is set.

A `node.setup` plan (ADR-0009) lists, on the node:
- `sudoers.write`, always;
- `log_broker.install` when `logs_mode: broker`.

They are executed by the setup job with its idempotent semantics; V1 exposes no standalone `sudoers.write` or `log_broker.install` job (changing the granted units or the log mode re-runs `node.setup`).

Each sub-action is evaluated like a target (steps 2–8). The plan is allowed only if the main action and every sub-action are allowed; approval and quorum are the maximum over all of them.

**Input:** actor, credential context (§11.1), action, target set, sub-actions, parameters.

```text
1. Catalog: action must exist; compute risk from the catalog and parameters.
2. Capability: for each target, the required capability must be advertised
   -> otherwise CAPABILITY_UNAVAILABLE (not a policy decision; still audited).
3. Match, per target: collect rules where
     subjects matches actor   ("type:<t>", "role:<r>", "identity:<uuid>", "*")
     AND resources matches    (omitted = all; "tag:<t>", "environment:<e>",
                               "provider:<name>", "node:<name>", "app:<name>";
                               entries are OR'ed; matched against effective attributes)
     AND (allow or deny) contains a pattern matching the action.
   Action patterns are dot-separated; "*" matches exactly one segment; a bare "*"
   matches any action. No other wildcards.
4. Deny overrides: any matched deny -> DENY.
5. Default deny: no matched allow -> DENY.
6. Destructive gate: risk=destructive requires a matched allow rule with
   allow_destructive: true, else DENY.
7. Credential scopes: if the credential has scopes, the action must also match one of
   them, else DENY. Scopes only narrow.
8. Approval, per target (skipped for read, query and governance): required if ANY of
     - a matched allow rule has require_approval: true
     - risk >= high
     - risk >= operational AND effective environment risk_level = production,
       unless a matched allow rule sets require_approval: false AND actor type is
       human or automation
     - actor type is mcp AND risk >= operational      (hard floor; not configurable)
   quorum = max(1, environment.approvals_required, max(rule.approvals over matched
   rules)), bounded to 1..5.
9. Combine targets and sub-actions: decision = ALLOW only if all are ALLOW;
   approval_required = OR; quorum = max.
10. Result: {decision, approval_required, quorum, reason, matched_rules[] per target}.
```

Every DENY and CAPABILITY_UNAVAILABLE emits an audit event. The algorithm is table-tested: each numbered step has positive and negative cases, plus property tests that adding allow rules never overrides a deny and that adding a target or sub-action never relaxes a decision.

## 11.4 Approvals

- An approval binds to the plan hash (Appendix C), which covers every execution input. Any change produces a new hash; prior approvals do not transfer.
- `approval.grant` and `approval.reject` are **governance** actions. They are evaluated with steps 1, 3–5 and 7 for every target and sub-action of the plan, need no capability, and never themselves require approval (no recursion). An approver must be allowed for all of them.
- `mcp` and `system` identities can never approve or reject. `automation` can do so only through an explicit rule.
- **Quorum** counts distinct identities. There is one row per (job, plan_hash, approver) (`UNIQUE`).
  - A decision while the approver's previous approval is unexpired returns `CONFLICT` (`ALREADY_DECIDED`).
  - After expiry, the same approver may **renew**: the row's `expires_at` and `renewed_at` are updated, the renewal is audited, and it counts again.
  - A rejection row is final and cannot be renewed.
- **Self-approval** (approver = requester) is forbidden when `security.allow_self_approval: false`. The default is `true` in local mode and `false` in server mode. When allowed, the requester counts at most once, only for `human` requesters, and only through an explicit approve action on the displayed plan hash, never implicitly.
- **Rejection** is accepted only while the job is in `waiting_ci`, `awaiting_approval` or `queued`. It moves the job to `failed` (`REJECTED`) and is final for that plan hash. From `preparing` onward a rejection returns `CONFLICT`; the remedy is cancel (where allowed) or a later rollback.
- **Expiry:** each approval expires `security.approval_ttl` after it was given or renewed. Quorum is evaluated at the transition out of `awaiting_approval` and again at claim (§20.4); only unexpired approvals from still-authorized approvers count. If quorum lapses, the job returns to (or stays in) `awaiting_approval`.
- **Plan expiry:** `plans.expires_at` (default 24h after the plan was finalized) is checked at submit (`CONFLICT`, `PLAN_EXPIRED`), at every approval, and at claim. An expired plan moves its job to `failed` (`PLAN_EXPIRED`) from any pre-execution state.
- Approve/reject requests MUST include the `plan_hash` the approver saw; a mismatch returns `CONFLICT` (`PLAN_STALE`).

## 11.5 Bootstrap bindings

- **Local mode:** on first daemon start, the OS user's identity `local:<uid>` is created and bound to `admin`.
- **Server mode:** `sm admin bootstrap-code` (admin socket only: root or the service user on the server, or inside the appliance via `pct exec`) **issues** a new one-time code and prints it once.
  - The code has ≥128 bits of entropy, is stored only as a hash in `bootstrap_codes`, and has TTL `auth.bootstrap.code_ttl`. Issuing a new code invalidates any unconsumed previous one.
  - It works only while no `admin` binding exists. Afterwards, `sm admin bootstrap-code` refuses, and recovery is `sm admin grant <identity-id> admin` (admin socket, audited).
  - Exchange: `POST /api/v1/auth/bootstrap` with the code, together with a completed OIDC login (§23.1), binds that identity to `admin`. If OIDC is not configured, the exchange creates an `admin` human identity named by the caller and returns a session token plus a first API token (shown once). The code is consumed atomically.
  - The installer (§3.5) runs `sm admin bootstrap-code` at the end and prints the code with the access instructions.

## 11.6 Example user policy

```yaml
version: 1
rules:
  - name: mcp-read
    subjects: ["type:mcp"]
    allow: ["*.read", "plan.create"]
  - name: human-staging
    subjects: ["role:operator"]
    resources: ["environment:staging"]
    allow: ["service.restart", "deployment.create"]
  - name: production-deploy
    subjects: ["role:deployer"]
    resources: ["environment:production"]
    allow: ["deployment.create", "deployment.rollback", "node.backup_template.run"]
    require_approval: true
    approvals: 2
  - name: ci-deploy-staging
    # automation identity registered for repository 123456789, workflow ci.yml
    subjects: ["identity:0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88"]
    resources: ["environment:staging"]
    allow: ["deployment.create"]
    require_approval: false
  - name: never-mcp-destructive
    subjects: ["type:mcp"]
    deny: ["node.shutdown", "provider.delete", "proxmox.snapshot.delete"]
```


---

# 12. SSH transport and agentless node management

SSH is the primary node transport.

Requirements:

- Credentials per §8.4 (agent in local mode; encrypted key in server mode).
- Strict host-key verification. First trust requires explicit fingerprint confirmation or trusted CA.
- Changed key hard-fails.
- One persistent, keepalive'd connection per managed node, multiplexing sessions (`max_sessions_per_connection`). New handshakes are bounded by `max_dials_in_flight`; total connections by `max_connections`. Connections idle beyond `idle_connection_ttl` close; unreachable nodes back off exponentially (cap 5m) without holding a dial slot.
- Context cancellation and timeouts on every dial and session.
- The SSH exec protocol transmits a single command string interpreted by the remote login shell, so "no concatenation" is enforced structurally: commands come only from the template catalog (`internal/transport/ssh/templates`), every argument passes a per-parameter validator (allowlist regex, e.g. unit names `^[A-Za-z0-9@._:-]+\.service$`) and is then POSIX single-quote escaped. Templates and validators have fuzz tests with injection payloads.
- Remote output is read with byte and time limits and treated as untrusted (§30).

Scale model (target 500 nodes, §34): status and metrics are collected by a single probe template per node that returns all values in one session (CPU% is computed from two `/proc/stat` samples taken inside the same command, 1s apart). Refresh is tiered per `refresh.*` (§8.2): only resources focused in some client refresh at `focused_interval`. With persistent connections a 500-node inventory cycle costs ~500 sessions, not ~500 handshakes.
- Interactive SSH hands terminal control to OpenSSH or a robust PTY implementation and audits session start/end, not keystrokes.

Probe commands gather OS, kernel, uptime, CPU, memory, disk, package manager, systemd, Docker and optional tools. Probe failure of one capability does not mark node wholly unavailable.

`sm nodes add ssh user@host` flow:

1. Parse host.
2. Connect and display host fingerprint.
3. User approves fingerprint.
4. Authenticate.
5. Probe capabilities read-only.
6. Show discovered capabilities.
7. Optionally create dedicated `supermgmt` user and scoped sudo policy through an explicit plan/approval: the `node.setup` job (ADR-0009), run as `admin_user` (root, or `sudo -n` for each privileged command). It creates the system user `supermgmt` (home `/var/lib/supermgmt`, shell `/bin/sh`, no password) and authorizes the instance identity `secret://ssh/default` (§8.4) for it with a `restrict` key. It adds the user to the `docker` group only when the plan parameter `docker_access` is `true`; that parameter has no default, because Docker access is root-equivalent (§17). It then installs the sudoers drop-in and, in broker mode, the log broker (§16). Removing the user and its files is a documented manual procedure in V1; automated teardown is deferred.
8. Persist node and credential reference.

No persistent agent is required in V1.

---

# 13. Optional join workflow

`join.sh` exists for users who want managed enrollment or future outbound connectivity. It is not required for basic SSH nodes.

Canonical UX:

```bash
curl -fsSL https://raw.githubusercontent.com/<ORG>/supermgmt/main/scripts/join.sh | sudo bash
```

Enrollment token MUST be supplied via stdin or secure prompt, not recommended as CLI argument:

```bash
printf '%s' "$SUPERMGMT_JOIN_TOKEN" | sudo ./join.sh --token-stdin --server https://mgmt.example.com
```

Join token is single-use, hashed in DB, short-lived and constrained by optional tags/node count/source. Re-running is idempotent.

V1 join may configure dedicated user/key and private connectivity but MUST NOT require a permanent agent. Any overlay network integration is optional and modular.

---

# 14. Local provider

When SuperMgmt runs locally it may register the current machine as `local` provider/node after user consent. It can discover Docker/systemd (Linux), local repositories and system information. Mutations still go through policy. macOS has no systemd; capabilities reflect reality.

---

# 15. Proxmox provider

## 15.1 Scope

Discover cluster nodes, QEMU VMs, LXCs, status, configured CPU/RAM/storage, selected metrics, storage metadata, tasks and snapshots/backups where authorized.

## 15.2 Authentication

Use a dedicated Proxmox identity/API token with privilege separation and minimum required roles. Do not use root password. The installer should create/read a project-defined least-privilege role when necessary. Because exact Proxmox privileges may vary by supported PVE version and operation, maintain a tested compatibility matrix and separate read-only vs write privilege sets.

Initial automatic appliance install SHOULD grant read/discovery plus explicitly selected operational capabilities. Destructive permissions are not enabled by default.

## 15.3 Discovery

- Discover cluster and resources periodically (default 30s) and on demand.
- VM/LXC resources are automatically `discovered`.
- QEMU guest IP data may use guest agent if available; absence is normal.
- LXC addressing may be derived from config/runtime where supported.
- A discovered guest becomes `managed` only after a management transport (e.g. SSH) is configured/validated.
- Proxmox power state and SSH reachability are separate.

## 15.4 Actions

Supported progressively:

```text
start / shutdown / reboot / stop (stop considered higher risk)
console handoff where feasible
snapshot create/list/delete under policy
backup create/list/status
```

Proxmox asynchronous task IDs must be polled and persisted. “Request accepted” is not “operation succeeded.”

Host package updates are not performed via Proxmox API; they require separate SSH capability and maintenance policy.

---

# 16. Runtime: systemd

Discover selected service units and status. Default filters should avoid flooding UI with irrelevant transient units. Allow user to include/exclude patterns.

Actions: status, logs, start, stop, restart, reload where supported.

Privilege model on nodes. All sudo invocations use `sudo -n` (non-interactive; fail instead of prompting).

- **Logs, `ssh.logs_mode: journal-group` (default):** the `supermgmt` user is added to `systemd-journal` (or `adm` where that is the distro convention). **Trust boundary:** this lets the node credential read the entire system journal on that node, not only selected units. API/MCP mediation limits what clients see, but a stolen node credential can read all of that node's logs. The installer's plan and `docs/security.md` state this explicitly.
- **Logs, `ssh.logs_mode: broker` (opt-in, recommended for production):** SuperMgmt installs a root-owned broker, `/usr/local/libexec/supermgmt/unit-logs` (mode 0755, owner root), through an approval-gated plan. It accepts exactly `<unit> <lines>`, validates the unit against `/etc/supermgmt/allowed-units` (root-owned, 0644) and `lines` ≤ 10000, then execs `journalctl --no-pager --output=short-iso -u <unit> -n <lines>` with a clean environment. Sudoers grants only `supermgmt ALL=(root) NOPASSWD: /usr/local/libexec/supermgmt/unit-logs`. The user is not in `systemd-journal`.
- In both modes `journalctl` itself is never granted through sudo, and every direct invocation passes `--no-pager` with `SYSTEMD_PAGER=` and `PAGER=cat`.
- **Unit actions:** a sudoers drop-in (`/etc/sudoers.d/supermgmt`, mode 0440, validated with `visudo -cf` before install) lists one exact line per selected unit and verb, e.g. `supermgmt ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx.service`. There are no wildcards in arguments. Adding a unit regenerates the drop-in through an approval-gated plan.
- **Unit trust profile (precondition for sudoers grants):** before a unit enters the sudoers drop-in, and again at every action, SuperMgmt reads `systemctl show -p FragmentPath,DropInPaths,ExecStartPre,ExecStart,ExecStartPost,ExecReload,ExecStop,ExecStopPost,EnvironmentFiles,WorkingDirectory,User` and requires:
  - the unit file, every drop-in, every executable named in any `Exec*` line, every `EnvironmentFile` and the `WorkingDirectory` are root-owned and not group/other-writable, and so is **every parent directory up to `/`**;
  - when an `Exec*` program is an interpreter (`sh`, `bash`, `dash`, `python*`, `perl`, `ruby`, `node`, `php`, or any file starting with `#!`), every script path argument satisfies the same rule; interpreter `-c`/`-e` inline code is not allowed;
  - anything that cannot be resolved to a path (shell wrappers using variables, `%` specifiers resolving outside the above) makes the unit ineligible.

  Ineligible units are refused with `CAPABILITY_UNAVAILABLE` and the failing path. This is a documented **trust profile**, not a proof: `docs/security.md` states that granting restart on a unit trusts everything that unit executes. Sudoers grants are `sudoers.write` (risk high, approval-gated).

Logs are bounded by line/byte/time limits and redacted for configured secret patterns.

---

# 17. Runtime: Docker / Compose / lazydocker

Docker discovery:

- Docker version/info availability.
- Containers: ID/name/image digest/status/health/ports/labels/Compose project.
- Compose projects where labels/config permit discovery.
- Resource stats sampled on demand/interval.
- Logs bounded and streamed when requested.

Docker access is effectively privileged on many systems. Document this prominently.

Actions: start/stop/restart selected containers, logs, Compose deployment, human interactive exec when policy permits.

## 17.1 lazydocker integration

The TUI node screen shows `D lazydocker` only when Docker is available and an execution path is valid.

Preferred order:

1. Run local `lazydocker` against a secure Docker context over SSH if supported/tested.
2. Otherwise launch lazydocker through interactive SSH if installed remotely.
3. If absent, offer installation instructions or an approval-gated install action; never silently install.

Before handoff, suspend Bubble Tea terminal state. On exit, restore alternate screen, mouse/keyboard mode, resize state and refresh node data. Exit code is displayed if nonzero.

Also support similar human-only handoffs for `btop`, `journalctl`, `tmux`, and raw SSH where available.

---

# 18. GitHub connector and CI-gated deployments

GitHub is a connector/provider for repositories, workflow status and deployment authorization.

Application creation flow from TUI:

```text
Select GitHub repository
Select deployment branch
Select target environment/node selector
Select strategy (Docker Compose V1)
Define health check
Define rollback policy
Choose required GitHub workflow/checks
Review plan
Save application
```

A deployment configured as “when CI passes” MUST deploy the exact commit/artifact that passed CI, never “latest main” at execution time.

**CI policy** (per app, `apps.ci_policy_json`, set at app creation by an admin, part of plan inputs):

```yaml
repository_id: 123456789          # numeric GitHub IDs; names are display only
owner_id: 987654
branch: main
allowed_events: [push]            # pull_request / pull_request_target never allowed
required_checks:
  - name: test
    app_id: 15368                 # GitHub App that must have produced the check run;
                                  # recorded from the repository at app creation, not hard-coded
    workflow_path: .github/workflows/ci.yml   # required when app_id is GitHub Actions
deploy_workflow: .github/workflows/ci.yml   # matched against the OIDC `workflow_ref` claim
deploy_reusable_workflow: ""               # optional: owner/repo/path@ref, matched against
                                            # `job_workflow_ref` when deploys run in a reusable workflow
```

**Check verification** (always performed through the GitHub API; never inferred from the request). For the exact commit SHA, every `required_checks` entry must have a completed check run that meets all of these:
- produced by the named `app_id`;
- named `name`;
- conclusion `success`;
- for GitHub Actions checks, belonging to a workflow run (resolved via the check suite → workflow run API) whose `path` = `workflow_path`, `head_branch` = `branch`, `head_sha` = the commit, and `event` ∈ `allowed_events`.

The latest attempt of each check is used. Evidence is persisted **per check** in `artifact_checks`. `source_run_id`/`source_run_attempt` on the artifact record only the run that built the digest. A request coming from a "protected dependent job" is **not** accepted as evidence of passing checks.

**GitHub Actions OIDC** (authenticates automation requests; it is not evidence that tests passed). Verification:
- signature against the issuer JWKS (`https://token.actions.githubusercontent.com`, cached, refreshed on unknown `kid`);
- `aud` = `github.oidc_audience` (default `server.public_url`);
- `exp` in the future, `iat` no older than 5 minutes, ≤ 60s clock skew;
- `jti` unseen, recorded in `oidc_replay` until `exp` (replay → `UNAUTHENTICATED`);
- `repository_id`, `repository_owner_id`, `ref` = `refs/heads/<branch>`, `sha`, `event_name` ∈ `allowed_events`, `workflow_ref` = `<owner>/<repo>/<deploy_workflow>@<ref>`; when `deploy_reusable_workflow` is set, `job_workflow_ref` MUST be present and equal it; when it is not set, `job_workflow_ref` MAY be absent, and if present MUST equal `workflow_ref` (a job running inside any reusable workflow is then rejected); `run_id`, `run_attempt`, and `environment` when the target environment requires one.

The token maps to the pre-registered automation identity for that repository and workflow. Tokens from forks or `pull_request*` events can never obtain deployment authority.

**Webhooks (server mode):** HMAC-SHA256 signature over the raw body (constant-time compare) plus `delivery_id` dedupe. Webhooks only trigger re-evaluation; the API remains the source of truth.

Delivery of CI results by mode:

- **Server mode:** a `check_run`/`check_suite`/`workflow_run` webhook triggers re-evaluation.
- **Local mode:** no inbound webhooks (§2.1.1). The daemon polls check status for deployments in `waiting_ci` (`github.ci_poll_initial` doubling to `github.ci_poll_max`; after `github.ci_timeout` → `failed`, `CI_NOT_PASSED`).

**Artifact ↔ commit binding.** A digest is accepted for a commit only if:

- **(a) `provenance_method = attestation`:** a GitHub artifact attestation (SLSA provenance) for that digest verifies, and its subject digest, source repository ID, workflow path and commit SHA match the CI policy and commit; or
- **(b) `provenance_method = oidc_claims`:** the digest was reported by an automation request whose verified OIDC claims (above) match the commit, run and workflow.

Environments with `require_provenance: true` accept only (a). Every image digest in the plan (deployed service and sidecars, §20.3) must be bound by (a) or (b), or be listed in the app's `image_policy.pinned` set approved by an admin.

---

# 19. Application manifest

Optional repository file `.supermgmt.yaml`, read from the exact CI-passed commit. It describes application-level deployment hints; it never carries infrastructure secrets, target selection or privilege.

Schema V1 (strict; unknown fields fail):

```yaml
apiVersion: supermgmt.dev/v1
kind: Application
metadata:
  name: myapp
spec:
  deployment:
    strategy: docker-compose
    composeFile: compose.yaml      # used only when apps.compose_source = repository
    service: web                   # must equal apps.deployed_service
  health:                          # hint; see precedence
    type: http                     # http | tcp | docker-health
    port: 8080                     # must be a host port published by the app's Compose model
    path: /health
    timeout: 3s
    interval: 5s
    attempts: 12
  rollback:
    mode: automatic                # automatic | manual
```

The manifest can NOT set: image repositories, target nodes or environments, secrets, variables, Compose security exceptions, CI policy, `stateful`, or backup steps. These live only in control-plane configuration (`apps`, `app_targets`). A manifest containing such fields fails validation; it never silently overrides control-plane values.

**Precedence (control plane always wins; the manifest can only tighten):**

```text
field                      control-plane source                  manifest effect
health check               app_target.deployment_policy.health   used only if control plane defines none;
                                                                 manifest health is always scope=node
rollback mode              app_target.deployment_policy.rollback  manifest "manual" downgrades automatic → manual;
                                                                 manifest "automatic" never upgrades manual
stateful / backup          app_target.deployment_policy           not settable
compose content            apps.compose_content (control-plane)   composeFile used only if compose_source=repository
```

## 19.1 Deployment policy (control plane)

`app_targets.deployment_policy_json`:

```yaml
rollback: automatic            # automatic | manual
stateful: false                # true forces rollback: manual
pre_deploy_backup:             # optional; required when stateful: true and environment is production
  template: postgres-dump      # id from the command-template catalog (§12)
  args: {container: db, database: app}
  timeout: 10m
snapshot: false                # Proxmox snapshot before deploy (only for Proxmox guests)
allowed_bind_addresses: []     # extra host IPs Compose may publish on (default: loopback only)
health:                        # optional; overrides manifest health
  type: http
  port: 8080
  path: /health
  timeout: 3s
  interval: 5s
  attempts: 12
```

`pre_deploy_backup` must exit 0 and print the path of the backup artifact on its last stdout line. The path is recorded in `deployment_steps.output_ref`. Any failure fails the deployment before services change. Proxmox snapshots are for manual recovery only: V1 never rolls back automatically to a snapshot.

## 19.2 Compose source

`apps.compose_source`:

- `control-plane` (default; required for production-risk environments unless an admin sets an exception): the Compose content is stored in `apps.compose_content` and edited by admins through an approval-gated `app.write` plan.
- `repository`: the file at `composeFile` in the exact CI-passed commit. Either way it passes the Compose pipeline (§20.3).


---

# 20. Deployment engine

## 20.0 Scope of a deployment in V1

A deployment targets exactly **one** `app_target`, which resolves to exactly **one** managed node (`app_targets.node_id`, fixed at configuration time). Multi-node orchestration is post-V1. A deployment is either:
- `kind: deploy` — a new artifact; or
- `kind: rollback` — redeploy the artifact and Compose hash of a previous known-good deployment.

A manual rollback is a new `kind: rollback` deployment with its own plan and approval. It never mutates the history of the deployment it reverts.

**Provisional vs final plan.** At creation, a deployment records only its **provisional inputs**: app_target, the exact commit SHA, and the requester's credential context. While CI is pending (`waiting_ci`) there is no final plan and nothing can be approved. When CI passes, the engine:
1. runs the Compose pipeline (§20.3);
2. binds every image digest (§18);
3. builds and persists the **final plan** (Appendix C);
4. evaluates policy (§11.3).

Approvals always refer to the final plan hash. Deployments without a CI gate finalize their plan immediately.

## 20.1 State machine

States:
- `created`, `waiting_ci`, `awaiting_approval`, `queued`;
- `preparing` (read-only preflight);
- `staging` (mutations that do not affect running services);
- `deploying`, `verifying`, `rolling_back`, `interrupted`;
- terminal: `succeeded`, `failed`, `rolled_back`, `rollback_failed`, `cancelled`.

The **first mutation boundary** is entry into `staging`. Nothing on any target changes before it. Running services first change on entry into `deploying`.

The table is exhaustive; the state machine rejects any other transition with `CONFLICT`. `failed` always records the pair `state_code` (top-level code, §38) + `state_reason` (reason enum). Table entries name the reason; where a top-level code is shown (e.g. `POLICY_DENIED`), the reason is the one returned by the failing check.

| From | To | Trigger / `state_reason` |
|---|---|---|
| `created` | `waiting_ci` | CI gate configured and not yet satisfied (provisional inputs only) |
| `created` | `awaiting_approval` | final plan built; approval required |
| `created` | `queued` | final plan built; no approval required |
| `created` | `failed` | `INVALID_ARGUMENT`, `POLICY_DENIED`, `ARTIFACT_NOT_IMMUTABLE`, `COMPOSE_REJECTED` |
| `waiting_ci` | `awaiting_approval` / `queued` | checks passed; final plan built; policy allows |
| `waiting_ci` | `failed` | `CI_NOT_PASSED`, `ARTIFACT_NOT_IMMUTABLE`, `COMPOSE_REJECTED`, `POLICY_DENIED` (on final plan), `REJECTED` (rejected while waiting) |
| `awaiting_approval` | `queued` | quorum of valid approvals reached (§11.4) |
| `awaiting_approval` | `failed` | `REJECTED`, `PLAN_EXPIRED`, `CREDENTIAL_REVOKED`, `CREDENTIAL_EXPIRED` |
| `queued` | `preparing` | claim succeeded: lease, locks and claim-time revalidation (§20.4) |
| `queued` | `awaiting_approval` | claim-time revalidation: quorum lapsed |
| `queued` | `failed` | `PLAN_STALE`, `PLAN_EXPIRED`, `POLICY_DENIED`, `CREDENTIAL_REVOKED`, `CREDENTIAL_EXPIRED`, `REJECTED` |
| `preparing` | `staging` | preflight passed |
| `preparing` | `failed` | `PREFLIGHT_FAILED` (no mutation has happened) |
| `staging` | `deploying` | snapshot/backup taken if configured; digests pulled; deployment directory materialized and verified |
| `staging` | `failed` | `STAGING_FAILED`. Running services untouched; staged directory garbage-collected; snapshot/backup kept per retention |
| `deploying` | `verifying` | `compose up` completed |
| `deploying` | `rolling_back` | update failed AND rollback available (below) |
| `deploying` | `failed` | update failed AND rollback unavailable (`ROLLBACK_UNAVAILABLE` + cause) |
| `verifying` | `succeeded` | health checks passed; deployment marked known-good |
| `verifying` | `rolling_back` | health failed AND rollback available |
| `verifying` | `failed` | health failed AND rollback unavailable (`ROLLBACK_UNAVAILABLE` + cause) |
| `rolling_back` | `rolled_back` | previous known-good restored and healthy |
| `rolling_back` | `rollback_failed` | restore failed or unhealthy (human required) |
| `created`, `waiting_ci`, `awaiting_approval`, `queued`, `preparing` | `cancelled` | user cancel (`job.cancel`) |
| `preparing`, `staging`, `deploying`, `verifying`, `rolling_back` | `interrupted` | lease expired and takeover performed (§20.4) |
| `interrupted` | `preparing` / `staging` / `deploying` / `verifying` | **forward resume** (resumable jobs only): completion evidence for every earlier step (§20.4) AND resume revalidation passed; continues at the first incomplete step under a new lease generation |
| `interrupted` | `rolling_back` | **safety recovery**: evidence shows a partial/unhealthy new deployment (or resume revalidation failed after `deploying` began) AND rollback available; performed by `system` (§20.4) |
| `interrupted` | `failed` | reconciler: interrupted before `deploying` with running services untouched (`INTERRUPTED_BEFORE_DEPLOY`), resume revalidation failed before `deploying` (its reason), or partial/unhealthy new deployment with rollback unavailable (`ROLLBACK_UNAVAILABLE`) |
| `interrupted` | `succeeded` | reconciler: evidence of the new deployment fully running and healthy |
| `interrupted` | `rolled_back` / `rollback_failed` | reconciler: interrupted during `rolling_back`; evidence of the outcome |
| `interrupted` | `failed` / `succeeded` / `rollback_failed` | human resolution (`job.resolve`, §20.4) when evidence is ambiguous |

**Rollback available** means all of the following hold. Otherwise the cause is recorded.
- the effective rollback mode is `automatic` (§19);
- the target is not `stateful`;
- the environment has `allow_automatic_rollback: true`;
- a previous known-good deployment exists for this `app_target` (none on a first deployment);
- `kind = deploy` (a `kind: rollback` deployment never auto-rolls back).

Cancellation is impossible from `staging` onward. Every transition is persisted with its event in one SQLite transaction, guarded by the lease generation (§20.4).

## 20.2 Docker Compose V1 flow

1. Create the deployment with its provisional inputs (§20.0). If a CI gate applies, enter `waiting_ci` and wait (§18).
2. Finalize: run the Compose pipeline (§20.3), bind every image digest, build and persist the final plan (Appendix C), and evaluate policy including sub-actions (§11.3).
3. Await approval if required (`awaiting_approval`).
4. Claim (§20.4): fence the generation, take locks (§20.5), and revalidate.
5. `preparing`: read-only preflight. Checks:
   - the node is reachable at the pinned endpoint with the pinned host key;
   - Docker and Compose versions are in the compatibility matrix;
   - free disk ≥ image sizes + 1 GiB;
   - project ownership labels (§20.5);
   - host ports are free or owned by this project;
   - health-check capability (§21).
6. `staging`, each step under its own deadline (§20.4):
   - optional Proxmox snapshot;
   - optional pre-deploy backup;
   - `docker pull <repo>@<digest>` for every image;
   - materialize a fresh deployment directory (§20.3 step 9);
   - on-node equivalence check (§20.3 step 10).
7. `deploying`: under the node-side project lock (§20.4), run `docker compose` with an explicit file, project name and project directory, `--no-build --pull never --remove-orphans`, under `env -i` with a fixed `PATH`.
8. `verifying`: health checks (§21).
9. Mark known-good, release locks, and persist the timeline. On failure, follow §20.1.

**Execution reads only the plan snapshot.** Workers read Compose model, policy, health configuration, endpoint and digests from the persisted final plan, never from live configuration. Edits to plan inputs during execution are prevented by shared locks (§20.5).

Shell deployments are post-V1, disabled by default, sandboxed/restricted and must use reviewed pinned scripts. Never execute arbitrary repository shell content as root merely because CI passed.

## 20.3 Compose pipeline (closed schema)

Docker access is root-equivalent (§17), so a Compose file is privileged code. Validation works on a **closed allowlist**: anything not listed is rejected. The node runs only the frozen output of this pipeline, never the original file.

**1. Raw input.** Exactly one YAML document, ≤ 256 KiB. Before any loader runs, reject:
- the top-level keys `include`, `secrets`, `configs` and `name`;
- `extends` anywhere;
- `env_file` anywhere.

`x-*` extension keys and YAML anchors are allowed; merged content is validated after loading like everything else.

**2. Interpolation (single pass, by SuperMgmt).**
- Recognized forms: `$NAME` and `${NAME}` (NAME = `[A-Za-z_][A-Za-z0-9_]*`), plus `$$` meaning a literal `$`. Any other `$` usage — `${NAME:-x}`, `${NAME?err}`, `${NAME-x}`, nested forms, or a lone `$` before a non-name character — is rejected.
- **Allowed locations:** values in `services.*.environment`, elements of `command`/`entrypoint`, and values in `labels`. A `$` anywhere else is rejected, except `$$`.
- **Variables:** NAME must exist in the app's `variables_json` (non-secret). Unknown names are rejected. The process environment and `.env` files are never consulted.
- **Secrets:** a value in `services.<svc>.environment` may be exactly `${secret:<ref-name>}`. This is a reference to `apps.secret_refs_json`, which maps ref-name → `secret://` path. It is not interpolated: it is removed from the public model and recorded as `{service, env_name, secret_id, secret_version}`.
- **Escaping:** after substitution, every literal `$` in every string is re-escaped as `$$` in the frozen output. The pinned loader and the node CLI therefore perform no further substitution: interpolation of the frozen file with an empty environment is the identity, which is a CI test.

**3. Load** with `compose-spec/compose-go` (pinned version, ADR-0006):
- in-memory single-file resource loader;
- environment lookup disabled;
- include/extends resolution disabled;
- path resolution disabled.

Loader-equivalence tests against the pinned `docker compose` CLI versions run in CI.

**4. Allowed top-level keys:** `services` (required), `volumes`, `networks`.

**5. Allowed service keys** (exhaustive), with closed nested schemas:

```text
image                 string (see step 8)
command, entrypoint   list of strings (string form rejected)
environment           map string->string (list form rejected)
ports                 long syntax only: {target:int, published:int, host_ip:addr,
                      protocol: tcp|udp}; host_ip ∈ {127.0.0.1, ::1} ∪
                      app_target.allowed_bind_addresses; no ranges
expose                list of int
healthcheck           {test: list, interval, timeout, retries, start_period,
                      start_interval, disable}
restart               no | always | on-failure | unless-stopped
depends_on            map service -> {condition: service_started | service_healthy |
                      service_completed_successfully}
volumes               long syntax only: {type: volume, source: <top-level volume>,
                      target, read_only, volume: {nocopy}} | {type: tmpfs, target,
                      tmpfs: {size, mode}}
networks              map network -> {aliases: list} (network declared at top level)
labels                map; keys under com.docker.* and dev.supermgmt.* rejected
logging               {driver: json-file | local, options: {max-size, max-file, compress}}
user, working_dir     string
read_only, init       bool
tmpfs                 list of absolute container paths
stop_signal           string;  stop_grace_period: duration
mem_limit, cpus, pids_limit
ulimits               {nofile: {soft, hard}} | {nproc: {soft, hard}}
deploy                {resources: {limits: {cpus, memory, pids}}} only
```

Everything else is rejected. Examples, non-exhaustive: `privileged`, `cap_add`, `cap_drop`, `security_opt`, `network_mode`, `pid`, `ipc`, `userns_mode`, `uts`, `devices`, `gpus`, `cgroup*`, `sysctls`, `extra_hosts`, `dns*`, `container_name`, `hostname`, `volumes_from`, `links`, `build`, `secrets`, `configs`, `platform`, `profiles`, `runtime`, `storage_opt`, `oom_*`, `shm_size`.

**6. Top-level `volumes`/`networks` entries:** allowed keys are `labels` only, and for networks also `internal: bool`. Compose prefixes their names with the project name (§20.5), so they cannot collide with or attach to other workloads.

**7. Exceptions.** An admin-approved per-app exception (part of `apps.spec_revision` and of the plan) may enable only these keys, with exact values:
- `cap_add` with values from {`NET_BIND_SERVICE`, `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `FOWNER`, `KILL`};
- `sysctls` with keys under `net.`;
- `extra_hosts`;
- `shm_size`.

Everything rejected in steps 1–2, 4 and 6, every bind mount, and every other key is **not exemptible** in V1.

**8. Images (per service).** `apps.image_policy_json`:

```yaml
deployed: ghcr.io/acme/api          # repository for apps.deployed_service
sidecars:                           # service name -> allowed repository
  redis: docker.io/library/redis
pinned: []                          # admin-approved repo@digest pairs (optional)
```

- The deployed service's `image` is **rewritten** to `<deployed>@<artifact digest>`.
- Every other service's `image` must already be `<allowed repository>@sha256:<64 hex>` for its service name, and the digest must be bound per §18 or listed in `pinned`.
- Tags are rejected.
- Validation (step 5) runs before and after the rewrite.

**9. Labels, freeze and materialize.**
- After validation, the pipeline injects the deterministic **ownership labels** on every service, volume and network: `dev.supermgmt.owner=<app_target_id>` and `dev.supermgmt.project=<compose_project>`.
- The model is serialized to canonical YAML (sorted keys, no anchors). That is the **public model**. `compose_hash` = SHA-256 of it.
- **Per-deployment labels** (`dev.supermgmt.deployment=<deployment_id>`) and secret wiring are added only at materialization. They are excluded from `compose_hash` but are deterministic and checked in step 10.
- On the node, SuperMgmt creates a new directory `<deploy_root>/<compose_project>/<deployment_id>/` (fails if it exists; `deploy_root` default `/srv/supermgmt`, root-owned 0755; project dirs owned by `supermgmt`, mode 0750). It then writes:
  - `compose.yaml`: the public model plus per-deployment labels plus, for each service with secrets, an `env_file: secrets/<service>.env` entry. Only the pipeline may emit `env_file`.
  - `secrets/` (mode 0700) containing `<service>.env` (mode 0600), with the decrypted values written from memory at staging. Values are never persisted unencrypted on the control plane.
- Files are created with `O_CREAT|O_EXCL|O_NOFOLLOW` semantics through a fixed template, and `stat` verifies that no path component is a symlink.
- Docker exposes container environment to anyone with Docker access. That is already root-equivalent and is documented.

**10. On-node equivalence check** (in `staging`): `docker compose -f <file> -p <project> --project-directory <dir> config --format json` under `env -i`, with secret values masked by the template before comparison. The **entire** output is compared with the expected effective model produced by the pinned `compose-go`. The comparison ignores only fields in a fixture-tested CLI-defaults normalization table (`internal/deployments/compose/normalize.go`). Any other difference → `STAGING_FAILED`.

**API views** of a Compose model always show the public model, with secret references and no secret values. Plans contain only `{secret_id, secret_version}`.

Each rule is unit-tested; the pipeline is fuzzed (raw YAML → reject or valid frozen model, never a panic).

## 20.4 Jobs: claim, fencing, intents and reconciliation

**Retry classes** come from the action catalog (§11.2):

```text
idempotent      safe to re-run from scratch -> retried up to max_attempts with backoff
resumable       step-checkpointed (deployments): resumes at the first incomplete step,
                only via the reconciler after an interruption (never blindly)
non_retryable   one-shot remote mutations; outcome is observed, never repeated
```

**Claim** (one SQLite transaction):
1. Pick a `queued` job; increment `lease_generation`; set `lease_owner` and `lease_until`.
2. Insert `resource_locks` for every lock in §20.5. On conflict, abort the claim and requeue with backoff.
3. **Revalidate:**
   - recompute every plan input's current `spec_revision` and content hash and compare with the plan (`PLAN_STALE`);
   - check `plans.expires_at` (`PLAN_EXPIRED`);
   - re-check the credential context (§11.1);
   - re-run policy for the requester, including sub-actions and scopes (§11.3);
   - re-check quorum (§11.4).
4. Commit, or roll back and apply the §20.1 transition.

**Fencing.** Every worker write (state, steps, intents, events, heartbeats, lock changes) carries `WHERE id = ? AND lease_generation = ? AND lease_owner = ?`. Zero rows affected means the lease was lost: the worker cancels its context and stops. A worker never renews a lease whose `lease_until` has passed; it stops instead.

**Takeover** (reconciler; one transaction): `UPDATE jobs SET lease_generation = lease_generation + 1, lease_owner = 'reconciler:<id>', lease_until = … WHERE id = ? AND lease_generation = <observed> AND lease_until < now()`. After this commit the old worker's writes all fail. The job moves to `interrupted` in the same transaction if it was in a mutating state.

**Per-step deadlines.** Every step has a deadline from the catalog or deployment policy: preflight 2m, snapshot 10m, `pre_deploy_backup.timeout`, pull 15m, materialize 1m, compose up 10m, health `attempts × interval + timeout`. The remote command runs under `timeout --kill-after=10s <deadline>`, and the intent stores `deadline_at`. `ssh.command_timeout` applies only to short read templates.

**Intents** (`operation_intents.state`: `recorded → completed`):
1. The worker commits an intent with a unique `marker`, the operation, the target, `pre_state_json` and `deadline_at`. Then it dispatches.
2. Every mutating remote template **first** creates the node-side marker file `/var/lib/supermgmt/markers/<marker>` (directory owned by `supermgmt`, created at enrollment) before doing anything else. The only exception is the `node.setup` steps that create that directory (ADR-0009): they are idempotent "ensure" steps that install files atomically, and an interrupted setup is requeued (retry class `idempotent`); markers are never consulted for it.
3. Compose operations additionally run under `flock /run/supermgmt/locks/<compose_project>.lock`, so the lock is held for the whole remote operation.
4. Proxmox calls cannot carry the marker. The intent records `type`, `vmid`, token `user` and `dispatched_at`, and the UPID is persisted as soon as the API returns it.

**Quiescence and completion** (required before any reconciler action and before human resolution releases locks). Two separate facts are needed, and a quiet interval alone proves neither.

1. **Our remote process has exited.**
   - Compose: acquire the node-side project flock, which the remote command held for its whole lifetime.
   - Other templates: `now > deadline_at + kill_after + connect_timeout`.
   - Proxmox: the task has status `stopped`.
2. **The platform operation has completed**, proven by **completion evidence** that does not depend on sampling resource state:

   | Operation | Completion evidence |
   |---|---|
   | Compose `up`, `pull` (via template) | the remote wrapper writes `/var/lib/supermgmt/markers/<marker>.done` containing the CLI exit status **after** the Compose CLI returns. Only `.done` with exit status **0** is completion evidence. A nonzero status (transport, cancellation or daemon errors can make the CLI return before the daemon finished) and a missing `.done` both count as **no evidence** (fallback below) |
   | Image pull by digest | `docker image inspect <repo>@<digest>` succeeds (content-addressed, so presence is final) |
   | systemd unit actions | `systemctl list-jobs` shows no queued/running job for the unit |
   | Proxmox tasks | task status `stopped` |
   | Node reboot/shutdown | `boot_id` changed, or provider power state `off` |

3. **Only after completion is proven**, the outcome is classified from operation-specific state. The reconciler collects it **twice, at least 30s apart**; both samples must be identical and must match one of the operation's defined terminal patterns:
   - `complete`: e.g. every service container carries this deployment's label, runs the expected digest, and no container of the previous deployment remains;
   - `not_started`;
   - `partial_stable`: an exactly defined mix that is identical across samples and has no container in `created`, `restarting` or `removing`.

   Samples that differ, or match no pattern, mean "still settling". The reconciler retries until `deadline_at + 5m`; after that the job stays `interrupted` for a human.

**Fallback (fixed; adapters may not weaken it):** if completion evidence is unavailable — the CLI was killed before writing `.done`, the node is unreachable, or the adapter has no completion signal — the reconciler performs **no** automatic resume and **no** automatic rollback. The job stays `interrupted` with all its locks held and is surfaced for human resolution (`job.resolve`). Sampled stability alone never authorizes a new mutation.

**Resume revalidation.** A forward resume (`interrupted` → an earlier execution state) is a new claim. It runs the full claim revalidation of the claim step:
- plan inputs unchanged;
- plan not expired;
- requester credential not revoked or expired (§11.1);
- policy still allows (scopes included);
- quorum: approvals already consumed at the first claim count only if no approver has since lost `approval.grant`.

If revalidation fails before `deploying` was entered, the job fails with that reason. If it fails after `deploying` was entered, the only permitted continuation is **safety recovery**: the `system` actor rolls back to the previous known-good deployment when rollback is available (else `failed`, `ROLLBACK_UNAVAILABLE`). Safety recovery restores an already-approved prior state and is audited with the failed revalidation reason.

**Reconciliation**, per job after takeover:

```text
idempotent jobs                -> requeued.
no intent recorded             -> nothing was mutated: failed (non_retryable) or
                                  resume at the current step (resumable).
intent recorded, no node marker
  (after quiescence)           -> never dispatched: treat as no intent.
intent recorded, marker present -> collect evidence (below).
all intents completed, state
  not terminal                 -> finish from step records: resume at the next step
                                  (resumable) or apply the terminal transition implied
                                  by the recorded outcome (non_retryable).
```

Evidence per operation:

```text
systemd service.restart   pre_state: InvocationID. Success: InvocationID changed and
                          ActiveState=active. Unchanged InvocationID -> failed.
service start/stop        ActiveState/SubState vs requested (start also requires new
                          InvocationID).
docker container restart  pre_state: State.StartedAt. Success: StartedAt > dispatched_at.
node.reboot / shutdown    pre_state: /proc/sys/kernel/random/boot_id. Success: boot_id
                          changed (reboot) or node unreachable + provider power state
                          off (shutdown).
proxmox task              UPID if recorded; else exactly one task matching the recorded
                          criteria. Success: status "stopped", exitstatus "OK".
deployment step           containers of the project labeled with this deployment id,
                          image digests and labels equal to the materialized model, then
                          a fresh health check. Complete -> resume or succeed; partial ->
                          rolling_back if available, else failed (ROLLBACK_UNAVAILABLE).
```

Missing or contradictory evidence (zero or several matching Proxmox tasks) leaves the job `interrupted` and surfaces it in the TUI Jobs/Approvals screens.

**Human resolution.** `POST /api/v1/jobs/{id}/resolve` with `{outcome: succeeded|failed|rollback_failed, note, plan_hash}`.
- It requires `job.resolve` (governance; self-resolution only in local mode) and a passing quiescence check.
- If the node is unreachable, the caller must also pass `assume_quiescent: true`, which is recorded and audited.
- It releases the locks and **never** re-executes anything. Re-running requires a new plan.

## 20.5 Project ownership, locks and concurrency

- `app_targets.compose_project` = `sm-<app>-<environment>`. It is unique per node (`UNIQUE(node_id, compose_project)`) and immutable after creation.
- Preflight fails with `CONFLICT` ("project not owned") if a Compose project, volume or network with the project's names exists on the node without `dev.supermgmt.owner=<app_target_id>`.
- Published host ports are plan inputs and are locked as `port:<node>:<addr>:<port>`. Preflight fails if anything other than this project holds them.

**Lock modes** (`resource_locks.mode`):

```text
exclusive   app_target, node+compose_project, each host port      (deployment)
            service's node+compose_project or unit                 (service action)
            node                                                   (reboot/shutdown/power,
                                                                    sudoers/log broker)
shared      every other plan input: app, environment, node (for deployments and
            service actions), provider, repository, health_check, secrets referenced
```

Exclusive conflicts with any lock on the same resource; shared conflicts only with exclusive. A `direct` configuration write (§11.2) to a resource holding any lock returns `CONFLICT` (`RESOURCE_LOCKED`). Locks are held until the job is terminal, including while `interrupted`.


---

# 21. Health checks and service model

Health check types:

```text
http/https
tcp
command-template (restricted; control-plane defined only)
docker-health
systemd-active
```

Every check has an execution `scope`.

**`node` scope** (repository-manifest checks are always `node`). The check is executed on the target node through a fixed SSH template.
- **Destination.** Only `127.0.0.1` or `::1`, with a port that is a host port published by the app's own frozen Compose model (§20.3) — not any loopback service. Manifests specify `port` and `path`, never a URL or hostname. Control-plane node checks may additionally target addresses in the app_target's `allowed_bind_addresses`. No hostnames are ever resolved on the node, so DNS rebinding does not apply.
- **Address selection.** The check uses the `host_ip` of the matching published port in the frozen model. If that is `127.0.0.1` or `::1` it is used as-is (IPv6 in brackets in URLs). For an `allowed_bind_addresses` entry, that address is used.
- **http** (capability `health.http` = `curl` present). Template, run under `env -i PATH=/usr/bin:/bin`:

  ```text
  curl -q --noproxy '*' --proto =http,https --max-redirs 0 --max-time <timeout>
       --silent --show-error --output /dev/null --write-out '%{http_code}' <url>
  ```

  `-q` is the first argument, so no `.curlrc` is read. Success requires curl exit 0 **and** an HTTP code of 200–299. A 3xx is a failure: redirects are never followed. `path` must match `^/[A-Za-z0-9._~/-]*$`; userinfo, query strings and fragments are rejected. If curl is absent, `health.http` is unavailable. There is no wget fallback in V1, because wget's exit-status semantics vary by implementation.
- **tcp** (capability `health.tcp` = `bash` and `timeout` present): `timeout <t> bash -c 'exec 3<>/dev/tcp/<addr>/<port>'`. Success is exit 0. It does not depend on curl.
- A missing capability for the configured check type fails preflight (`PREFLIGHT_FAILED`).

**`control_plane` scope.** Executed by the daemon. Defined only in control-plane configuration. The URL passes the SSRF filter below.

**`docker-health` / `systemd-active`.** Read through the runtime adapter on the node.

## 21.1 Outbound request filter (control-plane checks, provider endpoints, webhooks to external services)

1. **Scheme.** `https` (and `http` only for health checks); userinfo is rejected.
2. **Resolution and pinning.** Resolve DNS once. Normalize each address: IPv4-mapped/compatible IPv6 becomes IPv4, and NAT64 `64:ff9b::/96` is unwrapped to the embedded IPv4. Filter as below, then connect to that exact IP with a custom dialer. TLS uses the original hostname for SNI and certificate verification; `InsecureSkipVerify` is never set.
3. **Always denied, for every caller, checked before any allowlist:**
   - cloud metadata addresses: `169.254.169.254/32`, `fd00:ec2::254/128`, `169.254.170.2/32`;
   - `0.0.0.0/8`, `127.0.0.0/8`, `::/128`, `::1/128`;
   - `169.254.0.0/16`, `fe80::/10` (link-local);
   - `224.0.0.0/4`, `ff00::/8`, `240.0.0.0/4`, `255.255.255.255/32`.
4. **Private and special ranges** — denied unless the specific CIDR is allowed by the caller's allowlist:
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`;
   - `fc00::/7`, `192.0.0.0/24`, `198.18.0.0/15`;
   - the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
5. **Allowlists by caller:**
   - control-plane health checks: `health.allowed_private_cidrs`;
   - provider endpoints (Proxmox, etc.): private ranges are allowed, because homelab endpoints are private. Provider endpoints are admin-only configuration (`provider.write`, high-impact, audited), never derived from repository content.
6. **Redirects.** Disabled for health checks and provider APIs. For GitHub API calls, at most 3 redirects, each re-filtered, same scheme (no HTTPS→HTTP downgrade), and only to the configured GitHub API hosts.
7. **Limits.** Response bodies are capped (health: 64 KiB; provider: per adapter); connect and total timeouts always apply.
8. **Proxies.** The HTTP client never reads ambient proxy environment variables (`Transport.Proxy = nil`). If `outbound.proxy` is configured, the destination host is resolved and filtered by SuperMgmt first, then the request is sent via `CONNECT <pinned-ip>:<port>` with TLS verification against the original hostname. The proxy address itself must be configured by an admin.

The filter is a single package (`internal/netguard`) with table tests for every range and normalization case.

A node being online does not imply its application is healthy. TUI shows hierarchy:

```text
● node
  ├─ ● docker
  ├─ ● nginx
  ├─ ● myapp-web
  └─ ✕ worker
```

Health observations have timestamps and TTL. Do not present stale data as current without indicator.


---

# 22. TUI specification

Use Bubble Tea (current supported major version at implementation time), Lip Gloss/Bubbles as appropriate. The TUI must remain responsive while network operations execute asynchronously.

## 22.1 Main layout

```text
┌ SuperMgmt ───────────────────────────────────────────────────────┐
│ profile: home     7 nodes · 6 online · 23 services · 1 warning │
├────────────────────────┬─────────────────────────────────────────┤
│ RESOURCES              │ DETAIL                                  │
│                        │                                         │
│ ▼ Proxmox              │ docker-prod                             │
│   ● docker-prod        │ CPU   17%   RAM 41%   DISK 38%          │
│   ● postgres           │                                         │
│   ○ dev                │ Capabilities                            │
│                        │ SSH Docker systemd Deploy                │
│ ▼ External             │                                         │
│   ● ovh-prod           │ Services                                │
│   ● hetzner-01         │ ● api      healthy                      │
│                        │ ● worker   healthy                      │
│                        │ ● redis    healthy                      │
├────────────────────────┴─────────────────────────────────────────┤
│ / command  s ssh  d docker  l logs  u updates  ? help           │
└──────────────────────────────────────────────────────────────────┘
```

## 22.2 Navigation

- `j/k` or arrows move.
- `enter` opens detail.
- `esc` back.
- `/` command palette.
- `?` contextual help.
- `r` refresh.
- `s` SSH if allowed.
- `d` Docker/lazydocker if available.
- `l` logs.
- `v` services.
- `g` repository/GitHub view when linked.
- destructive shortcuts never execute immediately; they open plan/confirmation.

Keyboard shortcuts are contextual and shown in footer. Mouse support optional.

## 22.3 Screens

Mandatory V1 screens:

```text
Dashboard
Resources tree
Node detail
Service list/detail
Logs viewer
Applications
Deployments/history
Deployment creation wizard
Jobs/actions
Approvals
Events/timeline
Providers
Settings/profile
Help
```

Proxmox-specific detail adds power/snapshot/backup actions only when capability exists.

## 22.4 Command palette

Examples:

```text
ssh ovh-prod
logs api
services docker-prod
deploy myapp production
rollback myapp production
status @production
refresh proxmox
```

Palette resolves resources, previews action and routes writes through ActionPlan.

## 22.5 Error/loading/offline UX

Never freeze whole TUI for one slow node. Each resource can show loading/stale/error state. Errors include actionable short message and correlation ID. Background refresh uses bounded concurrency.

---

# 23. HTTP API

Version prefix `/api/v1`. JSON envelopes:

```json
{"data":{},"meta":{}}
```

Error:

```json
{
  "error": {
    "code": "POLICY_DENIED",
    "message": "action requires approval",
    "correlation_id": "...",
    "details": {}
  }
}
```

Required endpoints:

```text
GET    /api/v1/me
POST   /api/v1/auth/oidc/start        # {redirect_uri (loopback), code_challenge} -> {authorization_url, state}
POST   /api/v1/auth/oidc/exchange     # {code, state, code_verifier} -> session token
POST   /api/v1/auth/oidc/device       # device grant start (if IdP supports it)
POST   /api/v1/auth/oidc/device/poll
POST   /api/v1/auth/bootstrap        # one-time bootstrap code exchange (§11.5)
POST   /api/v1/auth/logout
GET    /api/v1/tokens
POST   /api/v1/tokens                # not idempotent-replayable (§23)
DELETE /api/v1/tokens/{id}           # revocation; rows are kept for audit
GET    /api/v1/mcp/clients
POST   /api/v1/mcp/clients           # register (mcp_client.register; may return a pending job)
POST   /api/v1/mcp/clients/{id}/token  # one-time token issuance (mcp_client.issue_token)
DELETE /api/v1/mcp/clients/{id}
POST   /api/v1/plans                 # build + persist a plan (read-risk)
GET    /api/v1/plans/{id}
POST   /api/v1/plans/{id}/submit     # body: {plan_hash}; creates the job
GET    /api/v1/approvals
POST   /api/v1/jobs/{id}/approve     # body: {plan_hash, reason?}
POST   /api/v1/jobs/{id}/reject      # body: {plan_hash, reason}
POST   /api/v1/jobs/{id}/resolve     # body: {plan_hash, outcome, note} (§20.4)
GET    /api/v1/ssh-key
GET    /api/v1/nodes/{id}/connect-info
POST   /api/v1/nodes/{id}/sessions   # interactive handoff session (node.connect); body: {tool}
POST   /api/v1/nodes/{id}/sessions/{sid}/end  # body: {reason, exit_code?}; first end wins (node.connect)
GET    /api/v1/presence              # held open by long-lived clients for daemon residency (exempt:self, §2.1.1)
GET    /api/v1/providers
POST   /api/v1/providers
GET    /api/v1/nodes
POST   /api/v1/nodes/ssh/host-key    # read-only keyscan for first-trust confirmation (node.add; no Idempotency-Key)
POST   /api/v1/nodes/ssh
PATCH  /api/v1/nodes/{id}            # If-Match: <spec_revision> (node.update)
DELETE /api/v1/nodes/{id}            # retire; If-Match required (node.remove)
GET    /api/v1/nodes/{id}
POST   /api/v1/nodes/{id}/probe
GET    /api/v1/nodes/{id}/services
GET    /api/v1/services/{id}
GET    /api/v1/services/{id}/logs
POST   /api/v1/services/{id}/actions/start    # literal routes, one per verb (service.start)
POST   /api/v1/services/{id}/actions/stop     # (service.stop)
POST   /api/v1/services/{id}/actions/restart  # (service.restart); any other verb is 404
GET    /api/v1/apps
POST   /api/v1/apps
GET    /api/v1/deployments
POST   /api/v1/deployments
GET    /api/v1/deployments/{id}
POST   /api/v1/deployments/{id}/rollback
GET    /api/v1/jobs
GET    /api/v1/jobs/{id}
POST   /api/v1/jobs/{id}/cancel
GET    /api/v1/events
GET    /api/v1/events/stream        # SSE
POST   /api/v1/enrollments
POST   /api/v1/enroll
GET    /health/live
GET    /health/ready
```

**Plans.** Every `job`-mode action (§11.2) goes through a persisted plan. `direct` actions apply inside the request transaction unless policy requires approval, in which case they too become a plan and a `control_plane.apply` job. `governance` actions act on existing jobs. Authentication endpoints are not actions.
- `POST /api/v1/plans` takes `{action, targets[], parameters}`. It requires `plan.create` plus the read permission on each target. It evaluates the proposed action (§11.3) and returns `{plan_id, plan, plan_hash, policy}` without needing permission for the action itself.
- `POST /api/v1/plans/{id}/submit` with the expected `plan_hash`:
  - the caller must be the plan's actor (else `POLICY_DENIED`);
  - the credential context of the submitting request is stored on the job (§11.1);
  - policy is re-evaluated;
  - in the same transaction, `plans.submitted_job_id` is set with `WHERE submitted_job_id IS NULL`, so a second submit returns `CONFLICT` (`ALREADY_SUBMITTED`);
  - a hash mismatch or stale input returns `CONFLICT` (`PLAN_STALE`), and an expired plan `CONFLICT` (`PLAN_EXPIRED`).
- Convenience endpoints (`…/actions/restart`, `POST /deployments`, `…/rollback`) do plan+submit internally and return the plan hash.
- Plans expire (`plans.expires_at`, default 24h).

**Idempotency.** Mutating retryable requests require `Idempotency-Key`. The handler runs the mutation, builds its response and inserts `idempotency_records(identity_id, key, request_hash, status_code, response_json, job_id)` in **one SQLite write transaction**:
- SQLite serializes writers, so a concurrent duplicate waits for that transaction and then finds the record.
- If the record exists with the same `request_hash`, the stored response is replayed; with a different `request_hash`, `CONFLICT`.
- A crash before commit leaves neither mutation nor record, so a retry is safe.
- Remote side effects never happen inside the request: they happen in jobs, which are created by that transaction.
- Records expire after 24h.
- Responses that contain newly issued credentials (`POST /tokens`, `POST /mcp/clients/{id}/token`, `POST /auth/bootstrap`) are never stored and those endpoints reject `Idempotency-Key`. Clients recover by listing and revoking.

**Concurrency.** Updates to configured resources require `If-Match: <spec_revision>`; a stale revision returns `CONFLICT`. While a job holds `resource_locks` on a resource (§20.4), updates to that resource return `CONFLICT` (`RESOURCE_LOCKED`). Pagination uses an opaque cursor.

**Tokens.** API tokens have optional `scopes` (action patterns, §11.3 step 7) and a mandatory expiry (max 365 days). Revocation takes effect on the next request; token lookups are not cached. Tokens are shown once at creation.

Sorting/filtering server-side. OpenAPI file is authoritative and CI validates implementation/schema drift.

Remote interactive terminals are not exposed through a generic command endpoint in V1.

## 23.1 Transports, TLS and login

- **Unix socket** (local mode): peer-credential auth and MCP client tokens (§2.1.1, §11.1).
- **HTTPS** (server mode), `server.tls.mode`:
  - `direct`: the daemon terminates TLS with `cert_file`/`key_file` (TLS ≥ 1.2; reloaded on SIGHUP).
  - `proxy`: `server.listen` must be a loopback or Unix address, `trusted_proxies` must be non-empty, and `X-Forwarded-For`/`X-Forwarded-Proto` are honored only from those peers. Requests whose forwarded proto is not `https` are rejected. Behind a proxy, a connection from loopback is **not** treated as local or privileged; there is no loopback trust in HTTP auth.
  - Plain HTTP on a non-loopback address is refused at startup.
- **Admin socket** (server mode): `server.admin_socket`, peer UID root or the service user. It serves only `sm admin bootstrap-code`, `sm admin grant`, `sm admin restore-complete`, and read-only `sm doctor`. Restore itself is offline (§29.2).
- **OIDC login** (the server is the OIDC client and holds the client secret):
  1. `sm login` creates a PKCE verifier and challenge (S256) and binds a loopback listener (`http://127.0.0.1:<random port>/callback`, RFC 8252). It calls `POST /auth/oidc/start` with `redirect_uri` and `code_challenge`.
  2. The server creates `state` and `nonce` (stored server-side for 10 minutes, bound to the `redirect_uri` and challenge) and returns the IdP authorization URL.
  3. The browser authenticates. The IdP redirects to the loopback listener with `code` and `state`.
  4. The CLI calls `POST /auth/oidc/exchange` with `{code, state, code_verifier}`. The server checks `state`, then redeems the code at the IdP with its client credentials, the `code_verifier` and the same `redirect_uri`.
  5. The server verifies the ID token: issuer, audience, signature, `exp`, `nonce`, and `allowed_domains` against a verified email.
  6. The server issues an opaque session token (TTL `security.session_ttl`), which the CLI stores in the OS credential store (Appendix B).

  The IdP must allow loopback redirect URIs with variable ports; where it does not, the device authorization grant (`/auth/oidc/device*`) is used instead. `docs/configuration.md` lists tested IdPs.

  **Discovery trust.** The discovery document's `issuer` must equal `auth.oidc.issuer` exactly. Every endpoint it names (authorization, token, device authorization, JWKS) must be `https` and on the issuer's origin or on an origin listed in `auth.oidc.allowed_endpoint_origins`. Calls to the IdP follow no redirects and go through the outbound filter as provider endpoints (§21.1). The userinfo endpoint is not used.
- Cookie auth is not used in V1, so CSRF is not applicable. If it is added, CSRF protection is mandatory (§30).

---

# 24. MCP specification

Use the official maintained Go MCP SDK available at implementation time. MCP shares the application service layer and policy engine; it is not a privileged adapter.

MCP is a client of the API (§2.1.1); it holds no database handle and no connector credentials.

Transport:

- **stdio** (`sm mcp`): a bridge process launched by the MCP client. It connects to the local daemon socket and presents the MCP client token issued by `sm mcp clients add <name>` (read from `--token-file`, mode 0600, or the OS keychain). The daemon resolves the token to that `mcp` identity (§11.1). Without a valid token the bridge refuses to start; it never falls back to the human identity.
- **Streamable HTTP** (server mode, `mcp.remote_enabled`): SuperMgmt is an OAuth 2.0 **protected resource only**. It does not issue OAuth tokens. It requires an external authorization server configured in `mcp.oauth` (most OIDC IdPs qualify). SuperMgmt:
  - serves Protected Resource Metadata (RFC 9728) at `/.well-known/oauth-protected-resource`, naming the issuer and `mcp.oauth.resource`;
  - answers unauthenticated requests with `401` and a `WWW-Authenticate` header pointing to that metadata;
  - validates access tokens as JWTs (via `jwks_url`) or by introspection (RFC 7662): `iss`, `aud` containing `mcp.oauth.resource`, `exp`/`nbf`, and the `required_scopes`;
  - maps `(iss, sub, client_id|azp)` to a pre-registered `mcp` identity (`POST /api/v1/mcp/clients`, admin; remote clients need no token issuance because the external authorization server issues their tokens). An unknown client gets `403`.

  The current MCP authorization specification must be checked at implementation time (§0) and any deviation recorded in an ADR. If `mcp.oauth` is incomplete, remote MCP refuses to start; local stdio is unaffected.

Document tested MCP clients.

Initial tools:

```text
infra_list_nodes
infra_get_node
infra_list_services
infra_get_service
infra_get_service_logs
infra_list_apps
infra_list_deployments
infra_get_deployment
infra_list_events
infra_get_health
infra_plan_action
```

Write tools, disabled by default:

```text
infra_submit_plan
infra_restart_service
infra_create_deployment
infra_rollback_deployment
infra_reboot_node
```

No default MCP tools for arbitrary shell, arbitrary container exec, secret reads, network/firewall changes or resource deletion.

`infra_plan_action` calls `POST /api/v1/plans` — builds and persists a plan, never executes:

```jsonc
{
  "input": {
    "action": "service.restart",          // MUST be an entry of the action catalog (§11.2)
    "targets": [{"type": "service", "ref": "api@ovh-prod"}],  // name or ID; resolved to IDs
    "parameters": {}                      // validated against the action's parameter schema
  },
  "output": {
    "plan_id": "...",
    "plan": { /* canonical plan, Appendix C */ },
    "plan_hash": "sha256:...",
    "policy": {"decision": "allow|deny", "approval_required": true, "quorum": 1, "reason": "...", "matched_rules": []},
    "submit_via": "infra_submit_plan"     // or null if write tools are disabled
  }
}
```

Unknown actions, unknown parameters and ambiguous target names fail with `INVALID_ARGUMENT`. Planning is `plan.create` (read risk) and is audited.

Write tools (when enabled) take `{plan_id, plan_hash}` and call `POST /api/v1/plans/{id}/submit`. `infra_restart_service`, `infra_create_deployment`, `infra_rollback_deployment` and `infra_reboot_node` are thin wrappers that plan, then submit the returned hash. The model never supplies a hash it did not receive from a plan.

Untrusted output to models: `infra_get_service_logs` and any tool returning remote text apply redaction (§16), strip control/ANSI sequences, cap size (default 64 KiB / 500 lines), and wrap content in a structured field marked `"untrusted_remote_output": true`. Policy can deny `service.logs` for `type:mcp` per environment (recommended for production).

Every write tool first performs policy evaluation (§11.3). For `type: mcp`, any write of risk ≥ operational always requires approval, so write tools return a structured pending job/plan and never execute directly.

Example result:

```json
{
  "status": "approval_required",
  "job_id": "...",
  "plan_hash": "sha256:...",
  "summary": "Deploy myapp sha256:abc to production on ovh-prod-01",
  "risk": "operational"
}
```

Tool schemas are versioned and covered by golden tests. MCP resources may expose sanitized node/app/deployment context. Prompts are optional and never grant authority.

---

# 25. Cloudflare and remote access

Cloudflare is optional. Core must work with localhost, LAN, VPN or any standard reverse proxy/OIDC provider.

When selected, recommended server topology:

```text
sm client/TUI -> HTTPS -> Cloudflare Access/Tunnel -> 127.0.0.1:8787 SuperMgmt
MCP client    -> HTTPS/OAuth/Access -> MCP endpoint
```

Do not open public inbound ports solely for SuperMgmt when Tunnel is used. `cloudflared` lifecycle may be guided/configured by installer plugin, but vendor credentials must be least privilege.

Cloudflare edge authentication does not replace application authorization. Validate identity assertions according to current Cloudflare documentation and configured trust boundary.
V1 consumes no edge identity assertion: `Cf-Access-*` headers are ignored and every request is authenticated by SuperMgmt itself (OIDC session or API token), so validation applies only if a later version consumes such assertions.

---

# 26. Events, audit and timeline

Every mutation and significant observation emits structured event:

```json
{
  "event_id": "...",
  "timestamp": "2026-01-01T12:00:00Z",
  "actor": {"type":"human","id":"..."},
  "source": "tui",
  "action": "deployment.create",
  "resource": {"type":"app","id":"..."},
  "correlation_id": "...",
  "result": "succeeded",
  "data": {"deployment_id":"...","commit":"a84f2d1"}
}
```

Never include credentials, Authorization headers, private keys, raw secret env vars or full unredacted command output.

Timeline UI correlates deployments, snapshots, service restarts, health failures, node changes and GitHub events. This is a key MCP context source.

---

# 27. Required public repository documents and exact intent

## 27.1 README.md

README MUST contain:

1. Logo/name/tagline placeholder.
2. Status badge and honest maturity statement.
3. 2–3 sentence product explanation.
4. Screenshot/GIF placeholder for TUI.
5. “Why SuperMgmt?” with local-first, agentless-first, MCP-native, provider-independent.
6. Architecture diagram.
7. Quick start:
   - universal installer
   - Proxmox auto-LXC behavior
   - local laptop install
   - `sm nodes add ssh`
   - `sm`
8. Feature matrix (implemented vs planned; never imply planned is shipped).
9. Security model summary.
10. Supported platforms/integrations matrix.
11. Configuration pointer.
12. MCP example.
13. Development commands.
14. Roadmap.
15. Contributing/security links.
16. License/trademark disclaimer.

Recommended opening copy:

```markdown
# SuperMgmt

**Your infrastructure, one control plane.**

SuperMgmt is a local-first, terminal-first control plane for developers. Connect Linux machines, Proxmox, Docker, systemd, GitHub repositories and deployments in one place; manage them from a fast TUI/CLI, or expose the same policy-controlled operations to AI agents through MCP.

It works on a laptop, a VPS, or as an automatically provisioned unprivileged LXC on Proxmox. Managed workloads never depend on SuperMgmt to keep running.
```

## 27.2 CONTRIBUTING.md

Must document Go version, setup, `make test`, architecture boundaries, commit/PR expectations, tests, security-sensitive changes, DCO/CLA decision, issue-first expectation for major changes and generated files.

## 27.3 SECURITY.md

Must document supported versions, private vulnerability reporting channel placeholder, response expectations, threat model link, security defaults, explicit statement that Docker access can be root-equivalent, and what data to redact from reports.

## 27.4 GOVERNANCE.md

Initially: maintainer-led project, decision process, release authority, ADR process, code of conduct enforcement and path to multiple maintainers.

## 27.5 ROADMAP.md

Use milestone statuses and distinguish committed V1 from exploratory integrations.

## 27.6 LICENSE

Default recommendation Apache-2.0 for permissive OSS with explicit patent grant. Before publication, maintainer must confirm name/trademark and license choice. Dependency license scan required.

---

# 28. Example GitHub Actions deployment contract

Example workflow should build/test image, push immutable image and request/allow deployment only after CI succeeds. Do not use long-lived SSH keys to production.

Conceptual example:

```yaml
name: ci
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<PINNED_SHA>
      - run: go test ./...

  build:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write          # artifact attestation signing only
      attestations: write
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@<PINNED_SHA>
      - id: build
        run: ./ci/build-and-push.sh
      - uses: actions/attest-build-provenance@<PINNED_SHA>
        with:
          subject-name: ghcr.io/acme/api
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true

  deploy:
    needs: build
    environment: production
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write          # OIDC token for SuperMgmt, this job only
    steps:
      - name: Request SuperMgmt deployment
        run: ./ci/request-supermgmt-deploy.sh "${{ needs.build.outputs.digest }}"
```

Only jobs that need `id-token: write` get it; the workflow default is `contents: read`. SuperMgmt still verifies required checks through the GitHub API (§18); the `deploy` job's success is not evidence of passing tests.

Repository examples MUST pin third-party actions to commit SHA in production examples and explain how OIDC token exchange works. The actual implementation may provide an official reusable action later.

---

# 29. Backups, restore, upgrades and uninstall

## 29.1 Backup

`sm backup create` (a `backup.create` job; scheduled runs use the `system` actor, §11.1) produces a versioned archive (`.tar.zst`) containing:

```text
manifest.json      format version, sm version, schema version, created_at, kek_ids
                   referenced, config generation, SHA-256 of every other member
supermgmt.db       SQLite online backup API snapshot (includes encrypted secrets, jobs,
                   approvals, events, and the loaded config/policy snapshot)
config/            config.yaml and policy file, extracted from that same snapshot
known_hosts
```

**Consistency.** Whenever the daemon loads or reloads `config.yaml` and the policy file, it stores their exact bytes and a generation counter in `settings.config_snapshot` in the same transaction that activates them. The database snapshot therefore contains the configuration that was in force at that instant. `config/` in the archive is written from that snapshot, not from disk. Secrets live in the database (§10), so the database snapshot is the single consistency boundary. KEK files are never included. The archive is written to a temp file (mode 0600), fsynced and renamed into place.

Automatic daily backup is the default in server/appliance mode; retention is configurable, and pruning is done by the `system` actor. In local mode, scheduled backups run only when `daemon.resident: true` (§2.1.1). Proxmox users should additionally back up the LXC with normal PVE/PBS mechanisms.

## 29.2 Restore

Restore is an **offline** operation: `sm backup restore --offline <archive>`. On a server: `systemctl stop supermgmt`, run the restore as root or the service user, then `systemctl start supermgmt`. In local mode the daemon must be stopped (`sm daemon stop`). The command takes the database lock (§2.1.1) and refuses if a daemon holds it.

**Phase A — stage** (no change to live files):
1. Validate `manifest.json`, every member checksum, format version, and schema version ≤ the binary's.
2. Safe extraction into `<data_dir>/restore-<id>/`: only listed members; no absolute paths, no `..`, no symlinks, hardlinks or devices; per-member size limits.
3. **Key check.** Open the staged database read-only. Every `kek_id` it references must have a key in `security.keys_dir` (`.key`, or `.key.pending` from an offline import) that passes the check record stored **in the staged database** (§10). Otherwise abort, exit 9, naming the missing keys. Pending keys that pass are promoted to `.key` in Phase B (they are listed in the restore journal).
4. Open the **staged** database and run forward migrations, then neutralize it in one transaction:
   - jobs (and their deployments) in `created`, `waiting_ci`, `awaiting_approval`, `queued` or `preparing` have never mutated a target. They become `failed` with reason `RESTORED_UNDISPATCHED`, and their locks are deleted. Requesters re-create them; a provisional deployment never had locks;
   - jobs in `staging`, `deploying`, `verifying`, `rolling_back` or `interrupted`, and `non_retryable` jobs with any recorded intent, become (or stay) `interrupted`, with their deployments set to `interrupted` too. Their `resource_locks` rows are **kept as they are in the snapshot**. The snapshot is a single SQLite transaction and locks are only held by claimed jobs, so these rows are mutually consistent by construction;
   - every other lock row is deleted;
   - approvals on non-terminal jobs are deleted;
   - all sessions and API/MCP tokens are revoked; identities and role bindings are kept;
   - unconsumed join and bootstrap codes are invalidated;
   - `settings.restore_hold = true`.
5. Run `PRAGMA wal_checkpoint(TRUNCATE)`, switch the staged DB to `journal_mode=DELETE`, close it, fsync.

**Phase B — activate.** Write `<data_dir>/restore.journal` (fsynced) listing each planned move:
1. move live `supermgmt.db`, `-wal` and `-shm` (if present) and live config files into `<data_dir>/pre-restore-<ts>/`;
2. move the staged files into place;
3. mark the journal `complete`, then delete it.

Every startup of the daemon or of the restore command checks for `restore.journal`:
- `staged` or no moves done → discard the staging dir and keep the live state;
- partially moved → finish the remaining moves forward (the staged files are already neutralized and complete);
- `complete` → delete the journal.

The live database is never opened during Phase B.

**Phase C — hold.** The daemon starts in **restore hold**. Workers and schedules do not claim jobs. Only these are served: reads, reconciliation (`system`), `job.resolve`, `sm doctor`, and `sm admin restore-complete`; every other write returns `CONFLICT` (`RESTORE_HOLD`). Humans regain access by logging in again over OIDC (identities are preserved). If no OIDC is configured, an admin issues a bootstrap code over the admin socket (§11.5), which during hold is accepted even though admin bindings exist. Discovery and the reconciler then run against real targets; resources mutated after the backup are detected by evidence (§20.4), not assumed. An admin reviews `sm doctor` and the remaining `interrupted` jobs, then runs `sm admin restore-complete` (audited) to clear the hold.

`SUPERMGMT_MODE=restore` (→ `sm install restore`) bootstraps a fresh control plane: it installs the binary, prompts for the key export and passphrase (`sm secrets import-key --offline`), then runs `sm backup restore --offline` before the service is first started.

## 29.3 Upgrade

- Download verified release.
- Validate compatibility and free disk.
- Create pre-upgrade backup.
- Stop service.
- Replace binary atomically.
- Run forward migrations.
- Start and health-check.
- If binary fails before irreversible migration, restore prior binary; database rollback uses backup, not down migrations.

## 29.4 Uninstall

Software removal and data deletion are separate confirmations. Proxmox appliance uninstall may remove the LXC only when installer metadata proves it owns that VMID and user explicitly confirms. Never delete provider resources merely because provider is removed from SuperMgmt.

---

# 30. Security requirements / threat model

Threats considered:

- stolen browser/OIDC session;
- compromised MCP client;
- malicious prompt attempting privileged action;
- compromised managed node;
- malicious repository/PR;
- forged/replayed GitHub webhook;
- SSH MITM/host key change;
- leaked API token;
- malicious container logs containing terminal escape/control sequences;
- command injection through resource names/parameters;
- SSRF through health-check URLs/provider endpoints;
- dependency/supply-chain compromise;
- backup theft;
- control-plane DB theft.

Mandatory mitigations:

- default deny and least privilege;
- strict host keys/TLS verification;
- output sanitization before TUI rendering;
- no ANSI/control sequence trust from remote logs;
- URL validation and SSRF protections for server-side checks;
- fixed command templates and argument escaping;
- bounded output/timeouts/concurrency;
- webhook signature + replay dedupe;
- immutable artifact digests;
- protected production policies;
- secret encryption/redaction;
- rate limiting on auth/MCP/write endpoints;
- CSRF protection where cookie auth exists;
- secure headers and origin policy;
- no debug endpoints publicly exposed;
- dependency pinning/scanning and release checksums/signatures;
- audit denied actions as well as accepted actions;
- outbound request filter for every server-side fetch (§21.1);
- closed-schema Compose pipeline (§20.3);
- lease fencing, intents and evidence-based reconciliation (§20.4);
- local-mode trust boundary documented: same-OS-user code is trusted (§2.1.1).

MCP content is untrusted input. A model asking for an action has no more authority than its authenticated identity and policy grants.

---

# 31. Implementation milestones

An implementation agent proceeds in this order. Each milestone depends only on earlier ones; each "Depends on" line states why.

## M0 — Repository and core

Deliver:

- repository skeleton (only directories needed by M0, §5);
- Go module;
- ADRs for the decisions fixed in this spec (ADR-0001 SQLite driver, ADR-0002 UUIDv7, ADR-0003 AES-256-GCM envelope, ADR-0004 OpenSSH release signatures, ADR-0005 daemon process model);
- config loader/validator (strict decoding; unknown fields fail);
- logging with redaction/correlation IDs;
- SQLite migrations/repository layer;
- domain entities with `spec_revision` (§6.4);
- event/audit service;
- action catalog and policy engine with the full §11.3 algorithm (table tests);
- canonical action plan + hashing (Appendix C), persisted plans, approval records with quorum rules (§11.4);
- durable job engine: claim/revalidation, lease generations and fencing, intents, resource locks, retry classes, reconciler interface (§20.4);
- offline CLI commands: version, completion, config validate, doctor --offline (§2.1.1);
- CI, lint, tests.

Acceptance: `go test ./...`, `go vet ./...`, lint pass; config examples validate; migrations create clean DB; policy tests cover every §11.3 step; a plan whose target `spec_revision` changes invalidates its approval.

## M1 — Local daemon, SSH, TUI alpha

Depends on: M0 jobs/policy/approvals.

Deliver:

- `sm daemon`: Unix socket API with peer-credential auth, lock file, idle exit (§2.1.1);
- typed API client (`internal/client`) used by TUI and CLI;
- local mode and local provider;
- SSH transport: strict host keys, persistent connections, templates + validators (§12);
- add/probe/list nodes; tiered refresh;
- system metrics snapshot;
- systemd discovery/logs; Docker discovery/logs;
- service start/stop/restart as `non_retryable` jobs through policy;
- TUI dashboard/node/service/log screens and Jobs/Approvals screens;
- interactive SSH handoff;
- minimal secret store (§10 envelope + file KEKs) for the SSH identity (§8.4); the rest of §10 stays in M2;
- audit events.

Acceptance: manage two fixture Linux nodes without agent; one offline node never freezes TUI; a restart on a service whose node is in a production-risk environment waits in Approvals until approved in the TUI; killing the daemon mid-restart leaves the job `interrupted` and the reconciler resolves it.

## M2 — Server/client/auth and release pipeline

Depends on: M1 API (the HTTP server exposes the same handlers over TCP).

Deliver:

- HTTPS transport for the API; OpenAPI and drift check;
- sessions/API tokens, local bootstrap token, OIDC adapter;
- client profiles (`sm login`, `sm profile`), remote TUI;
- SSE events;
- server-mode SSH identity (§8.4);
- TLS modes, admin socket and bootstrap code (§23.1, §11.5);
- release pipeline: GoReleaser, checksums, OpenSSH signatures, SBOM, provenance;
- `install.sh` bootstrap + `sm install local|server|client` (no Proxmox yet);
- `sm backup create|list|restore` (needed by upgrade in M3);
- Cloudflare deployment guide/integration hooks.

Acceptance: laptop `sm` controls remote server over authenticated HTTPS; local mode still works without an identity provider; `curl … | bash` installs a signed release on a clean Debian VM in server mode; a tampered archive or signature fails with exit code 5; backup → restore on a fresh VM round-trips.

## M3 — Proxmox provider and appliance installer

Depends on: M2 server mode (the appliance runs a server that clients reach), M2 release pipeline (bootstrap downloads signed artifacts), M2 backup (pre-upgrade backup).

Deliver:

- Proxmox provider discovery; VM/LXC resource tree;
- `sm install proxmox-lxc` with rollback journal and fake-PVE tests;
- restricted Proxmox credentials and secure token transfer (§3.5);
- power actions as `non_retryable` jobs with persisted UPIDs;
- `sm install upgrade|uninstall`.

Acceptance: fresh supported PVE host → one command → functioning LXC → cluster discovered → laptop `sm login` connects to it; injected failure at each installer step rolls back only created resources; upgrade N-1 → N with automatic pre-upgrade backup.

## M4 — Apps/GitHub/deployments

Depends on: M0 jobs/plans/approvals, M1 SSH templates and locks, M2 HTTPS server (the GitHub webhook endpoint delivered in M4 runs on it; local mode polls instead).

Deliver:

- GitHub connector (webhooks in server mode, polling in local mode);
- app manifest parser/schema; control-plane-only fields (§19);
- CI verification and artifact/provenance binding (§18);
- Compose pipeline (§20.3) and project ownership (§20.5);
- Docker Compose deploy engine with the §20.1 state machine, intents and evidence-based reconciliation;
- health checks with execution scope (§21);
- rollback (§20.1) and deployment policy (§19.1);
- deployment wizard/history/timeline.

Acceptance: successful CI exact commit/digest deploys to selected managed node; failed health check rolls back when declared safe; a repository Compose file with `privileged: true` is rejected; a health URL pointing off-node is rejected.

## M5 — MCP

Depends on: M0 policy/plans/approvals, M2 tokens and HTTPS server, M4 deployment actions. M5 itself delivers the OAuth protected-resource layer (§24) against an external authorization server.

Deliver:

- MCP client registration and tokens; stdio bridge; remote MCP as OAuth protected resource (RFC 9728 metadata, token validation) (§24);
- read tools; `infra_plan_action`;
- optional write tools disabled by default;
- MCP security tests (forbidden tools, prompt-injected logs, approval bypass attempts).

Acceptance: MCP can inspect graph without shell access; production write requiring approval cannot execute until exact plan approved; an MCP identity cannot approve.

## M6 — Hardening/release

Deliver:

- packaging/homebrew plan;
- fuzz tests for parsers/inputs;
- race tests;
- security scans;
- docs completion;
- compatibility matrix;
- beta migration tests.

Acceptance: clean machine install/upgrade/restore/uninstall E2E across all modes and documented release process.

---

# 32. Testing strategy

## Unit

Domain rules, policy, config, manifest, command templates, redaction, state machines, URL validation, canonical plan hashing.

## Integration

SQLite migrations, SSH fixture containers/VMs, fake Proxmox API, fake GitHub API/webhooks, Docker fixture, systemd where CI supports it.

## E2E

- local laptop-style install.
- generic Linux server install.
- Proxmox test environment when available.
- remote client authentication.
- add SSH node.
- Docker discovery/logs.
- deployment success/failure/rollback.
- MCP read and approval-gated write.
- backup/restore.
- upgrade N-1 -> N.

## Security tests

Command injection payloads, malicious ANSI logs, changed SSH host key, invalid TLS, webhook replay, forged OIDC claims, expired approval, changed plan after approval, SSRF URLs, secret leakage assertions, MCP forbidden tools, MCP self-approval, privileged Compose files, off-node health URLs, Unix socket access by another OS user, journalctl pager escape, lease expiry during non-retryable jobs.

## Quality gates

CI MUST run formatting, vet, golangci-lint, unit/integration tests, race tests where practical, govulncheck, dependency review, CodeQL/static analysis and secret scanning. Release requires all gates green.

---

# 33. Observability

Structured logs in JSON for server mode; human logs for CLI. Fields: timestamp, level, component, correlation_id, actor_id when safe, resource IDs, error code. Never log secrets.

Internal metrics endpoint may expose Prometheus-compatible metrics on loopback/private bind when enabled:

```text
supermgmt_jobs_total
supermgmt_job_duration_seconds
supermgmt_provider_sync_errors_total
supermgmt_provider_sync_duration_seconds
supermgmt_ssh_connections_active
supermgmt_api_requests_total
supermgmt_deployments_total
```

Metrics endpoint disabled or private by default.

---

# 34. Performance targets

This is network-bound software; optimize correctness first.

Targets for typical homelab/small-team scale:

- 500 nodes represented without architectural redesign.
- 5,000 services in DB/TUI filtering.
- TUI keypress response <50 ms excluding remote operation.
- Dashboard initial cached render <500 ms.
- Background sync bounded and cancellable.
- SSH: persistent connection per managed node; 16 concurrent handshakes and 512 connections by default, configurable (§8.2, §12).
- No unbounded goroutine creation.
- Log endpoints enforce byte/line limits.

Use profiling before optimization.

---

# 35. Compatibility

Initial release targets:

```text
Client: macOS amd64/arm64, Linux amd64/arm64
Server: Debian/Ubuntu-class systemd Linux amd64/arm64
Proxmox: explicitly tested currently supported PVE major versions
Nodes: common systemd Linux distributions with OpenSSH
Docker: supported modern Docker Engine + Compose v2
```

Do not claim unsupported versions. Maintain `docs/compatibility.md` once implementation begins.

---

# 36. Release engineering

Use semantic versioning. Pre-1.0 may break APIs only with changelog/migration notes.

Release artifacts:

```text
sm_<version>_linux_amd64.tar.gz
sm_<version>_linux_arm64.tar.gz
sm_<version>_darwin_amd64.tar.gz
sm_<version>_darwin_arm64.tar.gz
checksums.txt
checksums.txt.sig          # OpenSSH signature, namespace supermgmt-release (§3.2)
SBOM files
provenance attestation    # Sigstore/SLSA, for auditors
```

Use GoReleaser or equivalent. Builds should be reproducible where practical, include version/commit/build date, and generate SBOM/provenance. GitHub release workflow uses minimal permissions and protected release environment.

`sm version` prints version, commit, build date, Go version and platform.

---

# 37. Developer workflow

Recommended Make targets:

```text
make build
make test
make test-race
make lint
make vuln
make generate
make api-check
make integration
make e2e
make snapshot
make release-check
```

Local dev:

```bash
go mod download
make test
make build
./dist/sm --config ./dev/config.yaml
```

Generated files must have headers and CI drift checks.

---

# 38. Error model

Two levels: a small set of stable **top-level codes** (`error.code`), and a **reason** (`error.details.reason`, and `deployments.state_reason`) from a closed enum. Clients branch on the code; the reason is informative and may grow in minor versions.

```text
code                     reasons (non-exhaustive list is a bug; enum lives in internal/errors)
INVALID_ARGUMENT         COMPOSE_REJECTED, MANIFEST_INVALID, UNKNOWN_ACTION, AMBIGUOUS_TARGET
NOT_FOUND                —
CONFLICT                 PLAN_STALE, PLAN_EXPIRED, ALREADY_SUBMITTED, ALREADY_DECIDED,
                         RESOURCE_LOCKED, RESTORE_HOLD, IDEMPOTENCY_MISMATCH,
                         INVALID_TRANSITION, PROJECT_NOT_OWNED
UNAUTHENTICATED          CREDENTIAL_EXPIRED, CREDENTIAL_REVOKED, OIDC_REPLAY, OIDC_INVALID
POLICY_DENIED            DENY_RULE, DEFAULT_DENY, DESTRUCTIVE_GATE, SCOPE_DENIED,
                         APPROVAL_NOT_SUPPORTED, NOT_PLAN_ACTOR, SELF_APPROVAL
APPROVAL_REQUIRED        —
CAPABILITY_UNAVAILABLE   UNIT_NOT_ELIGIBLE, HEALTH_CAPABILITY_MISSING
NODE_UNREACHABLE         —
SSH_HOST_KEY_MISMATCH    —
PROVIDER_ERROR           —
CI_NOT_PASSED            CHECK_FAILED, CHECK_MISSING, CI_TIMEOUT
ARTIFACT_NOT_IMMUTABLE   DIGEST_UNBOUND, TAG_REFERENCE
DEPLOYMENT_FAILED        PREFLIGHT_FAILED, STAGING_FAILED, HEALTH_FAILED,
                         ROLLBACK_UNAVAILABLE, INTERRUPTED_BEFORE_DEPLOY, REJECTED,
                         RESTORED_UNDISPATCHED
ROLLBACK_FAILED          —
TIMEOUT                  —
INTERNAL                 —
```

`deployments.state_reason` values are the reasons above. A job that fails at claim records the reason of the corresponding code (e.g. `PLAN_STALE`). Errors shown to users should be actionable but must not leak credentials or sensitive internal values.


---

# 39. UX examples / required workflows

## 39.1 First launch local

```text
Welcome to SuperMgmt

Where should SuperMgmt run?
  > This machine
    Connect to an existing SuperMgmt server

What do you want to connect?
  > Local machine
    SSH server
    Proxmox
    GitHub
    Skip
```

## 39.2 Add SSH node

```text
Add SSH node
Host: ovh-prod.example.net
User: supermgmt

Host fingerprint:
SHA256:...
Trust this host? [y/N]

Connected.
Detected:
✓ systemd
✓ Docker 28.x
✓ Docker Compose
○ lazydocker not installed

Save node? [Y/n]
```

## 39.3 Discovered vs managed Proxmox guest

```text
100 windows       VM   ○ discovered
101 docker-prod   VM   ● managed
102 postgres      LXC  ● managed
```

## 39.4 Service detail

```text
SERVICE: api
NODE: ovh-prod
TYPE: Docker
IMAGE: ghcr.io/acme/api@sha256:...
STATUS: running
HEALTH: healthy
DEPLOYMENT: a84f2d1

[l] logs  [r] restart  [e] exec  [g] github
```

## 39.5 Approval

```text
PLAN #184

1. Pull ghcr.io/acme/api@sha256:abc
2. Update Compose service api on ovh-prod
3. Check http://127.0.0.1:8080/health
4. Mark deployment known-good

Impact: 1 production node
Risk: operational
Expected downtime: none

[A] Approve  [R] Reject
```

---

# 40. Provider/connector extension contracts

Avoid Go runtime plugins. Compile adapters into releases behind interfaces/registries; Go plugin ABI is unsuitable for portable OSS distribution.

Conceptual interfaces:

```go
type Provider interface {
    Type() string
    Validate(ctx context.Context) error
    Sync(ctx context.Context) (SyncResult, error)
    Capabilities(ctx context.Context, resource ResourceRef) ([]Capability, error)
}

type NodeTransport interface {
    Probe(ctx context.Context, node Node) (ProbeResult, error)
    RunTemplate(ctx context.Context, node Node, cmd CommandTemplate, args map[string]string) (Result, error)
    Interactive(ctx context.Context, node Node, req InteractiveRequest) error
}

type Runtime interface {
    Discover(ctx context.Context, node Node) ([]Service, error)
    Logs(ctx context.Context, service Service, opts LogOptions) (LogStream, error)
    Action(ctx context.Context, service Service, action ServiceAction) error
}

type Deployer interface {
    Plan(ctx context.Context, req DeploymentRequest) (ActionPlan, error)
    Execute(ctx context.Context, plan ActionPlan) error
    Rollback(ctx context.Context, deployment Deployment) error
}
```

Actual interfaces should be small and split when implementations do not need all methods.

---

# 41. Dependency policy

Prefer standard library and mature dependencies. Pin versions through `go.mod`. Avoid frameworks that obscure HTTP/auth behavior. Candidate categories:

- Bubble Tea ecosystem for TUI.
- SQLite driver suitable for static/cross-platform builds; choose deliberately and document CGO implications.
- Official/maintained MCP Go SDK.
- Maintained SSH package/OpenSSH handoff.
- YAML library with strict decoding.
- UUID library if needed.

Before first release, produce dependency/license inventory and vulnerability scan. No dependency may silently phone home.

---

# 42. Naming and branding

Working project name: **SuperMgmt**. CLI: **`sm`**.

Before public launch, perform GitHub repository/org, package registry, domain and trademark checks. If conflict exists, rename before ecosystem adoption. Code should avoid hard-coding public domain names; use build/config constants.

Suggested tagline:

> **Your infrastructure, one control plane.**

Long description:

> SuperMgmt is a local-first, terminal-first infrastructure control plane for developers. Connect machines, hypervisors, containers, services, repositories and deployments; operate them from one TUI/CLI, and expose the same policy-controlled context and actions to AI agents through MCP.

---

# 43. Definition of V1

V1 is complete only when all of the following work and are documented:

- Install locally on supported macOS/Linux without cloning repo.
- Install server on supported Linux without cloning repo.
- On supported Proxmox, one bootstrap command automatically creates an unprivileged LXC and installs/registers SuperMgmt.
- Add generic Linux nodes agentlessly via SSH with strict host keys.
- Discover Proxmox VM/LXC resources.
- Discover systemd and Docker services.
- TUI navigates nodes/services/logs and opens SSH/lazydocker where supported.
- GitHub repository can be linked to an app.
- CI-passed immutable Docker artifact can deploy via Compose to a selected node/environment.
- Health check and safe rollback work.
- Events/audit timeline works.
- Remote server/client mode works with authenticated HTTPS.
- MCP can safely read normalized infrastructure and submit policy-controlled actions.
- Production writes can require human approval.
- Backup/restore/upgrade/uninstall are tested.
- Documentation, security policy, CI, release checksums/signing and migration tests exist.

Anything else is post-V1 unless needed to satisfy these requirements.

---

# 44. Post-V1 roadmap

Potential modules, not V1 promises:

- Hetzner/OVH provider APIs.
- Vercel API deployments/status as API-only resources, not SSH nodes.
- Cloudflare DNS/Tunnel management.
- AWS/GCP/Azure connectors.
- Podman.
- Kubernetes read-only/context integration.
- Optional outbound node agent.
- Headscale/Tailscale/WireGuard onboarding helpers.
- Scheduled maintenance policies.
- Security-only unattended update workflows.
- Canary/blue-green strategies.
- Notification integrations.
- External secret managers.
- Multi-user teams and SSO refinements.
- HA control plane only if real demand justifies complexity.

---

# 45. Final implementation rules

1. Never make Proxmox mandatory.
2. Never make Cloudflare mandatory.
3. Never require an agent for ordinary Linux management.
4. Never expose unrestricted privileged shell through MCP by default.
5. Never deploy a mutable branch/tag when an immutable digest can be used.
6. Never bypass policy/audit because an action originated from TUI, CLI, API or MCP.
7. Never silently trust a changed SSH host key or invalid TLS certificate.
8. Never claim a queued provider task succeeded until verified.
9. Never store plaintext secrets in SQLite/logs/config examples.
10. Never block the whole TUI on a slow provider/node.
11. Never make managed workloads depend on SuperMgmt availability.
12. Keep the domain/application core independent of transport/UI/vendor adapters.
13. All writes must be idempotent, revision-guarded, or explicitly non-retryable.
14. All remote operations require timeout/cancellation.
15. Every release must have a tested upgrade and backup/restore path.

---

# 46. Deferred decisions (ADR backlog)

These items have fixed constraints here, but their concrete mechanism is decided by an ADR delivered **inside the named milestone**, before that milestone's first implementation PR. An ADR may not relax a constraint listed here; changing one requires a spec change.

| ADR | Milestone | Decision | Constraints the ADR must satisfy |
|---|---|---|---|
| ADR-0007 Execution snapshots | M4 | Where the executable contents behind plan hashes live (public Compose model, effective health config, deployment policy) and how long they are kept | Immutable, content-addressed by the hashes in Appendix C; stored in SQLite; retained at least while the deployment is a rollback candidate (`known_good` chain) and for the plan's job lifetime; workers read only these records (§20.2) |
| ADR-0008 Secret versions | M4 | Whether historical secret versions are kept (encrypted) or rollback fails when a referenced version is gone | Plans reference `{secret_id, version}`; values never stored unencrypted on the control plane; if a required version is unavailable, rollback fails with `ROLLBACK_UNAVAILABLE` (reason `SECRET_VERSION_GONE`) rather than using a newer value silently |
| ADR-0009 Node provisioning | M1 | The approved setup operation that creates `/var/lib/supermgmt/markers`, `/run/supermgmt/locks` (tmpfiles.d), `deploy_root`, the broker and sudoers drop-in, and the capabilities it advertises | A `node.setup` job (high risk, approval-gated, idempotent); nodes lacking it do not advertise `docker.compose.deploy` or any `non_retryable` mutating capability; marker-based recovery (§20.4) applies only to SSH templates. Proxmox recovery uses task correlation only, and missing evidence never implies safe re-dispatch |
| ADR-0010 Secret env-file encoding | M4 | How secret values are written to `secrets/<service>.env` so Compose reads them byte-exact | Must round-trip every value in a test corpus (`$`, quotes, `#`, spaces, unicode). Values with NUL or newline are rejected at `secret.write` time unless the ADR proves support (e.g. a pinned Compose version with `format: raw`). The node-side check compares resolved values privately (hash-only output) before masking |
| ADR-0011 Provisional deployment API | M4 | Request/response shape of a deployment before its final plan exists | `plan_hash: null` while provisional; persisted in `deployments` with commit, requested digest(s) and credential context; only `job.cancel` applies before finalization; approve/reject accepted only once a final hash exists; finalization emits a `deployment.finalized` event carrying the hash |
| ADR-0012 Route metadata | M2 | OpenAPI extension marking every route with exactly one of `action:<catalog id>`, `exempt:auth`, `exempt:health`, `exempt:self` | CI fails on unmapped routes; exempt routes are listed explicitly; key-management CLI commands map to `secret.write` (rotate/retire/export) or are offline-only (`import-key`); enrollment consumption is `exempt:auth`; planning on resource types without a read action (secrets, repositories) requires `config.read` |

Each ADR lives in `docs/adr/` and is referenced from this table once accepted.

---

# Appendix A — systemd unit contract

```ini
[Unit]
Description=SuperMgmt control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=supermgmt
Group=supermgmt
ExecStart=/usr/local/bin/sm server --config /etc/supermgmt/config.yaml
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/supermgmt
RuntimeDirectory=supermgmt
RuntimeDirectoryMode=0750
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

Implementation must test hardening options against required SSH/network behavior and relax only documented incompatible directives.

---

# Appendix B — sample local profile

```yaml
version: 1
current: home
profiles:
  home:
    type: remote
    url: https://mgmt.example.com
    auth: oidc
  local:
    type: local
    config: ~/.config/supermgmt/config.yaml
```

Tokens belong in OS credential storage where available, not this file.

---

# Appendix C — canonical action plan

A plan lists **every input** that can change what executes. The hash covers all of them.

```jsonc
{
  "version": 3,
  "action": "deployment.create",
  "actor": "identity/0190…",
  "targets": [                                   // sorted by (type, id)
    {"type": "app_target", "id": "…", "spec_revision": 7}
  ],
  "inputs": [                                   // sorted by (type, id); every configured
                                                 // resource the execution reads
    {"type": "app",          "id": "…", "spec_revision": 12},
    {"type": "environment",  "id": "…", "spec_revision": 3},
    {"type": "health_check", "id": "…", "spec_revision": 1},
    {"type": "node",         "id": "…", "spec_revision": 42,
     "endpoint": {"address": "10.42.0.10", "port": 22, "user": "supermgmt"},
     "host_public_key_sha256": "SHA256:…"},
    {"type": "repository",   "id": "…", "spec_revision": 2},
    {"type": "secret",       "id": "…", "version": 4}
  ],
  "content": {                                   // content hashes of materialized inputs
    "commit_sha": "a84f2d1…",
    "manifest_blob_sha": "…",                    // git blob of .supermgmt.yaml, if used
    "compose_hash": "sha256:…",                  // frozen normalized model (§20.3)
    "images": [                                  // sorted by service
      {"service": "redis", "ref": "docker.io/library/redis@sha256:…", "binding": "pinned"},
      {"service": "web",   "ref": "ghcr.io/acme/api@sha256:…",       "binding": "attestation"}
    ],
    "exceptions_hash": "sha256:…",
    "health_hash": "sha256:…",                   // effective health config after precedence
    "deployment_policy_hash": "sha256:…",        // rollback/stateful/backup/snapshot
    "host_ports": ["127.0.0.1:8080"],            // sorted
    "rollback_target": {"deployment_id": "…", "compose_hash": "sha256:…"}, // or null
    "secret_bindings": [                         // sorted by (service, env_name); refs only
      {"service": "web", "env_name": "DATABASE_URL", "secret_id": "…", "version": 4}
    ]
  },
  "sub_actions": [                               // sorted by (action, target id)
    {"action": "node.backup_template.run", "target": {"type": "node", "id": "…"}}
  ],
  "parameters": {},
  "steps": ["preflight", "snapshot", "pre-deploy-backup", "pull", "materialize",
            "verify-on-node", "deploy", "health-check"],   // execution order; not sorted
  "risk": "operational"
}
```

**Serialization.** RFC 8785 (JSON Canonicalization Scheme) over the plan object. Hash = SHA-256 of the canonical bytes, rendered `sha256:<hex>`.

**Rules RFC 8785 does not cover:**
- `targets` and `inputs` are sorted by `(type, id)` (type compared as an ASCII string, then id); `images` by `service`; `secret_bindings` by `(service, env_name)`; `sub_actions` by `(action, target.id)`; `host_ports` lexically.
- `steps` keeps execution order.
- Numbers are integers in `[0, 2^53-1]`; floats are forbidden in plans.
- Absent optional values are `null`, never omitted.
- No timestamps, random values, observation data (metrics, reachability), secret values or credential context appear in a plan. The approval TTL, plan expiry and the requester's credential context are stored in `plans`, outside the hash.

Golden tests pin hashes for fixed plans. Claim-time revalidation (§20.4) recomputes every `inputs[*].spec_revision` and every `content` hash and compares them with the plan.


---

# Appendix D — minimal README quick-start contract

```markdown
## Quick start

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/<ORG>/supermgmt/main/install.sh | bash
```

On a Proxmox VE host, the installer detects PVE and offers the recommended appliance mode: it creates an unprivileged Debian LXC, installs SuperMgmt inside it, creates restricted API credentials and registers the cluster automatically.

On macOS/Linux it can install SuperMgmt locally or connect the TUI to an existing server.

### Add a Linux machine

```sh
sm nodes add ssh user@server
```

No agent is required.

### Open the TUI

```sh
sm
```
```

Replace `<ORG>` only after the final repository location is known.

---

# Appendix E — implementation completion checklist

Before declaring the implementation complete, verify:

```text
[ ] Repository matches §5
[ ] README accurately distinguishes implemented/planned
[ ] Universal curl bootstrap works
[ ] Release verification works
[ ] Local install works
[ ] Generic server install works
[ ] Proxmox auto-LXC install works
[ ] Proxmox rollback on installer failure works
[ ] Strict SSH host keys work
[ ] Offline nodes do not block TUI
[ ] Docker/systemd discovery works
[ ] lazydocker handoff restores TUI
[ ] GitHub CI exact commit/digest validation works
[ ] Compose deployment state machine works
[ ] Health failure rollback works where safe
[ ] Audit timeline covers all mutations
[ ] Policy/approval hash invalidates on plan change
[ ] Sync/observations never invalidate approvals
[ ] Compose validator rejects privileged constructs
[ ] Interrupted jobs reconcile, never blind re-run
[ ] Single daemon owns the DB; second daemon refuses
[ ] MCP bridge without client token is refused; MCP identity cannot approve
[ ] Lost lease cannot write (fencing); locks held while interrupted
[ ] Claim-time revalidation rejects stale plans and lapsed quorum
[ ] Outbound filter blocks metadata/loopback/mapped addresses
[ ] Restore starts in hold; stale jobs interrupted; tokens revoked
[ ] Restore crash at every journal step recovers to a consistent state
[ ] Every API route maps to a catalog action (CI check)
[ ] Revoked/expired credential fails a queued job at claim
[ ] Takeover fences the old worker; quiescence required before reconcile/resolve
[ ] Frozen Compose model is identical after node CLI interpolation
[ ] Secret values never appear in plans, API views or control-plane disk
[ ] MCP client registration may need approval; token issuance happens once, afterwards
[ ] Forward resume re-runs claim revalidation; safety recovery only rolls back
[ ] No automatic resume/rollback without completion evidence (killed CLI -> human)
[ ] Restore fails undispatched work and keeps snapshot locks only for dispatched work
[ ] Fresh-host restore works with an offline key import
[ ] ADR-0007..0012 accepted in their milestones
[ ] MCP has no generic privileged shell
[ ] MCP write tools disabled by default
[ ] Remote auth works
[ ] Secrets do not leak in logs/API/backups
[ ] Backup/restore tested
[ ] Upgrade N-1 -> N tested
[ ] Uninstall preserves data unless separately confirmed
[ ] OpenAPI validated
[ ] Config/manifest schemas validated
[ ] Unit/integration/E2E/security tests pass
[ ] Race/vulnerability/static scans pass
[ ] Release artifacts/checksums/signatures/SBOM generated
[ ] License/dependency audit completed
[ ] Name/trademark/repository availability checked
```

---

# Appendix F — Change log

## F.1 Changes from 1.0.0-draft to 1.1.0-draft

```text
§2.1.1  New: single-daemon process model; TUI/CLI/MCP are always API clients; Unix socket
        with peer-credential auth; local mode cannot receive webhooks.
§3.2    install.sh reduced to verify+exec; installer logic moved to Go (sm install).
        Release signing fixed to OpenSSH signatures and made mandatory.
§3.5    Secure token transfer into the LXC specified; PVE CLIs behind interfaces.
§4/§5   Removed supermgmt-server; added sm daemon/install; layout split transport/ssh
        vs providers/ssh; removed future-milestone directories and shell installer libs.
§6.3    UUIDv7 fixed.  §6.4 New: spec_revision vs observations.
§8      macOS paths fixed; tiered refresh; SSH connection pooling settings; per-type
        retries; credential_ref schemes (§8.4) and server-mode SSH identity.
§9      Driver fixed (modernc.org/sqlite, CGO off). New tables: sessions, api_tokens,
        idempotency_records. events PK fixed. spec_revision columns; jobs retry/heartbeat.
§10     AES-256-GCM (stdlib) with per-secret DEK fixed.
§11     Rewritten: identities per actor type, policy as single grant source, built-in
        roles via default policy, deterministic evaluation algorithm, approvals rules
        (self-approval, MCP can never approve), risk-class typo fixed.
§12     Structural command-injection defense; persistent connections; scale model.
§16     journalctl never via sudo; exact sudoers lines.
§18     Local-mode CI polling; artifact↔commit binding via attestation or OIDC claims.
§19     Image repository/targets/Compose exceptions are control-plane-only;
        compose_source (control-plane | repository).
§20     Exhaustive transition table incl. awaiting_approval/interrupted; Compose
        validator (§20.1); rollback safety (§20.2); retry classes + reconciler (§20.3).
§21     Health-check execution scope (node | control_plane) and SSRF rules.
§23     Auth/token/approval endpoints; If-Match; plan_hash in approve/reject.
§24     MCP as API client; stdio identity; OAuth for remote; infra_plan_action
        contract; untrusted-output handling.
§31     Milestones reordered so each depends only on earlier ones: jobs/policy/approvals
        → M0; server+release+backup → M2; Proxmox/installer → M3.
App. C  RFC 8785 canonical JSON; spec_revision in targets.
```

## F.2 Changes from 1.1.0-draft to 1.2.0-draft

```text
§2.1.1  Offline commands; lock keyed to canonical DB path; socket dir/stale/autostart
        rules; mutual peer-UID check; explicit local-mode trust boundary; residency.
§3.2    Verifier probed before download; honest trust-root statement; signed install.sh
        per release; key validity/rotation/revocation; version-bound signatures;
        downgrade refusal.
§3.5    Full token transfer procedure incl. offline secrets import and failure cleanup.
§4      Added admin, mcp clients, ssh-key, secrets, jobs commands.
§6      Configured management_state vs observed reachability; endpoint pinning.
§8      TLS modes, admin socket, bootstrap TTL, keys_dir, logs_mode, reconcile_grace,
        health/github/mcp.oauth keys, environment schema (§8.2.1), mode-specific SSH
        examples, file:// validation, interactive access in server mode.
§9      identities.actor_type/issuer/client_id; plans, operation_intents, resource_locks,
        oidc_replay, bootstrap_codes; lease_generation; semantic constraints and enums.
§10     Versioned envelope with both nonces, AAD encoding, KEK ids, atomic rotation.
§11     Daemon-issued identities (MCP tokens); full action catalog and default policy;
        effective-attribute inheritance; multi-target "all must allow"; token scopes;
        non-recursive governance actions; distinct-approver quorum, rejection
        precedence, claim-time expiry; bootstrap bindings (§11.5).
§16     Journal trust boundary + opt-in log broker; unit integrity precondition; sudo -n.
§18     CI policy bound to repository/owner IDs, check app IDs, events, run attempts;
        "protected dependent job" removed; OIDC exp/iat/jti replay rules.
§19     Strict manifest schema; precedence table; deployment policy schema incl.
        pre-deploy backup contract; compose_source.
§20     One node per deployment in V1; exhaustive table incl. staging, rollback
        unavailable, interrupted rollback, claim-time failures; closed-schema Compose
        pipeline with interpolation, frozen model and on-node equivalence check;
        per-service image policy; claim/fencing/intents/locks; evidence per action;
        human resolution API; project ownership and lock scope.
§21     Node checks restricted to own published loopback ports, no proxies/redirects;
        outbound request filter (§21.1) incl. normalization and provider endpoints.
§23     Plans API; idempotency reservation and non-replayable credential responses;
        RESOURCE_LOCKED; token scopes/revocation; TLS/proxy/admin socket/OIDC PKCE.
§24     MCP client tokens for stdio; remote MCP as protected resource with external AS.
§28     id-token: write only on jobs that need it; provenance attestation step.
§29     Backup consistency boundary; restore key check, safe extraction, restore hold,
        job/approval/token neutralization, reconciliation before writes.
§31     Dependency lines corrected; offline M0 commands; M5 owns OAuth resource layer.
App. C  Plan version 2: all inputs and content hashes; ordering and numeric rules.
```

## F.3 Changes from 1.2.0-draft to 1.3.0-draft

```text
§2.1.1  Separate socket lock; canonical DB path before creation; offline restore.
§3.1/2  Review-first flow verifies signed install.sh; version precedence restored;
        signed channel files with valid_until (freshness for "latest").
§3.5    Restrictive in-container dir before push; cleanup on every failure path.
§6.4/§8 Full host public keys (known_hosts constructible); github.oidc_audience;
        outbound.proxy.
§9      Credential context on plans/jobs; one job per plan; approval renewal;
        intent state + deadline; lock modes; secret versions; artifact_checks;
        providers UNIQUE(name); idempotency state removed (single-transaction model).
§10     Check-record format; key retirement checks all retained backups; export format
        with bounded scrypt parameters.
§11     Complete action catalog with modes (query/job/direct/governance) incl. reads,
        node.connect, admin and credential-issuing actions; endpoint->action mapping
        enforced in CI; credential context re-checked at claim; composite plans with
        sub-actions; tags control-plane-only; approval renewal, rejection window, plan
        expiry; bootstrap code issuance; system actor may back up; identity-id example.
§16     Unit trust profile covering all Exec*, interpreters, env files and parent dirs.
§18     workflow_ref vs job_workflow_ref; checks bound to workflow path; per-check
        evidence; configurable OIDC audience.
§20     Provisional vs final plan; table adds rejection/expiry/credential failures and
        resume transitions; plan-snapshot execution; single-pass interpolation with
        $$ re-escaping; secrets as references materialized to 0600 env files; closed
        nested schemas; enumerated exceptions; ownership vs per-deployment labels;
        full-model equivalence; takeover increments generation; per-step deadlines;
        node-side markers and project flock; quiescence; completed-intent recovery;
        shared/exclusive locks.
§21     Address selection; exact curl template, 3xx = failure, no wget; tcp
        independent of curl; metadata always denied (incl. fd00:ec2::254); proxies.
§23     Plan submit actor equality and single submission; idempotency in one
        transaction; OIDC server-mediated PKCE exchange; admin socket scope.
§29     Config snapshot inside the DB; offline staged restore with journal-based
        crash recovery; neutralization before activation; recovery access during hold.
§38     Top-level codes vs reason enums.
App. C  Plan v3: sorted inputs, secret bindings (refs), sub-actions, credential context
        excluded from hash.
```

## F.5 Changes from 1.4.0-draft to 1.4.1-draft

```text
§20.4   Completion evidence (.done markers with exit 0 only, digest presence, systemd job queue, PVE task
        status, boot_id) required before outcome classification; without it no
        automatic resume or rollback — job stays interrupted with locks for a human.
```

## F.4 Changes from 1.3.0-draft to 1.4.0-draft

```text
§11.2   MCP client: approval-gated registration (high) separated from one-time token
        issuance (operational, never approval-gated); credential-issuing rules made
        consistent with step 8.
§20.1   Forward resume vs system safety recovery; reason/code pair (state_code).
§20.4   Completion evidence: two identical samples matching a defined terminal
        pattern, separate from process exit; resume revalidation.
§29.2   Restore fails undispatched work (RESTORED_UNDISPATCHED); keeps snapshot locks
        only for dispatched work; key check against the staged DB; offline key import.
§2.1.1/§10  `sm secrets import-key --offline` with .pending keys.
§18     job_workflow_ref optional for ordinary workflows.
§3.1/§3.2  Fail-closed review-first example; channel validity bounded to 30 days.
§46     New: ADR backlog (snapshots, secret versions, node provisioning, env-file
        encoding, provisional deployment API, route metadata) with fixed constraints.
```

## F.6 Changes from 1.4.1-draft to 1.4.2-draft

```text
§6.4    SSH endpoint gains admin_user; user defaults to supermgmt; connection-user rule
        (user iff capability node.setup, else admin_user for read-only probes).
§8.3/4  Examples show admin_user and admin_credential_ref; the instance SSH identity
        secret://ssh/default is generated in both modes and is the default credential_ref.
§11.2   node.setup (node, high, job, idempotent, node.ssh, 3) granted in builtin-admin.
§11.3   Composite node.setup plans with sub-actions sudoers.write and log_broker.install.
§12     Step 7 names the dedicated user, home, shell, key and docker_access; teardown manual.
§20.4   node.setup steps are the only mutating commands exempt from marker-first.
§31     M1 includes the minimal secret store for the SSH identity.
```

---

## F.7 Changes from 1.4.2-draft to 1.4.3-draft

```text
§8.2    auth.oidc.allowed_endpoint_origins (default empty: issuer origin only).
§10     export-key only on the local-mode socket; offline in server mode.
§23.1   OIDC discovery trust: exact issuer, https endpoints on allowed origins, no redirects.
§25     V1 consumes no Cloudflare edge assertion; app authentication is always SuperMgmt's.
```

---

## F.8 Changes from 1.4.3-draft to 1.4.4-draft

```text
§10     secret.write approval: rotate/retire/ssh-key rotate become control_plane.apply jobs; import is sealed as a
        staged version that approval activates (rejection deletes it); export-key is a request plus a one-time
        execution by the same identity within 24h. Plans never hold a secret value or a passphrase.
§11.2   note on secret.write approval.
§3.2    minimum OpenSSH is 8.2, not 8.1: the verifier self-test needs valid-after in allowed_signers (install.sh
        already enforced 8.2; ADR-0019 follows).
```

---

**End of master specification.**
