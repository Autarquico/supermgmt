# Architecture

Source of truth: [`spec/SUPERMGMT-SPEC.md`](spec/SUPERMGMT-SPEC.md). This page summarizes it and states what exists today. Markers: **[M0]** exists in the repository now; **[planned Mx]** does not exist.

## Process model (SPEC §2.1.1)

Exactly one process, the **daemon**, owns the database, job workers, sync loops and connectors. TUI, CLI and MCP are always clients of its API; there is no in-process TUI backend. Local and remote use share one code path. **[planned M1]** (local), **[planned M2]** (HTTPS).

```text
Laptop / server
├── daemon (single owner of state)          [planned M1]
│   ├── API: Unix socket 0600 / HTTPS       [planned M1 / M2]
│   ├── SQLite                              [M0: schema, migrations, repositories]
│   ├── job workers, reconciler, scheduler  [M0: job engine and reconciler; planned M1: wiring into the daemon]
│   └── connectors: SSH, Proxmox, GitHub    [planned M1, M3, M4]
└── sm TUI / CLI / MCP bridge: API clients  [planned M1, M5]
```

Two exceptions to "everything is an API client":

- **Offline commands** need no daemon: `sm version`, `sm completion` **[M0]**, `sm config validate`, `sm doctor --offline` **[M0]**. They take the database lock themselves and refuse while a daemon holds it. Other offline commands (`sm install`, `sm secrets import --offline`, `sm backup restore --offline`) are planned for later milestones.
- The daemon's own entry points and the server admin socket.

Two independent `flock`s protect a running daemon: a database lock on `<canonical db path>.lock` and a socket lock on `<socket>.lock` **[M0: database lock; planned M1: socket lock and peer-credential auth]**. Local mode trusts code running as the same OS user (see [security.md](security.md)).

## Layers and package map (SPEC §5)

Dependencies point inward: adapters (CLI, API, TUI, MCP) call application services, which use the pure domain, policy and storage. No business logic lives in `cmd/`, HTTP handlers, TUI models or MCP handlers. The rules are enforced by `depguard` in [`.golangci.yml`](../.golangci.yml).

| Package | Role | Status |
|---|---|---|
| `cmd/sm` | entry point, imports only `internal/cli` | M0 |
| `internal/cli` | command tree, exit codes, output | M0 (`version`, `completion`, `config validate`, `doctor --offline`) |
| `internal/domain`, `internal/domain/plan` | pure types, enums, clock, IDs, canonical plan and hash | M0 |
| `internal/errors` | typed errors and reason codes (`smerr`) | M0 |
| `internal/version` | build metadata | M0 |
| `internal/config` | typed schema, strict decoding, env overrides, validation, paths | M0 |
| `internal/audit` | event creation, redaction, correlation IDs, structured logger | M0 |
| `internal/database`, `migrations` | SQLite, embedded migrations, lock, transaction-scoped repositories | M0 |
| `internal/policy` | action catalog, evaluation, governance, quorum, default policy | M0 |
| `internal/jobs` | claim, leases and fencing, intents, resource locks, retry classes, reconciler | M0 |
| `internal/app` | application services: plans, approvals, revalidation, lock planning, audit of denials | M0 |
| `internal/yamlstrict` | strict YAML decoding with path and line errors, shared by config and policy | M0 |
| `internal/daemon`, `internal/api`, `internal/client` | process lifecycle, API, typed client | planned M1, M2 |
| `internal/secrets`, `internal/auth` | envelope encryption, identities and sessions | planned M2 |
| `internal/tui` | Bubble Tea UI | planned M1 |
| `internal/transport/ssh`, `internal/providers/*`, `internal/runtimes/*` | SSH, inventory sources, Docker and systemd | planned M1, M3, M4 |
| `internal/deployments/*`, `internal/health` | Compose pipeline, health checks | planned M4 |
| `internal/mcp` | MCP transport, tools, resources | planned M5 |
| `internal/installer`, `internal/backup` | installer logic, backup and restore | planned M2, M3 |

Enforced boundaries today: `internal/domain` imports only the standard library, `uuid` and `internal/errors`; `internal/policy` does not import `internal/database` or `internal/jobs`; `database/sql` and the SQLite driver stay in `internal/database`, `internal/jobs` and `migrations`; `time.Now` and `fmt.Print*` are linted away from library code.

## Domain graph (SPEC §6)

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

M0 defines the cross-cutting entities and the tables for providers, nodes, runtimes, services, environments, identities, roles, plans, jobs, approvals, intents, locks, observations and events. Repository, Application and Deployment arrive with M4.

Configured state and observed state are kept apart (SPEC §6.4). Configured resources carry one `spec_revision`, which increments only when desired state changes and is used for optimistic concurrency. Observations (reachability, metrics, versions) live in separate records and never bump it. Consequence: periodic discovery does not invalidate approvals. **[M0]**

## Policy, approval and job flow (SPEC §11, §20.4)

```text
request (actor + credential context)
   │
   ▼
 plan ── canonical form, RFC 8785 hash over every input ──────────── [M0]
   │
   ▼
 policy evaluation (§11.3) ──► deny / allow + approval_required + quorum ─ [M0]
   │ allow
   ▼
 job submitted
   ├─ approval needed ─► awaiting_approval ◄─ approvals bound to plan hash ── [M0]
   │                         │ quorum reached
   ▼                         ▼
 queued ──► claim (one transaction) ───────────────────────────── [M0]
              1. lease_generation++, lease owner
              2. take resource locks (shared / exclusive)
              3. revalidate: spec_revisions and content hashes vs plan
                 (PLAN_STALE), plan expiry, credential, policy, quorum
   ▼
 running (every write fenced by lease_generation) ─► succeeded | failed
   │ lease lost
   ▼
 interrupted ──► reconciler: acts only with completion evidence; otherwise the
                 job stays interrupted with its locks held; never blind re-execution
```

Key properties:

- Evaluation order (SPEC §11.3): catalog, capability, rule match, deny override, default deny, destructive gate, credential scopes, approval and quorum, then combine targets and sub-actions. Adding an allow never overrides a deny; adding a target never relaxes a decision. **[M0]**
- Approval binds to the plan hash. Changing any input yields a new hash; prior approvals do not transfer. Approvals expire and quorum counts distinct approvers. **[M0]**
- Job states follow [ADR-0013](adr/0013-generic-job-state-machine.md). The claim step re-checks everything the plan depended on, so a changed `spec_revision` fails the job with `PLAN_STALE`. **[M0]**
- Retry classes (`idempotent`, `resumable`, `non_retryable`) come from the action catalog. Non-retryable remote mutations are observed, never repeated. **[M0]**
- Locks are acquired at claim and held until the job is terminal, including while it is `interrupted` or requeued, so a retrying job cannot lose its resources to a rival (ADR-0013, SPEC §20.5). **[M0]**
- The reconciler acts only on a quiescent job and only on confirmed evidence: the completion signal with exit status 0 plus a classification observed identically in two samples at least 30 seconds apart, collected until `deadline_at` + 5 minutes. Missing, contradictory or inconclusive evidence holds the job `interrupted`. Only fake evidence adapters exist in M0; real ones (SSH, Docker, systemd, Proxmox) arrive with their milestones. **[M0]**
- A claim error that is a per-job data fault fails only that job, so one poison job cannot block the queue. **[M0]**
- Human resolution of a held job (`job.resolve`) is an action in the catalog; its API arrives in M1. **[planned M1]**

## Further reading

- [`security.md`](security.md): threat model and controls
- [`configuration.md`](configuration.md): configuration and environment overrides
- [`adr/`](adr/): architecture decision records
