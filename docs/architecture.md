# Architecture

Source of truth: [`spec/SUPERMGMT-SPEC.md`](spec/SUPERMGMT-SPEC.md). This page summarizes it and states what exists today. Markers: **[M0]** to **[M4]** exist in the repository now; **[planned Mx]** does not exist.

## Process model (SPEC §2.1.1)

Exactly one process, the **daemon**, owns the database, job workers, refreshers and connectors. The TUI and the CLI are clients of its API; there is no in-process TUI backend ([ADR-0005](adr/0005-daemon-process-model.md), [ADR-0014](adr/0014-local-api-and-daemon-lifecycle.md)). Local and remote use share one code path. **[M1]** (local), **[M2]** (HTTPS server mode), **[planned M5]** (MCP).

```text
Laptop
├── daemon (single owner of state)            [M1]
│   ├── API: Unix socket 0600                 [M1]   (server mode: HTTPS + admin socket, M2)
│   ├── SQLite                                [M0 schema; M1 migration 000002]
│   ├── job workers, reconciler, refresher    [M0 engine; M1 wired to SSH, systemd, Docker]
│   └── connectors: SSH, local, Proxmox       [M1; Proxmox M3]   [M4: GitHub]
└── sm TUI / CLI: API clients                 [M1]   (MCP bridge: planned M5)
        │ interactive SSH only: the terminal is handed to the system `ssh`, which
        └ the daemon authorizes and audits but does not proxy
```

Two exceptions to "everything is an API client":

- **Offline commands** need no daemon: `sm version`, `sm completion`, `sm config validate`, `sm doctor --offline` **[M0]**. They take the database lock themselves and refuse while a daemon holds it. `sm doctor` without `--offline` asks a server over its admin socket **[M2]**. Other offline commands: `sm install` (the installer runs outside the daemon), `sm secrets import-key --offline`, `sm secrets export-key --offline`, `sm secrets import --offline` and `sm backup restore --offline` **[M2]**.
- The daemon's own entry point, `sm daemon` **[M1]**. Any other command that needs the daemon starts it when none runs: a new session, output to `daemon.log` in the state directory, then up to 5 seconds of polling the socket (ADR-0014).

Two independent `flock`s protect a running daemon: a database lock on `<canonical db path>.lock` and a socket lock on `<socket>.lock`, with the PID written in both **[M1]**. The socket directory must be a real directory owned by the daemon user with mode 0700, and the daemon refuses to start otherwise. Both ends check the peer's UID (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS) and close the connection on a mismatch or a lookup failure. Local mode trusts code running as the same OS user (see [security.md](security.md)).

**Residency (ADR-0014).** The daemon exits after `daemon.idle_exit` only when no client holds the presence stream open, no request is in flight and no job is outside `succeeded`, `failed` and `cancelled`. A job waiting in `awaiting_approval` therefore keeps the daemon alive. `daemon.resident: true` disables the idle exit; `sm install local --resident` registers a user unit or launch agent that starts it at login **[M2]**.

## Layers and package map (SPEC §5)

Dependencies point inward: adapters (CLI, API, TUI, MCP) call application services, which use the pure domain, policy and storage. No business logic lives in `cmd/`, HTTP handlers, TUI models or MCP handlers. The rules are enforced by `depguard` in [`.golangci.yml`](../.golangci.yml).

| Package | Role | Status |
|---|---|---|
| `cmd/sm` | entry point, imports only `internal/cli` | M0 |
| `internal/cli` | command tree, exit codes, output; talks to the daemon through `internal/client` | M0 offline commands; M1 `nodes`, `services`, `jobs`, `approvals`, `events`, `status`, `ssh`, `docker`, `ssh-key`, `daemon`, `tui` |
| `internal/domain`, `internal/domain/plan` | pure types, enums, clock, IDs, canonical plan and hash | M0 |
| `internal/errors` | typed errors and reason codes (`smerr`) | M0 |
| `internal/version` | build metadata | M0 |
| `internal/config` | typed schema, strict decoding, env overrides, validation, paths | M0 |
| `internal/audit` | event creation, redaction, correlation IDs, structured logger | M0 |
| `internal/database`, `migrations` | SQLite, embedded migrations (`000001_initial`, `000002_m1`), lock, transaction-scoped repositories | M0, M1 |
| `internal/policy` | action catalog, evaluation, governance, quorum, default policy | M0 |
| `internal/jobs` | claim, leases and fencing, intents, resource locks, retry classes, reconciler | M0 |
| `internal/app` | application services: plans, approvals, inventory, probes, services, `node.setup`, sessions, idempotent writes, refresher | M0, M1 |
| `internal/yamlstrict` | strict YAML decoding with path and line errors | M0 |
| `internal/api`, `internal/api/wire` | `/api/v1` on the Unix socket; the JSON contract shared with the client | M1 |
| `internal/client` | typed client, daemon autostart, interactive-session command builder | M1 |
| `internal/daemon` | process lifecycle: locks, socket, residency, assembly | M1 |
| `internal/tui` | Bubble Tea UI | M1 |
| `internal/transport`, `internal/transport/ssh`, `.../templates` | the `Executor` seam, the SSH pool and credentials, the closed catalog of remote commands | M1 |
| `internal/providers/ssh`, `internal/providers/local` | SSH node description and connection-user rule; the read-only local executor | M1 |
| `internal/runtimes`, `internal/runtimes/systemd`, `.../docker` | runtime adapter contract; systemd (logs, trust profile, setup, actions); Docker | M1 |
| `internal/discovery` | turns one probe into a typed snapshot and capabilities | M1 |
| `internal/secrets` | AES-256-GCM envelope, file KEKs, versioned store, instance SSH identity | M1 (slice of M2; ADR-0016) |
| `internal/textsafe` | sanitizing of untrusted text | M1 |
| `internal/auth`, `internal/auth/oidc` | credentials, sessions, tokens, OIDC adapter | M2 |
| `internal/netguard` | outbound request filter | M2 |
| `internal/join` | node enrollment (`sm join`) | M2 |
| `internal/providers/proxmox` | Proxmox VE API client, UPID parsing, task correlation; `pvefake` is its test fake | M3 |
| `internal/providers/github` | GitHub connector: REST client, origin-pinned redirects, CI checks, contents, Actions OIDC verification, Sigstore attestation verification, webhook HMAC; `ghfake` is its test fake | M4 |
| `internal/deployments`, `internal/deployments/compose`, `internal/deployments/manifest` | the §20.1 state table, step catalog and rollback rules; the closed Compose pipeline (raw and model schema passes, freeze, canonicalisation, env-file encoding, resolved-environment hash); the app manifest | M4 |
| `internal/health` | health-check validation (manifest versus control-plane origin rules) and node-side checks | M4 |
| `internal/mcp` | MCP transport, tools, resources | planned M5 |
| `internal/installer`, `internal/backup` | installer logic, backup and restore | M2; Proxmox LXC appliance, upgrade and uninstall: M3 |

Enforced boundaries today (`.golangci.yml`): `internal/domain` imports only the standard library, `uuid` and `internal/errors`; `internal/api/wire` imports only the standard library, `internal/domain` and `internal/errors`; `internal/policy` does not import `internal/database` or `internal/jobs`; `database/sql` and the SQLite driver stay in `internal/database`, `internal/jobs` and `migrations`; `internal/tui` and `internal/client` never import `app`, `jobs`, `database`, `daemon`, `transport`, `runtimes` or `providers`; `internal/api` reaches nodes only through `app`; `internal/cli` does not import `app`, `jobs` or `transport`; `cmd/` imports only `internal/cli`; `time.Now` and `fmt.Print*` are linted away from library code.

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

M0 defines the cross-cutting entities and the tables for providers, nodes, runtimes, services, environments, identities, roles, plans, jobs, approvals, intents, locks, observations and events. M1 adds the `secrets` table and the rows the SSH connector needs (migration `000002_m1`). Repository, Application, App target and Deployment arrived with M4 (migration `000005`).

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
- The reconciler acts only on a quiescent job and only on confirmed evidence: the completion signal with exit status 0 plus a classification observed identically in two samples at least 30 seconds apart, collected until `deadline_at` + 5 minutes. Missing, contradictory or inconclusive evidence holds the job `interrupted`. Only fake evidence adapters exist in M0; real ones (SSH, Docker, systemd, Proxmox, deployments) arrived with their milestones. **[M0]**
- A claim error that is a per-job data fault fails only that job, so one poison job cannot block the queue. **[M0]**
- Human resolution of a held job (`job.resolve`) is an action in the catalog, served by `POST /api/v1/jobs/{id}/resolve` and `sm jobs resolve`. It needs the plan hash and an outcome. **[M1]**

## Remote execution (M1)

How a service restart reaches a node (ADR-0009, ADR-0015):

1. The caller is the `human` identity `local:<uid>` on the socket. Every route maps to exactly one catalog action, and every POST, PATCH and DELETE carries an `Idempotency-Key`; a replay returns the stored response bytes.
2. A restart is a plan, then a job. In a `production` environment it waits in `awaiting_approval` until a plan-hash-bound approval arrives.
3. Before dispatch the worker captures the unit's pre-state, records the intent and commits `MarkDispatched`. The command is rendered from the closed template catalog and runs as `supermgmt` over the pooled SSH connection: `sudo -n <systemctl> <verb> <unit>` wrapped so a marker file exists before it starts and a `.done` file records its exit status.
4. If the daemon dies mid-job, the job becomes `interrupted` and keeps its locks. After the node is quiet, the reconciler judges completion from evidence read over SSH (the marker, `systemctl` job list and `InvocationID`, or Docker state plus `.done`). Evidence is accepted only when two samples at least `SampleGap` apart agree; anything else holds the job for `sm jobs resolve`.
5. Reads (discovery, logs) never need setup, but a node without `node.setup` is read as `admin_user` and advertises no mutating capability.

Nodes are never given a SuperMgmt binary. What `node.setup` creates on them is listed in [providers.md](providers.md).

## Applications and deployments (M4)

Sources: SPEC §18-§21; [ADR-0006](adr/0006-pinned-compose-go-and-cli-equivalence.md), [0007](adr/0007-execution-snapshots.md), [0008](adr/0008-secret-versions.md), [0010](adr/0010-secret-env-file-encoding.md), [0011](adr/0011-provisional-deployment-api.md), [0028](adr/0028-github-connector.md), [0029](adr/0029-deployment-engine.md), [0030](adr/0030-node-setup-v2.md). Everything below ran against a **fake GitHub, a virtual Sigstore and a local registry**; see [compatibility.md](compatibility.md) and [manual-checks/m4-real-github.md](manual-checks/m4-real-github.md) for what was never run against the real services.

```text
GitHub (REST, OIDC, attestations, webhook)        providers/github        [M4, fake-verified]
   │ CI checks for a commit, contents at that commit, attestation per digest
   ▼
create deployment (provisional, ADR-0011) ─► waiting_ci ─► finalize
   │   server mode: webhook nudge + backstop poll at ci_poll_max; local mode: poll
   ▼
finalize: manifest + Compose read from the CI-passed commit (never branch head),
          closed-schema checks, target-bound freeze, every image bound to a digest,
          plan (App. C) with frozen rollback target, snapshots, policy ─► job
   ▼
preflight ► [snapshot] ► [pre-deploy backup] ► pull ► materialize ► verify ► compose up ► health
   │ health fails and rollback is declared safe
   ▼
rolling_back ─► rolled_back | rollback_failed          (restore steps only)
```

- **Two machines, one transaction.** `deployments.state` holds the fine §20.1 machine (`internal/deployments/state.go`, an exhaustive table); the job keeps the coarse state, and `TypePolicy.Mirror` writes both in the same transaction (ADR-0029). Tests: `TestDeploymentState_TransitionTable`.
- **Exact commit, exact digest.** Finalization reads the manifest and Compose from the commit CI passed; every image must be bound (`oidc_claims`, attestation or `pinned`) or the deployment fails `ARTIFACT_NOT_IMMUTABLE`. Tests: `TestFinalize_UsesCIPassedCommitNeverBranchHead`, `TestM4_DeployExactAttestedDigest`.
- **Closed Compose pipeline.** A raw closed-schema pass before the loader, then a model pass after it (ADR-0006); `compose-go` v2.15.0 and Docker Compose CLI v5.5.1 are the only pair supported. Tests: `TestCheckRaw_RejectsSourceForms`, `TestM4_RepositoryComposePrivilegedRejected`, `TestComposeEquivalence_Corpus`.
- **Secrets never reach the control plane's disk.** Env files are written on the node from stdin, byte-exact (`format: raw`), and the node compares the **resolved** environment hash only (ADR-0010; needs `jq` on the node). Tests: `TestM4_SecretNeverOnControlPlane`.
- **Rollback and recovery.** Health failure rolls back only when the rollback is declared safe and a known-good deployment exists; otherwise the deployment fails with `ROLLBACK_UNAVAILABLE` and its cause. An interrupted deployment is reconciled from node evidence (`.done` marker, flock, labelled containers, two samples); a proven partial deploy escalates to a durable, fenced safety-recovery claim that only restores (ADR-0029). Tests: `TestM4_HealthFailureRollsBackToKnownGood`, `TestReconcileDeploy_KilledCLIHeldDespiteStableSamples`, `TestClaimRecovery_*`.
- **Ownership and locks.** Compose projects, volumes and networks carry a `dev.supermgmt.owner` label; preflight refuses foreign projects and ports. A deployment holds exclusive locks on the target, the project and its host ports (the plan's and the frozen rollback target's). Tests: `TestPreflight_*`.
- **Nodes.** A deploy-capable node needs `node.setup` v2 (`deploy_root`, default `/srv/supermgmt`), Compose CLI 5.5.1 exactly, and `flock`, `jq`, `bash`, `timeout`, `ss`, `sha256sum`, `base64`, `df`; discovery reports `docker.compose.deploy` as unavailable with the first unmet requirement (`internal/discovery/capabilities.go`). Local-provider nodes are never deploy targets.

## Further reading

- [`security.md`](security.md): threat model and controls
- [`configuration.md`](configuration.md): configuration and environment overrides
- [`adr/`](adr/): architecture decision records
