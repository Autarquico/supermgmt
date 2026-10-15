# Architecture

This page explains how SuperMgmt is put together: one daemon that owns all state, clients that talk to it, and the path every change takes from a request to a job on a node. It describes what exists in the repository today. The package map for contributors is at the end, under [For contributors](#for-contributors).

## Process model

Exactly one process, the **daemon**, owns the database, job workers, refreshers and connectors. The TUI, the CLI and the MCP bridge are clients of its API; there is no in-process TUI backend. Local and remote use share one code path: in server mode the same API is served over HTTPS.

```text
Laptop
├── daemon (single owner of state)
│   ├── API: Unix socket 0600        (server mode: HTTPS + admin socket, remote MCP at /mcp)
│   ├── SQLite
│   ├── job workers, reconciler, refresher
│   └── connectors: SSH, local, Proxmox, GitHub
└── clients of the API: sm TUI, sm CLI, sm mcp (stdio bridge for MCP hosts)
        │ interactive SSH only: the terminal is handed to the system `ssh`, which
        └ the daemon authorizes and audits but does not proxy
```

MCP reaches the daemon in two ways, and neither bypasses the API:

- **Local:** `sm mcp` is a stdio bridge. An MCP host on your machine starts it; it authenticates to the Unix socket as a registered MCP client, never with your human credentials.
- **Remote:** in server mode, `sm server` can serve MCP over streamable HTTP at `/mcp`. Tool calls reach the API in process as the admitted client. See [mcp.md](mcp.md).

Two exceptions to "everything is an API client":

- **Offline commands** need no daemon: `sm version`, `sm completion`, `sm config validate` and `sm doctor --offline`. They take the database lock themselves and refuse while a daemon holds it. `sm doctor` without `--offline` asks a server over its admin socket; on a local installation it runs the offline checks and reports a running daemon instead of failing. Other offline commands: `sm install` (the installer runs outside the daemon), `sm secrets import-key --offline`, `sm secrets export-key --offline`, `sm secrets import --offline` and `sm backup restore --offline`.
- **The daemon's own entry point**, `sm daemon`. Any other command that needs the daemon starts it when none runs: a new session, output to `daemon.log` in the state directory, then up to 5 seconds of polling the socket.

Two independent `flock`s protect a running daemon: a database lock on `<canonical db path>.lock` and a socket lock on `<socket>.lock`, with the PID written in both. The socket directory must be a real directory owned by the daemon user with mode 0700, and the daemon refuses to start otherwise. Both ends check the peer's UID (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS) and close the connection on a mismatch or a lookup failure. Local mode trusts code running as the same OS user (see [security.md](security.md)).

**Residency.** The daemon exits after `daemon.idle_exit` only when no client holds the presence stream open, no request is in flight and no job is outside `succeeded`, `failed` and `cancelled`. A job waiting in `awaiting_approval` therefore keeps the daemon alive. `daemon.resident: true` disables the idle exit; `sm install local --resident` registers a user unit or launch agent that starts it at login.

## Domain graph

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

The database holds providers, nodes, runtimes, services, environments, identities, roles, plans, jobs, approvals, intents, locks, observations, events and secrets, plus repositories, applications, app targets and deployments. Embedded migrations `000001_initial` to `000006_m5` build the schema.

Configured state and observed state are kept apart. Configured resources carry one `spec_revision`, which increments only when desired state changes and is used for optimistic concurrency. Observations (reachability, metrics, versions) live in separate records and never bump it. Consequence: periodic discovery does not invalidate approvals.

## Policy, approval and job flow

```text
request (actor + credential context)
   │
   ▼
 plan ── canonical form, RFC 8785 hash over every input
   │
   ▼
 policy evaluation ──► deny / allow + approval_required + quorum
   │ allow
   ▼
 job submitted
   ├─ approval needed ─► awaiting_approval ◄─ approvals bound to plan hash
   │                         │ quorum reached
   ▼                         ▼
 queued ──► claim (one transaction)
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

- **Evaluation order:** catalog, capability, rule match, deny override, default deny, destructive gate, credential scopes, approval and quorum, then combine targets and sub-actions. Adding an allow never overrides a deny; adding a target never relaxes a decision.
- **Approval binds to the plan hash.** Changing any input yields a new hash; prior approvals do not transfer. Approvals expire and quorum counts distinct approvers.
- **The claim step re-checks everything the plan depended on**, so a changed `spec_revision` fails the job with `PLAN_STALE`.
- **Retry classes** (`idempotent`, `resumable`, `non_retryable`) come from the action catalog. Non-retryable remote mutations are observed, never repeated.
- **Locks are acquired at claim and held until the job is terminal**, including while it is `interrupted` or requeued, so a retrying job cannot lose its resources to a rival.
- **The reconciler acts only on a quiescent job and only on confirmed evidence:** the completion signal with exit status 0 plus a classification observed identically in two samples at least 30 seconds apart, collected until `deadline_at` + 5 minutes. Missing, contradictory or inconclusive evidence holds the job `interrupted`. Evidence is read from the node over SSH (systemd and Docker), from Proxmox tasks and from deployment markers.
- **One poison job cannot block the queue:** a claim error that is a per-job data fault fails only that job.
- **A human resolves a held job** with `job.resolve`, an action in the catalog, served by `POST /api/v1/jobs/{id}/resolve` and `sm jobs resolve`. It needs the plan hash and an outcome.

## Remote execution

How a service restart reaches a node:

1. The caller is the `human` identity `local:<uid>` on the socket. Every route maps to exactly one catalog action, and every POST, PATCH and DELETE carries an `Idempotency-Key`; a replay returns the stored response bytes.
2. A restart is a plan, then a job. In a `production` environment it waits in `awaiting_approval` until a plan-hash-bound approval arrives.
3. Before dispatch the worker captures the unit's pre-state, records the intent and commits `MarkDispatched`. The command is rendered from the closed template catalog and runs as `supermgmt` over the pooled SSH connection: `sudo -n <systemctl> <verb> <unit>` wrapped so a marker file exists before it starts and a `.done` file records its exit status.
4. If the daemon dies mid-job, the job becomes `interrupted` and keeps its locks. After the node is quiet, the reconciler judges completion from evidence read over SSH (the marker, `systemctl` job list and `InvocationID`, or Docker state plus `.done`). Evidence is accepted only when two samples at least `SampleGap` apart agree; anything else holds the job for `sm jobs resolve`.
5. Reads (discovery, logs) never need setup, but a node without `node.setup` is read as `admin_user` and advertises no mutating capability.

Nodes are never given a SuperMgmt binary. What `node.setup` creates on them is listed in [providers.md](providers.md).

## Applications and deployments

Everything below ran against a **fake GitHub, a virtual Sigstore and a local registry**. See [compatibility.md](compatibility.md) and the [real-GitHub manual checklist](manual-checks/m4-real-github.md) for what was never run against the real services.

```text
GitHub (REST, OIDC, attestations, webhook)        providers/github        [fake-verified]
   │ CI checks for a commit, contents at that commit, attestation per digest
   ▼
create deployment (provisional) ─► waiting_ci ─► finalize
   │   server mode: webhook nudge + backstop poll at ci_poll_max; local mode: poll
   ▼
finalize: manifest + Compose read from the CI-passed commit (never branch head),
          closed-schema checks, target-bound freeze, every image bound to a digest,
          plan with frozen rollback target, snapshots, policy ─► job
   ▼
preflight ► [snapshot] ► [pre-deploy backup] ► pull ► materialize ► verify ► compose up ► health
   │ health fails and rollback is declared safe
   ▼
rolling_back ─► rolled_back | rollback_failed          (restore steps only)
```

- **Two machines, one transaction.** `deployments.state` holds the fine-grained deployment state machine (`internal/deployments/state.go`, an exhaustive table); the job keeps the coarse state, and `TypePolicy.Mirror` writes both in the same transaction. Tests: `TestDeploymentState_TransitionTable`.
- **Exact commit, exact digest.** Finalization reads the manifest and Compose from the commit CI passed; every image must be bound (`oidc_claims`, attestation or `pinned`) or the deployment fails `ARTIFACT_NOT_IMMUTABLE`. Tests: `TestFinalize_UsesCIPassedCommitNeverBranchHead`, `TestM4_DeployExactAttestedDigest`.
- **Closed Compose pipeline.** A raw closed-schema pass before the loader, then a model pass after it; `compose-go` v2.15.0 and Docker Compose CLI v5.5.1 are the only pair supported. Tests: `TestCheckRaw_RejectsSourceForms`, `TestM4_RepositoryComposePrivilegedRejected`, `TestComposeEquivalence_Corpus`.
- **Secrets never reach the control plane's disk.** Env files are written on the node from stdin, byte-exact (`format: raw`), and the node compares the **resolved** environment hash only (needs `jq` on the node). Tests: `TestM4_SecretNeverOnControlPlane`.
- **Rollback and recovery.** Health failure rolls back only when the rollback is declared safe and a known-good deployment exists; otherwise the deployment fails with `ROLLBACK_UNAVAILABLE` and its cause. An interrupted deployment is reconciled from node evidence (`.done` marker, flock, labelled containers, two samples); a proven partial deploy escalates to a durable, fenced safety-recovery claim that only restores. Tests: `TestM4_HealthFailureRollsBackToKnownGood`, `TestReconcileDeploy_KilledCLIHeldDespiteStableSamples`, `TestClaimRecovery_*`.
- **Ownership and locks.** Compose projects, volumes and networks carry a `dev.supermgmt.owner` label; preflight refuses foreign projects and ports. A deployment holds exclusive locks on the target, the project and its host ports (the plan's and the frozen rollback target's). Tests: `TestPreflight_*`.
- **Nodes.** A deploy-capable node needs version 2 of `node.setup` (`deploy_root`, default `/srv/supermgmt`), Compose CLI 5.5.1 exactly, and `flock`, `jq`, `bash`, `timeout`, `ss`, `sha256sum`, `base64`, `df`; discovery reports `docker.compose.deploy` as unavailable with the first unmet requirement (`internal/discovery/capabilities.go`). Local-provider nodes are never deploy targets.

## For contributors

### Layers and package map

Dependencies point inward: adapters (CLI, API, TUI, MCP) call application services, which use the pure domain, policy and storage. No business logic lives in `cmd/`, HTTP handlers, TUI models or MCP handlers. The rules are enforced by `depguard` in [`.golangci.yml`](../.golangci.yml).

| Package | Role |
|---|---|
| `cmd/sm` | entry point, imports only `internal/cli` |
| `internal/cli` | the `sm` command tree, exit codes and output; talks to the daemon through `internal/client`; `sm mcp` is the stdio MCP bridge |
| `internal/domain`, `internal/domain/plan` | pure types, enums, clock, IDs, canonical plan and hash |
| `internal/errors` | typed errors and reason codes (`smerr`) |
| `internal/version` | build metadata |
| `internal/config`, `internal/config/gen` | typed schema, strict decoding, env overrides, validation, paths; `gen` writes the environment table in [configuration.md](configuration.md) |
| `internal/audit` | event creation, redaction, correlation IDs, structured logger |
| `internal/database`, `migrations` | SQLite, embedded migrations, lock, transaction-scoped repositories |
| `internal/policy` | action catalog, evaluation, governance, quorum, default policy |
| `internal/jobs` | claim, leases and fencing, intents, resource locks, retry classes, reconciler |
| `internal/app` | application services: plans, approvals, inventory, probes, services, `node.setup`, sessions, idempotent writes, refresher, the MCP floor |
| `internal/yamlstrict` | strict YAML decoding with path and line errors |
| `internal/api`, `internal/api/wire` | `/api/v1` on the Unix socket and the HTTPS listener; the JSON contract shared with the client |
| `internal/client` | typed client, daemon autostart, interactive-session command builder, credential storage |
| `internal/daemon` | process lifecycle: locks, socket, residency, assembly |
| `internal/tui` | Bubble Tea UI |
| `internal/transport`, `internal/transport/ssh`, `.../templates` | the `Executor` seam, the SSH pool and credentials, the closed catalog of remote commands |
| `internal/providers/ssh`, `internal/providers/local` | SSH node description and connection-user rule; the read-only local executor |
| `internal/runtimes`, `internal/runtimes/systemd`, `.../docker` | runtime adapter contract; systemd (logs, trust profile, setup, actions); Docker |
| `internal/discovery` | turns one probe into a typed snapshot and capabilities |
| `internal/secrets` | AES-256-GCM envelope, file KEKs, versioned store, instance SSH identity, key management |
| `internal/textsafe` | sanitizing of untrusted text |
| `internal/auth`, `internal/auth/oidc` | credentials, sessions, tokens, OIDC adapter, remote-MCP access-token validation; `oauthfake` is its test authorization server |
| `internal/netguard` | outbound request filter |
| `internal/join` | node enrollment (`sm join`) |
| `internal/providers/proxmox` | Proxmox VE API client, UPID parsing, task correlation; `pvefake` is its test fake |
| `internal/providers/github` | GitHub connector: REST client, origin-pinned redirects, CI checks, contents, Actions OIDC verification, Sigstore attestation verification, webhook HMAC; `ghfake` is its test fake |
| `internal/deployments`, `internal/deployments/compose`, `internal/deployments/manifest` | the deployment state table, step catalog and rollback rules; the closed Compose pipeline (raw and model schema passes, freeze, canonicalisation, env-file encoding, resolved-environment hash); the app manifest |
| `internal/health` | health-check validation (manifest versus control-plane origin rules) and node-side checks |
| `internal/mcp` | MCP server: transports, tools, resources, untrusted-output marking; an API client like the TUI |
| `internal/installer`, `internal/backup` | installer logic (local, server, Proxmox LXC appliance, upgrade and uninstall); backup and restore |

### Enforced boundaries

These are checked by `depguard` in [`.golangci.yml`](../.golangci.yml):

- `internal/domain` imports only the standard library, `uuid` and `internal/errors`.
- `internal/api/wire` imports only the standard library, `internal/domain` and `internal/errors`.
- `internal/policy` does not import `internal/database` or `internal/jobs`.
- `database/sql` and the SQLite driver stay in `internal/database`, `internal/jobs` and `migrations`.
- `internal/tui` and `internal/client` never import `app`, `jobs`, `database`, `daemon`, `transport`, `runtimes` or `providers`.
- `internal/api` reaches nodes only through `app`.
- `internal/cli` does not import `app`, `jobs` or `transport`.
- `cmd/` imports only `internal/cli`.
- Only `internal/mcp` and the stdio bridge in `internal/cli` import the MCP SDK, and `internal/mcp` imports only the standard library, the MCP SDK, `internal/api/wire`, `internal/domain`, `internal/errors`, `internal/audit` and `internal/textsafe`.
- `time.Now` and `fmt.Print*` are linted away from library code.

## Further reading

- [`security.md`](security.md): trust boundaries, threat model and controls
- [`configuration.md`](configuration.md): configuration and environment overrides
- [`mcp.md`](mcp.md): connecting AI agents over MCP
- [`adr/`](adr/): architecture decision records

## References

- Specification: [SUPERMGMT-SPEC.md](spec/SUPERMGMT-SPEC.md), sections 2.1.1 (process model), 5 (layers), 6 and 6.4 (domain, configured versus observed state), 11 and 11.3 (policy), 18 to 21 (applications and deployments; 20.1 state table, 20.4 and 20.5 jobs and locks), Appendix C (deployment plan).
- Process model and daemon: [ADR-0005](adr/0005-daemon-process-model.md), [ADR-0014](adr/0014-local-api-and-daemon-lifecycle.md).
- Jobs: [ADR-0013](adr/0013-generic-job-state-machine.md).
- Remote execution: [ADR-0009](adr/0009-node-provisioning.md), [ADR-0015](adr/0015-ssh-transport-and-command-templates.md).
- Deployments: [ADR-0006](adr/0006-pinned-compose-go-and-cli-equivalence.md), [ADR-0007](adr/0007-execution-snapshots.md), [ADR-0008](adr/0008-secret-versions.md), [ADR-0010](adr/0010-secret-env-file-encoding.md), [ADR-0011](adr/0011-provisional-deployment-api.md), [ADR-0028](adr/0028-github-connector.md), [ADR-0029](adr/0029-deployment-engine.md), [ADR-0030](adr/0030-node-setup-v2.md).
- MCP: [ADR-0031](adr/0031-mcp-server-sdk-transports-tools.md), [ADR-0032](adr/0032-mcp-clients-tokens-identity.md), [ADR-0033](adr/0033-remote-mcp-oauth-protected-resource.md).
