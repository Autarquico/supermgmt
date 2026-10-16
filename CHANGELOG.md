# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a first release. No stable release yet; pre-releases may exist.

## [Unreleased]

Milestones M0 (repository and core), M1 (local daemon, SSH, TUI), M2 (server, auth, releases), M3 (Proxmox and the appliance installer), M4 (applications, GitHub and deployments), M5 (MCP) and M6 (hardening and the release gate). Pre-alpha: no stable release yet.

### Added: reach nodes through Cloudflare Tunnel (experimental)

- A node can have the transport `cloudflare`: `sm nodes setup <node> --tunnel` provisions a Cloudflare Tunnel, an Access application with a service-token policy and an owners policy, and a DNS record, installs `cloudflared` on the node from Cloudflare's package repository (key fingerprint pinned in the build), verifies the tunnel over a fresh connection with the pinned host key, and only then switches. `sm nodes tunnel disable <node>` returns the node to direct SSH and removes the node's tunnel, Access application and DNS record and the files setup installed; the instance's service token and Access policies stay, and a `cloudflared` that was already installed (for example from Cloudflare's guide) is never removed. It also abandons a tunnel setup that cannot finish. A node name must make a valid hostname `ssh-<node-name>.<zone>`; this is checked when the plan is created. `sm cloudflare rotate-access-token` rotates the instance's Access service token with overlap.
- New optional `cloudflare:` configuration block (`account_id`, `zone`, `api_token_ref`, `access_token_ref`, `owner_emails`, `access_identity_providers`). Without it nothing changes.
- The provisioning API token and the runtime service token are separate; dialling never reads the API token, which you can revoke in the Cloudflare dashboard after provisioning (the secret store has no delete); `sm doctor` then warns instead of failing once every tunnel is provisioned. `sm doctor` gains `cloudflare_*` checks, and says "not verifiable" for edit rights. An empty `access_identity_providers` allows exactly the account's One-time PIN login method, and setup fails with an actionable error if the account has none.
- `sm ssh` and the TUI's `s` on a tunnel node go through the operator's own Access login and `cloudflared` (the daemon refuses a `cloudflared` that others can write); the node runs `cloudflared` in a sandboxed unit with its own keyring path; `sm nodes list` and `sm nodes get` show the transport.
- Database migration `000007_cloudflare_tunnels` adds the operation records. Backups keep them and never plaintext credentials; a restored instance changes nothing in Cloudflare until `sm admin restore-complete`, then reports missing or recreated objects.
- Experimental: tested against a Cloudflare API fake and a fake `cloudflared` only. The real-account checklist (`docs/manual-checks/cloudflare-tunnel.md`) is open.
- Docs: `docs/cloudflare.md` rewritten (node tunnels first, the server guide as its own section), and updates to providers, security, configuration, troubleshooting, dependencies (egress to the Cloudflare API, Access and `pkg.cloudflare.com`), architecture and project status.

### Changed: a setup re-run keeps the node's choices

- `sm nodes setup` and the TUI palette keep the node's Docker access, logs mode and tunnel on a re-run unless a flag or word says otherwise (`--docker-access=false`, `--logs-mode`, palette `no-docker`, `journal`), as they already did for unit grants. Before, a bare re-run silently removed Docker access. A setup without the tunnel on a tunnelled node is refused.

### Added: unit grants at setup

- `sm nodes setup --unit <unit>[:start,stop,restart]` (repeatable) and `--no-units`, and `unit <unit>[:verbs]` / `no-units` in the TUI palette, grant systemctl on units. Before, neither sent any grant, so unit actions after setup were refused. A re-run without units keeps the node's grants; the plan shows the old and new lists.

### Fixed: found testing the first pre-release on two Macs

- `sm doctor` on a local installation runs the offline checks instead of asking for `--offline`, and reports a running local daemon instead of failing.
- Node connection errors name the network cause (`scan host key: connect: no route to host`, `lookup web1: no such host`), and the daemon logs them with the correlation ID.
- An empty ssh-agent is reported as such, `sm nodes add` warns when the agent cannot sign in, and an authentication failure says the node does not accept the offered keys.
- macOS nodes: CPU usage (from `top`) and memory in use (from `vm_stat`) are measured; memory showed 100% and CPU 0%.
- Setup refuses a node that is not Linux before changing anything, and the TUI offers it only on SSH nodes that are not macOS.
- Troubleshooting covers macOS's Local Network permission, which can block `sm` from the LAN while `ssh` works.

### Added: website and documentation

- A static website in `site/` (Astro and Starlight) with a landing page and the documentation, built from `docs/*.md` at build time; `docs/public-pages.txt` lists the public pages. Fonts are self-hosted, and the site source references no third-party script, font or analytics service. The `pages` workflow publishes it to GitHub Pages from release tags only; it is not published yet. The `site` CI job builds and checks it on every change.
- New pages: overview, getting started (build from source, a local node, an SSH node, setup and approval), concepts, project status (the canonical list of what is verified, claim by claim), using the TUI, policies and approvals, and a CLI reference generated from the command tree (`docs/cli.md`, drift-checked by `make generate`).
- A shorter README that points to the status page and the getting-started path, and a roadmap organised by area.

### Fixed: documentation

- The README and the roadmap said the Providers and Settings screens of the TUI were not built. They exist, read-only, since the server-mode work (`TestProvidersScreenListsProvidersReadOnly`, `TestSettingsScreenShowsModeProfileServerAndIdentity`).

### Added in M6

- Fuzzing: a fuzz target for every parser of untrusted input, 55 targets mapped in `scripts/fuzz-inventory.txt` (`sh scripts/fuzz.sh count`). `test/fuzzinv` finds parser candidates from the syntax tree and fails on an unmapped one; `scripts/fuzz.sh reach` proves the seeds execute each mapped function. Seeds run in every `go test`; mutation runs in the new `nightly.yml` (6 shards, 5 minutes per target). 25 known parsers are exempt as `gap` rows with no target.
- A stress suite (`test/stress`, build tag `stress`, `make race-stress`) for job claim and lease, the SSE broker, the SSH pool, Proxmox sync, lock exclusion and MCP token issuance; `-race` unit tests now run on Ubuntu and macOS.
- Scans and gates in CI: gitleaks over the full history (`secret-scan`), a licence allowlist over the compiled modules (`licenses`), `fuzz-inventory`, `reproducible` (the real GoReleaser configuration built twice from clean roots), `migration-test`, `docs-check`.
- Release gates (ADR-0034): `release.yml` runs a `gates` job that requires every check named in `packaging/release/required-checks.txt`, and a `nightly` run, to have succeeded on the exact tag commit before anything is built; `sign-publish` checks the notices and SBOM against each compiled binary and verifies the provenance statement before publishing. Every archive ships `THIRD_PARTY_LICENSES`.
- Homebrew: formula template and a renderer from the signed `checksums.txt` (`packaging/homebrew/`, `make brew-formula`). Linux packages are not shipped.
- Upgrade (ADR-0035): the service is held before `Stop` (a systemd drop-in with `RefuseManualStart`, or `launchctl disable`) and released only when the new service starts; a resumed upgrade retakes the pre-upgrade backup before the swap; `SUPERMGMT_CRASH_AT=<point>` (builds with the `crashpoints` tag only) kills the installer at any of the 20 upgrade crash points; `--allow-downgrade` writes a pending audit record in `<DataDir>/audit-pending/` that the daemon imports as `instance.downgrade_authorized` on its next start; the daemon records `instance.version_changed` when its version changes.
- `sm doctor --offline --json` carries `format_version`, `database_schema_version` and `binary_schema_version`; the upgrader reads them and keeps the text parser only for binaries that predate them. `sm doctor` has a `tls` check (warns 30 days before expiry, fails when expired) and warns when the Proxmox clock differs from the appliance's by more than 60 seconds.
- Tests: migration fixtures written by real binaries built from the M1 to M5 merge commits, restored and migrated with provenance enforced in CI; install, upgrade, backup and restore, and uninstall in a Debian 13 systemd container, and on disposable Ubuntu 24.04 and macOS 15 runners behind a host-mutation guard; the appliance across a release boundary; a real-process crash at each upgrade point; an upgrade from the M2 build to the current tree; an Ubuntu 24.04 node fixture.
- Docs: platform and operation matrix, troubleshooting, releasing, dependencies and egress inventory, the [release checklist](docs/release-checklist.md) and [m6-release.md](docs/manual-checks/m6-release.md), contribution rules for fuzzing, stress and flaky tests. ADRs 0034 to 0036; ADRs 0006 to 0008, 0010 to 0012 and 0017 to 0033 accepted; master specification 1.4.8.

### Changed in M6

- Appliance-installer journals live in a root-only directory, `/var/lib/supermgmt-installer/journals/<id>`; journals left in `/var/tmp` by earlier builds are still recovered.
- The Proxmox token created by the installer carries the comment `supermgmt install <id>`, and rollback revokes a token of that name only if it carries it.
- `sm providers check` reads the effective privileges of `/` and requires `Sys.Audit` there; the whole-tree permissions call was removed.
- The installer reaches the host through typed ports (`Lock`, `Canonical`, `FreeBytes`, `ListDir`, `Lstat`, bridge address) instead of optional-interface assertions, and a path that cannot be canonicalised is now an error.
- The TUI header and dashboard count nodes and guests separately, and start, stop and probe keys are refused on guests. A handoff command that cannot start no longer wedges the terminal.

### Known limits in M6

- No stable release yet. The production release key is embedded in the installer; the Homebrew tap, the licence decision and the name checks are human steps that have not been done.
- Proxmox, GitHub and MCP remain verified against fakes only. The new Proxmox assumptions (the token comment field, the task-list filters, clock skew) are rows of [m3-real-pve.md](docs/manual-checks/m3-real-pve.md).
- The new lifecycle, crash and chain jobs, including the arm64 and macOS legs, first passed on GitHub on `main` at `6f89609` (2026-10-14). The nightly workflow has not run, and no run of the release workflow on a real tag has been checked by a person yet.
- Unresolved flake: the daemon-restart test (`TestM1_DaemonKilledMidRestartReconciles`) has a second failure mode that was seen once and not explained. A downgrade to a build older than M6 leaves its audit record pending until an M6 or newer binary starts. See the [release checklist](docs/release-checklist.md#unresolved-items-and-stated-limitations) for the full list.

### Added in M5

- MCP server (`internal/mcp`, ADR-0031) on the official Go SDK v1.8.0: `sm mcp` over stdio and `/mcp` over stateless streamable HTTP (server mode, protocol versions 2026-07-28, 2025-11-25, 2025-06-18; `Origin` checked). Tools: `infra_list_nodes`, `infra_get_node`, `infra_list_services`, `infra_get_service`, `infra_get_service_logs`, `infra_list_apps`, `infra_list_deployments`, `infra_get_deployment`, `infra_list_events`, `infra_get_health`, `infra_plan_action`; with `mcp.write_tools_enabled: true` also `infra_submit_plan`, `infra_restart_service`, `infra_reboot_node`, `infra_create_deployment`, `infra_rollback_deployment`. Every tool is one or more API calls, so policy, audit and rate limits are the API's.
- MCP clients (ADR-0032, migration `000006`): `sm mcp clients add|list|remove`, approval-gated registration, one token (`smm_`, mandatory expiry, default 90 days) issued once to a 0600 file or the OS keychain after a preflight, never printed; routes `GET|POST /api/v1/mcp/clients`, `POST /api/v1/mcp/clients/{id}/token`, `DELETE /api/v1/mcp/clients/{id}`. The local socket admits `smm_` tokens as the MCP caller. Restore revokes MCP credentials.
- Remote MCP as an OAuth 2.0 protected resource (ADR-0033, RFC 9728, RFC 9068, RFC 7662): metadata at `/.well-known/oauth-protected-resource/mcp` (and the root path), `WWW-Authenticate` challenges, JWT (`at+jwt`) or authenticated introspection, `resource` equal to `<public_url>/mcp`, per-address and per-identity rate limits. SuperMgmt issues no OAuth tokens. New keys `mcp.oauth.introspection_client_id` and `introspection_client_secret_ref`.
- Safety floors: an MCP identity can never approve, reject or resolve, nor perform credential-mode actions, client registration or deletion, or identity and role changes (`MCP_ACTION_FORBIDDEN`); with writes off every non-query action is denied (`MCP_WRITES_DISABLED`), including deployment admission before any row is stored. Tool output separates remote-discovered data under an `untrusted_remote_output` object, sanitized, scrubbed (`audit.ScrubCredentials`) and bounded.
- Test infrastructure: `oauthfake` (JWKS and introspection fake with `PROVENANCE.md`), raw JSON-RPC goldens, the per-route writes-gate matrix, MCP security and secret-scrub suites, `make e2e-mcp` and CI job `e2e-mcp`. Examples in `examples/mcp/`.

### Changed in M5

- `mcp.oauth.resource` must equal `<server.public_url>/mcp`; `remote_enabled` requires server mode; `mcp.allow_interactive_exec: true` is refused.

### Known limits in M5

- **No real MCP client and no real OAuth authorization server was used.** Verification is the Go SDK client, raw JSON-RPC goldens and a fake authorization server. The real-client run (`docs/manual-checks/m5-real-mcp-clients.md`) is deferred; RFC 8707 `resource` handling at a real authorization server is unverified.
- Output redaction is pattern-based; unknown secrets in remote text are not detected. The default policy gives MCP no `service.logs`. Root metadata discovery is a known RFC 9728 deviation. No MCP resources, prompts or interactive exec.

### Added in M4

- GitHub connector (`internal/providers/github`, ADR-0028): read-only fine-grained token, required CI checks for a commit, file contents at one commit, repositories, origin-pinned redirects (at most 3 hops, the token never leaves the `api_url` origin), webhook HMAC verification, GitHub Actions OIDC verification with replay protection, Sigstore attestation verification (sigstore-go v1.3.0, TUF-refreshed trusted roots through the outbound filter, fail closed when stale). Provider type `github` in the configuration and `POST /api/v1/providers` for it.
- Applications and targets: repositories, apps, app targets (one per application and environment), automation identity for Actions OIDC created with no role, execution snapshots (ADR-0007), secret versions (ADR-0008); migration `000005_m4`. CLI `sm apps list|get|create`, `sm apps target add`.
- Manifest and closed Compose pipeline (ADR-0006): raw and model schema passes, target-bound freeze, compose-go v2.15.0 equivalence with Compose CLI 5.5.1, byte-exact secret env files with a node-side resolved-environment hash check (ADR-0010; needs `jq`).
- Deployments (ADR-0011, ADR-0029): provisional create, wait for CI (webhook plus backstop poll in server mode, polling in local mode), finalization from the CI-passed commit, digest binding (`oidc_claims`, attestation, `pinned`), preflight (ownership of project, volumes and networks, ports, disk space), pre-deploy backup (`postgres-dump`), staging, `compose up` under `flock`, health verification, automatic rollback to the last known-good deployment when declared safe, manual `sm rollback`, durable safety recovery of interrupted deployments. CLI `sm deploy`, `sm rollback`, `sm deployments list|get|cancel`. Route `POST /api/v1/github/webhook` (`exempt:webhook`).
- `node.setup` v2 (ADR-0030): `deploy_root` (default `/srv/supermgmt`) and the capability `docker.compose.deploy`, gated on Compose CLI 5.5.1, `flock`, `jq`, `bash`, `timeout`, `ss`, `sha256sum`, `base64` and `df`.
- TUI: Applications, Deployments, deployment timeline, creation wizard with plan review, palette `deploy` and `rollback`.
- Test infrastructure: `ghfake` (GitHub REST fake with `test/fixtures/github/PROVENANCE.md`), `ghsim` (fake GitHub, virtual Sigstore, webhook sender), a local TLS registry, `make e2e-deploy`, `make compose-equivalence`, the example workflow `examples/github-actions.yml` checked against SPEC §28.
- Documentation: `docs/architecture.md`, `docs/compatibility.md` (deployments matrix), `docs/providers.md` (GitHub), and the deferred real-GitHub checklist `docs/manual-checks/m4-real-github.md`.

### Changed in M4

- `node.setup` accepts `deploy_root`; nodes set up before M4 must re-run setup to become deploy targets.
- `jq` is a required node tool for deployments.
- The outbound request filter also serves control-plane health URLs and the GitHub `api_url`.

### Known limits in M4

- **No real GitHub was used.** GitHub REST, GHCR, attestations, Actions OIDC, the GitHub TUF anchor and redirect behaviour are verified against fakes only; the real-GitHub run (`docs/manual-checks/m4-real-github.md`) is deferred.
- Docker Compose CLI 5.5.1 is the only supported version. One target per application and environment. `compose_source: repository` is refused for production. No `environment` claim can be required. Only `postgres-dump` backups; `deployment_policy.snapshot: true` is refused. See [ROADMAP.md](ROADMAP.md) for the full list.

### Added in M3

- Proxmox VE provider (`internal/providers/proxmox`): HTTPS API client with a pinned CA (`ca_file`; `verify_tls: false` is a configuration error), UPID parsing, task listing and correlation. Supported: Proxmox VE 9.x, amd64 (ADR-0023).
- Discovery (ADR-0024): cluster nodes, VMs and containers as discovered nodes with configured CPU/RAM/disk and metrics, storages as provider observations, `absent` versus `inaccessible` from the token's effective permissions, capability `proxmox.vm.power` per guest. `POST /api/v1/providers/{id}/refresh` (`provider.read`, rate limited), `sm providers list|get|refresh|check`, `sm nodes list --tree`, doctor `providers` check, TUI tree and `refresh proxmox`.
- Power actions (ADR-0025): `sm nodes power <node> start|shutdown|reboot|stop [--wait]` and the TUI palette. Non-retryable jobs; exactly one POST per request; task id persisted before polling; interrupted jobs are settled by task correlation across the cluster, and a task-tracked job is quiescent only on stored proof that its task stopped (`job.resolve --assume-quiescent` is the audited override). `stop` is high risk. Migration `000004` (`operation_intents.external_ref`).
- Per-install Proxmox identities: user `sm-<id>@pve`, token with privilege separation, roles `SMAudit-<id>` and `SMPower-<id>` (`SUPERMGMT_PVE_POWER=0` omits the latter).
- `sm install proxmox-lxc` (ADR-0026): unprivileged LXC, self-signed appliance TLS (`sm install server --tls self-signed --no-start`, `sm server init`), the Proxmox chain verified from inside the container before any token exists, token transfer through tmpfs and `sm secrets import --offline --from-file --delete-source`, write-ahead journal with commit protocol and crash recovery, variables `SUPERMGMT_VMID|HOSTNAME|STORAGE|TEMPLATE_STORAGE|BRIDGE|NETWORK|IP|GATEWAY|DNS|CORES|MEMORY|SWAP|DISK_GIB|PVE_POWER|PVE_ENDPOINT|PVE_CA_FILE`. Installer mode `auto`.
- `sm install upgrade` and `sm install uninstall` (ADR-0027): stop-verified read-only offline backup (`sm backup create --offline`), phase state, `sm.prev`, revert only when the schema did not move, `--allow-downgrade`; uninstall keeps data unless `--purge-data` plus a separate confirmation; on a Proxmox host both act on the appliance after record and tag proof (`--vmid`), and a purge removes that install's Proxmox identities only.
- Test infrastructure: `pvefake`, the `pvesim` command shims, `make e2e-appliance` and `make e2e-upgrade`, compatibility matrix `docs/compatibility.md`.
- Documentation: Proxmox, upgrade, uninstall and `auto` in `docs/installation.md`, `docs/providers.md`, `docs/operations.md`, `docs/security.md`, and the deferred real-host checklist `docs/manual-checks/m3-real-pve.md`.

### Changed in M3

- Installer modes `auto`, `proxmox-lxc`, `upgrade` and `uninstall` no longer exit 3; exit codes 6 to 9 gained the meanings in `docs/installation.md#exit-codes`.
- A Proxmox provider in the configuration file is no longer ignored. A guest renamed in Proxmox bumps its `spec_revision`, so pending plans for it go stale.

### Known limits in M3

- **No real Proxmox VE host was used.** Everything Proxmox is verified against fakes built from the documentation; the real-host run (`docs/manual-checks/m3-real-pve.md`) is deferred and "Proxmox auto-LXC install works" stays unchecked.
- Proxmox VE 8.x (upstream end of life 2026-08) and arm64 hosts are unsupported.
- Not built: snapshot, backup and console handlers and task-history listings, `POST /api/v1/providers`, promoting discovered guests to managed.
- The appliance certificate is self-signed and not renewed; it names the container address at install time. `--allow-downgrade` is not yet an audit event.

### Added in M2

- Server mode (`sm server`): the API over HTTPS, either terminated by the daemon (`server.tls.mode: direct`, certificate re-read on `SIGHUP`) or behind a reverse proxy (`proxy`, forwarding headers believed only from `server.trusted_proxies`). No ACME (ADR-0017).
- Bearer credentials: sessions, API tokens with expiry and narrowing scopes, bootstrap codes and join tokens, stored as SHA-256 only. Admin socket (`sm admin bootstrap-code|grant|restore-complete`, read-only `sm doctor`), rate limits, response headers, event stream (`GET /events/stream`). Migration `000003`.
- OIDC login: Authorization Code with PKCE (loopback, `--callback-port`) and the device grant, discovery-trust rules and the new key `auth.oidc.allowed_endpoint_origins` (ADR-0018, spec 1.4.3). Exercised against Dex only.
- Client profiles, `sm login|logout`, `sm profile`, `sm tokens`, remote TUI over SSE, and a credential store (macOS keychain, `secret-tool`, 0600 file fallback).
- Secrets: `sm secrets import|keys|rotate-master-key|retire-key|export-key|import-key`, `sm ssh-key rotate`, `sm nodes repin`. Key operations are approval-gated `secret.write` jobs (spec 1.4.4); key export is local-socket only or `--offline` on a server (ADR-0021).
- Outbound request filter `internal/netguard` (SPEC §21.1), used for identity-provider endpoints.
- Backup and restore: `sm backup create|list`, scheduled backups (`backup.schedule`, `backup.retention`), offline `sm backup restore --offline` with a crash-safe journal and restore hold, `sm admin restore-complete` (ADR-0020).
- Join: `sm enrollments create`, `sm join`, `scripts/join.sh` (ADR-0022).
- Release pipeline: GoReleaser archives, OpenSSH signatures, SPDX SBOMs, provenance on tag builds, signed channel pointers, and `install.sh` with `sm install local|server|client|restore` (ADR-0019). The production key is a placeholder, so real installs fail closed.
- OpenAPI description with a drift check (`make api-check`), ADR-0012 route metadata, and `make snapshot`, `make release-check`, `make install-test`.
- Documentation: `docs/installation.md`, `docs/operations.md`, `docs/cloudflare.md` (guide only), updates to `docs/configuration.md` and `docs/security.md`, and the manual checklist `docs/manual-checks/m2-handoff.md`.

### Known limits in M2

- Nothing is signed with a production key; production signing and provenance are unverified. The "clean Debian VM" acceptance is amended to a systemd container and a VM run is deferred.
- `install.sh` requires OpenSSH 8.2 or newer (the spec says 8.1) and its default mode `auto`, like `upgrade`, `uninstall` and `proxmox-lxc`, exits 3 until M3.
- Dex puts the OIDC client secret in the device-flow verification URL; there is no separate device client key. Only Dex has been exercised.
- Backup archives are not encrypted. A lost master key without an export is unrecoverable.
- Cloudflare is a guide, not tested against a real account. The real macOS keychain and `secret-tool` are manual checks.
- Not built: SSH CA trust, per-node keys.

### Added in M1

- Local daemon (`sm daemon`) that owns the database, serving `/api/v1` on a Unix socket with peer-credential checks in both directions, a typed client with autostart, API idempotency keys, and idle exit that waits for clients and unfinished jobs (ADR-0014).
- Agentless SSH nodes: pinned host key confirmed by fingerprint, pooled connections with bounded dials and sessions, and a closed catalog of remote commands with allowlisted, quoted arguments (ADR-0015).
- `node.setup`: an approval-gated job that creates the dedicated `supermgmt` user with a restricted `authorized_keys`, scoped sudoers lines, optional `docker` group and optional log broker, then verifies as that user (ADR-0009). Bootstrap as `root` or with `sudo -n`.
- systemd and Docker discovery, bounded and sanitized logs, the unit trust profile, and start/stop/restart as policy-gated jobs with completion evidence for crash recovery (production waits for approval).
- Instance SSH identity (Ed25519) stored in an AES-256-GCM envelope with file-based KEKs in `security.keys_dir` (ADR-0016). Migration `000002_m1`.
- TUI (Dashboard, Resources, Node, Services, Logs, Jobs, Approvals, Events, Help; command palette) and CLI (`nodes`, `services`, `jobs`, `approvals`, `events`, `status`, `ssh`, `docker`, `ssh-key`, `daemon`, `tui`).
- Interactive SSH handoff (`s`, `d`, `sm ssh`, `sm docker`) through the system OpenSSH client, isolated from user configuration, with the session audited. SuperMgmt never installs `lazydocker`.
- Local provider (this machine, read-only).
- Documentation: `docs/providers.md`, trust boundaries in `docs/security.md`, and the manual terminal checklist `docs/manual-checks/m1-handoff.md`.

### Known limits in M1

- Not built: SSE, SSH CA trust, the secrets CLI and `secret.write`, identity rotation, per-node keys, key export (M2); Applications, Deployments and Wizard screens (M4); the metrics endpoint; automated node teardown (manual steps in `docs/security.md`).
- `sm doctor` without `--offline` is not implemented.
- `ssh.known_hosts_file`, `ssh.host_key_policy` and `ssh.logs_mode` are validated but not read.
- Refusal of another local user on the socket is tested on Linux CI only. Terminal restoration after a handoff is covered by a PTY test plus a manual checklist that has not been run yet.
- Node setup is verified on a Debian fixture only.

### Added in M0

- Go module `github.com/autarquico/supermgmt` and the `sm` command skeleton with `sm version` and `sm completion`.
- Domain model with stable UUIDv7 identifiers, configured-versus-observed state and `spec_revision`, and a typed error model.
- Strict configuration loader: unknown fields fail, `SUPERMGMT_*` environment overrides, validation that reports every problem with its YAML path, and a generated environment table in `docs/configuration.md`.
- Audit events, secret redaction and correlation IDs for structured logging. Values under sensitive keys are always masked; a `secret://`, `ssh-agent://` or `file://` reference stays visible only in a field whose name ends in `_ref` and whose value matches the reference grammar.
- SQLite storage (pure Go driver, WAL), embedded migrations, database lock, and append-only protection of audit events.
- Canonical action plan with RFC 8785 hashing.
- Action catalog and policy engine: default deny, deny override, destructive gate, credential scopes, approval rules and quorum.
- Architecture decision records ADR-0001 to ADR-0005 and ADR-0013.
- Continuous integration (format, vet, lint, tests on Linux and macOS, race detector, module tidy, generate drift, cross-build, govulncheck), CodeQL, dependency review and Dependabot.
- Application services (`internal/app`): plan creation and submission, approvals and rejections with quorum, claim-time revalidation of plan inputs, credentials and policy, and lock planning. Denied and capability-unavailable decisions are written to the audit trail.
- Durable job engine (`internal/jobs`): claim with revalidation, lease generations and fencing, intents, shared and exclusive resource locks held until the job is terminal, retry classes, and a reconciler that acts only on completion evidence and otherwise holds the job `interrupted`. Only fake evidence adapters exist; real ones arrive with their milestones.
- Shared strict YAML decoder (`internal/yamlstrict`): errors carry the YAML path and line; duplicate keys, aliases, anchors and merge keys are rejected.
- `sm config validate` (with `--policy` and `--json`) and `sm doctor --offline`.
- Integration tests (`test/integration`) and a test that validates every YAML example in the spec and in `examples/` (`test/specexamples`).
- Public documents: README, CONTRIBUTING, SECURITY, GOVERNANCE, ROADMAP, CODE_OF_CONDUCT, `docs/architecture.md`, `docs/security.md`, `docs/configuration.md`.

[Unreleased]: https://github.com/autarquico/supermgmt/commits/main
