# Compatibility

What runs where, and how each statement was checked. The page has three parts: [platforms and operations](#supported-platforms), [Proxmox VE](#proxmox-ve) and [MCP](#mcp). For the state of the project as a whole, see [Project status](project-status.md).

## Supported platforms

A row gets exactly one status:

- **supported**: CI runs install, upgrade, backup plus restore and uninstall on that platform and architecture, and the row cites the test and the job for each. Nothing weaker earns the word.
- **container-verified**: run in a container on a CI runner. For a server platform that is the same four operations in a systemd container; the kernel and the init are the runner's, not those of a real machine of that distribution.
- **fake-verified**: the operations run against a simulator or a fake API.
- **manual**: only a human checklist row covers it (the [release checklist](release-checklist.md)).
- **not claimed**: nothing is promised.

`test/docs` (`make docs-check`, job `docs-check`) fails when a *supported* or *container-verified* row has an empty operation cell, when a cited test does not exist, when a cited job is not in `ci.yml`, or when that job's runners do not include the row's architecture (or its mode). The status says what the cited jobs check. This page was written before these jobs had run on GitHub. They have since passed in the CI run recorded on [Project status](project-status.md#the-ci-run-behind-these-claims); a person reviewing that first run is still an open release check. `release.yml` refuses to build a tag whose commit lacks a green run of each ([releasing.md](releasing.md#the-gates)).

## Platforms and operations

Each cell is `test` and `job`. Every operation of a mode runs inside one lifecycle test: N-1 install, a held upgrade to N, backup, restore, uninstall that keeps the data, then `--purge-data`.

| Platform | Arch | Mode | Status | Install | Upgrade | Backup and restore | Uninstall |
|---|---|---|---|---|---|---|---|
| Ubuntu 24.04 LTS | amd64 | server | supported | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` |
| Ubuntu 24.04 LTS | arm64 | server | supported | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` | `TestLifecycleVM_Server`, job `e2e-lifecycle-linux` |
| Ubuntu 24.04 LTS | amd64 | local-client | supported | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` |
| Ubuntu 24.04 LTS | arm64 | local-client | supported | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` | `TestLifecycleVM_LocalClient`, job `e2e-lifecycle-linux` |
| macOS 15 | arm64 | local-client | supported | `TestLifecycleMacOS_LocalClient`, job `e2e-lifecycle-macos` | `TestLifecycleMacOS_LocalClient`, job `e2e-lifecycle-macos` | `TestLifecycleMacOS_LocalClient`, job `e2e-lifecycle-macos` | `TestLifecycleMacOS_LocalClient`, job `e2e-lifecycle-macos` |
| Debian 13 | amd64 | server | container-verified | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` |
| Debian 13 | arm64 | server | container-verified | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` | `TestM6_LifecycleServerContainer`, job `e2e-lifecycle-container` |
| Debian 13 | amd64, arm64 | local-client | not claimed | - | - | - | - |
| macOS (Intel) | amd64 | local-client | manual | - | - | - | - |
| Proxmox VE 9.x host, `proxmox-lxc` appliance | amd64 | appliance | fake-verified | `TestM6_ApplianceLifecycleAcrossAReleaseBoundary`, job `e2e-appliance` | `TestM6_ApplianceLifecycleAcrossAReleaseBoundary`, job `e2e-appliance` | `TestM6_ApplianceLifecycleAcrossAReleaseBoundary`, job `e2e-appliance` | `TestM6_ApplianceLifecycleAcrossAReleaseBoundary`, job `e2e-appliance` |

How to read the rows:

- **Ubuntu 24.04 and macOS 15 rows** run on a fresh GitHub-hosted VM per leg (`ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15`). The host-mutating tests refuse any other machine. The server install goes through `install.sh` from a local signed mirror; the `local-client` legs install the resident daemon and, on macOS, also log a client in to a server.
- **Debian 13** runs in a systemd container on the Ubuntu runners of both architectures. Whether a real Debian 13 VM behaves the same is a human row of the release checklist.
- **Intel macOS** is compiled (job `cross-build`) and published, and has no lifecycle run. A person checks it by hand.
- **Proxmox appliance**: the host is a Docker container running `pvesim`, so every `pct`, `pveum` and `pvesh` call is answered by a simulator. See [Proxmox VE](#proxmox-ve) for what the simulator is built from. A real PVE 9.x host is still a manual row.
- **Upgrade source.** "Upgrade" is N-1 to N, where N-1 is the newest earlier build listed in `test/e2e/milestones_test.go` (today `v0.5.0`, a synthetic version built from its merge commit on `main`), plus one job from the oldest listed build to N: `TestM6_UpgradeChainOldestToLatestInOneJump` (job `e2e-chain`). Migration from the fixture of every listed build: job `migration-test`. The crash matrix over all 20 upgrade crash points: job `e2e-crash`. An upgrade from an authentic signed release has not been run, so it is a human row.
- **Not claimed anywhere**: 32-bit hosts, Windows, Alpine/musl, RHEL-family, Linux distributions other than Ubuntu 24.04 and Debian 13 for the server, Debian as a local-client host.

## Nodes and tools

| Node | Status | Evidence |
|---|---|---|
| Debian 13 (Docker fixture) | container-verified | job `integration-fixtures` runs `SM_FIXTURE_DISTRO=debian13` |
| Ubuntu 24.04 (Docker fixture) | container-verified | job `integration-fixtures` runs `SM_FIXTURE_DISTRO=ubuntu2404` |
| Any other distribution | not claimed | |

A fixture node is a container with a real `sshd` and Docker, not a machine.

## Proxmox VE

Every Proxmox row below was checked against a fake or a simulator, never against a real Proxmox VE host. Fixture origin: [test/fixtures/pve/PROVENANCE.md](../test/fixtures/pve/PROVENANCE.md).

### Supported versions

| Proxmox VE | Debian | Status |
|---|---|---|
| 9.x | 13 | Supported (amd64 only). |
| 8.x | 12 | Not supported. Upstream end of life 2026-08 (support table in the [Proxmox FAQ](https://pve.proxmox.com/wiki/FAQ)). |
| anything else | | Not supported; the installer exits 3. |

Tests: `TestVersionIsSupportedOnlyForPVE9` (`internal/providers/proxmox/client_test.go`), `TestPVE_VersionAndTemplatesAndNextID` (`internal/installer/pve_test.go`).

### Reading the table

- **Fake**: the behaviour is exercised by the test named in the row against a fake built from the PVE documentation (see PROVENANCE.md). The fake may differ from a real host.
- **Real host**: `not verified` for every row until the manual run (`docs/manual-checks/m3-real-pve.md`). No row is real-verified yet.

### HTTP API (provider, `internal/providers/proxmox`)

| Row | Used as | Test | Fake | Real host |
|---|---|---|---|---|
| `GET /version` | Version gate (major 9) | `TestVersionIsSupportedOnlyForPVE9` | verified | not verified |
| `GET /cluster/resources` | Nodes, guests, storages; limited to what the token may audit | `TestResourcesMapNodesGuestsAndStorages`, `TestResourcesOnlyContainWhatTheTokenMayAudit` | verified | not verified |
| `GET /access/permissions?path=` | Effective privileges of the exact path asked; a path the sparse list omits is neither guessed from a parent nor from an old pool | `TestPathPermissionsAreEffectivePrivilegesOfTheExactPath`, `TestPrivilegesHasIgnoresPropagation` | verified | not verified |
| Permission propagation and deeper-ACL replacement | A role on `/vms` replaces the one inherited from `/` (hence `VM.Audit` in `SMPower-<id>`) | `TestDeeperPathReplacesInheritedRole`, `TestNonPropagatingGrantStopsAtItsPath`, `TestNonPropagatingGrantIsKeptAsEffectiveOnItsOwnPath` | verified | not verified |
| Privilege separation | Token privileges are the intersection with its user's | `TestPrivilegeSeparationIsTheIntersectionOfUserAndToken` | verified | not verified |
| `GET /nodes/{node}/tasks` | Task list, newest first, paginated; read to the end | `TestTasksReadsEveryPageAndFiltersServerSide`, `TestCorrelationFindsATaskThatOnlyAppearsOnPageTwo`, `TestTaskListIsNewestFirstPaginatedAndFiltered` | verified | not verified |
| Task list `total` field | Top-level `total` as modelled by the fake | `TestTaskListIsNewestFirstPaginatedAndFiltered` | verified | not verified |
| `GET /nodes/{node}/tasks/{upid}/status` | Poll a task | `TestPowerTaskLifecycle`, `TestTaskRejectsMalformedAndForeignUPIDs` | verified | not verified |
| Running-task status shape | Running: `status: running`, no `exitstatus`; ended: `status: stopped` plus `exitstatus` | `TestPowerTaskLifecycle`, `TestAutomaticTasksEndAtOnce` | verified | not verified |
| `POST /nodes/{node}/{qemu,lxc}/{vmid}/status/{start,stop,shutdown,reboot}` | Power verbs; exactly one POST, never retried | `TestPowerOutcomes`, `TestPowerSendsExactlyOnePostWhenTheAnswerIsLost`, `TestPowerTimeoutIsUncertain`, `TestPowerStateMachine` | verified | not verified |
| `timeout` parameter | Sent as 240 s on `shutdown` and `reboot` only. Whether each verb and guest type accepts it is unconfirmed | `TestPowerOutcomes` | verified | not verified |
| Task type names | `qm` or `vz` prefix plus verb: `qmstart`, `qmstop`, `qmshutdown`, `qmreboot`, `vzstart`, `vzstop`, `vzshutdown`, `vzreboot` | `TestTaskType`, `TestParseUPID` | verified | not verified |
| UPID format | `UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:` | `TestParseUPID`, `TestParseUPIDRefusesAnythingElse` | verified | not verified |
| Error document and status codes | 400 bad parameter, 401 token, 403 privilege, 500 failed precondition, 501 unknown endpoint | `TestUnknownEndpointsParametersAndMethodsAreRejected`, `TestAuthentication`, `TestPrivilegesAreEnforcedPerPath` | verified | not verified |
| Guest migrated to another node | Reachable only on its new node | `TestMigratedGuestIsOnlyReachableOnItsNewNode` | verified | not verified |
| TLS trust | Pinned CA or fingerprint; no verify-off | `TestTLSTrust` | verified | not verified |

### Host CLI (installer, `internal/installer`)

Every tool runs by name through `env` with a fixed `PATH` and a clean environment, never through a shell: `TestPVE_RunsToolsByNameThroughAFixedPathWithACleanEnvironment`, `TestPVE_MissingToolsAreNamedBeforeAnythingRuns`, `TestPVE_ToolLookupFindsAnExecutableInAnyListedDirectory`, `TestPVE_ExecNeverUsesAShellAndSeparatesOptions`, `TestPVE_ArgvValidation`.

| Row | Used as | Test | Fake | Real host |
|---|---|---|---|---|
| `pveversion` | Version string `pve-manager/9.x.y/...` | `TestPVE_VersionAndTemplatesAndNextID` | verified | not verified |
| `pct create` options | `--hostname --cores --memory --swap --rootfs --net0 --unprivileged 1 --features nesting=1,keyctl=0 --onboot 1 --tags --description [--nameserver]` | `TestPVE_CreateArgvIsTheFrozenShape` | verified | not verified |
| `pct config` | Readback of `unprivileged`, `features`, `tags`, `description`, `lock`, mounts, raw `lxc.*` keys | `TestPVE_Parsers` | verified | not verified |
| `pct list` columns | `VMID Status [Lock] Name`; the lock column is blank when unlocked | `TestPVE_Parsers` | verified | not verified |
| `pct start`, `stop`, `destroy` | Container lifecycle | `TestPVE_RunsToolsByNameThroughAFixedPathWithACleanEnvironment` | verified | not verified |
| `pct exec <vmid> -- runuser -u <user> --` | Run as the service user inside the container; `runuser` assumed present in the Debian 13 template | `TestPVE_ExecNeverUsesAShellAndSeparatesOptions` | verified | not verified |
| `pct push --user --group --perms` | File transfer into the container; uid/gid mapping in an unprivileged container is unconfirmed | `TestPVE_ArgvValidation`, `TestProxmoxLXC_NoTokenBeforeBootstrapDirIsVerified` | verified | not verified |
| `/run` is tmpfs in the container | Token staged under `/run/supermgmt-bootstrap`; a stop clears it | `TestProxmoxLXC_NoTokenBeforeBootstrapDirIsVerified` | verified | not verified |
| `pveam list`, `available --section system`, `download` | Template discovery; newest `debian-13-standard_*_amd64.tar.zst` | `TestPVE_VersionAndTemplatesAndNextID`, `TestHighestTemplatePicksTheNewestDebian13` | verified | not verified |
| `pvesm status` JSON | Storages with `content` and `active` | `TestPVE_Parsers` | verified | not verified |
| `pvesh get /cluster/nextid --vmid N` | Free-VMID probe (non-zero exit means taken) | `TestPVE_VersionAndTemplatesAndNextID`, `TestPVE_NextIDStopsOnAToolFailure` | verified | not verified |
| `pvesh get /nodes/<node>/network --type any_bridge` JSON | Bridge discovery | `TestPVE_ArgvValidation` | verified | not verified |
| `pveum user`, `role`, `acl list` | Per-install identity (`sm-<id>@pve`, `SMAudit-<id>`, `SMPower-<id>`) | `TestParseACLNameRoundTrips`, `TestPVE_ArgvValidation` | verified | not verified |
| `pveum user token add ... --privsep 1 --output-format json` | Token secret read from JSON, never echoed | `TestPVE_AddTokenIsSensitiveAndNeverEchoesOutput` | verified | not verified |

### Deferred: assumed, not confirmed on a real host

Written into the fakes from documentation; a real PVE 9.x host may differ. Each is on the manual checklist.

1. Task list `total` field and pagination behaviour.
2. Shape of the status of a running task.
3. Which verbs and guest types accept the `timeout` parameter.
4. `/access/permissions` propagation and deeper-ACL replacement, as modelled in `pvefake`.
5. `pct list` column layout.
6. `pvesm status` and `pvesh` JSON field names.
7. `pct push` uid/gid mapping in an unprivileged container.
8. `runuser` available in the Debian 13 container template.

"Proxmox auto-LXC install works" stays unchecked in the [release checklist](release-checklist.md) until that run.

## MCP

How to set it up: [MCP](mcp.md).

**Tested MCP clients: none.** This page is where tested clients will be listed; today the honest list is empty. Every MCP interaction in CI is driven by the official Go SDK's own client (the same module the server uses, `github.com/modelcontextprotocol/go-sdk` v1.8.0) and by hand-written raw JSON-RPC messages. A real client may differ in transport details, protocol version negotiation, authorization discovery or tool-schema handling in ways the SDK's client does not reveal. Rows for Claude Code, Claude Desktop and MCP Inspector are in [manual-checks/m5-real-mcp-clients.md](manual-checks/m5-real-mcp-clients.md) and have not been run.

### Reading the table

- **verified** means a test in this repository exercises it. The test is named.
- **assumed** means written from the specification text or documentation and not exercised against the real counterpart.
- No row says "works with" a named product.

### Protocol and transports

| Item | Behavior | Evidence | Status |
|---|---|---|---|
| Protocol versions over streamable HTTP | `2026-07-28`, `2025-11-25`, `2025-06-18`; any other version is `400` | `TestHTTP_UnsupportedProtocolVersionIsRefused`, `TestWire_GoldensOverHTTP` | verified with raw messages and the SDK client |
| Protocol versions over stdio | those three in the raw goldens; the SDK negotiates its other versions | `TestWire_GoldensOverStdio`, `TestSDK_ProtocolVersionsAreTheOnesADR0031Records` | the three verified; older versions rely on the SDK and are not pinned by a SuperMgmt test |
| Streamable HTTP mode | stateless, JSON responses, no session id; `GET`/`DELETE` are `405` | `TestHTTP_StatelessServerRefusesGetAndDelete`, `TestHTTP_NoSessionIsIssued` | verified; **a real client that insists on a session or on SSE is not tested** |
| `Origin` | refused with `403` unless equal to the origin of `server.public_url`; absent is served | `TestHTTP_OriginMustMatchTheConfiguredOne`, `TestHTTP_RequestWithoutOriginIsServed` | verified |
| stdio bridge | `sm mcp` over stdin/stdout, JSON-RPC only on stdout | `TestBridge_ServesTheMCPToolsToAHost`, `TestE2E_MCPStdioReadsGraph` (SDK `CommandTransport`) | verified with the SDK client; real hosts not tested |
| Tools | Read tools plus `infra_plan_action`, and write tools when enabled, pinned by golden files; no resources, no prompts | `TestReadTools_ListGolden`, `TestNewServer_AllToolsGolden` | verified |
| Host configuration files | `examples/mcp/*.json` launch `sm mcp` with real flags and name the `<origin>/mcp` resource | `TestMCPExamples_StdioHostsLaunchSmMcpWithRealFlags`, `TestMCPExamples_RemoteNamesTheMCPResourceOfAnOrigin` | the files are checked for shape; **whether Claude Desktop or Claude Code accept them is not verified** |

### Remote authorization

| Item | Behavior | Evidence | Status |
|---|---|---|---|
| Protected Resource Metadata (RFC 9728) | served at `/.well-known/oauth-protected-resource/mcp` and at the root path | `TestRemote_MetadataBothPaths`, `TestHTTP_ProtectedResourceMetadataDocument` | verified; **the root path is a known deviation from RFC 9728 section 3.3** for strict clients |
| `401` challenge | `WWW-Authenticate: Bearer resource_metadata="<path-suffixed URL>", scope="..."` | `TestRemote_ChallengeCarriesThePathSuffixedMetadataURL` | verified |
| JWT access tokens (RFC 9068) | `typ` `at+jwt`, signature via JWKS, `iss`, `aud`, `exp`, `iat`, `client_id`, scopes; ID-token shapes refused | `TestOAuthJWT_ClaimAndHeaderRules` | verified against `oauthfake`, which signs with RS256 only (the other allowed algorithms are not exercised); **a real authorization server's tokens are assumed to follow RFC 9068** |
| Token introspection (RFC 7662) | authenticated POST, `active: true`, same claim rules, never cached | `TestOAuthIntrospect_ClaimAndResponseRules`, `TestOAuthIntrospect_NothingIsCachedAcrossRequests` | verified against `oauthfake`; real authorization servers not tested |
| Audience binding / RFC 8707 `resource` | `aud` must contain exactly `<origin>/mcp` | `TestOAuthJWT_ClaimAndHeaderRules` (audience rows) | the check on the token is verified; **whether a real authorization server puts the resource in `aud` when the client sends the `resource` parameter at authorization and at token exchange is not tested** |
| Authorization server fidelity | the fake serves JWKS (with rotation) and RFC 7662 introspection, written from the RFCs | `internal/auth/oauthfake/PROVENANCE.md`, `internal/auth/oauthfake/server_test.go` | assumed to match real servers; its provenance file says the RFC texts were not re-read when it was written |
| Client registration at the authorization server | not implemented; no dynamic client registration; an administrator registers each client's `(iss, sub, client_id)` in SuperMgmt | `TestAnUnregisteredOAuthSubjectIsRefusedOnMCP` | verified (refusal) |
| MCP authorization specification text | `2026-07-28` and `2025-06-18` read; `2025-11-25` served but its authorization text was not read | the design record for remote MCP (see [References](#references)) | recorded there |

### Deferred: assumed, not confirmed against real software

Each is a row of [manual-checks/m5-real-mcp-clients.md](manual-checks/m5-real-mcp-clients.md).

1. Claude Code launching `sm mcp` over stdio and listing and calling the tools.
2. Claude Desktop launching `sm mcp` over stdio from its configuration file.
3. MCP Inspector (or another real client) connecting to `/mcp`, following the `401` challenge to the metadata, completing an OAuth flow and calling a tool.
4. A real authorization server (Keycloak is the planned one) issuing `at+jwt` tokens or answering introspection, including the RFC 8707 `resource` parameter at authorization and at token exchange.
5. Real clients' behavior with a stateless server, with root-path discovery, and with tool descriptions that contain the untrusted-content notice.

"Read without shell" and "remote MCP as an OAuth protected resource" are done against the SDK client and a fake; they are **not** "verified with real clients" until those rows are run and dated.

## References

- Platform statuses and the host-mutating test guard: [ADR-0036](adr/0036-distribution-notices-platform-claims.md) (see its section on [host-mutating tests](adr/0036-distribution-notices-platform-claims.md#host-mutating-tests)); [specification](spec/SUPERMGMT-SPEC.md), section 35.
- Proxmox identities, privileges and compatibility: [ADR-0023](adr/0023-pve-identity-privileges-compatibility.md).
- Node setup: [ADR-0030](adr/0030-node-setup-v2.md).
- MCP: [ADR-0031](adr/0031-mcp-server-sdk-transports-tools.md) (server, SDK, transports and tools), [ADR-0033](adr/0033-remote-mcp-oauth-protected-resource.md) (remote MCP as an OAuth protected resource).
- What is verified across the project: [Project status](project-status.md).
