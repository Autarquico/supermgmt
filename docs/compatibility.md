# Proxmox VE compatibility

Source: [ADR-0023](adr/0023-pve-identity-privileges-compatibility.md). Fixture origin: [test/fixtures/pve/PROVENANCE.md](../test/fixtures/pve/PROVENANCE.md).

## Supported versions

| Proxmox VE | Debian | Status |
|---|---|---|
| 9.x | 13 | Supported (amd64 only). |
| 8.x | 12 | Not supported. Upstream end of life 2026-08 (support table in the [Proxmox FAQ](https://pve.proxmox.com/wiki/FAQ)). |
| anything else | | Not supported; the installer exits 3. |

Tests: `TestVersionIsSupportedOnlyForPVE9` (`internal/providers/proxmox/client_test.go`), `TestPVE_VersionAndTemplatesAndNextID` (`internal/installer/pve_test.go`).

## Reading the table

- **Fake**: the behaviour is exercised by the test named in the row against a fake built from the PVE documentation (see PROVENANCE.md). The fake may differ from a real host.
- **Real host**: `not verified` for every row until the manual run (`docs/manual-checks/m3-real-pve.md`). No row is real-verified yet.

## HTTP API (provider, `internal/providers/proxmox`)

| Row | Used as | Test | Fake | Real host |
|---|---|---|---|---|
| `GET /version` | Version gate (major 9) | `TestVersionIsSupportedOnlyForPVE9` | verified | not verified |
| `GET /cluster/resources` | Nodes, guests, storages; limited to what the token may audit | `TestResourcesMapNodesGuestsAndStorages`, `TestResourcesOnlyContainWhatTheTokenMayAudit` | verified | not verified |
| `GET /access/permissions` | Effective privileges per path; nearest listed ancestor decides | `TestPermissions`, `TestPermsHasUsesTheNearestListedAncestor` | verified | not verified |
| Permission propagation and deeper-ACL replacement | A role on `/vms` replaces the one inherited from `/` (hence `VM.Audit` in `SMPower-<id>`) | `TestADeeperListedPathReplacesWhatAParentGrants`, `TestDeeperPathReplacesInheritedRole`, `TestNonPropagatingGrantStopsAtItsPath` | verified | not verified |
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

## Host CLI (installer, `internal/installer`)

Every tool runs by absolute path with a clean environment, never through a shell: `TestPVE_RunsToolsByAbsolutePathWithACleanEnvironment`, `TestPVE_ExecNeverUsesAShellAndSeparatesOptions`, `TestPVE_ArgvValidation`.

| Row | Used as | Test | Fake | Real host |
|---|---|---|---|---|
| `pveversion` | Version string `pve-manager/9.x.y/...` | `TestPVE_VersionAndTemplatesAndNextID` | verified | not verified |
| `pct create` options | `--hostname --cores --memory --swap --rootfs --net0 --unprivileged 1 --features nesting=0,keyctl=0 --onboot 1 --tags --description [--nameserver]` | `TestPVE_CreateArgvIsTheFrozenShape` | verified | not verified |
| `pct config` | Readback of `unprivileged`, `features`, `tags`, `description`, `lock`, mounts, raw `lxc.*` keys | `TestPVE_Parsers` | verified | not verified |
| `pct list` columns | `VMID Status [Lock] Name`; the lock column is blank when unlocked | `TestPVE_Parsers` | verified | not verified |
| `pct start`, `stop`, `destroy` | Container lifecycle | `TestPVE_RunsToolsByAbsolutePathWithACleanEnvironment` | verified | not verified |
| `pct exec <vmid> -- runuser -u <user> --` | Run as the service user inside the container; `runuser` assumed present in the Debian 13 template | `TestPVE_ExecNeverUsesAShellAndSeparatesOptions` | verified | not verified |
| `pct push --user --group --perms` | File transfer into the container; uid/gid mapping in an unprivileged container is unconfirmed | `TestPVE_ArgvValidation`, `TestProxmoxLXC_NoTokenBeforeBootstrapDirIsVerified` | verified | not verified |
| `/run` is tmpfs in the container | Token staged under `/run/supermgmt-bootstrap`; a stop clears it | `TestProxmoxLXC_NoTokenBeforeBootstrapDirIsVerified` | verified | not verified |
| `pveam list`, `available --section system`, `download` | Template discovery; newest `debian-13-standard_*_amd64.tar.zst` | `TestPVE_VersionAndTemplatesAndNextID`, `TestHighestTemplatePicksTheNewestDebian13` | verified | not verified |
| `pvesm status` JSON | Storages with `content` and `active` | `TestPVE_Parsers` | verified | not verified |
| `pvesh get /cluster/nextid --vmid N` | Free-VMID probe (non-zero exit means taken) | `TestPVE_VersionAndTemplatesAndNextID`, `TestPVE_NextIDStopsOnAToolFailure` | verified | not verified |
| `pvesh get /nodes/<node>/network --type any_bridge` JSON | Bridge discovery | `TestPVE_ArgvValidation` | verified | not verified |
| `pveum user`, `role`, `acl list` | Per-install identity (`sm-<id>@pve`, `SMAudit-<id>`, `SMPower-<id>`) | `TestParseACLNameRoundTrips`, `TestPVE_ArgvValidation` | verified | not verified |
| `pveum user token add ... --privsep 1 --output-format json` | Token secret read from JSON, never echoed | `TestPVE_AddTokenIsSensitiveAndNeverEchoesOutput` | verified | not verified |

## Deferred: assumed, not confirmed on a real host

Written into the fakes from documentation; a real PVE 9.x host may differ. Each is on the manual checklist.

1. Task list `total` field and pagination behaviour.
2. Shape of the status of a running task.
3. Which verbs and guest types accept the `timeout` parameter.
4. `/access/permissions` propagation and deeper-ACL replacement, as modelled in `pvefake`.
5. `pct list` column layout.
6. `pvesm status` and `pvesh` JSON field names.
7. `pct push` uid/gid mapping in an unprivileged container.
8. `runuser` available in the Debian 13 container template.

"Proxmox auto-LXC install works" (spec Appendix E) stays unchecked until that run.
