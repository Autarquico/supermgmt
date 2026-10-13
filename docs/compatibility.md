# Compatibility

This page has two matrices: [Proxmox VE](#proxmox-ve-m3) (M3) and [Deployments: Docker Compose, node tools and GitHub](#deployments-m4) (M4).

# Proxmox VE (M3)

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

# Deployments (M4)

Sources: [ADR-0006](adr/0006-pinned-compose-go-and-cli-equivalence.md), [ADR-0010](adr/0010-secret-env-file-encoding.md), [ADR-0028](adr/0028-github-connector.md), [ADR-0030](adr/0030-node-setup-v2.md). Fixture origin of the GitHub fake: [test/fixtures/github/PROVENANCE.md](../test/fixtures/github/PROVENANCE.md).

## Reading the table

- **Verified**: exercised by the test named in the row against the thing named in the column. `Fixture` means a real Docker daemon, a real sshd and the pinned Compose CLI inside the node fixture (`test/fixtures/node`, build tag `fixtures`); these tests were not run for this page.
- **GitHub fake**: the behaviour is exercised against `ghfake` (hand-written from the GitHub documentation, never recorded from the live API), a virtual Sigstore and a local registry. The fake may differ from github.com. **Real GitHub is `not verified` for every GitHub row** until the manual run ([manual-checks/m4-real-github.md](manual-checks/m4-real-github.md)). GitHub Enterprise Server is not verified either.

## Docker Compose and node tools

| Row | Used as | Test | Verified |
|---|---|---|---|
| Docker Compose CLI **5.5.1**, exact | The only supported node CLI. `docker compose version --short` must print exactly `5.5.1`; a `v` prefix or any other release makes `docker.compose.deploy` unavailable. New CLI versions need a new row | `TestComposeSupportedPinsTheShortVersionFormat`, `TestComposeDeployCapability`, `TestPreflight_ComposeDeployCapabilityMissing` | unit; the fixture image installs v5.5.1 (`test/fixtures/node/Dockerfile`) |
| compose-go **v2.15.0** | The control-plane loader; same code base as the CLI (`go.mod`) | `TestComposeEquivalence_Corpus` | Fixture, CLI 5.5.1, six corpus files (`internal/deployments/compose/testdata/equivalence`) |
| Loader versus CLI `config` output | The model the control plane freezes equals what the node's CLI resolves, within the table in `normalize.go`. `config` drops `env_file`, and omits top-level networks and volumes no service references | `TestComposeEquivalence_Corpus`, `TestFrozen_EmptyEnvInterpolationIsIdentity` | Fixture (CLI 5.5.1) / unit |
| Other Compose CLI versions | Not supported, not tested | | not verified |
| `jq` on the node | Required for deployments: `compose.verify` pipes `config --format json` through a fixed `jq` program and `sha256sum` to compare the **resolved** environment hash. A node without `jq` reports `docker.compose.deploy` unavailable ("jq missing"). The `jq` version is not pinned | `TestComposeDeployCapability`, `TestFixtures_EnvHashResolvedPrecedenceAndTamper` | unit / Fixture; only the `jq` of the fixture image was tried |
| Other node tools | `flock`, `bash`, `timeout`, `ss`, `sha256sum`, `base64`, `df` gate `docker.compose.deploy`; `curl` gates `health.http` | `TestComposeDeployCapability` | unit; GNU versions as in the fixture image only |
| `node.setup` v2 and `deploy_root` | Default `/srv/supermgmt`, owned by the dedicated user | `TestFixtures_MaterializeRefusesSymlinks` and the other `TestFixtures_*` deploy tests | Fixture |
| Secret env files | `format: raw`, byte-exact; the node compares resolved values hash-only | `TestEnvFile_CorpusRoundTrip`, `TestFixtures_EnvHashResolvedPrecedenceAndTamper`, `TestM4_SecretNeverOnControlPlane` | unit / Fixture / e2e (secret scan covers the control plane only, not the node or CLI stdout) |
| Disk-space preflight | Sum of layer and config sizes of images not on the node, plus 1 GiB, from `docker manifest inspect --verbose`; unknown size fails closed | `TestPreflight_DiskThreshold`, `TestPreflight_UnknownImageSizeFailsClosed` | unit; the real `manifest inspect` output shape was exercised only against the local test registry |
| Pre-deploy backup | One template, `postgres-dump` | `TestFixtures_BackupStep` | Fixture |
| Registry | The e2e registry is served over TLS with a test CA and reached by a non-loopback address | `TestM4_*` (job `e2e-deploy`) | e2e only; **GHCR and Docker Hub: not verified** |

## GitHub (provider `github`, `internal/providers/github`)

All rows: real GitHub `not verified`.

| Row | Used as | Test | GitHub fake |
|---|---|---|---|
| REST API version `2022-11-28` | Sent as `X-GitHub-Api-Version`; fine-grained read-only token | `TestClient_SendsGitHubHeadersAndTheToken` | verified |
| `GET /repos/{o}/{r}/commits/{sha}/check-runs` | Required checks for a commit; `filter=latest` and `all`, `Link` pagination | `TestVerifyChecks_Verdicts`, `TestVerifyChecks_EvidencePerPassedCheck`, `TestVerifyChecks_IgnoresRunsOfAnotherCommit` | verified |
| `GET /repos/{o}/{r}/actions/runs?check_suite_id=` | Binds a check to its workflow file; assumed that `path` is the bare workflow path and a re-run adds a higher check-run id to the same suite | `TestVerifyChecks_WorkflowLookupFailureIsAnError` | verified (assumption; see PROVENANCE.md) |
| `GET /repos/{o}/{r}/contents/{path}?ref=<sha>` | Manifest and Compose read at the CI-passed commit, with blob SHA | `TestFile_ReadsTheExactCommitWithItsBlobSHA`, `TestFinalize_UsesCIPassedCommitNeverBranchHead` | verified |
| `GET /repositories/{id}`, `GET /user/repos` | Repository lookup and listing | `TestRepositoriesList_PagesThroughTheProvidersRepositories` | verified |
| `GET /repos/{o}/{r}/attestations/{digest}` | Bundles for an image digest, verified with sigstore-go v1.3.0 | `TestAttestation_VerifiesWhatGitHubServes`, `TestAttestation_RejectsTamperedBundle`, `TestAttestation_RejectsWrongSigner`, `TestM4_DeployExactAttestedDigest` | verified against a **virtual Sigstore**; no real Fulcio, Rekor or timestamp authority |
| Trusted roots (Sigstore public good, GitHub) | TUF-refreshed through netguard, last-good cached, fail closed when stale | `TestTrustRoots_*`, `TestAttestation_StaleRootFailsClosed` | verified with a fake TUF repository; the embedded GitHub TUF anchor (`githubTUFAnchor`) and the live refresh path were never checked against the real repositories |
| Actions OIDC | Token verified against the issuer's JWKS; replay refused; `repository_owner_id`, repository id and workflow claims matched | `TestOIDC_*`, `TestCredentialStatus_GitHubOIDC` | verified with a fake issuer; **real Actions tokens not seen** (claim names and `job_workflow_ref` format are from the documentation) |
| Redirects | Followed only to the exact `api_url` origin (scheme, host, port), at most 3 hops; the token never leaves that origin | `TestRedirect_OriginPinned`, `TestRedirect_FourthHopIsRefused`, `TestClient_TokenNeverOffOrigin` | verified; **whether real GitHub redirects the endpoints used (renamed repositories, contents) and to which hosts is unknown** |
| Webhook | `X-Hub-Signature-256` HMAC over the raw body, delivery-id dedupe, rate limit; only `check_run`, `check_suite`, `workflow_run` act | `TestVerifyWebhook_*`, `TestWebhookForgedDeliveriesAreRefusedAndActOnNothing`, `TestWebhookReplayedDeliveryIsAcknowledgedAndNotReevaluated` | verified with the `ghsim` sender; no real delivery |
| Rate limits | Reported with the reset time | `TestClient_RateLimitIsReportedWithItsReset` | verified (fake headers) |

## Deferred: assumed, not confirmed against real services

Written into the fakes from documentation. Each is on [manual-checks/m4-real-github.md](manual-checks/m4-real-github.md).

1. Real attestations and the real Sigstore and GitHub trusted roots, public and private repositories.
2. The GitHub TUF anchor and the real TUF refresh.
3. Real GitHub redirect behaviour for the endpoints used.
4. GHCR pulls from a managed node.
5. Real Actions OIDC token claims.
6. Re-run semantics of check runs and the `path` shape of workflow runs.
7. Compose CLI releases other than 5.5.1.
8. GitHub Enterprise Server.

"CI-gated deployment against real GitHub, GHCR and real attestations" (spec Appendix E) stays unchecked until that run.
