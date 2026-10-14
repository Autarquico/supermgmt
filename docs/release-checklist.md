# Release checklist

The gate between "M6 is merged" and "a version is released". Sources: spec Appendix E, [ADR-0034](adr/0034-release-hardening-gates.md), [ADR-0036](adr/0036-distribution-notices-platform-claims.md), [releasing.md](releasing.md), and the manual-check pages in [manual-checks/](manual-checks/m6-release.md).

**Nothing is released and no row on this page is ticked.** The Appendix E boxes in the spec stay unchecked. A row becomes a fact when its evidence has run, not when it is written down; the automated rows below name the tests and jobs that will say so, and the release workflow refuses to build unless every required job is green on the exact tag commit ([releasing.md](releasing.md#the-gates)).

## How to read this page

Each Appendix E row has one state:

| State | Meaning |
|---|---|
| automated | A named test or CI job covers it. It counts only when the job is green on the tag commit. This page was written without a CI run, so "automated" means "a gate exists", not "the gate was seen passing". |
| automated + human | The automation covers what a fake, a container or a test key can cover. The rest is a numbered human row in the next section. |
| partial | The automation has a named gap. |
| human | Only a person can check it. |
| not met | The row cannot be ticked until a human row passes. The automation is fake-based. |

The tests cited here are checked by `make docs-check` (job `docs-check`): a cited test that does not exist, or a cited job that is not in `ci.yml`, fails the build.

## Appendix E sweep

| # | Appendix E row | State | Evidence |
|---|---|---|---|
| 1 | Repository matches §5 | human | No test compares the tree to spec section 5. Known differences, patched in the spec (1.4.8): no `internal/providers/cloudflare` (guide only), no `packaging/nfpm.yaml`. Row H19. |
| 2 | README accurately distinguishes implemented/planned | human | No test. README and ROADMAP were rewritten in M6; the MCP examples are checked by `TestMCPExamples_StdioHostsLaunchSmMcpWithRealFlags`. Row H20. |
| 3 | Universal curl bootstrap works | automated + human | `TestM2_CurlBashInstallsServer`, jobs `e2e-install` and `install-sh`, against a test key. With the real key and a real release: rows H1, H2. |
| 4 | Release verification works | automated + human | `TestM2_TamperedReleaseFailsWithExit5` (job `e2e-install`); `check.sh` over a snapshot (job `release-snapshot`); byte-identical rebuild (job `reproducible`). Real key, provenance and the first tag: rows H1, H2. |
| 5 | Local install works | automated + human | `TestLifecycleVM_LocalClient` (job `e2e-lifecycle-linux`), `TestLifecycleMacOS_LocalClient` (job `e2e-lifecycle-macos`), `TestM2_LocalModeWithoutIdP` (job `e2e-server`). First GitHub run of the lifecycle jobs: row H5. Intel macOS: row H4. |
| 6 | Generic server install works | automated + human | `TestLifecycleVM_Server` (job `e2e-lifecycle-linux`), `TestM6_LifecycleServerContainer` (job `e2e-lifecycle-container`), `TestM2_CurlBashInstallsServer` (job `e2e-install`). A real Debian 13 VM: row H3. |
| 7 | Proxmox auto-LXC install works | not met | Fake-verified only: `TestM3_ApplianceInstallDiscoversAndLogsIn` (job `e2e-appliance`, a simulated host). Stays unchecked until the real-host run passes: row H14. |
| 8 | Proxmox rollback on installer failure works | not met | Fake-verified only: `TestM3_ApplianceRollbackLeavesHostClean`, `TestProxmoxLXC_CrashAtEveryJournalBoundary`, `TestM6_ApplianceJournalLivesInTheRootOnlyRoot` (job `e2e-appliance`). Real host: row H14 and the interactive recovery of row H11. |
| 9 | Strict SSH host keys work | automated | `TestM1Security_PinnedHostKeyChangeStopsAuthentication`, `TestM1Security_HostKeyChangedBetweenScanAndFirstProbeIsRefused` (job `integration-fixtures`, Debian 13 and Ubuntu 24.04 nodes). |
| 10 | Offline nodes do not block TUI | automated | `TestM1_OfflineNodeDoesNotFreezeTUI` (job `integration-fixtures`). |
| 11 | Docker/systemd discovery works | automated | `TestFixturesDocker_DiscoveryLogsAndActions`, `TestFixturesSystemd_DiscoveryLogsAndTrust` (job `integration-fixtures`, both distributions). The Docker test failed once with a transient start error in M4 and was never investigated: listed under unresolved items. |
| 12 | lazydocker handoff restores TUI | automated + human | `TestHandoffRestoresTerminalAfterNormalExit`, `TestCtrlCInTheChildDoesNotKillTheTUI` (PTY suite, job `test`). Real terminal emulators: row H18. |
| 13 | GitHub CI exact commit/digest validation works | not met | `TestM4_DeployExactAttestedDigest` (job `e2e-deploy`) against a fake GitHub, a virtual Sigstore and a local registry. Real GitHub, GHCR and attestations: row H15. Stays unchecked until then. |
| 14 | Compose deployment state machine works | automated | `TestM4DeploymentStatesMatchTheStateMachine`, `TestM4_DeployExactAttestedDigest` (jobs `test`, `e2e-deploy`). |
| 15 | Health failure rollback works where safe | automated | `TestM4_HealthFailureRollsBackToKnownGood` (job `e2e-deploy`). |
| 16 | Audit timeline covers all mutations | partial | Audit is tested per feature (for example `TestEmitRedactsDataOnACopy`, `TestRevokingATokenIsAuditedOnceAndGuardedForOthersTokens`, `TestInstanceAudit_ImportsPendingOnce`). No test enumerates every mutating route and asserts an event. Interim: row H21; the missing test is a followup. |
| 17 | Policy/approval hash invalidates on plan change | automated | `TestDecisionOnADifferentPlanHashIsStale`, `TestSpecRevisionChangeInvalidatesApproval` (jobs `test`, `integration-fixtures`). |
| 18 | Sync/observations never invalidate approvals | automated | `TestClaimSucceedsWhenOnlyObservationsChanged`, `TestObservationWritersNeverBumpSpecRevision`, `TestRevalidateDeploy_ObservationsIgnored`. |
| 19 | Compose validator rejects privileged constructs | automated | `TestCheckRaw_RejectsPrivilegedConstructsIntroducedByAnchorsAndMerges`, `TestM4_RepositoryComposePrivilegedRejected` (job `e2e-deploy`). |
| 20 | Interrupted jobs reconcile, never blind re-run | partial | `TestReconcilerNeverRedispatchesWithoutEvidence`, `TestReconcilerContinuesWhenEvidenceProvesCompletion`. The end-to-end restart test `TestM1_DaemonKilledMidRestartReconciles` has an unexplained second failure mode: unresolved flake F1. |
| 21 | Single daemon owns the DB; second daemon refuses | automated | `TestM1Lifecycle_SecondDaemonOnTheSameStateExitsTwoNamingTheOwner`, `TestM1Lifecycle_SecondDaemonOnTheSameDatabaseThroughASymlinkExitsTwo`. |
| 22 | MCP bridge without client token is refused; MCP identity cannot approve | automated | `TestBridge_RefusesWithoutToken`, `TestE2E_MCPCannotApprove` (job `e2e-mcp`), `TestSystemAndMCPIdentitiesCanNeverApprove`. |
| 23 | Lost lease cannot write (fencing); locks held while interrupted | automated | `TestLeaseFencing`, `TestTakeoverFencesOldWorker`, `TestInterruptedJobKeepsLocksAndBlocksConflictingClaims`. |
| 24 | Claim-time revalidation rejects stale plans and lapsed quorum | automated | `TestClaimFailsPlanStaleWhenAConfiguredInputChangedAfterApproval`, `TestClaimSendsTheJobBackToAwaitingApprovalWhenTheQuorumLapsed`. |
| 25 | Outbound filter blocks metadata/loopback/mapped addresses | automated | `TestPermit`, `TestProductionClientCannotReachLoopback`, `TestDialRefusesRebindingToInternalAddresses` (package `internal/netguard`). |
| 26 | Restore starts in hold; stale jobs interrupted; tokens revoked | automated | `TestRestoreHoldStopsClaims`, `TestRestoreNeutralizesTheStagedDatabase`, `TestRestoreRevokesMCPCredentials`, `TestMigrationFixtures_RestoringAnArchiveRevokesEveryCredential` (job `migration-test`). |
| 27 | Restore crash at every journal step recovers to a consistent state | automated | `TestCrashBeforeAndAfterEveryRenameAndJournalWriteLeavesOldOrNew`, `TestRepeatedlyInterruptedRecoveryStillConverges`. |
| 28 | Every API route maps to a catalog action (CI check) | automated | `TestEveryRouteMapsToExactlyOneCatalogActionOrExemption`, `TestEveryM4RouteMapsToExactlyOneCatalogActionOrExemption`, `TestMCPClientRoutesMapToExactlyOneCatalogAction` (job `test`). |
| 29 | Revoked/expired credential fails a queued job at claim | automated | `TestClaimFailsWhenTheCredentialWasRevokedAfterSubmit`, `TestClaimFailsWhenAnAPITokenExpiredButNotWhenASessionDid`, `TestACredentialThatIsGoneByClaimTimeFailsTheQueuedMCPJob`. |
| 30 | Takeover fences the old worker; quiescence required before reconcile/resolve | automated | `TestTakeoverFencesOldWorker`, `TestResolveRequiresQuiescenceUnlessAssumed`. |
| 31 | Frozen Compose model is identical after node CLI interpolation | automated | Job `compose-equivalence` (`TestComposeEquivalence_Corpus` against the pinned Compose CLI 5.5.1); `TestEquivalent_Differences`. |
| 32 | Secret values never appear in plans, API views or control-plane disk | automated | `TestM4_SecretNeverOnControlPlane` (job `e2e-deploy`), `TestNoKeyMaterialLeaksAnywhere`, `TestM1Secrets_NoPlaintextKeyAfterSetupActionsAndLogs`. The leak scans cover the control plane, not the node or CLI output. |
| 33 | MCP client registration may need approval; token issuance happens once, afterwards | automated | `TestMCPClientsRegister_WaitsForApprovalAndCreatesNothingBefore`, `TestMCPClientsIssueToken_OnlyTheRequesterOnceAndOnlyPending`. |
| 34 | Forward resume re-runs claim revalidation; safety recovery only rolls back | automated | `TestReconcileDeploy_ForwardResumeBeforeDeployFailsWithTheRevalidationReason`, `TestReconcileDeploy_ForwardResumeAfterDeployingOnlyRollsBack`, `TestDeployStage_ForwardStepsRefuseUnderSafetyRecovery`. |
| 35 | No automatic resume/rollback without completion evidence (killed CLI -> human) | automated | `TestReconcileDeploy_CrashAfterLongComposeUpReconcilesFromTheHandlersOwnEvidence`, `TestReconcilerNeverRedispatchesWithoutEvidence`. |
| 36 | Restore fails undispatched work and keeps snapshot locks only for dispatched work | automated | `TestRestoreNeutralizesDeployments`. |
| 37 | Fresh-host restore works with an offline key import | automated | `TestM2_BackupRestoreFreshHost` (job `e2e-server`), `TestOfflineExportThenImportRoundTripsAKeyIntoAFreshHost`. |
| 38 | ADR-0007..0012 accepted in their milestones | automated | Read in the M6 release task, no test: ADR-0007 to ADR-0012 carry `Status: Accepted` in `docs/adr/`. Row H19 covers the ADR index. |
| 39 | MCP has no generic privileged shell | automated | `TestReadTools_NoShellExecSecretOrDeleteTools`, `TestConfig_MCPInteractiveExecIsRefused`, `TestMCPRouteMatrix`. |
| 40 | MCP write tools disabled by default | automated | `TestMCPWritesOff_EveryNonQueryActionIsDenied`, `TestMCPWritesOff_HumansAreUnaffected`. |
| 41 | Remote auth works | automated + human | `TestM2_RemoteControlOverHTTPS` (job `e2e-server`, Dex). A real identity provider and reverse proxy: row H17. |
| 42 | Secrets do not leak in logs/API/backups | automated | `TestM4_SecretNeverOnControlPlane`, `TestRestoreReplacesLiveStateKeepsLockAndWritesNoSecretsOutsideKeysDir`, `TestMCPClientsIssueToken_NeverStoresOrAuditsThePlaintext`; the e2e leak scans (jobs `e2e-server`, `e2e-deploy`, `e2e-mcp`). Archives are not encrypted: a stated limit. |
| 43 | Backup/restore tested | automated + human | `TestM2_BackupRestoreFreshHost`, `TestMigrationFixtures_EveryArchiveRestoresWithTheCurrentBinaryAtTheLatestSchema` (job `migration-test`), and the restore step of the lifecycle tests. Real machines: rows H3, H17. |
| 44 | Upgrade N-1 -> N tested | automated + human | `TestM3_UpgradeNMinus1ToN`, `TestM6_UpgradeChainOldestToLatestInOneJump` (job `e2e-chain`), `TestM6_CrashUpgrade_ResumesForwardFromEveryPoint` (job `e2e-crash`). The sources are binaries built from milestone merge commits; an authentic signed release: row H6. |
| 45 | Uninstall preserves data unless separately confirmed | automated | `TestM3_UninstallKeepsData`, `TestM3_UninstallPurgeDataRemovesIt` (job `e2e-upgrade`). |
| 46 | OpenAPI validated | automated | `TestOpenAPI_EveryRouteIsDocumentedAndNothingElse` and the others in `internal/api/openapi_test.go` (job `api-check`). |
| 47 | Config/manifest schemas validated | automated | `TestSpecExamples_AppManifestParses`, `TestValidateBaseConfigsAreValid`; the loaders also have fuzz targets (job `fuzz-inventory`). |
| 48 | Unit/integration/E2E/security tests pass | partial | Every job named in `packaging/release/required-checks.txt` must be green on the tag commit; the `gates` job enforces it and this page cannot. Not run by this task. Open: unresolved flake F1 and the unresolved items below. |
| 49 | Race/vulnerability/static scans pass | partial | Jobs `race` (Ubuntu and macOS), `govulncheck`, `lint` (gosec), `secret-scan`, `licenses`, `fuzz-inventory`. CodeQL runs in its own workflow and is not in the required list. Mutation fuzzing and the stress suite run only in the nightly workflow. 25 parsers are exempt as `gap` rows in `scripts/fuzz-inventory.txt`. |
| 50 | Release artifacts/checksums/signatures/SBOM generated | automated + human | Jobs `release-snapshot`, `reproducible`; `check.sh` and `verify-provenance.sh` in `release.yml`. Verified with a throwaway key only. The first real tag: rows H1, H2. |
| 51 | License/dependency audit completed | automated + human | Job `licenses` (go-licenses against the allowlist), `dependency-review.yml`, `check.sh` comparing `THIRD_PARTY_LICENSES` with the compiled binary. The legal reading and the licence decision: row H7. |
| 52 | Name/trademark/repository availability checked | not met | Not checked by anyone. Row H8. A conflict means a rename before any announcement. |

## Human-gated rows

A row is ticked by a person who has run its procedure and recorded the date, the build and the platform in the page the procedure names. An agent never ticks one. `make docs-check` fails if one of these rows is ticked or lacks an owner or a procedure.

- [ ] [human] H1 Signing key generated, `release` environment configured, public key embedded in `install.sh` and `scripts/join.sh`, fingerprint published. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#1-signing-key-and-trust-root)
- [ ] [human] H2 Release candidate tagged; `gates`, notices, SBOM, provenance verification, attestation and channel pointer behave on a real tag; yank rehearsed. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#2-first-tag-release-candidate-and-gate-behaviour)
- [ ] [human] H3 Install, upgrade, backup, restore and uninstall on a real Debian 13 virtual machine. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#3-real-debian-13-vm)
- [ ] [human] H4 Install, resident daemon, upgrade and uninstall on an Intel Mac. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#4-intel-macos)
- [ ] [human] H5 First GitHub run of the lifecycle jobs (arm64 and macOS never ran anywhere) read, assumptions confirmed, the "not seen running" sentence removed from the compatibility page. owner: maintainer. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#5-first-runs-on-github-of-the-lifecycle-jobs)
- [ ] [human] H6 Upgrade and restore starting from an authentic signed release, once a tag exists. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#6-upgrade-from-an-authentic-signed-release)
- [ ] [human] H7 Legal reading of `THIRD_PARTY_LICENSES` and the licence decision (Apache-2.0 by default). owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#7-third-party-notices-legal-reading)
- [ ] [human] H8 Name, trademark, domain, module path, registry and formula-name checks. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#8-name-trademark-and-registries)
- [ ] [human] H9 Homebrew tap repository created, first formula rendered from the signed checksums and installed. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#9-homebrew-tap)
- [ ] [human] H10 GitHub settings: secret scanning and push protection, branch protection with the required checks, `release` environment reviewers, private vulnerability reporting, security contact. owner: repository owner. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#10-github-repository-settings)
- [ ] [human] H11 Interactive recovery of a kept appliance-installer journal on a terminal. owner: maintainer. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#11-interactive-journal-recovery)
- [ ] [human] H12 Downgrade to a pre-M6 binary leaves the offline audit record pending and a later M6 start imports it once. owner: maintainer. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#12-downgrade-to-a-pre-m6-binary-stated-limitation)
- [ ] [human] H13 First week of nightly runs read: fuzz crashers, stress, flake loops, fuzz budget. owner: maintainer. procedure: [manual-checks/m6-release.md](manual-checks/m6-release.md#13-nightly-and-flake-loops)
- [ ] [human] H14 Proxmox on a real PVE 9.x host: discovery, power actions, appliance install, rollback, upgrade, uninstall, and the unverified assumptions SEC-7, SEC-9, SEC-12 and the clock-skew check. owner: repository owner. procedure: [manual-checks/m3-real-pve.md](manual-checks/m3-real-pve.md)
- [ ] [human] H15 GitHub for real: token, check runs, Actions OIDC, attestations, Sigstore trust root, webhooks, GHCR. owner: repository owner. procedure: [manual-checks/m4-real-github.md](manual-checks/m4-real-github.md)
- [ ] [human] H16 Real MCP clients (Claude Code, Claude Desktop, MCP Inspector) and a real OAuth authorization server, with dated and versioned evidence. owner: repository owner. procedure: [manual-checks/m5-real-mcp-clients.md](manual-checks/m5-real-mcp-clients.md)
- [ ] [human] H17 Credential stores, real OIDC provider, real reverse proxy, backup and restore on real machines, and the suspected `sm login --bootstrap` defect. owner: repository owner. procedure: [manual-checks/m2-handoff.md](manual-checks/m2-handoff.md)
- [ ] [human] H18 Terminal handoff on real terminal emulators. owner: maintainer. procedure: [manual-checks/m1-handoff.md](manual-checks/m1-handoff.md)
- [ ] [human] H19 Repository layout read against spec section 5 (version 1.4.8) and the ADR index against the ADR files. owner: maintainer. procedure: compare `git ls-files` with the section 5 tree of the master spec and the status lines in [adr/README.md](adr/README.md); record every difference as a spec patch or a task
- [ ] [human] H20 README, ROADMAP and the docs read for any capability described as shipped without a test, job or checklist row behind it. owner: maintainer. procedure: read [README.md](../README.md) feature matrix and [ROADMAP.md](../ROADMAP.md) against this page; the rule is "Documentation honesty" in [CONTRIBUTING.md](../CONTRIBUTING.md#documentation-honesty)
- [ ] [human] H21 Audit coverage until a test exists: list the mutating routes of `api/openapi.yaml` and confirm each handler writes an audit event. owner: maintainer. procedure: read the route table in `internal/api` against `internal/app` audit calls and record the routes that write none

## Unresolved items and stated limitations

These are open on purpose. None is hidden by a retry or an exemption, and none is a reason to tick a row.

**Flakes** (policy: [CONTRIBUTING.md](../CONTRIBUTING.md#flaky-tests))

- **F1, the daemon-restart test, partly unresolved.** `TestM1_DaemonKilledMidRestartReconciles` failed in CI in two ways. The first was a test synchronization defect (it read the wrong invocation id out of an unordered map) and is fixed, pinned by `TestS4EvidenceInvocationIDsIgnoreThePreStateEchoedInEvidence`. The second, a job left `interrupted` after the six-minute poll under heavy Docker load, was seen once and was not reproduced or explained. The daemon log was not captured. No quarantine, no retry: the test stays in the gate and the nightly flake loop reruns it 20 times.
- **F2, the TUI wedge after a handoff that cannot start, fixed for the case seen.** Root cause: a race in the pinned bubbletea version between stopping and restarting its render ticker when the child exits at once. The TUI no longer hands the terminal over for a command that cannot start (`TestHandoffThatCannotStartSkipsTheTerminalHandover`). The reproduction (60 runs per batch on macOS arm64) failed in at least 2 of 6 batches before the fix and passed 4 of 4 batches after it. Residual: any other command that exits instantly may reach the same upstream race; Linux was not measured; no upstream issue has been filed. The nightly job runs the PTY suite 50 times on macOS.
- **A transient `start demo container` failure** of `TestFixturesDocker_DiscoveryLogsAndActions`, recorded at the end of M4 and never investigated. It is unclassified, not fixed.

**Stated limitations**

- **Downgrade audit (F6).** An `--allow-downgrade` upgrade writes a pending audit record before the swap. A target built before M6 cannot import it, so the event appears only once a binary of M6 or later has started. Row H12.
- **Upgrade hold.** The hold is proven on real systemd by the lifecycle jobs only (`TestLifecycleVM_Server`), not inside an unprivileged Proxmox container.
- **Fuzzing.** 25 parsers are listed as `gap` rows in `scripts/fuzz-inventory.txt` with no target yet. `sh scripts/fuzz.sh count` reports 55 targets today. The archive-reading target is slow, and the nightly budget (60 minutes per shard) has never been measured.
- **Migration fixtures.** The M4 and M5 worlds contain no deployment, and the M5 world has no OAuth access-token row; restore revocation of OAuth tokens is covered by `TestRestoreRevokesMCPCredentials` instead.
- **Unrun on GitHub (to my knowledge):** the lifecycle, crash and chain jobs, the nightly workflow, the Homebrew audit and the reproducibility check on every platform. Rows H2, H5, H13.
- **Shell tooling.** `shellcheck` was not available when the release scripts were written; `make install-test` runs it where it exists.

**Residuals recorded in ADRs and checked by hand only**

- SEC-7: PVE roles have no comment field, so rollback recognises roles by name only ([ADR-0026](adr/0026-appliance-installer.md)). The token comment marker is unverified against a real `pveum` listing: row H14, check 5.13 of [manual-checks/m3-real-pve.md](manual-checks/m3-real-pve.md).
- SEC-9: a guest recreated with the same type, VMID and name between two syncs still receives an approved power action ([ADR-0025](adr/0025-proxmox-power-jobs-task-correlation.md)). Row H14, check 6.11.
- SEC-12: the task-list filters `source=all` and `userfilter` were implemented from a finding's text; the Proxmox source was not read. Row H14, check 6.10.
- A server's TLS certificate has an expiry check in `sm doctor` and a documented manual re-issue; a renewal command is post-V1.

**Post-V1 (not required by the spec's definition of done)**

- Proxmox `POST /providers`, promotion of discovered guests, snapshot, backup, console and task-history handlers, the metrics endpoint, and `internal/providers/cloudflare`.
- Linux packages (`.deb`, `.rpm`): a package manager's upgrade would bypass the upgrade protocol ([ADR-0036](adr/0036-distribution-notices-platform-claims.md)).
- Sharing the database path canonicaliser with the installer: not done, on purpose (a dependency rule keeps the installer from importing the database package).

## Followups

- A test that enumerates mutating routes and asserts an audit event (Appendix E row 16).
- Fuzz targets for the 25 `gap` rows.
- Add the fuzz, stress and lifecycle results to this page after the first nightly and the first full CI run.
