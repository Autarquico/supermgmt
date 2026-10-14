# Project status and what is verified

SuperMgmt is **pre-alpha. No stable release yet.** Pre-releases may exist, but the installer has not been verified on a clean machine, so [build `sm` from source](getting-started.md). The code for the first version is written; the checks that need real hosts, real services, a release key and people are still open.

This is the canonical page for what is verified. Other pages carry a one-line status and link here. When this page and another page disagree, this page is the one to fix.

## How to read the claims

Each claim has exactly one level:

- **implemented and tested in CI**: the code exists and the cited tests pass in the cited CI job. For these rows the job passed on a recorded commit (see [The CI run behind these claims](#the-ci-run-behind-these-claims)).
- **tested against fakes**: the code exists and its tests pass, but the outside system it talks to was a fake, a simulator or a test client. Nothing was run against the real one.
- **configured, not yet run**: the pipeline or workflow is written and its parts are tested, but it has never run for real.
- **not verified**: stated from reading the code or a guide; no test or run backs it.

"Scope" says where the claim holds. "Limitation" says what the evidence does not show. A Docker fixture node is a container with a real `sshd`, systemd and Docker; it is not a machine.

## Claims

| Claim | Scope | Evidence | Level | Limitation |
|---|---|---|---|---|
| One daemon owns all state; the TUI, the CLI and the MCP bridge are clients of its API | Local mode on Linux and macOS | `TestM1_ManageTwoNodesWithoutAgent` (job `integration-fixtures`); `TestM1Lifecycle_TenConcurrentClientsAutostartOneDaemon` (job `test`); passed at `6f89609` | implemented and tested in CI | Managed nodes were Docker fixtures. Real terminal emulators are checked by hand only |
| Agentless: nothing of SuperMgmt runs on your machines, only a dedicated account and a narrow sudoers file | SSH nodes on Debian 13 and Ubuntu 24.04 | `TestFixturesSetup_CreatesTheDedicatedUserAndItsFiles`, `TestFixturesSetup_RerunIsANoOp` (job `integration-fixtures`), passed at `6f89609` | implemented and tested in CI | Container fixtures only; other distributions are untested. Setup needs root or passwordless sudo once. Setup from the CLI or the TUI grants no systemd unit yet |
| Host keys are pinned; a changed key is refused | SSH nodes | `TestFixturesTransport_ChangedHostKeyIsRefused` (job `integration-fixtures`), passed at `6f89609` | implemented and tested in CI | The first trust is yours: you confirm the fingerprint when you add the node |
| Default deny: nothing runs unless a rule allows it, and a deny always wins | Policy engine, every mode | `TestEvaluate_Step5_DefaultDeny`, `TestPolicyProperty_NoAllowOverridesAMatchingDeny` (job `test`), passed at `6f89609` | implemented and tested in CI | In local mode, any program running as your OS user can drive SuperMgmt |
| Approvals bind to the hash of the exact plan; production changes wait for one | Every job | `TestClaimFailsPlanStaleWhenAConfiguredInputChangedAfterApproval`, `TestActInProductionWaitsForApprovalWithAPlan` (job `test`), passed at `6f89609` | implemented and tested in CI | In local mode you may approve your own plans by default |
| Append-only audit trail with secrets redacted | Audit events and logs | `TestEventsAreAppendOnly`, `TestSecretNeverRevealsItself` (job `test`), passed at `6f89609` | implemented and tested in CI | Redaction matches known key names and token patterns; an unknown secret inside remote output is not detected |
| AI agents get no bypass: an MCP client can never approve, and write tools are off by default | MCP over stdio and remote MCP | `TestAnMCPClientCanNeverApproveOrRejectAJob`, `TestNewServer_WritesDisabledRefusesWriteToolsByName` (job `test`); `TestE2E_MCPStdioReadsGraph`, `TestE2E_MCPRemoteStreamable` (job `e2e-mcp`) | tested against fakes | Only the official Go SDK client, hand-written JSON-RPC goldens and a fake authorization server. No real MCP client (Claude Code, Claude Desktop, MCP Inspector) and no real OAuth server has been used |
| Deploys only a commit that passed CI and an image digest CI attested, with health checks and rollback | Docker Compose apps on SSH nodes | `TestM4_DeployExactAttestedDigest`, `TestM4_HealthFailureRollsBackToKnownGood` (job `e2e-deploy`) | tested against fakes | A fake GitHub, a virtual Sigstore and a local registry. No real GitHub, GHCR or attestation has been used. Nodes need Docker Compose CLI 5.5.1 and `jq` |
| An upgrade interrupted at any point resumes or reverts safely | Installed server | `TestM6_CrashUpgrade_ResumesForwardFromEveryPoint` (job `e2e-crash`), passed at `6f89609` | implemented and tested in CI | Upgrades between test builds in containers. Upgrading from a published release has not been verified yet  |
| Install, upgrade, backup and restore, and uninstall run on Ubuntu 24.04 (amd64, arm64) and macOS 15 (arm64) | Server and local-client lifecycle | `TestLifecycleVM_Server`, `TestLifecycleVM_LocalClient` (job `e2e-lifecycle-linux`); `TestLifecycleMacOS_LocalClient` (job `e2e-lifecycle-macos`); passed at `6f89609` | implemented and tested in CI | Fresh CI runners installing from a local mirror signed with a test key. Installing from a published release has not been verified on a clean machine yet (release checklist H22). A Debian 13 server runs only in a container; Intel macOS is a manual check |
| Proxmox VE: discovery, power actions and a one-command appliance install | Proxmox VE 9.x on amd64 | `TestPowerTaskLifecycle` (job `test`); `TestM3_Appliance*`, `TestM6_ApplianceLifecycleAcrossAReleaseBoundary` (job `e2e-appliance`) | tested against fakes | A simulated Proxmox host. Nothing has run on a real Proxmox VE host. Proxmox VE 8.x is not supported |
| The docs cite only tests and CI jobs that exist, and a platform is "supported" only when CI runs every operation on it | `docs/*.md` | `TestEveryCitedTestExists`, `TestEveryCitedJobExists`, `TestPlatformMatrixClaimsOnlyWhatCIRuns` (job `docs-check`), passed at `6f89609` | implemented and tested in CI | It checks that cited tests and jobs exist, not that the prose matches what they assert. The README is not checked |
| Every module compiled into `sm` has an allowed open-source licence | The `sm` binary | job `licenses`, passed at `6f89609` | implemented and tested in CI | Whether the shipped licence notices are legally sufficient is an open human check |
| Signed releases with checksums, SBOM and provenance, verified by the installer before anything runs | Release pipeline and `install.sh` | Snapshot builds signed with a throwaway key (job `release-snapshot`) and installer tamper tests (job `install-sh`) | tested against fakes | Tested with a throwaway key and a local mirror. No stable release yet. The first run of this pipeline on a real tag is the pre-release `v0.1.0-rc.1`; until a person has checked that run (release checklist H2), signing, SBOM and provenance on real tags count as unverified |
| No telemetry, no update check, no request you did not configure | The `sm` binary | Egress inventory in [Dependencies and egress](dependencies.md#egress) | not verified | Assembled from reading the code, not from capturing the traffic of a running instance |
| Cloudflare Tunnel and Access can sit in front of a server | Server mode | [Cloudflare guide](cloudflare.md) | not verified | A guide only; never tried against a real Cloudflare account |

## The CI run behind these claims

Rows marked "passed at `6f89609`" refer to the `ci` workflow run on `main` at commit `6f89609`, on 2026-10-14: [run 38573703589](https://github.com/autarquico/supermgmt/actions/runs/38573703589). Every job cited above passed in that run. Every job of the run passed on its second attempt (the first failed in `secret-scan` while downloading a Go module, a network error, not a finding).

The rows marked "tested against fakes" also passed in that run. Their level stays lower because the outside system was a fake.

Not run yet: the nightly workflow (fuzzing and stress tests) has no recorded run, and no run of the release workflow on a real tag has been checked by a person yet (release checklist H2).

## Not verified

Nothing on this list has been tried. Do not rely on it.

- An installer verified on a clean machine. No stable release exists yet, and `install.sh` has not been run against a published release on a clean machine; build from source.
- A real Proxmox VE host. Every Proxmox behaviour was checked against a simulator.
- Real GitHub, GitHub Container Registry, real attestations or GitHub Actions OIDC tokens. Every GitHub behaviour was checked against a fake.
- Any real MCP client (Claude Code, Claude Desktop, MCP Inspector) or real OAuth authorization server.
- Any identity provider other than Dex for OIDC login.
- A real Debian 13 machine (only a container), an Intel Mac, or the real macOS keychain and Linux `secret-tool`.
- Linux distributions other than Debian 13 and Ubuntu 24.04 as managed nodes, and RHEL-family systems anywhere.
- A real Cloudflare account.
- Homebrew and Linux packages (`.deb`, `.rpm`): there are none.
- The project name: "SuperMgmt" is a working name and may change before the first release.

## What you can use today

| You want to | Today |
|---|---|
| Manage Linux machines from your laptop | Build from source and follow [Getting started](getting-started.md). Tested against container fixtures |
| Run a shared server | Not with `install.sh` until an install from a published release is verified on a clean machine; `sm install server` from a binary you built works. The steps are in [Installation](installation.md) |
| Install on Proxmox VE | Not verified: no install from a published release on a clean host, and never tried on a real Proxmox VE host |
| Deploy Compose apps from GitHub | Implemented, never run against real GitHub. See [Applications and deployments](deployments.md) |
| Connect an AI agent | Implemented, never tried with a real MCP client. See [MCP](mcp.md) |

Per-platform detail, operation by operation: [Compatibility](compatibility.md#platforms-and-operations).

## Open human checks

These need a person, a real host or a real account. Each is a checklist with a procedure; none has been completed.

- [First release: signing key, real hosts, repository settings, legal and naming](manual-checks/m6-release.md)
- [Real Proxmox VE host](manual-checks/m3-real-pve.md)
- [Real GitHub](manual-checks/m4-real-github.md)
- [Real MCP clients and authorization server](manual-checks/m5-real-mcp-clients.md)
- [Server mode: keychain, identity providers, reverse proxy, VM install](manual-checks/m2-handoff.md)
- [Terminal emulators](manual-checks/m1-handoff.md)

## References

- [Compatibility](compatibility.md): the platform matrix, enforced by `test/docs`.
- [Roadmap](../ROADMAP.md) and the [release checklist](release-checklist.md).
- Platform claims rule: [ADR-0036](adr/0036-distribution-notices-platform-claims.md).
