# Applications and deployments (M4)

SuperMgmt deploys one Docker Compose application to one node, from a commit that passed CI and an image digest that CI built. This page describes what the code in this repository does. Specification: SPEC §18-§21 and §31 M4 (`docs/spec/SUPERMGMT-SPEC.md`), [`docs/specs/m4-apps-deployments.md`](specs/m4-apps-deployments.md); design decisions: [ADR-0006](adr/0006-pinned-compose-go-and-cli-equivalence.md), [0007](adr/0007-execution-snapshots.md), [0008](adr/0008-secret-versions.md), [0010](adr/0010-secret-env-file-encoding.md), [0011](adr/0011-provisional-deployment-api.md), [0028](adr/0028-github-connector.md), [0029](adr/0029-deployment-engine.md), [0030](adr/0030-node-setup-v2.md) (all `Proposed` until the M4 PR merges).

## What is verified, and what is not

**No real GitHub, GHCR or Sigstore was contacted by any test.** GitHub is replaced by a hand-written fake (`internal/providers/github/ghfake`, provenance in [`test/fixtures/github/PROVENANCE.md`](../test/fixtures/github/PROVENANCE.md)), attestations are signed by a virtual Sigstore (`sigstore-go` `pkg/testing/ca`), and images come from a local TLS registry. The fake was written from the GitHub documentation, not recorded from the live API. Everything on this page that depends on GitHub's real behavior is marked **not verified against real GitHub** and has a row in [manual-checks/m4-real-github.md](manual-checks/m4-real-github.md), which is **DEFERRED** (nothing on it has been run).

Tests that exercise the node run against a Docker fixture node with Docker Compose 5.5.1 (CI jobs `integration-fixtures`, `compose-equivalence`, `e2e-deploy`). A statement below that names a test was read from the test source; the tests were not re-run while this page was written.

## Concepts

| Thing | What it is |
|---|---|
| GitHub provider | `type: github` provider with a read-only token ([Configuration](configuration.md#github)) |
| Repository | A GitHub repository known by its numeric ID (names are display only), created when an app links to it |
| App | The configuration of one application: deployed service, image policy, Compose source, variables, secret references, CI policy |
| App target | An app bound to one environment and one node, with a deployment policy. Unique per (app, environment) in V1 |
| Deployment | One request to put a commit's digests on a target (`kind: deploy`) or to restore a known-good one (`kind: rollback`) |

The Compose project of a target is `sm-<app>-<environment>`; it cannot be changed after creation (a database trigger refuses it, test `TestM4ImmutabilityTriggers`). App names match `^[a-z0-9][a-z0-9-]{0,39}$` (`internal/app/apps.go`).

## Prerequisites on the node

1. **Set the node up with `docker_access=true`.** The `supermgmt` user then joins the `docker` group, which is root-equivalent ([security.md](security.md#apps-github-and-deployments-m4)).
2. **Run `node.setup` again if the node was set up before M4.** `setup_version` 2 creates `deploy_root` (default `/srv/supermgmt`) owned by the `supermgmt` user with mode 0750, refuses a symlink there, and requires `jq` on the node (`internal/transport/ssh/templates/setup.go`, `internal/app/setup.go`; tests `TestSetupV2CreatesDeployRootAndRequiresJQ`, `TestDeployRootStepCreatesADirectoryOwnedByTheDedicatedUserOnlyForValidPaths`). `deploy_root` is a `node.setup` parameter: absolute, clean, outside `/var/lib/supermgmt` (`TestValidateDeployRoot`). Nodes at version 1 keep working for everything else but cannot deploy.
3. **Install the tools.** The node must have the Docker Compose plugin at exactly **5.5.1**, `jq` and `flock` (util-linux); `curl` is needed for `http` health checks and `bash` plus `timeout` for `tcp` checks (`internal/runtimes/runtime.go`, `internal/discovery`). Discovery advertises the `docker.compose.deploy` capability only when all of these hold and `docker_access=true`; a node without it is refused at request time and again by the preflight (`TestDeploymentsCreate_NeedsTheComposeDeployCapability`, `TestPreflight_ComposeDeployCapabilityMissing`).
4. **Compose 5.5.1 is the only supported CLI.** Any other `docker compose version --short` makes the preflight fail with `PREFLIGHT_FAILED` (cause `COMPOSE_UNSUPPORTED`); adding a version needs a new fixture row and a review of the CLI-default normalization table (`internal/deployments/compose/normalize.go`). The loader and CLI are compared on a five-file corpus for this one version (`TestComposeEquivalence_Corpus`).
5. **A registry the node can pull from.** The node pulls `<repository>@<digest>` itself; SuperMgmt never sees registry credentials. Registry authentication on the node is not managed by SuperMgmt in M4 (private GHCR pulls are not verified against real GHCR).

## Register GitHub

Add a `github` provider to the configuration file ([configuration.md](configuration.md#github)) and import its token as a secret:

```bash
sm secrets import --name providers/github/token
```

`POST /api/v1/providers` with `type: github` registers the provider over HTTP; the request is approval-gated (`provider.write`), so it is applied at once or parked for approval (`TestPostProvidersAcceptsAGitHubProvider`, `internal/api/routes_providers_m4_test.go`). The file route still works.

The token is a fine-grained, read-only personal access token with Contents, Checks, Actions, Attestations and Metadata read access. Whether this permission set is exactly sufficient is **not verified against real GitHub**.

## Create an app and a target

Apps are created with the CLI or `POST /api/v1/apps`; they are not in the configuration file.

```bash
sm apps create --file app.json
sm apps target add myapp --environment production --node ovh-prod-01 --policy-file policy.json
```

`app.json` is a `CreateAppRequest` (`internal/api/wire/m4.go`):

```json
{
  "name": "myapp",
  "provider_id": "<id of the github provider>",
  "repository_id": 123456789,
  "deployed_service": "web",
  "image_policy": {
    "deployed": "ghcr.io/acme/web",
    "sidecars": {"db": "docker.io/library/postgres"},
    "pinned": ["docker.io/library/postgres@sha256:<64 hex>"]
  },
  "compose_source": "control-plane",
  "compose_content": "services:\n  web:\n    image: ghcr.io/acme/web\n    ports:\n      - {target: 8080, published: 8080, host_ip: 127.0.0.1}\n",
  "variables": {"LOG_LEVEL": "info"},
  "secret_refs": {"db_password": "secret://apps/myapp/db-password"},
  "ci_policy": {
    "branch": "main",
    "allowed_events": ["push"],
    "required_checks": [{"name": "test", "app_id": 15368, "workflow_path": ".github/workflows/ci.yml"}],
    "deploy_workflow": ".github/workflows/ci.yml"
  },
  "automation_identity": true
}
```

Writes are validated before anything is stored, and again when an approved write is applied (`internal/app/apps_test.go`). Resource IDs of the repository and its owner are resolved from GitHub when the app is created; the stored CI policy carries numeric IDs (`TestAppsCreate_LinksTheRepositoryAndResolvesTheCIPolicyToNumericIDs`). `app.write` and `app_target.write` are `direct` actions: applied at once when policy allows, otherwise submitted as a job that waits for approval. Only `admin` holds them by default (`internal/policy/default.yaml`).

### Image policy

- `deployed` is a bare repository (no tag, no digest) for the one service CI builds. Its image becomes `<deployed>@<digest requested by the deployment>`.
- Every other service must already be `<repository>@sha256:<digest>` in the Compose file, use the repository its `sidecars` entry names, and the digest must be listed in `pinned`. A tag or an unlisted digest fails the deployment as `ARTIFACT_NOT_IMMUTABLE` (`TestFinalize_ATagOrUnboundSidecarAtTheCommitFailsAsNotImmutable`, `TestFinalize_UnboundDigestFailsAsNotImmutable`).

### Compose source

`compose_source` is `control-plane` (the Compose text is stored in the app and edited through `app.write`) or `repository` (read from the exact commit that passed CI, at the manifest's `composeFile`).

**V1 limitation:** a `repository` source is refused for any target in a `production` environment. The spec lets an admin grant an exception but defines no place to record one, so none is honored (`requireSourceForEnvironment`, `internal/app/apps.go`; test `TestAppsUpdate_RefusesARepositorySourceWhileAProductionTargetExists`). Production Compose content always comes from the control plane.

Either source runs through the same closed pipeline (ADR-0006), in this order: a **raw pass** over the YAML tree (anchors and merge keys expanded and checked as if written inline; `version`, port ranges, short port syntax, string-form `command`/`entrypoint` and list-form `environment` rejected), the pinned `compose-go` v2.15.0 loader, a **model pass** against an allowlist, image rewriting, then both passes again. Tests: `TestCheckRaw_RejectsSourceForms`, `TestCheckRaw_RejectsPrivilegedConstructsIntroducedByAnchorsAndMerges`, `TestCheckModel_RejectsDeniedServiceKeys`.

What the model pass allows (`internal/deployments/compose/schema.go`):

- Services with `image`, `command`, `entrypoint` (list form), `environment`, `ports` (long syntax; `host_ip` must be `127.0.0.1`, `::1` or an address in the target's `allowed_bind_addresses`), `expose`, `healthcheck`, `restart`, `depends_on`, `volumes` (named volumes and `tmpfs` only), `networks`, `labels`, `logging`, `user`, `working_dir`, `read_only`, `init`, `tmpfs`, `stop_signal`, `stop_grace_period`, `mem_limit`, `cpus`, `pids_limit`, `ulimits`, `deploy`.
- Bind mounts, `privileged`, `network_mode`, `pid`, `devices`, `build`, `env_file`, profiles and any key not listed are rejected as `COMPOSE_REJECTED`. Top-level `name` must be the target's project; volume and network names cannot be set explicitly or attach to `external` resources.
- Four keys are admitted only through exact per-service exceptions in `compose_exceptions`: `cap_add` (only `NET_BIND_SERVICE`, `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `FOWNER`, `KILL`), `sysctls` (only `net.*`, exact value), `extra_hosts` and `shm_size` (`TestExceptions_*`).
- Ownership labels (`dev.supermgmt.owner=<app_target_id>` and the deployment label) are injected by SuperMgmt into every service, volume and network.

Variables and secrets: `${NAME}` takes a value from `variables`; `${secret:<ref>}` in an `environment` value is replaced by a secret reference from `secret_refs` and never appears in the stored Compose, the plan or the API. A `$` anywhere else must be `$$`. Interpolating the frozen file with an empty environment is the identity (`TestFrozen_EmptyEnvInterpolationIsIdentity`).

### Manifest

`.supermgmt.yaml` in the repository (see [`examples/app.supermgmt.yaml`](../examples/app.supermgmt.yaml)) carries hints only: `spec.deployment.service`, `composeFile`, `spec.health` and `spec.rollback.mode`. Images, targets, secrets, CI policy, backups and similar keys are rejected as `MANIFEST_INVALID`; the manifest is at most 64 KiB (`internal/deployments/manifest`). `rollback.mode: manual` can tighten what the target allows; `automatic` never loosens it (`TestEffective_RollbackPrecedence`).

### Health checks

A target needs an effective health check or the deployment is rejected (`TestFinalize_ATargetWithoutAnEffectiveHealthCheckIsRejected`). The target's `deployment_policy.health` wins; the manifest `spec.health` is used only when the policy has none (`TestFinalize_AManifestHealthHintStandsInWhenThePolicyHasNone`).

| Field | Allowed | Default |
|---|---|---|
| `type` | `http`, `tcp`, `docker-health` (node scope); `http`, `https` (control-plane scope, policy only) | |
| `timeout` | 1s to 30s | 3s |
| `interval` | 1s to 1m | 5s |
| `attempts` | 1 to 60 | 12 |
| `path` (http) | absolute path of `A-Za-z0-9._~/-`, no query or fragment | |

These bounds are not in the spec; they are a V1 decision enforced in `internal/app/apps.go` and the manifest parser. `command-template` and `systemd-active` checks are rejected for app targets.

Where a node-scope check may connect is never taken from user input. The destination is resolved from a port the frozen Compose model publishes: a manifest check only on `127.0.0.1` or `::1`; a control-plane check also on an address in `allowed_bind_addresses`. A URL or host in a manifest health block is `MANIFEST_INVALID` (`TestManifest_RejectsHealthURLAndHost`, `TestM4_ManifestHealthOffNodeRejected`); a port the model does not publish is rejected (`TestFinalize_AHealthCheckOnAPortTheModelDoesNotPublishIsRejected`). Control-plane checks go through the outbound filter and may reach private ranges only if `health.allowed_private_cidrs` lists them.

### Deployment policy

`deployment_policy` of a target:

```json
{
  "rollback": "automatic",
  "stateful": false,
  "allowed_bind_addresses": [],
  "pre_deploy_backup": null,
  "snapshot": false,
  "health": {"type": "http", "scope": "node", "port": 8080, "path": "/health"}
}
```

- `snapshot: true` is refused (`INVALID_ARGUMENT`): Proxmox snapshots in the deployment path are not part of M4.
- `stateful: true` in a `production` environment requires `pre_deploy_backup`; finalization and `app_target.write` reject it otherwise (`TestFinalize_StatefulProductionWithoutABackupIsRejected`, `TestAppsUpdateTarget_ProductionStatefulKeepsItsBackupRule`).
- `pre_deploy_backup` is `{template: "postgres-dump", args: {container, database}, timeout}` (timeout 1s to 1h, default 10m). It is the only backup template. The dump goes to `/var/lib/supermgmt/db-backups` on the node (`internal/transport/ssh/templates/compose_stage.go`).

## CI policy and what is checked

`ci_policy` fixes the repository (by ID), the branch, the allowed events (`pull_request*` events never qualify), the deploy workflow path, an optional reusable deploy workflow, and the required checks (name, GitHub App ID that reports them, workflow path).

SuperMgmt asks GitHub itself; it does not believe the requester. For the exact commit it requires each configured check to be `success` for the latest attempt, reported by the configured app, and traced through the Actions check suite to a workflow run whose `path`, `head_branch`, `head_sha` and `event` match the policy (`internal/providers/github/checks.go`). The fake models re-run attempts, suite-to-run mapping and pagination; the real behavior is **not verified against real GitHub**.

While CI is not decided the deployment waits in `waiting_ci` without a job. Polling starts at `github.ci_poll_initial` (15s) and backs off to `github.ci_poll_max` (2m); `github.ci_timeout` (2h) ends the wait. A failed required check fails the deployment at once (`CI_NOT_PASSED`, reason `CHECK_FAILED`); a check that never appears keeps waiting until the deadline and then fails with `CHECK_MISSING`; otherwise `CI_TIMEOUT` (`TestCIWatch_AFailedCheckFailsTheDeploymentAtOnce`, `TestCIWatch_AMissingCheckWaitsForTheDeadlineThenFailsAsMissing`, `TestCIWatch_PendingChecksPastTheDeadlineFailAsATimeout`). In server mode a verified webhook triggers an immediate re-evaluation and polling continues only as a backstop at `ci_poll_max`; in local mode there is no webhook and SuperMgmt only polls (`TestCIWatch_ServerModePollsOnlyAsABackstopAtTheMax`).

Finalization reads the manifest and Compose file from the commit that passed CI, never from the branch head (`TestFinalize_UsesCIPassedCommitNeverBranchHead`).

### How a digest is bound to the commit

Each deployed image digest must be bound in one of three ways (`internal/app/binding.go`):

- **Attestation:** GitHub holds a SLSA v1 build-provenance attestation for the digest, verified with `sigstore-go`: the certificate SAN is `https://github.com/<owner>/<repo>/<deploy_workflow>@refs/heads/<branch>`, the issuer is the Actions issuer, and the certificate's repository ID and commit SHA match. Consequence of how the code builds the SAN: **the workflow that signs the attestation must be the file named by `ci_policy.deploy_workflow`** (as in [`examples/github-actions.yml`](../examples/github-actions.yml), where build and deploy are jobs of one workflow). Tested against the virtual Sigstore only (`TestFinalize_AnAttestationBindsTheDigestAndIsAskedForTheExactCommit`); real attestations are **not verified against real GitHub**.
- **OIDC claims:** the request came from a GitHub Actions token whose verified `sha` is the commit. The claims are stored when the request is accepted, so a long CI wait past the token's lifetime is fine (`TestFinalize_OIDCClaimsBindTheDigestAfterTheTokenExpired`).
- **Pinned:** the digest is in the app's `image_policy.pinned`.

An environment with `require_provenance: true` accepts only an attestation for the deployed service; pinned sidecars stay allowed (`TestFinalize_RequireProvenanceAcceptsOnlyAnAttestation`). A rejected attestation falls back to the pinned set; one that cannot be verified at all (GitHub unreachable, trusted root stale) is retried, not treated as unverified (`TestFinalize_ARejectedAttestationFallsBackToThePinnedSet`, `TestFinalize_AnUnverifiableAttestationIsRetried`). A digest bound by none of these fails as `DIGEST_UNBOUND`.

## Request a deployment

### From the CLI

```bash
sm deploy myapp production --commit <40-hex sha> --image web=sha256:<64 hex> --wait
sm deployments list --app myapp
sm deployments get <deployment-id> --follow
sm deployments cancel <deployment-id>
sm rollback myapp production            # newest deployment of the target -> its newest earlier known-good
sm rollback myapp production --to <known-good-deployment-id>
```

`--wait` blocks until the deployment succeeds, fails or is rolled back and exits non-zero unless it succeeded. The TUI has Applications and Deployments screens (keys 8 and 9) with a deploy wizard.

### From GitHub Actions

[`examples/github-actions.yml`](../examples/github-actions.yml) is the conceptual workflow (it follows SPEC §28: `contents: read` by default, `id-token: write` only in the build and deploy jobs, actions pinned to a SHA; `TestSpecExamples_GitHubActionsPermissions`). The deploy job requests an Actions OIDC token whose audience is `github.oidc_audience` (default: `server.public_url`) and calls `POST /api/v1/deployments` with an `Idempotency-Key`. This works on the server's HTTPS listener only; GitHub Actions tokens are not accepted when no audience is configured (`TestGitHubActionsTokensAreAcceptedOnlyWithAnAudience`).

The token is verified against the Actions JWKS: issuer, audience, RS256, `iat` not older than 5 minutes (60 seconds of skew), `jti` accepted once (`TestOIDC_ReplayIsRefused`), and `MatchClaims` requires the policy's repository ID, owner ID, `ref`, `sha` equal to the requested commit, allowed `event_name`, `workflow_ref`, and `job_workflow_ref`; a pull-request token never matches (`TestMatchClaims`).

**Automation identity.** `app.write` with `automation_identity: true` creates (or links) an identity `repository_id:<id>:workflow:<deploy_workflow>` with **no role**. An admin must grant it a role such as `deployer` (or a narrower policy rule) before it can do anything; its credentials carry only the scopes `deployment.create` and `deployment.read`. Unlinking revokes its open OIDC credentials (`TestAutomation_ChangingTheDeployWorkflowMovesTheLinkAndRevokesTheOldCredentials`, `TestCredentialStatus_GitHubOIDC`).

**V1 limitation:** no environment requires an `environment` claim in the token, because the spec defines no field to configure it. `MatchClaims` supports the check, but the caller never turns it on (`internal/app/deployments.go`, `github.EnvRequirement{}`). The `environment:` line in the example workflow documents intent; SuperMgmt does not enforce it.

Real Actions tokens, the real JWKS and fork behavior are **not verified against real GitHub**.

### What the request does

`POST /api/v1/deployments` answers 202 with a deployment in `created` or `waiting_ci` (ADR-0011). Nothing is frozen yet. When CI is decided, finalization runs in one transaction: it freezes the Compose model for that target, stores the execution snapshots, builds the plan, evaluates policy (including the backup sub-action) and enqueues the job. A production target then waits for approval (`awaiting_approval`; `TestFinalize_ProductionWaitsForApproval`). The requester's credential is checked again at finalization (`TestFinalize_ARevokedRequesterFailsTheDeployment`). `POST /deployments/{id}/cancel` ends a deployment that has no job yet and delegates to `job.cancel` otherwise.

## Lifecycle

States: `created`, `waiting_ci`, `awaiting_approval`, `queued`, `preparing`, `staging`, `deploying`, `verifying`, `rolling_back`, `interrupted`, `succeeded`, `failed`, `rolled_back`, `rollback_failed`, `cancelled` (`TestDeploymentState_TransitionTable`).

Steps, each with a deadline (`internal/deployments/steps.go`): `preflight` (2m), `pre-deploy-backup` (policy timeout, only when configured), `pull` (15m), `materialize` (1m), `verify-on-node` (2m), `deploy` (10m), `health-check` (attempts times interval plus timeout).

- **Preflight is read-only** and runs before anything is pulled or written. It checks the node pin, the Compose version, project/volume/network ownership labels (`PROJECT_NOT_OWNED`), host ports (TCP and UDP) free or owned, the health capability, and **free disk of at least the sizes of the images not already on the node plus 1 GiB** on both the Docker root and `deploy_root`. An image size that cannot be established fails closed (`PREFLIGHT_FAILED`, cause `IMAGE_SIZE_UNKNOWN`). Tests: `TestPreflight_ProjectNotOwned`, `TestPreflight_ForeignPort`, `TestPreflight_VolumesAndNetworksMustBeOwned`, `TestPreflight_DiskThreshold`, `TestPreflight_UnknownImageSizeFailsClosed`. A failing backup stops the deployment before any image is pulled (`TestBackup_FailuresNeverReachComposeUp`).
- **Materialize** writes `<deploy_root>/<project>/<deployment_id>/` with the frozen `compose.yaml` and `secrets/<service>.env`, refusing symlinks and an existing directory (`TestFixtures_MaterializeRefusesSymlinks`, `TestMaterializeRefusesAnExistingDeploymentDirectory`).
- **Verify-on-node** runs the node's `docker compose config` and compares it with the model SuperMgmt froze, with the CLI-default normalization table and hash-only comparison of resolved environment values (`TestFixtures_EnvHashResolvedPrecedenceAndTamper`). A difference is `STAGING_FAILED`.
- **Deploy** runs `docker compose up --detach --pull never --no-build --remove-orphans` under a non-blocking `flock /run/supermgmt/locks/<project>.lock`. Volumes are never removed.
- **Locks:** exclusive on the app target, the Compose project on the node and every published host port (and the rollback target's ports, so the set is identical after a recovery claim); `RESOURCE_LOCKED` while a deployment holds them (`TestDeploymentLocks_TheRollbackTargetsPortsAreLockedToo`).

A deployment that succeeded is **known good**. Only a succeeded deployment can be a rollback source.

### Health failure and rollback

If health fails after `deploy`, rollback is automatic only when all of these hold (`internal/deployments/rollback.go`, `TestRollbackAvailable_Table`): the deployment is `kind: deploy`; the effective mode is `automatic` (target policy, tightened by the manifest); the target is not `stateful`; the environment sets `allow_automatic_rollback: true` (default false); a known-good deployment exists. Otherwise the deployment ends `failed` with `HEALTH_FAILED` and the cause of the first failing condition (`TestSettleVerification_UnhealthyWithoutRollbackFailsWithItsCause`). The automatic rollback redeploys the frozen rollback target into a new directory and ends `rolled_back` or `rollback_failed` (`TestM4_HealthFailureRollsBackToKnownGood`).

A manual rollback (`sm rollback`) creates a `kind: rollback` deployment. Its plan binds the known-good deployment's frozen snapshots: Compose model, image digests, **exact secret versions**, and its health and policy snapshots. Later edits to the app's Compose, health checks or secrets do not change what is restored, and rotating a secret changes nothing in an existing plan (`TestRollbackPlan_BindsKnownGoodSnapshot`, `TestRevalidateRollback_AfterSourceEditAndRotation`). If a bound secret version or snapshot is gone the rollback is refused before any change (`ROLLBACK_UNAVAILABLE`; `TestRollback_MissingVersionIsUnavailableBeforeAnythingIsEnqueued`). Rollback needs no CI gate; production still needs approval (`TestRollback_ProductionRollbackWaitsForApproval`).

A failed deployment ends with its reason and, when one was recorded, its cause: `sm deployments get` shows `reason: ROLLBACK_UNAVAILABLE (STATEFUL)`, and `--wait` errors and the TUI timeline show `ROLLBACK_UNAVAILABLE: STATEFUL` (`state_cause` in the API).

Old deployment directories on the node are collected after a deployment ends `succeeded` or `rolled_back` (`internal/app/deploy_gc.go`, template `compose.gc`). The newest five deployments of the target are always kept. Beyond those, only a `rolled_back` deployment, or a `failed` one that never started changing services, is removed. A known-good deployment, the current deployment and its frozen rollback target are never removed (`TestCollectableDeployments`, `TestDeployHandler_SuccessCollectsOldDirectoriesBeyondTheNewestFive`). A collection failure never fails the deployment; it leaves a `deployment.gc_failed` event (`TestDeployHandler_AFailingCollectionNeverFailsTheDeployment`).

### Interruption and recovery

A job interrupted mid-deployment is never re-run blind. Reconciliation needs proof that each dispatched command completed (exit status recorded) and two matching container samples at least 30 seconds apart. Without proof the job is held with its locks (`TestReconcileDeploy_KilledCLIHeldDespiteStableSamples`, `TestFixtures_KilledComposeUpHasNoProof`). Depending on the evidence it is failed as `INTERRUPTED_BEFORE_DEPLOY`, resumed forward after re-running claim-time revalidation, or, after a partial update, recovered by restoring the plan's frozen rollback target. That safety recovery runs as the `system` actor, skips requester, policy and quorum revalidation, never waits for approval, and dispatches only restore steps (`TestReconcileDeploy_ForwardResumeAfterDeployingOnlyRollsBack`, `TestClaimRecovery_StalePlanRevokedRequesterLostQuorum`, `TestClaimRecovery_KeepsLocksNeverAwaitingApproval`, `TestDeployStage_ForwardStepsRefuseUnderSafetyRecovery`). Restoring a backup neutralizes deployments like jobs (`TestRestoreNeutralizesDeployments`).

## Secrets

Secrets referenced by apps live under `apps/` (`secret://apps/...`). `secret.write` on that prefix rejects NUL, CR, LF and invalid UTF-8. The values are written to `secrets/<service>.env` on the node as `NAME=value` with `format: raw` (byte-exact; corpus test `TestEnvFile_CorpusRoundTrip`). Plans bind `{secret name, version}`; a new deployment takes the newest version at finalization; a missing version fails the deployment (`TestFinalize_BindsTheNewestSecretVersion`, `TestFinalize_AMissingSecretFailsTheDeployment`). Secret values are never in plans, API views, events, logs or backup archives of the control plane (`TestM4_SecretNeverOnControlPlane`, e2e). That scan excludes the node side and CLI stdout.

## Known limits of this version

- Compose CLI **5.5.1 only**; one node per target; one target per (app, environment).
- `repository` Compose source refused in production environments.
- Health bounds (30s / 1m / 60) are a V1 decision, not spec text. Health types limited to `http`, `tcp`, `docker-health` on the node and `http`/`https` from the control plane.
- No environment-claim requirement for Actions tokens.
- `snapshot` in a deployment policy and the Proxmox items deferred from M3 are not available.
- Real GitHub, GHCR and Sigstore behavior, including redirects, the TUF trust anchor and attestation verification: **not verified**, see [the manual checklist](manual-checks/m4-real-github.md).
