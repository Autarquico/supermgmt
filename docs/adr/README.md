# Architecture Decision Records

Decisions that the master specification (`docs/spec/SUPERMGMT-SPEC.md`) leaves to the implementation, or that it fixes and we record with their rationale. An ADR may define what the spec leaves open; it may never relax a spec constraint (§46). Changing a constraint requires a spec change.

Process: copy the format of an existing ADR, open it as `Proposed` in the PR that needs it, and mark it `Accepted` when that PR merges. Accepted ADRs are not edited; they are superseded by a new ADR.

| ADR | Title | Status | Milestone |
|---|---|---|---|
| [0001](0001-sqlite-driver.md) | SQLite driver and connection settings | Accepted | M0 |
| [0002](0002-uuidv7.md) | UUIDv7 identifiers | Accepted | M0 |
| [0003](0003-aes-gcm-envelope.md) | AES-256-GCM envelope encryption | Accepted (envelope + file KEKs in M1, [ADR-0016](0016-m1-secrets-slice-and-ssh-identity.md); rotation, export and import in M2, [ADR-0021](0021-key-and-identity-management.md)) | M0 |
| [0004](0004-openssh-release-signatures.md) | OpenSSH release signatures | Accepted (implemented in M2) | M0 |
| [0005](0005-daemon-process-model.md) | Single-daemon process model | Accepted (implemented in M1) | M0 |
| 0006 | Pinned compose-go version | Reserved | M4 |
| 0007 | Execution snapshots | Reserved (§46) | M4 |
| 0008 | Secret versions | Reserved (§46) | M4 |
| [0009](0009-node-provisioning.md) | Node provisioning (`node.setup`) and the dedicated `supermgmt` user | Accepted | M1 |
| 0010 | Secret env-file encoding | Reserved (§46) | M4 |
| 0011 | Provisional deployment API | Reserved (§46) | M4 |
| [0012](0012-route-metadata.md) | Route metadata | Proposed | M2 |
| [0013](0013-generic-job-state-machine.md) | Generic job state machine | Accepted | M0 |
| [0014](0014-local-api-and-daemon-lifecycle.md) | Local API transport and daemon lifecycle | Accepted | M1 |
| [0015](0015-ssh-transport-and-command-templates.md) | SSH transport and command templates | Accepted | M1 |
| [0016](0016-m1-secrets-slice-and-ssh-identity.md) | M1 secrets slice and the instance SSH identity | Accepted | M1 |
| [0017](0017-server-transport-credentials-sessions.md) | Server transport, credentials and sessions | Proposed | M2 |
| [0018](0018-oidc-adapter.md) | OIDC adapter | Proposed | M2 |
| [0019](0019-release-pipeline-and-installer.md) | Release pipeline and installer | Proposed | M2 |
| [0020](0020-backup-format-and-offline-restore.md) | Backup format, offline restore and startup order | Proposed | M2 |
| [0021](0021-key-and-identity-management.md) | Key and identity management (extends 0016) | Proposed | M2 |
| [0022](0022-join-enrollment.md) | Join and enrollment (minimal) | Proposed | M2 |
| [0023](0023-pve-identity-privileges-compatibility.md) | Proxmox identity, privileges, compatibility matrix and fake fidelity | Proposed | M3 |
| [0024](0024-proxmox-discovery.md) | Proxmox discovery model | Proposed | M3 |
| [0025](0025-proxmox-power-jobs-task-correlation.md) | Proxmox power jobs, task correlation and quiescence | Proposed | M3 |
| [0026](0026-appliance-installer.md) | Appliance installer (`proxmox-lxc`, `auto`) | Proposed | M3 |
| [0027](0027-upgrade-and-uninstall.md) | Upgrade and uninstall | Proposed | M3 |
