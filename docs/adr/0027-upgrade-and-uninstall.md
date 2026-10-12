# ADR-0027: Upgrade and uninstall

- Status: Proposed
- Spec: §3.2 (downgrade protection), §29.1, §29.3, §29.4; ADR-0020, ADR-0026

## Context

§29.3 requires a verified release, a pre-upgrade backup, an atomic binary swap, forward migrations and a health check, with database rollback by backup only. §29.4 separates software removal from data deletion and lets an appliance uninstall remove the LXC only when installer metadata proves ownership. Crashes during either must leave a recoverable state.

## Decision

### Upgrade state

`/var/lib/supermgmt/upgrade.json` (temp file, fsync, rename, directory fsync) holds the phase (`prepared → stopped → backed_up → swapped → started → done`) and the sha256 of the old and new binaries. A rerun with an unfinished state resumes or rolls back by phase; it never overwrites the known-good binary.

### Order

1. Version check: a lower version is refused unless `--allow-downgrade`, which is audited.
2. Free-disk check.
3. Stage `sm.new` (fsync); hard-link the current binary as `sm.prev` (copy + fsync if linking fails). The live path is never removed.
4. Stop the service, verify termination (unit inactive, main PID gone) and take the database lock.
5. Pre-upgrade backup with `sm backup create --offline`: read-only open, never migrates, never activates; the archive's `schema_version` must equal the pre-upgrade schema.
6. Release the lock; `rename(sm.new, sm)`; directory fsync.
7. Start; the daemon applies forward migrations; wait for readiness.

The spec's order (backup, then stop) becomes stop, then backup: the archive is taken with the database quiescent and the lock held.

### Failure policy

- Backup fails before the swap → restart the old service, exit 9.
- Readiness fails after the swap → stop, verify termination, take the lock, read the schema version:
  - unchanged → `rename(sm.prev, sm)`, start the previous version, exit 9;
  - advanced → leave the service stopped and print the exact `sm install restore --archive <pre-upgrade archive>` and previous-binary commands, exit 9. No automatic data restore.

### Appliances

On a Proxmox host, `sm install upgrade` requires the appliance record and a matching `install_id` in the container's description and the `supermgmt` tag. With several appliances `--vmid` is required. It pushes the verified binary and runs `pct exec <vmid> -- sm install upgrade --binary <path>`.

### Uninstall

- Default: stop, disable and remove the unit and the binary; configuration, data and backups stay.
- Data deletion is a separate confirmation: `--purge-data` plus a typed confirmation; non-interactive runs need `SUPERMGMT_YES=1` and `--purge-data`.
- On a Proxmox host (same ownership proof) the default keeps the LXC and removes the software inside it; `--purge-data` with the typed VMID destroys the LXC and removes that install's per-install identities (ADR-0023). Other appliances are untouched by construction.

## Consequences

- An N-1 archive taken during upgrade restores with the N-1 binary.
- A failed migration never silently leaves a half-upgraded service running.
