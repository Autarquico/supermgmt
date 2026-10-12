# ADR-0024: Proxmox discovery model

- Status: Proposed
- Spec: §6.2, §15.1, §15.3, §21.1, §39.3; ADR-0023

## Context

§15 asks for periodic and on-demand discovery of cluster nodes, VMs and LXCs with status, configured resources, metrics and storage metadata, with discovered guests kept apart from managed ones. Proxmox power state and SSH reachability are separate facts.

## Decision

### Rows

| PVE object | `nodes.kind` | `native_id` |
|---|---|---|
| cluster member | `proxmox.node` | `node/<name>` |
| QEMU VM | `proxmox.qemu` | `qemu/<vmid>` |
| LXC | `proxmox.lxc` | `lxc/<vmid>` |

- VMIDs are cluster-unique, so a migrated guest keeps its row; only `metadata_json.pve_node` changes.
- `metadata_json` = `{pve_node, vmid, type, template, maxcpu, maxmem, maxdisk}`. Metrics (`cpu`, `mem`, `disk`, `uptime`) fill the existing node metrics. Storages (`/cluster/resources?type=storage`: id, node, plugin, content, total, used) are provider observations.
- The VM/LXC tree is derived from `pve_node`; there is no parent column.
- Guests are always `discovered` in M3 (promotion to managed is M4). Power state is an observation (`proxmox.status`), never `reachability`.

### Absent versus inaccessible

A guest missing from a successful sync is `absent` only if the token still holds `VM.Audit` over it (per `GET /access/permissions`); otherwise it is `inaccessible`, and its capabilities are dropped. Rows are never deleted: removing a provider or losing a guest never deletes provider resources (§29.4).

### Sync

- One loop per provider, every `sync_interval` (default 30s), plus on demand: `POST /api/v1/providers/{id}/refresh` runs the same discovery, requires `provider.read`, is rate-limited, and writes observations and discovered rows only.
- One sync in flight per provider. Results go to `providers.status` and `last_sync_at`; status transitions are audited once.
- The admin doctor reports a `providers` check (status, last sync, last error). The installer uses it, bounded, as proof of the first discovery.

### Transport and trust

- The client uses `netguard.NewClient` (provider endpoints may be private, §21.1) with the production option `WithRootCAs`; filtering and the no-redirect rule are unchanged.
- `verify_tls: true` with `ca_file` (the appliance pushes the host's public `/etc/pve/pve-root-ca.pem`). `verify_tls: false` is rejected by validation.
- Guest addresses: LXC `/interfaces`, QEMU guest agent when available; absence is normal.

## Consequences

- A token whose ACL shrinks does not make guests look deleted.
- Snapshot, backup and task-history listings are deferred to M4.
