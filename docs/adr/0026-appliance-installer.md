# ADR-0026: Appliance installer (`proxmox-lxc`, `auto`)

- Status: Proposed
- Spec: §2.3, §3.3–3.7, §8.1; ADR-0019, ADR-0020, ADR-0023, ADR-0024

## Context

§3.5 fixes what `sm install proxmox-lxc` does on a Proxmox host, the secure token transfer and a rollback journal that undoes only created resources. The installer runs as root on the host, so its inputs, subprocesses and crash windows need explicit rules.

## Decision

### Execution safety

- PVE tools run by absolute path (`/usr/sbin/pct`, `/usr/sbin/pveam`, `/usr/bin/pvesh`, `/usr/sbin/pveum`, `/usr/bin/pveversion`) with a clean environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`). `pct exec <vmid> -- argv…` never goes through a shell.
- Typed validation before use: VMID 100–999999999; storage and bridge `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` and present in the discovered list; hostname RFC 1123; addresses parsed with `net/netip`; paths absolute and clean, no `..`, no leading `-`.
- Commands that carry the token run in `Sensitive` mode: stdout and stderr are captured in memory and errors are sanitized.

### Container shape

`pct create` gets a fixed argument set: `--unprivileged 1 --features nesting=0,keyctl=0 --onboot 1 --tags supermgmt --description "supermgmt install <install_id>"`, sizing from §2.3, no `mpN` and no raw `lxc.*` keys. A `pct config` readback after creation must match, or the install rolls back.

### Steps

`install_id` is fixed and the journal created (and its directory fsynced) before any side effect. Brackets give the §3.5 step.

| Step | Action |
|---|---|
| S1 [1] | `flock /run/lock/supermgmt-installer.lock` |
| S2–S5 [2–5] | version, VMID, storages, bridge |
| S6 [6] | Debian 13 template via `pveam` (never deleted on rollback: a shared cache, reported) |
| S7–S9 [7–9] | create + readback, network, start + wait |
| S10 [10] | push the already-verified running `sm` |
| S11 [11] | as root inside: `sm install server --no-start --tls self-signed` (unit written, not enabled) |
| S11b | as `supermgmt`: `sm server init` |
| S11c | verify `/run` is tmpfs and the account exists; create `/run/supermgmt-bootstrap` 0700 `supermgmt` |
| S11d | as `supermgmt`: `sm providers check --offline --tls-only --endpoint E --ca-file C` (verifies the chain the endpoint actually serves; mismatch → refuse before any token exists) |
| S12a–c [12] | per-install user, roles, ACLs (ADR-0023) |
| S12d | token (name journaled first; `Sensitive`) |
| S12e–h | host temp dir (path journaled first) and file `O_EXCL\|O_NOFOLLOW` 0600; `pct push` with owner/mode; readback (fallback `chown/chmod`); delete host temp |
| S13 [13] | as `supermgmt`: `sm secrets import --offline --name providers/<name>/token --from-file … --delete-source` |
| S14 [14] | provider config + CA (`/etc/pve/pve-root-ca.pem`, or `SUPERMGMT_PVE_ENDPOINT`/`SUPERMGMT_PVE_CA_FILE`) |
| S15a–c [15] | as `supermgmt`: `sm providers check --offline <name>`; `systemctl enable --now`; readiness and doctor `providers` ok within 120s |
| S16 [16] | commit, then print the CA PEM, its fingerprint, the bootstrap code and the backup recommendation |

Every offline command inside the container except S11 runs as `supermgmt` (`runuser -u supermgmt --`), so the database, WAL/SHM, keys and config are owned by the service user.

### Journal

- `/var/tmp/supermgmt-installer-<install_id>/journal.jsonl`, directory 0700, file 0600. Each append is followed by `fsync(file)`; the directory is fsynced on creation.
- Entries `{seq, step, phase: pending|done|undone, resource, name}`. A torn last line is discarded.
- Rollback runs in reverse, journals its own progress and is idempotent: every undo reads back existence first.
- A `pending` entry is undone only when readback shows a resource carrying our `install_id` (in its name, or in the LXC description). Otherwise the entry is kept and reported for manual recovery (exit 7).
- Token recovery revokes the token by name if it exists, removes the host temp dir, and removes `/run/supermgmt-bootstrap` in the container.
- PVE CLIs run without a kill deadline during create, start and template download. If a CLI fails with the state uncertain (guest `lock: create`, task still running), rollback waits for the task to stop, bounded; if it is still uncertain the journal is kept and the run reports "pending recovery" (exit 6).

### Commit

1. Write the appliance record `/var/lib/supermgmt-installer/appliances/<vmid>.json` (root 0600; temp file, fsync, rename, directory fsync): `install_id`, vmid, identities, template, version, CA fingerprint.
2. Append `committed` to the journal.
3. Remove the journal directory.

A journal counts as committed if it has `committed` or if a record with the same `install_id` exists; recovery then only finishes cleanup. A stale uncommitted journal found by a later run is rolled back first, after confirmation (non-interactive: exit 7 with instructions).

### `auto`

Proxmox host → `proxmox-lxc`; macOS, or Linux with `XDG_CURRENT_DESKTOP`, `WAYLAND_DISPLAY` or `DISPLAY` → `local`; other Linux → interactive prompt for `server`, non-interactive → exit 2 asking for `SUPERMGMT_MODE`. Non-interactive runs fail on an ambiguous storage or bridge (exit 2).

## Consequences

- The token never appears in arguments, environment, output, logs or the journal.
- `sm` gains offline commands the installer relies on: `server init`, `providers check --offline`, `secrets import --offline --from-file --delete-source`, `install server --no-start --tls self-signed`.
- A downloaded template survives rollback; the run says so.
