# ADR-0023: Proxmox identity, privileges, compatibility matrix and fake fidelity

- Status: Proposed
- Spec: §15.2, §35, §3.5 steps 2 and 12; ADR-0016

## Context

§15.2 asks for a dedicated Proxmox identity with privilege separation, least-privilege roles, a tested compatibility matrix and separate read and write privilege sets. There is no real Proxmox host in CI: everything is verified against fakes, so the fakes themselves need a contract.

## Decision

### Per-install identities

Every appliance install draws an `install_id` (8 random hex digits) before any side effect. It creates only resources whose names carry that id:

| Resource | Name |
|---|---|
| user (realm `pve`, no password) | `sm-<id>@pve` |
| API token, `--privsep 1` | `sm-<id>@pve!sm` |
| read role | `SMAudit-<id>` = `VM.Audit, Sys.Audit, Datastore.Audit, Pool.Audit` |
| power role | `SMPower-<id>` = `VM.PowerMgmt` |
| ACLs | `SMAudit-<id>` on `/`, `SMPower-<id>` on `/vms`; each granted to the user **and** the token (privsep is the intersection) |

- A create that collides with an existing name fails; the installer never adopts a resource it did not create.
- Rollback and uninstall remove exactly these names. No shared user, role or ACL is ever created, modified or deleted.
- `SUPERMGMT_PVE_POWER=0` omits `SMPower-<id>` and its ACLs. Nothing for snapshots, backups or console is granted in M3, and nothing destructive.
- The token secret is stored as `secret://providers/<name>/token` with the value `<user>!<tokenid>=<secret>`, sent as `Authorization: PVEAPIToken=<value>`.

### Capabilities

Effective ability = discovered capability ∩ policy (§7). The provider reads `GET /access/permissions` and advertises `proxmox.vm.power` on a guest only when `VM.PowerMgmt` is effective on it. The power handler rechecks the permission right before dispatch.

### Supported versions

- Proxmox VE **9.x** only (Debian 13), amd64 only. Proxmox VE 8 reached upstream end of life in 2026-08 (Proxmox FAQ support table); any other version exits 3.
- `docs/compatibility.md` holds the matrix: CLI flags used (`pct create` options, `pct push --user/--group/--perms`, `pveum … --output-format json`), API endpoints and fields, task type names (`qmstart`, `vzstart`, `qmshutdown`, …), the template pattern, `/run` being tmpfs in the container. Each row is marked *fake-verified* or *real-verified*; the real column stays open until a real host run (`docs/manual-checks/m3-real-pve.md`).

### Fake fidelity contract

- The CLI fake and the API fake have separate contracts. Fixtures are JSON with a provenance file naming the PVE documentation version, the API viewer URL and the date.
- Fakes reject unknown flags and endpoints, enforce the token's privileges per path, and model state machines (guest stopped/running/locked, task running/stopped, template present/absent). Impossible transitions fail.
- Behaviour a fake cannot validate is listed as deferred in the matrix, never claimed.

## Consequences

- Two appliances on one cluster never share or remove each other's identities.
- Supporting a new PVE major version is a matrix change plus fixtures, then a real run.
- Until the manual real-host checklist runs, "Proxmox auto-LXC install works" (Appendix E) stays unchecked.
