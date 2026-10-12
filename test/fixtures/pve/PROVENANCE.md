# Provenance of the Proxmox VE fakes

Contract: [ADR-0023](../../../docs/adr/0023-pve-identity-privileges-compatibility.md), "Fake fidelity contract".

## What the fakes are built from

- The Proxmox VE API documentation (the published REST API schema of PVE 9.x,
  <https://pve.proxmox.com/pve-docs/api-viewer/>) and the PVE admin guide, chapter
  "User Management" (<https://pve.proxmox.com/pve-docs/chapter-pveum.html>), read on 2026-10-12.
- The author's knowledge of those documents when the fakes were written.

## What they are not built from

- They are **not** a dump of the live API viewer, and no response was recorded from a real
  Proxmox VE host. Field shapes were written from the documented schema; error message texts
  are approximations of PVE's. Only status codes and document structure are meant to be relied on.
- The CLI-side fakes (the installer's `PVE` port tests in `internal/installer`) reproduce
  `pct`, `pveam`, `pvesm`, `pvesh` and `pveum` output from the manual pages and documentation,
  not from captured terminal output.

## Where the fakes live

| Fake | Path | Covers |
|---|---|---|
| PVE HTTP API | `internal/providers/proxmox/pvefake` | `/version`, `/cluster/resources`, `/access/permissions`, `/nodes/{node}/tasks`, task status, guest power verbs |
| PVE CLI tools | `internal/installer/fakes_m3_test.go`, `internal/installer/appliance_fake_test.go` | `pct`, `pveam`, `pvesm`, `pvesh`, `pveum` |

## Status

Everything these fakes verify is "fake-verified" in [docs/compatibility.md](../../../docs/compatibility.md).
It becomes "real-verified" only after the manual run on a real PVE 9.x host
(`docs/manual-checks/m3-real-pve.md`). A change to a fake that alters a documented shape
must update this file and the matrix.
