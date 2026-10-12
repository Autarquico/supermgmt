// Package pvefake is a fake Proxmox VE 9.x HTTP API for tests (ADR-0023 fake
// fidelity contract). It is test-only: nothing outside *_test.go files and
// test harnesses may import it.
//
// Fidelity contract:
//   - unknown endpoints answer 501, unknown or malformed parameters 400, a
//     missing or wrong token 401, a missing privilege 403, and a failing
//     precondition (guest already running, locked, wrong node) 500, with the
//     JSON error document PVE uses ({"data":null,"message":...,"errors":{...}});
//   - privileges follow the pveum rules of the PVE 9 admin guide: roles are
//     granted to a user or token on a path, propagate to children, permissions
//     on a deeper path REPLACE those inherited from above, and a
//     privilege-separated token holds the intersection of its own and its
//     user's privileges;
//   - guests, tasks and locks are state machines; an impossible transition is
//     an error, and a power task changes the guest only when it ends "OK";
//   - task lists are newest first and paginated (default 50 per page) with a
//     top-level "total", so a client that reads one page misses tasks.
//
// Provenance (PVE documentation version, API viewer URL, date):
//   - PVE admin guide, chapter "User Management" (pveum), PVE 9.x:
//     https://pve.proxmox.com/pve-docs/chapter-pveum.html (read 2026-10-12);
//   - REST API schema: https://pve.proxmox.com/pve-docs/api-viewer/ (PVE 9.x),
//     endpoints /version, /cluster/resources, /access/permissions,
//     /nodes/{node}/tasks, /nodes/{node}/tasks/{upid}/status,
//     /nodes/{node}/{qemu,lxc}/{vmid}/status/{start,stop,shutdown,reboot}.
//
// NOT verified against a real host or the live API viewer in this
// implementation pass: field shapes were written from the published schema as
// the author knows it, and error message texts are approximations of PVE's.
// The status codes and the structure are what clients may rely on. Everything
// here stays "fake-verified" in docs/compatibility.md until the manual
// real-host run.
package pvefake
