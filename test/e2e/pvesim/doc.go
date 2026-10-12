// Package pvesim simulates a Proxmox VE 9.x host for the M3 e2e tests: the command-line tools the
// installer runs (pct, pvesh, pveum, pvesm, pveam, pveversion) and the REST API of a node.
//
// The tools are shims in a Debian systemd container (the "PVE host") that forward their argv and
// stdin to a Sim in the test process. The Sim holds the state of the host, parses every command
// strictly (an unknown option or a malformed value fails with exit 255, as the real tools do) and
// maps containers onto Docker: a guest of `pct create` is a privileged systemd container on the
// test network, started, stopped, executed in and destroyed through the docker CLI. Users, roles,
// ACLs, tokens and guests are mirrored into the fake PVE API (internal/providers/proxmox/pvefake),
// which runs in a container of its own at 10.77.0.1:8006, so a token created with pveum
// authenticates against the API with exactly the privileges pveum granted.
//
// Fidelity contract (ADR-0023): what is implemented follows the PVE 9 admin guide and the man
// pages of the tools as the author knows them. Option names and error classes are meant to be
// exact, message texts are approximations, and everything stays "fake-verified" until the manual
// real-host run (docs/manual-checks/m3-real-pve.md).
//
// Known gaps: no cluster and no QEMU guests from the tools; tools print JSON only when asked for
// it (list commands without --output-format json are refused instead of drawing a table); a power
// task run through the API changes the fake's guest but not the Docker container; a removed token
// stays valid in the API but holds no privilege.
package pvesim
