# ADR-0005: Single-daemon process model

- Status: Accepted (implementation in M1)
- Spec: §2.1.1, §4

## Decision

Exactly one daemon process owns the database, job workers, sync loops and connectors. TUI, CLI and MCP are always API clients; there is no in-process backend. The daemon holds two `flock` locks (canonical database path and socket path) for its lifetime. Only the offline commands listed in §2.1.1 open the database directly, and only while the database lock is free.

## Consequences

Local and remote use share one code path. M0 ships only offline commands (`version`, `completion`, `config validate`, `doctor --offline`); every other command arrives with the daemon and API in M1.
