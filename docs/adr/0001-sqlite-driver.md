# ADR-0001: SQLite driver and connection settings

- Status: Accepted
- Spec: §9, §20.4, §23, §34

## Context

The spec fixes SQLite as the default store, requires static cross-compiled releases for darwin/linux × amd64/arm64 (§36) and makes durability of job intents a safety property (§20.4: an intent must be durable before a remote mutation is dispatched).

## Decision

- Driver: `modernc.org/sqlite` (pure Go). Releases build with `CGO_ENABLED=0`.
- Every connection sets `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=<storage.sqlite.busy_timeout>` and `synchronous=FULL`; write transactions begin with `BEGIN IMMEDIATE` (`_txlock=immediate`).
- Two pools: a writer pool with exactly one connection, and a reader pool (4 connections, `query_only=ON`).
- Tables are `STRICT`; every enum from §9 is a `CHECK` constraint; timestamps are integer Unix milliseconds supplied by an injected clock, never `CURRENT_TIMESTAMP`; identifiers are lowercase UUIDv7 text.
- `events` is append-only at the database level: triggers abort `UPDATE` and `DELETE`.
- Migrations are forward-only, embedded with `go:embed`, and a database whose schema is newer than the binary is refused.

## Consequences

- `synchronous=FULL` costs write latency compared with `NORMAL`; it is required so a committed intent survives power loss before dispatch. Write volume is small (control-plane events, not metrics), so the cost is acceptable.
- One writer connection serializes writes in-process, matching SQLite's own single-writer model and making the single-transaction idempotency model of §23 hold.
- The pure-Go driver is slower than CGO drivers; profiling comes before any change (§34).
- `modernc.org/sqlite` and `modernc.org/libc` versions are tightly coupled; Dependabot updates them as a group and the migration tests run on every bump.
