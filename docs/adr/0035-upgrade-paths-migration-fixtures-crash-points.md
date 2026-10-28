# ADR-0035: Upgrade paths, migration fixtures and crash points

- Status: Proposed
- Spec: §26, §29.1, §29.3, §31 M6 ("beta migration tests"), §32; ADR-0020, ADR-0027, ADR-0034

## Context

§31 M6 asks for beta migration tests and an end-to-end upgrade on a clean machine; §29.3 fixes the upgrade order and failure policy. No release tag exists, so "every previous release" has no artifact to test against. The M3 upgrade e2e pins N-1 by commit and injects a synthetic version (`test/e2e/harness_m3_test.go`). The M3 security review left four upgrade residuals (SEC-4 hold, SEC-5 stale archive, F6 offline downgrade audit, F7 schema version parsed from text), and crash hooks exist only in process.

## Decision

### Supported paths

Any milestone build M1…M5 upgrades to N by forward-only sequential migrations. The upgrade e2e covers N-1 → N and the oldest → N in one jump. Upgrading from an authentic signed release is testable only after the first tag; until then it is a `[human]` row of the release checklist.

### Milestones and fixtures

- `test/e2e/milestones_test.go` lists each milestone: name, full merge commit on `main`, synthetic version `v0.N.0`, schema version. A milestone without a merge commit on `main` has an empty commit; nothing may pin a branch head in its place, because a squash merge orphans it.
- `test/fixtures/migrations/<mN>/` holds `sm.db` and, from M2, one backup archive; `test/fixtures/migrations/master.key` is test-only. One `PROVENANCE.md` records per milestone the full commit, synthetic version, Go version, schema version, generator transcript and the sha256 of every file.
- Fixtures are produced by **real older binaries**, built from those commits with `git archive`, driving a scripted world: configuration, policy, secrets, tokens, an SSH node through the fixture container, jobs in every terminal state and events; from M4 an app and deployments; from M5 a local MCP client with its token and an `oauth_access_tokens` row. `make migration-fixtures` regenerates them; pull-request CI does not.
- `TestMigrationFixtures_Provenance` enforces in CI: every commit is a full SHA and an ancestor of HEAD (full history); the schema equals `milestones_test.go`; every file hash equals `PROVENANCE.md`.

### `sm doctor --offline --json`

Additive fields, always present: `format_version: 1`, `database_schema_version: int | null` (null when there is no database or it cannot be read), `binary_schema_version: int`. Existing fields keep their meaning. The upgrader reads these fields and parses the `schema` check's text only when `format_version` is absent, i.e. for binaries that predate M6.

### Version-transition audit

On start, before serving, the daemon compares `version.Version` with the `settings` key `instance.binary_version` (`{"version","commit"}`) and records `instance.version_changed` (actor `system`, resource `instance`, data `{from, to, direction}`) when they differ. The first start records only the setting.

### Offline downgrade audit

- Before the swap, an upgrade run with `--allow-downgrade` writes `<DataDir>/audit-pending/<event_id>.json` (0600; fsync of the file and the directory) with `{event_id, action: "instance.downgrade_authorized", os_uid, os_user, sudo_user, from, to, at}`.
- On start, before serving, a daemon of M6 or later inserts each record as an event and then deletes the file. `events.event_id` is `UNIQUE` (`000001_initial.up.sql`), so a crash between the insert and the delete never duplicates the event. A malformed record is kept and logged; start continues.
- A downgrade to a binary older than M6 leaves the record pending until an M6 or later binary starts. This is a stated limitation.

### Service hold

Before `Stop` (not after it, closing the SEC-4 crash window):

- **systemd.** Write the drop-in `<unit>.d/50-upgrade-hold.conf` with `[Unit] RefuseManualStart=yes` and `ConditionPathExists=/nonexistent/supermgmt-upgrade-hold`, run `daemon-reload`, then `disable`. That blocks manual, dependency and boot activation and survives a reboot because it lives in `/etc/systemd/system` (user scope: `~/.config/systemd/user`). `systemctl mask` is not usable: it refuses a unit file that lives in `/etc/systemd/system`.
- **launchd.** `launchctl disable gui/<uid>/<label>`, a persistent override.
- `Register`, reached only through `startService`, lifts the hold: remove the drop-in, reload and `enable`, or `launchctl enable`.

### Stale archive

Resuming an upgrade in phase `backed_up`, before the swap, always retakes the pre-upgrade archive under the database lock (crash point `U:backup:retaken`). The superseded archive is removed once the new one is complete. No inference about the WAL or the service's history is made.

### Crash hook

`SUPERMGMT_CRASH_AT=<point>` is honoured only in builds with the `crashpoints` tag and exits the process with code 86 at the named point. The point set is every `hit("U:…")` literal in `internal/installer/upgrade.go` plus every `U:<phase>:recorded` point that `record` emits:

`U:staged`, `U:prev-linked`, `U:prepared:recorded`, `U:hold:applied`, `U:stopped:applied`, `U:stopped:recorded`, `U:backed_up:applied`, `U:backup:retaken`, `U:backed_up:recorded`, `U:swap:before`, `U:swap:renamed`, `U:swapped:recorded`, `U:started:applied`, `U:started:recorded`, `U:done:recorded`, `U:abort:restarted`, `U:revert:renamed`, `U:revert:started`;

plus the existing appliance and uninstall points (`S*`, `journal:*`, `rollback:*`, `UN:*`). A test fails when a `hit(...)` literal in `upgrade.go` is missing from the list. Release builds ignore the variable.

### Recovery per point

| Crash at | Rerun outcome |
|---|---|
| `U:staged` … `U:prepared:recorded` | forward resume, or `--abandon` restores the old service |
| `U:hold:applied` … `U:backed_up:recorded` | forward resume; the archive is retaken |
| `U:abort:restarted` | the old service runs; the rerun finds the state and clears it |
| `U:swap:before`, `U:swap:renamed`, `U:swapped:recorded` | forward resume; schema unchanged |
| `U:started:applied`, `U:started:recorded`, new binary failing, **schema unchanged** | automatic revert to the previous binary (`U:revert:*`, then converge) |
| same, **schema advanced** | no automatic rollback: the service stays stopped, exit 9 with the restore commands (§29.3) |
| `U:revert:renamed`, `U:revert:started` | the revert resumes and converges |
| `U:done:recorded` | no-op |

## Consequences

- Migration compatibility is proven against databases and archives written by real older binaries, not hand-built SQL.
- The upgrader no longer depends on doctor's wording for binaries of M6 and later.
- A downgrade leaves an audit trail even when the downgraded binary cannot write it, as soon as an M6 or later binary starts.
- An upgrade interrupted at any point cannot be restarted by hand, by a dependency or by a reboot until `startService` lifts the hold.

## Amendment (2026-10-15): a pending schema

A migration's fixture can only be generated from a merge commit on `main`, so the first pull request that adds a migration after this ADR cannot list a milestone for it. Both milestone tables accept one **pending schema**, `pendingSchema` (`test/e2e/milestones_test.go`, `test/fixtures/migrations/gen/provenance.go`): the newest migration, one above the last milestone. After the merge, `make migration-fixtures` generates the next milestone from its merge commit, the tables gain that row, and `pendingSchema` returns to 0. First use: schema 7, `000007_cloudflare_tunnels` (ADR-0037).
