# ADR-0008: Secret versions

- Status: Proposed
- Spec: §10, §20.3 step 2, §46, App. C `secret_bindings`; ADR-0007, ADR-0010

## Context

§46 asks whether historical secret versions are kept or whether a rollback fails when a referenced version is gone. The store already keeps one encrypted row per version (`UNIQUE(name, version)`, migration 000002; `secrets.Store.Put` inserts a new version).

## Decision

- Historical versions are kept, encrypted, under the existing envelope (§10). V1 has no API that deletes a secret version.
- Plans bind `{secret_id = secret name, version}` (App. C `secret_bindings`), never a value.
- Finalization of a `deploy` binds the newest version of each referenced secret at that moment.
- A rollback plan binds the known-good deployment's exact versions.
- Rotating an app secret changes nothing in existing plans.
- A version missing at finalization, claim or rollback fails with `DEPLOYMENT_FAILED` (finalization or claim of a deploy) or `ROLLBACK_UNAVAILABLE` (rollback, safety recovery), `details.cause = SECRET_VERSION_GONE`. A newer value is never substituted.
- Values are decrypted in memory only while a deployment is staged (ADR-0010); they are never written unencrypted on the control plane.

## Consequences

- A rollback after a rotation runs with the old secret version, which is what was healthy.
- Retention of secret versions follows the database: a restore that predates a version cannot roll back to a deployment that needs it, and says so.
