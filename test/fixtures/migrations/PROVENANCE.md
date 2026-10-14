# Migration fixtures provenance (ADR-0035)

Each section records a fixture set produced by the **real binary** of one milestone: built from the
full merge commit on `main` (`git archive`, synthetic version) and driven through the scripted world
of `test/fixtures/migrations/gen`. Regenerate with `make migration-fixtures`; pull-request CI does not.

Volatile fields: the generator is deterministic in its steps, its transcript and the file names. These
differ on every run and are not reproducible: the bytes of `sm.db` (row ids, timestamps, wrapped keys), the
master key and its id, the bytes of the archive, and the host key of the node. Files are therefore pinned by
hash, and a changed hash is a regeneration, not a drift.

CI checks per section: the commit is a full SHA and an ancestor of HEAD, the schema equals
`test/e2e/milestones_test.go`, and every file hash below equals the file on disk.

## m1

- commit: `0c31ac148e3b78668c1e9425eb34d089700a6eba`
- synthetic version: `v0.1.0`
- Go version: `go1.27.2`
- schema version: 2
- master key id: `01a139c8-2baa-773b-8498-607170f78524`

| file | sha256 |
|---|---|
| `m1/master.key` | `6f359a5ff9db9311c67590f00634b2b05fc1dd561de550fff347870562fb6a26` |
| `m1/sm.db` | `17e8a3ed1621dd06d4f78c16cf5b37b0acc67c466e9f656905f5e8677701c5d8` |

Transcript:

1. add the SSH node fixture-1 (staging) through the fixture container and probe it -> succeeded
2. add a node in production and reject the approval -> failed
3. add a node in production and cancel it -> cancelled
4. probe fixture-1 while its container is paused -> failed

## m2

- commit: `e6d5577bb51e8837a58d9d48cd06e9c2bfd2641a`
- synthetic version: `v0.2.0`
- Go version: `go1.27.2`
- schema version: 3
- master key id: `01a139c8-c7ee-7232-b8a6-98622285a3e8`

| file | sha256 |
|---|---|
| `m2/master.key` | `cf52704d54fa2c5a88a8b023c72600e55923e02c21ea60f54a9dd76090b741bf` |
| `m2/sm.db` | `9c8d5eb3b03e9a2639d95d9fc06833ea283131ba1ee7de2afde9723651ee2ace` |
| `m2/supermgmt-m2-20260101T000000Z.tar.zst` | `4409922d17ee42debb3ebb6f04d1ead792be802f6b3d1dddaa8a6947015f456f` |

Transcript:

1. import the secrets app/credential and app/api-token (approved) and app/parked (left awaiting approval)
2. add the SSH node fixture-1 (staging) through the fixture container and probe it -> succeeded
3. add a node in production and reject the approval -> failed
4. add a node in production and cancel it -> cancelled
5. probe fixture-1 while its container is paused -> failed
6. node.setup on fixture-1 -> succeeded
7. create the API token fixture-ci
8. create a backup and keep it as the archive of the milestone

## m3

- commit: `e13d021a09a796d50527a92b8f2a9832fbe01c99`
- synthetic version: `v0.3.0`
- Go version: `go1.27.2`
- schema version: 4
- master key id: `01a139c9-7e46-7271-bd72-035a83f8ea82`

| file | sha256 |
|---|---|
| `m3/master.key` | `f593232a82cb7970a78f00d95b7e5449eecb32f333efe0a69b0d8ebbb26e4205` |
| `m3/sm.db` | `0f62bbacf2841c66fb29040b18360576a6b415c9098ffd45821534ce030c81a2` |
| `m3/supermgmt-m3-20260101T000000Z.tar.zst` | `ea76cfc83c66eca40663ba44cca8ab57c8feba3873e5d4d09919410a6b05d780` |

Transcript:

1. import the secrets app/credential and app/api-token (approved) and app/parked (left awaiting approval)
2. add the SSH node fixture-1 (staging) through the fixture container and probe it -> succeeded
3. add a node in production and reject the approval -> failed
4. add a node in production and cancel it -> cancelled
5. probe fixture-1 while its container is paused -> failed
6. node.setup on fixture-1 -> succeeded
7. create the API token fixture-ci
8. create a backup and keep it as the archive of the milestone
