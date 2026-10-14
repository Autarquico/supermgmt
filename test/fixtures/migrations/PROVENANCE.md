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

## m4

- commit: `f4195937b25e1570e49f63158e3bcca83ee42e54`
- synthetic version: `v0.4.0`
- Go version: `go1.27.2`
- schema version: 5
- master key id: `01a139cb-7d03-737a-998d-30ecfc04a360`

| file | sha256 |
|---|---|
| `m4/master.key` | `16f6a18b66c4fc960806ce92d34418dc50311a114dfca3a09b188d320827b087` |
| `m4/sm.db` | `083c1a0635de67937759ecb19614c8d495ad33c36ba38b2f1c38f62074efbe06` |
| `m4/supermgmt-m4-20260101T000000Z.tar.zst` | `c550c2c55b5e394e9eef0dc640e4d1f945a5f2d3a63bba5eeb2fe40f0273dbed` |

Transcript:

1. import the secrets app/credential and app/api-token (approved) and app/parked (left awaiting approval)
2. add the SSH node fixture-1 (staging) through the fixture container and probe it -> succeeded
3. add a node in production and reject the approval -> failed
4. add a node in production and cancel it -> cancelled
5. probe fixture-1 while its container is paused -> failed
6. node.setup on fixture-1 -> succeeded
7. create the API token fixture-ci
8. create the app fixture-web and bind it to fixture-1 in staging
9. create a backup and keep it as the archive of the milestone

## m5

- commit: `658078b15d68846ed67b80d4e2f463c114be27cf`
- synthetic version: `v0.5.0`
- Go version: `go1.27.2`
- schema version: 6
- master key id: `01a139cc-3a05-74e2-90d4-b86b3cbc56d6`

| file | sha256 |
|---|---|
| `m5/master.key` | `908292fedddb7bab78dbc4305cd9bcdcd05ecd3b24e712f3640717d9b91cc4ab` |
| `m5/sm.db` | `8a1b72fc393b7113ce30c1030407d2bfe37301d7fc5f717c765a934d4cd05461` |
| `m5/supermgmt-m5-20260101T000000Z.tar.zst` | `f81c04a6272b461f53502e03c773b598b7c8bcd3e30317782e4e8e6446993ab4` |

Transcript:

1. import the secrets app/credential and app/api-token (approved) and app/parked (left awaiting approval)
2. add the SSH node fixture-1 (staging) through the fixture container and probe it -> succeeded
3. add a node in production and reject the approval -> failed
4. add a node in production and cancel it -> cancelled
5. probe fixture-1 while its container is paused -> failed
6. node.setup on fixture-1 -> succeeded
7. create the API token fixture-ci
8. create the app fixture-web and bind it to fixture-1 in staging
9. register the local MCP client fixture-agent and store its token
10. create a backup and keep it as the archive of the milestone
