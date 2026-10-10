# Governance

SuperMgmt is a **maintainer-led** project. This document describes how decisions are made today and how that is meant to change.

## Roles

- **Maintainer.** Merges pull requests, owns releases, enforces the Code of Conduct and decides when contributors disagree. Today there is a single maintainer (the repository owner, `autarquico`).
- **Contributor.** Anyone who opens an issue, reviews, or sends a pull request. Contributions are accepted under the Apache-2.0 license with a DCO sign-off (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Decision process

1. Day-to-day changes: pull request, review, merge by a maintainer once CI passes.
2. Major changes (new feature, behavior change, new dependency, security control): issue first, discussion in the issue, maintainer decision recorded there.
3. The master specification (`docs/spec/SUPERMGMT-SPEC.md`) is binding. Changing it is itself a pull request to that file and needs maintainer approval.
4. When there is no consensus, the maintainer decides and writes down the reason.

## ADR process

Architecture decisions that the spec leaves open, or that it fixes and we record with rationale, are ADRs in [`docs/adr/`](docs/adr/). An ADR is proposed in the pull request that needs it and is accepted when that pull request merges. Accepted ADRs are not edited; a new ADR supersedes them. An ADR may fill a gap in the spec but may never relax a spec constraint; that needs a spec change.

## Release authority

Only a maintainer can tag a release. Release signing keys live in a protected release environment and are not held by individuals' machines (SPEC §36). No release has been made yet, and the signing key is not yet provisioned (see [ROADMAP.md](ROADMAP.md)).

## Code of Conduct enforcement

The [Code of Conduct](CODE_OF_CONDUCT.md) is enforced by the maintainers. Reports go through GitHub private reporting or directly to a maintainer. Where the maintainer is the subject of a report, the reporter may contact any other project member with repository admin rights; until a second maintainer exists, this is a known gap.

## Path to multiple maintainers

The aim is to move from one maintainer to several:

1. A contributor with a sustained record of reviewed, merged work and good judgment on security-sensitive changes may be invited as a maintainer.
2. Invitations are made by the existing maintainers; with more than one maintainer, by consensus of them.
3. Security-sensitive areas (policy, approvals, secrets, installer, release) should have two maintainers able to review before the project leaves pre-alpha.
4. When there are three or more maintainers, this document will be revised to describe voting and succession.

## Naming and license

The project name is a working name and the license is Apache-2.0 pending final maintainer confirmation before the first release (SPEC §27.6, §42). See [ROADMAP.md](ROADMAP.md).
