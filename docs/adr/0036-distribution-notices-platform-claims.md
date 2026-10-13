# ADR-0036: Distribution, notices and platform claims

- Status: Proposed
- Spec: §5, §35, §36, §41, §42; ADR-0019, ADR-0027, ADR-0034

## Context

§35 says not to claim unsupported versions and to maintain `docs/compatibility.md`. §5 lists `packaging/homebrew/README.md` and `packaging/nfpm.yaml`. §36 requires SBOM and provenance and reproducible builds where practical. §41 forbids silent phone-home. The acceptance of §31 M6 is a clean-machine install, upgrade, restore and uninstall in every mode, but some environments (a real Proxmox host, a real Debian VM, Intel macOS) are not available to CI.

## Decision

### Platform claims

- A platform and architecture row is **supported** only if CI jobs run each of install, upgrade, backup plus restore, and uninstall on it. `docs/compatibility.md` cites the test and the job per operation.
- **Container-verified** (a systemd container on a CI runner), **fake-verified** (a simulator or fake API) and **manual** (a checklist row a human runs) rows are labelled as such. Anything else is **not claimed**.
- V1 claims: server on Ubuntu 24.04 LTS amd64 and arm64, supported (GitHub-hosted runner VMs, every operation); Debian 13 amd64 and arm64, container-verified (real VM manual). Client and local: macOS 15 or later on arm64 and Ubuntu 24.04 amd64/arm64; Debian local not claimed; Intel macOS built, manual check only. Nodes: Debian 13 and Ubuntu 24.04 fixtures. Proxmox VE 9.x fake-verified, real host manual. Docker: the Compose CLI pinned by ADR-0006.

### Host-mutating tests

- They compile only with build tag `hostlifecycle`, and run only with `SM_E2E_VM=1` and a disposable-runner identity (`GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`), or, for the local proxy run, with systemd as PID 1 inside the e2e container.
- Before any mutation a guard asserts that no installation exists: server layout, user layout, units, launchd plists. The installer prefers a system installation whenever its binary or unit exists, so a leftover install would change what later steps operate on.
- Each mode runs on a fresh runner; cleanup runs on failure. `make test`, `make e2e` and `go test ./...` never compile these files.

### Homebrew

- An own tap, `autarquico/homebrew-tap`, with formula **`supermgmt`** that installs the `sm` binary (the name `sm` would clash).
- `packaging/release/brew-formula.sh` renders the formula from the **signed** `checksums.txt` of a release. The owner commits it to the tap: CI holds no tap token. macOS CI audits the rendered formula against a snapshot.

### Linux packages

Not shipped in V1. A package manager's upgrade would bypass the ADR-0027 protocol (pre-upgrade backup, phase state, revert rules). The spec's `packaging/nfpm.yaml` is removed (1.4.8).

### Third-party notices

Every archive ships `THIRD_PARTY_LICENSES`, generated from the compiled binary's build info, with full licence texts and `NOTICE` files (ADR-0034 "Supply chain"). The legal reading of that file is a human checklist row.

### Egress inventory

Every outbound destination, with its trigger and its off-switch, is listed in `docs/dependencies.md`: the Sigstore TUF refresh and the GitHub API (M4), OIDC issuers, MCP JWKS and introspection endpoints (M5), Proxmox endpoints, and release and channel downloads. A destination missing from that list is a defect.

## Consequences

- The compatibility matrix states exactly what a test proves, per operation and architecture.
- Developer machines are never mutated by the test suite.
- Homebrew users get a formula whose checksums come from the signed release, at the cost of a manual tap update per release.
- Debian and Ubuntu users install with `install.sh`; there is no `.deb`/`.rpm` in V1.
