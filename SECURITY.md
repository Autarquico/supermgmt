# Security Policy

SuperMgmt is **pre-alpha**. It is not suitable for production use, and no security guarantee is made for any current code.

## Supported versions

| Version | Supported |
|---|---|
| none released | n/a |

There are no releases yet. Once releases exist, this table will list the supported lines. Until then, only the `main` branch receives fixes.

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub private vulnerability reporting:

<https://github.com/autarquico/supermgmt/security/advisories/new>

Do not open a public issue or pull request for a vulnerability, and do not post details in discussions.

If you cannot use GitHub reporting, open a public issue that says only "I need a private security contact" (no details) and a maintainer will arrange a channel. _Placeholder: a dedicated security contact address will be added before the first release._

### Response targets

These are targets for a volunteer-run project, not guarantees:

| Step | Target |
|---|---|
| Acknowledge the report | 5 business days |
| Initial assessment and severity | 10 business days |
| Fix or mitigation plan for confirmed issues | 30 days |
| Coordinated disclosure | agreed with the reporter, normally within 90 days |

Reporters are credited in the advisory unless they ask not to be.

### What to redact from reports

Reports are stored and discussed in tooling we do not fully control. Before sending, remove or replace:

- passwords, API tokens, bearer tokens, OIDC client secrets, session cookies and bootstrap codes;
- private keys, key files and master-key material;
- real hostnames, IP addresses and host public keys of machines you do not want associated with the report;
- contents of `secret://` values and of database or backup files;
- personal data in logs or audit events.

Describe the shape instead ("a 64-character token") and give a minimal reproduction using fake values. If a secret has already been exposed, rotate it first.

## Security model and limits

The threat model is summarized in [docs/security.md](docs/security.md) and specified in `docs/spec/SUPERMGMT-SPEC.md` §30. Defaults: deny by default, least privilege, strict host-key and TLS verification, approvals bound to an exact plan hash, append-only audit, secret redaction. These sit behind a local daemon and an HTTPS server mode (sessions, API tokens, OIDC, approvals, encrypted secrets, signed-release installer), the Proxmox, GitHub and MCP integrations (M3 to M5), and an upgrade protocol with a service hold and a pre-upgrade backup. Nothing is released and none of it has had an independent audit. Proxmox, GitHub and MCP were verified against fakes only, and the installer and release pipeline with test keys ([docs/security.md](docs/security.md) says which); the open human checks are in the [release checklist](docs/release-checklist.md).

Explicit statements:

- **Docker access is root-equivalent.** Anyone or anything that can drive the Docker daemon on a host can obtain root on that host. Granting SuperMgmt (or an agent through it) Docker-level actions on a node is granting root on that node. Scope policies accordingly.
- **Local mode trusts code running as the same OS user** (SPEC §2.1.1). Peer credentials prove the OS user, not which program is speaking. Any process running as that user can already read its SSH keys and agent, so local mode does not defend against malicious code running as the same user. Users who need isolation from a compromised MCP client run it under a different OS user, or use server mode with per-client OAuth (both planned).
- **`curl | bash` has a trust root.** The installer path trusts the repository's `main` branch: whoever can change `install.sh` there can replace both the verifier and the embedded key, so a repository compromise defeats that path. For users who need independence, every release attaches `install.sh` and `install.sh.sig`, and the release key fingerprint is published out-of-band (this file at a signed tag, the project website, release notes), so the script can be verified with `ssh-keygen -Y verify` before it is run (SPEC §3.1, §3.2, [docs/installation.md](docs/installation.md)). The installer needs OpenSSH 8.2 or newer on the machine running it. No release has been published yet.
- **Server mode exposes a network service.** Requests are authenticated by bearer tokens only. A reverse proxy or Cloudflare in front can read them; SuperMgmt consumes no Cloudflare identity assertion ([docs/cloudflare.md](docs/cloudflare.md)). Backup archives are not encrypted, and master keys are never in them.
- **MCP content is untrusted input.** A model asking for an action has no more authority than its authenticated identity and policy grants (M5; verified with the Go SDK client and a fake authorization server only, never with a real MCP client).

## Automated security scanning

What runs on every change and what runs on a schedule. None of it replaces an audit or a review, and a green run is evidence for the code it ran on, not a guarantee.

| Check | Where | What it covers |
|---|---|---|
| Static analysis | `golangci-lint` with gosec (job `lint`); CodeQL (own workflow, not a required check) | Go source |
| Known vulnerabilities | `govulncheck` (job `govulncheck`) | Go modules and standard library reachable from the binary; test-only fakes excluded |
| Secrets | gitleaks over the full history (job `secret-scan`, config `.gitleaks.toml`) | Every allowlist entry names one test fixture file and a reason; no blanket pattern |
| Licences | go-licenses against an allowlist (job `licenses`); dependency review on pull requests | Modules compiled into `sm`; `THIRD_PARTY_LICENSES` ships in every archive |
| Race detector | `-race` on Ubuntu and macOS (job `race`); stress suite nightly | Unit tests; concurrency seams |
| Fuzzing | seeds on every change, mutation nightly (job `fuzz-inventory`; workflow `nightly.yml`) | Parsers of untrusted input; 25 known parsers have no target yet ([release checklist](docs/release-checklist.md#unresolved-items-and-stated-limitations)) |
| Release integrity | reproducible rebuild, SBOM and notices check, provenance verification | Release artifacts; verified with a throwaway key until the first real tag |

GitHub secret scanning and push protection are repository settings that only the owner can turn on; until the [release checklist](docs/release-checklist.md) records them as done, assume they are off. If a scan finds a real secret in the history, rotate it first, then remove it.

## Release signing key

Release artifacts (`checksums.txt`, `install.sh`, `join.sh`, channel files) are signed with an OpenSSH key in the namespace `supermgmt-release`, principal `release@supermgmt`. The private key will live only as a secret of the protected GitHub environment `release` (the repository owner is its required reviewer).

```text
Fingerprint: SHA256:<RELEASE-KEY-FINGERPRINT-NOT-PUBLISHED-YET>
```

The key and its fingerprint do not exist yet; the value above is a placeholder, and until the real key is embedded in `install.sh` every signature check fails closed. This file will state the real fingerprint at the first signed tag. Verify it against a second source (project website, release notes) before trusting it.
