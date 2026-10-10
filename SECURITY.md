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

The threat model is summarized in [docs/security.md](docs/security.md) and specified in `docs/spec/SUPERMGMT-SPEC.md` §30. Defaults: deny by default, least privilege, strict host-key and TLS verification, approvals bound to an exact plan hash, append-only audit, secret redaction. In the current state (M0) these exist as tested libraries only; no network service ships yet.

Explicit statements:

- **Docker access is root-equivalent.** Anyone or anything that can drive the Docker daemon on a host can obtain root on that host. Granting SuperMgmt (or an agent through it) Docker-level actions on a node is granting root on that node. Scope policies accordingly.
- **Local mode trusts code running as the same OS user** (SPEC §2.1.1). Peer credentials prove the OS user, not which program is speaking. Any process running as that user can already read its SSH keys and agent, so local mode does not defend against malicious code running as the same user. Users who need isolation from a compromised MCP client run it under a different OS user, or use server mode with per-client OAuth (both planned).
- **`curl | bash` has a trust root.** The planned installer path (M2) trusts the repository's `main` branch: whoever can change `install.sh` there can replace both the verifier and the embedded key, so a repository compromise defeats that path. For users who need independence, every release will attach `install.sh` and `install.sh.sig`, and the release key fingerprint will be published out-of-band (this file at a signed tag, the project website, release notes), so the script can be verified with `ssh-keygen -Y verify` before it is run (SPEC §3.1, §3.2). None of this exists yet.
- **MCP content is untrusted input.** A model asking for an action has no more authority than its authenticated identity and policy grants (planned, M5).

The release signing key and its fingerprint do not exist yet; this file will state them at the first signed tag.
