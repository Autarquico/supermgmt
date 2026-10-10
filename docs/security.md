# Security

Authoritative sources: SPEC §30 (threat model), §11 (policy and approvals), §2.1.1 (local trust boundary). Vulnerability reporting: [`../SECURITY.md`](../SECURITY.md).

SuperMgmt is **pre-alpha**. In M0 the controls below exist as tested libraries. No daemon, network service, installer or MCP endpoint ships yet, so most of the attack surface in the threat model does not exist yet either. **[M0]** = implemented in the repository now; **[planned Mx]** = not implemented.

## Threat model summary (SPEC §30)

Threats the design considers:

| Threat | Main mitigation | Status |
|---|---|---|
| Stolen browser or OIDC session | short TTLs, CSRF protection, secure headers | planned M2 |
| Compromised MCP client; malicious prompt asking for a privileged action | MCP is its own actor type with no inherited roles; hard approval floor for operational writes; MCP can never approve | policy rules **[M0]**; MCP itself planned M5 |
| Compromised managed node | least privilege, bounded output and timeouts | planned M1 |
| Malicious repository or PR | closed-schema Compose pipeline, immutable digests | planned M4 |
| Forged or replayed GitHub webhook | signature check and replay dedupe | planned M4 |
| SSH MITM or host key change | strict pinned host keys; changed keys fail the job | planned M1 |
| Leaked API token | hashed storage, scopes, revocation, rate limits | planned M2 |
| Terminal escape sequences in remote logs | output sanitization before rendering | planned M1 |
| Command injection via names or parameters | fixed command templates, argument escaping | planned M1 |
| SSRF via health URLs or provider endpoints | outbound request filter | planned M4 |
| Supply-chain compromise | pinned dependencies, scanning, signed releases | CI scanning **[M0]**; signing planned M2 |
| Backup theft; control-plane database theft | envelope encryption of secrets | planned M2 |

Trust boundary in local mode: code running as the same OS user is trusted (SPEC §2.1.1), so local mode does not defend against malicious software under that user. MCP content is untrusted input: a model asking for an action has no more authority than its authenticated identity and policy grant.

Docker access is root-equivalent on the host it controls. Treat any grant of Docker-level actions on a node as a grant of root there.

## Controls implemented in M0

### Default deny policy engine **[M0]**

`internal/policy` evaluates a request in the order of SPEC §11.3: catalog, capability, rule match, deny override, default deny, destructive gate, credential scopes, approval and quorum, then combination across targets and sub-actions.

- No matching allow rule means deny. Any matching deny wins over every allow.
- Destructive actions require an allow rule that explicitly sets `allow_destructive`.
- Credential scopes only narrow what an actor may do.
- MCP identities need approval for operational-or-higher actions as a fixed floor, and `mcp` and `system` identities can never approve or reject.
- Property and table tests assert that adding allow rules never overrides a deny and that adding targets never relaxes a decision.
- The built-in default policy is embedded; a user policy file replaces it entirely, and the engine can diff the two.

### Approvals bound to the plan hash **[M0]**

A plan lists every input that can change what executes, including the `spec_revision` of each configured resource, and is serialized with RFC 8785 canonical JSON and hashed with SHA-256. Observation data, timestamps, random values and secrets never enter the plan. Approval records are tied to that hash, so any change to an input yields a new hash and earlier approvals do not transfer. Quorum counts distinct approvers, approvals expire, and self-approval is controlled by `security.allow_self_approval`. Claim-time revalidation in `internal/app` recomputes the plan from current state: a changed plan hash or input fails the job with `PLAN_STALE`, an expired plan fails with `PLAN_EXPIRED`, and credentials, policy and quorum are re-checked.

### Append-only audit **[M0]**

The `events` table is protected by database triggers that reject `UPDATE` and `DELETE` (migration `000001_initial.up.sql`). The emitter assigns the event ID and timestamp itself, so callers cannot backdate the trail, and every event carries actor, resource and correlation ID. The requirement that denied actions and unavailable capabilities are audited as well as accepted ones (SPEC §30) is implemented in `internal/app`, which writes a `policy.<decision>` event with result `denied` for every DENY and CAPABILITY_UNAVAILABLE outcome on plan creation, submission, revalidation and approval decisions.

### Redaction **[M0]**

`internal/audit` defines a `Secret` type that renders as `[REDACTED]` through every formatting, JSON, text and logging path, and redacts values by sensitive key name (password, token, authorization, cookie, session, private key and similar, matched case-insensitively) and bearer-token patterns. Over-redaction is the intended failure mode. Values under sensitive keys are always masked. The single exception is a credential reference (`secret://<path>`, `ssh-agent://default`, `file:///<abs-path>`): it stays visible only in a field whose name ends in `_ref` (such as `credential_ref`) and whose whole value matches the reference grammar, because a reference points at a secret and is not one. Plaintext secrets must never reach SQLite, logs, config examples or error messages (SPEC §45 rule 9).

### Strict configuration **[M0]**

Unknown configuration fields fail validation, credential references are limited to a closed set of schemes, and validation reports every problem with its YAML path. See [configuration.md](configuration.md).

### Storage and build **[M0]**

SQLite runs in WAL mode with `synchronous=FULL` and a single writer ([ADR-0001](adr/0001-sqlite-driver.md)). CI runs `go vet`, `golangci-lint` (including `gosec`), tests with the race detector on Linux and macOS, `govulncheck`, CodeQL and dependency review.

## Planned controls

Not implemented; listed so nothing is mistaken for shipped.

- Peer-credential authentication on the local socket; mutually verified daemon UID (M1)
- Strict SSH host-key pinning, fixed command templates, output sanitization and bounds (M1)
- AES-256-GCM envelope encryption of secrets and key management ([ADR-0003](adr/0003-aes-gcm-envelope.md), M2)
- Sessions, API tokens, OIDC, CSRF protection, rate limiting, secure headers (M2)
- Signed releases, checksums, SBOM, provenance; signature-verifying installer ([ADR-0004](adr/0004-openssh-release-signatures.md), M2)
- Outbound request filter and closed-schema Compose pipeline (M4)
- Webhook signature and replay protection (M4)
- MCP registration, tokens, OAuth protected-resource layer and security tests (M5)
- Fuzzing and security scans across all parsers (M6)

## Accepted limitations

- Local mode does not protect against malicious code running as the same OS user.
- The `curl | bash` installer path (planned M2) trusts the repository's `main` branch; the review-first path with an out-of-band key avoids that (SPEC §3.2).
- No independent security audit has been performed.
