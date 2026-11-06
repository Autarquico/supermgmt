---
codename: supermgmt
title: Tunnel nodes wait for the Cloudflare edge before dialling
type: task
status: draft
priority: P0
size: M
issue: 69
prs: []
related_issues: [69]
depends_on: []
supersedes: []
related_specs: [node-enroll-tunnel, cloudflare-tunnel-transport]
created: 2026-11-06
updated: 2026-11-06
---

# Tunnel nodes wait for the Cloudflare edge before dialling

## Contexto / problema

The first run on a real Cloudflare account (results of 2026-11-05, D6, D7, D9, D26, D27) showed that SuperMgmt dials a tunnel hostname as soon as it has created its DNS record:

- **D6, enrollment.** The scan runs in the same job, milliseconds after the CNAME is created (`internal/app/tunnel_enroll_run.go:125-141`), through the system resolver (`internal/netguard/dial.go:34`). A caching resolver that answers before the record is served keeps NXDOMAIN for the zone's negative TTL (1800 s on a Cloudflare zone), and the enrollment waits until it expires with only "no such host". `cloudflared access ssh`, which SuperMgmt spawns, resolves through the same system resolver, so dialling by address alone would not help.
- **D9, re-enable.** After a disable, the same hostname is deleted and created again. The verification over the tunnel runs right away; every failure, including a dial or DNS one, becomes "cannot log in as the dedicated user" (`internal/runtimes/systemd/verify.go:49-53`), and the job's retries come after 5 s and 10 s.
- **D7, token race.** `dns_created` is committed before the tunnel token is fetched and stored (`internal/app/tunnel_steps.go:59,197`), so the CLI reads "waiting for the node" and the token request answers "still being built".
- **D26, plan preview.** `sm nodes setup --tunnel` repeats the Proxmox part of an earlier setup, prints no approval line and lists none of the Cloudflare objects it will create.
- **D27, fake.** `cffake` gives a new Zero Trust organisation the One-time PIN login; since June 2026 Cloudflare gives it the Cloudflare login.

No fake models DNS or edge readiness, which is why none of this was caught.

## Scope

**Entra:**
- A publication gate: before any dial of a hostname SuperMgmt created or recreated in the current operation (the Access preflight and the `cloudflared` child alike), wait until Cloudflare's own resolver publishes it. This narrows the race that poisons a caching resolver; it cannot prove the operator's resolver already sees the record.
- Tunnel readiness after publication: the verification over the tunnel is retried within a bounded deadline of its step, so edge or connector latency does not exhaust the job's attempts.
- A diagnosis when the system resolver answers NXDOMAIN for a published hostname: a likely cached negative answer, an estimate of how long it can last, and that flushing the workstation may not clear a router's cache. The original error is kept.
- Keeping the cause of a failed verification over the tunnel.
- Storing the connector token before an enrollment reaches the waiting phase.
- The setup plan preview: the approval line, the Cloudflare objects to be created, and the Proxmox part only when asked for.
- Fakes that model a hostname that is not served yet and a cached negative answer, and a `cffake` organisation with the Cloudflare login by default.

**No entra:**
- Replacing the system resolver for `cloudflared`, or bundling a resolver for it.
- Any change to what Cloudflare objects are created or their order.
- Enrollment states other than the waiting phase's precondition.
- Any other public resolver: Cloudflare already holds the hostname (it is in the operator's zone), so asking Cloudflare's resolver discloses nothing new; another provider would.

## Criterios de aceptación

### Scenario: a new hostname is not looked up before it is served
- **Given** an enrollment whose DNS record has just been created and that Cloudflare does not serve yet
- **When** the enrollment advances
- **Then** no system lookup of the hostname (preflight or `cloudflared`) happens until Cloudflare's resolver publishes it, each enrollment job checks for a bounded time and yields to the scheduler, and the enrollment's note says it is waiting for Cloudflare to publish the hostname

### Scenario: Cloudflare's resolver cannot be reached
- **Given** a network where HTTPS to Cloudflare's resolver fails (blocked, proxy authentication, captive portal, TLS error, malformed reply)
- **When** the gate runs
- **Then** that failure is reported as such, distinct from "not published yet"; the gate falls back to a fixed wait after the record's creation before the first system lookup, and the note says so

### Scenario: a restart does not skip the gate
- **Given** an enrollment or a tunnel setup that created its DNS record and whose daemon restarted before the first dial
- **When** the operation resumes, on this daemon or after a takeover
- **Then** the gate still applies, because it is derived from the operation's persisted phase, not from memory

### Scenario: a likely cached negative answer is named, not hidden
- **Given** a hostname that the readiness check finds served
- **And** a system resolver that still answers NXDOMAIN for it
- **When** the scan or the verification dials it
- **Then** the error says the local resolver likely cached a negative answer, estimates its lifetime as min(SOA TTL, SOA minimum) when the SOA can be read, says that flushing the workstation's cache may leave a router's or upstream resolver's in place, and keeps the original error

### Scenario: re-enabling right after a disable succeeds without manual retries
- **Given** a node whose tunnel was disabled a minute ago
- **When** `sm nodes setup <node> --tunnel` runs and the edge takes 40 s to serve the recreated hostname
- **Then** the verification waits for the hostname to be served and the job succeeds on its first attempt

### Scenario: a failed verification keeps its cause
- **Given** a tunnel verification whose dial fails (preflight refused, hostname not served, connection refused)
- **When** the setup job fails
- **Then** the error names the dial failure and the step, and does not say "cannot log in as the dedicated user"; that message is kept for an SSH authentication failure only

### Scenario: the connector token exists whenever the enrollment is waiting
- **Given** an enrollment in any state the CLI shows as "waiting for the node"
- **When** the CLI asks for the connector token
- **Then** the token is returned; "still being built" is answered only in the provisioning phases, and the CLI keeps polling through it instead of exiting

### Scenario: the setup plan says what it will do
- **Given** a node previously set up with `--proxmox`
- **When** the operator runs `sm nodes setup <node> --tunnel`
- **Then** the preview lists the tunnel, the Access application and the DNS record by name, omits the Proxmox part (in the preview and in the submitted parameters) unless `--proxmox` is passed, and prints `to approve: sm jobs approve <job> --plan-hash <hash>` when the plan waits for approval

### Scenario: the fake starts like a real organisation
- **Given** a `cffake` account with no identity provider configured by the test
- **When** a tunnel setup runs with an empty `access_identity_providers`
- **Then** it fails before creating the Access application with the actionable One-time PIN error, as on a real account created after June 2026

## Notas técnicas

- **Publication gate.** DNS-over-HTTPS to Cloudflare's resolver (`https://cloudflare-dns.com/dns-query`, JSON) through `netguard`, A and AAAA; published means an answer for either. NXDOMAIN and NODATA mean "not yet"; SERVFAIL, HTTP or TLS errors and malformed replies mean "cannot ask". Each request has a short deadline and honours cancellation. In enrollment each job checks for a bounded time (proposal: 20 s) and yields to the scheduler; in setup the step waits up to a deadline (proposal: 3 min). When the resolver cannot be asked, the first system lookup waits until a fixed delay after the record's creation (proposal: 60 s) and the note says why.
- **Which dials are gated.** Every dial of the hostname in an operation whose persisted phase shows its DNS record was created or recreated and not yet verified: the enrollment scan, the setup's verification over the tunnel, and any verification that already resolves the tunnel endpoint. Established tunnel nodes are not gated.
- **Tunnel readiness.** After publication, the verification over the tunnel is retried with backoff until the step's deadline; the job's attempts are kept for other failures.
- **Diagnosis.** NXDOMAIN from the system resolver while Cloudflare's resolver has answers becomes `TUNNEL_DNS_NEGATIVE_CACHE` (wrapping the original). The estimate is min(SOA TTL, SOA MINIMUM) per RFC 2308, read through the same resolver; when unavailable, the message gives no figure.
- **Verification mapping.** `verifyIdentity` keeps the underlying error (`%w`) and says "cannot log in as the dedicated user" only for an SSH authentication failure.
- **Token before waiting.** Fetch and store the tunnel token before `ensureDNS` commits `dns_created`; `ensureToken` stays for a worker that died in between; a failed store leaves the enrollment provisioning.
- **Fakes and tests.** A resolver seam in `netguard` and the preflight that counts lookups; a fake DoH endpoint (not published for N polls, NODATA, SERVFAIL, unreachable, stale positive); `cffake` organisations get the Cloudflare login unless a test adds One-time PIN. Tests assert zero target lookups before publication, the fallback wait, resume after restart and takeover, token-store failure, and the real preflight-to-child boundary.
