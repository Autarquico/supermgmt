# Cloudflare

Two independent things, both optional. Nothing in SuperMgmt requires Cloudflare.

1. [Reach nodes through Cloudflare Tunnel](#reach-nodes-through-cloudflare-tunnel): SuperMgmt reaches an SSH node that has no inbound path. **Experimental**, tested against fakes only.
2. [Put the SuperMgmt server behind Cloudflare](#put-the-supermgmt-server-behind-cloudflare): a guide, **not verified**.

## Reach nodes through Cloudflare Tunnel

**Status: experimental.** The code is written and its tests pass against a hand-written Cloudflare API fake and a fake `cloudflared`. Nothing has run against a real Cloudflare account yet; the [manual checklist](manual-checks/cloudflare-tunnel.md) is open and the feature stays experimental until it passes. See [Project status](project-status.md).

### What it does

By default SuperMgmt dials a node's `host:port` directly, so it reaches the node only while it can route to it. With a tunnel:

```text
sm daemon --(cloudflared access ssh, Access service token)--> Cloudflare --> cloudflared on the node --> ssh://localhost:22
```

- `cloudflared` on the node keeps an outbound connection to Cloudflare. The node needs no inbound port and no public address.
- A hostname `ssh-<node-name>.<zone>` routes to the node's local SSH port. A Cloudflare Access application in front of that hostname admits two kinds of caller: SuperMgmt's own service token (automation) and the people listed in `owner_emails` (interactive sessions).
- SSH stays end to end. The pinned host key, the dedicated `supermgmt` account, policy and approvals are the same as for a direct node. Cloudflare carries the stream; no step ever repins a host key automatically.

Scope: SSH nodes running Debian 13 or Ubuntu 24.04. A node that was never reachable directly cannot be turned into a tunnel node yet (see [What it does not do](#what-it-does-not-do)).

### What you need

- **A zone on Cloudflare**, whose DNS Cloudflare serves, for the hostnames `ssh-<node-name>.<zone>`. The node name must make a valid hostname ([rule below](#what-gets-created)).
- **Your account ID** (`account_id`): the 32-character hexadecimal ID of the account. Where the dashboard shows it is not verified here.
- **Zero Trust enabled** on the account (Access applications and service tokens are Zero Trust features), which means a Zero Trust team domain exists. Which Cloudflare plan or limits apply to your usage is not verified here.
- **At least one login method** in Zero Trust (Settings, Authentication) that your owners can use. If `access_identity_providers` is empty, that method must be **One-time PIN**: see [Who can open `sm ssh`](#who-can-open-sm-ssh).
- **A Cloudflare API token**, used only to provision. Create it in the Cloudflare dashboard with these permissions (the labels follow the design and are **not confirmed on a real account**; the checklist asks you to confirm them):
  - Account: Cloudflare Tunnel: Edit
  - Account: Access: Apps and Policies: Edit
  - Account: Access: Service Tokens: Edit
  - Zone: DNS: Edit, on the configured zone only
  - Account: Access: Organizations, Identity Providers, and Groups: Read, needed to find the One-time PIN login method when `access_identity_providers` is empty (**to confirm on a real account**; without it the enable fails before the Access application exists)

  **Blast radius.** Whoever holds this token can create tunnels, Access applications and service tokens in the whole account, and edit DNS in the zone. SuperMgmt reads it only inside tunnel jobs, and you can revoke it once your nodes are provisioned ([below](#revoke-the-api-token-after-provisioning)). Whether the zone lookup needs a further read permission is not verified; if a job fails at the zone lookup, check this first.
- **The owners' identities.** `owner_emails` are the addresses Access admits for interactive sessions, and `access_identity_providers` lists the Access identity provider IDs they may log in with (empty: see [Who can open `sm ssh`](#who-can-open-sm-ssh)).
- **`cloudflared` on the machine that runs the SuperMgmt daemon**, for automated dialling. If it is missing, a tunnel node fails with `CAPABILITY_UNAVAILABLE` naming `cloudflared`, and `sm doctor` fails the `cloudflare_cloudflared` check (`TestMissingCloudflaredIsCapabilityUnavailable`). SuperMgmt looks in `/usr/local/bin`, `/opt/homebrew/bin` and `/usr/bin`, never in `PATH`. The daemon also refuses a binary that group or others can write, or that is not owned by root or the daemon's user, and applies the same test to the directories above it (`TestCloudflaredThatOthersCanReplaceIsNotTrusted`).
- **`cloudflared` on your own machine**, for `sm ssh` and `s` in the TUI: it carries your own Access login. Same directories. In local mode the daemon and your machine are the same machine, so one install covers both.
- **Installing `cloudflared`:** on Linux use Cloudflare's package repository (`pkg.cloudflare.com`); on macOS use Homebrew, which puts it in `/opt/homebrew/bin` or `/usr/local/bin`. The install steps are Cloudflare's; check their current documentation. `sm doctor` gives the reason the binary was refused and the usual install route for the daemon host's OS (Homebrew on macOS, `pkg.cloudflare.com` otherwise).
- **Outbound access from the node** to `pkg.cloudflare.com` (setup installs the package) and to Cloudflare's edge (`cloudflared` itself; the ports it needs are in Cloudflare's documentation and were not checked here).

### Configure

Add a `cloudflare:` block. Without it the feature is off: no Cloudflare call is made, no `cloudflared` is needed, and `--tunnel` is refused saying the connection is not configured (`TestTunnelIsRefusedWithoutACloudflareConnection`, `TestCloudflareAbsentMeansTheFeatureIsOff`).

```yaml
cloudflare:
  account_id: 0123456789abcdef0123456789abcdef
  zone: example.com
  owner_emails:
    - alice@example.com
  access_identity_providers: []
  # api_token_ref: secret://cloudflare/api-token
  # access_token_ref: secret://cloudflare/access-service-token
```

Every key, default and validation rule is in [configuration.md](configuration.md#cloudflare). Both references accept `secret://` only.

Store the API token in the secret store (the name is the reference without `secret://`):

```bash
sm secrets import --name cloudflare/api-token
```

The command reads the value from the terminal without echo; it is sealed and never shown again. You do not store the Access service token yourself: SuperMgmt creates it on first use.

### Turn a node into a tunnel node

Run a plain `sm nodes setup <node>` first and make sure the node is reachable directly; the switch happens only after the tunnel is proven. `--tunnel` is not refused on a node that was never set up, but then a tunnel that fails to start leaves the dedicated account unreachable until you rerun it, so do not combine the two for a node you cannot reach another way.

```bash
sm nodes setup web1 --tunnel
```

The plan shows `transport: cloudflare (experimental)`. The hostname is checked when the plan is created, before anyone approves it ([the rule](#what-gets-created)). The job waits for approval like any setup. While the node is still reachable directly it:

1. Ensures the instance's Access service token (created on first use, serialised by an instance-wide lock).
2. Creates or finds, in this order: the tunnel with its ingress rule, the Access application with its policies, and only then the proxied DNS record, so the hostname is never routable without its Access application.
3. Installs `cloudflared` on the node from Cloudflare's package repository, writes the tunnel credential and starts the service.
4. Verifies over a **fresh** connection through the tunnel, not a pooled one, with the pinned host key, and runs the same dedicated-account verification as setup (`TestTheTunnelPathIsVerifiedOverAFreshCloudflareConnectionWithThePinnedKey`).
5. Only then commits `transport: cloudflare` and `tunnel_hostname` and retires the pooled direct connections (`TestTunnelSetupProvisionsEverythingProvesTheTunnelAndOnlyThenSwitches`).

If any step fails, the job fails naming the step, the transport stays `direct`, and the operation is recorded so a rerun resumes it (`TestAFailedTunnelVerificationLeavesTheNodeDirectAndTheOperationResumable`, `TestADedicatedAccountThatFailsOverTheTunnelKeepsTheTransportDirect`). Rerunning is idempotent and repairs an object that vanished from Cloudflare (`TestEnableRepairsAnObjectThatVanishedFromCloudflare`). Tunnel steps on the node run after the dedicated-account checks and before the key is authorised.

#### When a setup does not finish

Two exits, both leaving the transport `direct`:

- **Resume:** run `sm nodes setup <node> --tunnel` again. A halted conflict resumes the same operation once you have resolved it in the dashboard.
- **Abandon:** run `sm nodes tunnel disable <node>`. It takes over a tunnel setup that is running, halted, failed or interrupted, checks that the direct path works, then removes the route, the Access application and the tunnel recorded for the node, and the node's `cloudflared` files. It also works on a node whose first setup never completed, where only the admin account is checked (`TestDisableAbandonsAnEnableThatIsUnfinishedHaltedOrFailing`). The abandoned setup is ended as `committed` in the operation history, and the audit event `node.tunnel.enable_abandoned` records it.

If an object the setup recorded vanished from Cloudflare, or the DNS record now points at another tunnel, the setup ends as `failed` instead of retrying; the error names both exits. A new `--tunnel` setup then starts over and reuses the objects that still exist (`TestAVanishedRecordedObjectEndsTheEnableAsFailedAndANewSetupRepairsIt`).

Limits of abandoning: the Access application and the tunnel are deleted only by the ID the setup recorded, never by name, so one that was created but whose answer was lost and never recorded stays in Cloudflare as an orphan (delete it in the dashboard). A foreign object that caused a conflict is never touched.

### What gets created

In Cloudflare, with `<instance>` and `<node-id>` the full IDs of the SuperMgmt instance and of the node, and `<node-name>` the node's name. Object names use the IDs and are the ownership marker, because Cloudflare offers no settable marker on tunnels; only the hostname uses the name.

**Node name rule.** `ssh-<node-name>.<zone>` must be a valid DNS name, so the node name must be letters, digits and hyphens, with no dots or underscores, not ending in a hyphen, and `ssh-<node-name>` at most 63 characters. Uppercase letters are lowercased in the hostname. A name that breaks the rule is refused when the plan is created, with a message that asks for a DNS-safe name; the way to get one is to remove the node and add it again (`sm nodes remove <node>`, then `sm nodes add --name <new-name> ...`), since no command renames a node (`TestATunnelPlanForANodeWhoseNameIsNoDNSLabelIsRefusedBeforeApproval`).

| Object | Name | Notes |
|---|---|---|
| Tunnel | `sm-<instance>-<node-id>` | Remotely managed; ingress sends `ssh-<node-name>.<zone>` to `ssh://localhost:22` |
| Access application | `supermgmt <instance> <node-id>` | Self-hosted, domain `ssh-<node-name>.<zone>` |
| Access policy (service) | `supermgmt service <instance>` | Service Auth, admits the instance's service token. One per instance |
| Access policy (owners) | `supermgmt owners <instance>` | Allow, `owner_emails`. The application allows only `access_identity_providers`, or the One-time PIN provider when that is empty. One per instance |
| DNS record | `ssh-<node-name>.<zone>` | Proxied, pointing at the tunnel; comment `supermgmt:<instance>:<node-id>` |
| Service token | `supermgmt-<instance>` | One per instance, valid for one year; Cloudflare shows its secret once, SuperMgmt stores it at `access_token_ref` |

An object with the expected name but another owner is a conflict: the job stops and never adopts it (`TestAnObjectWithTheExpectedNameButAnotherOwnerIsAConflictNeverAdopted`).

On the node:

| Path | Content |
|---|---|
| `/etc/supermgmt/cloudflared/token` | The tunnel credential, root-owned, mode 0600 |
| `/etc/systemd/system/supermgmt-cloudflared.service` | A sandboxed unit (`DynamicUser`, no capabilities, read-only system, `LoadCredential` for the token) that runs `cloudflared --no-autoupdate tunnel run --token-file ${CREDENTIALS_DIRECTORY}/token` (`TestTheTunnelUnitIsSandboxed`). Not verified on a real host |
| `/etc/apt/sources.list.d/cloudflared.list` | `deb [signed-by=/etc/apt/keyrings/supermgmt-cloudflare.gpg] https://pkg.cloudflare.com/cloudflared any main` |
| `/etc/apt/keyrings/supermgmt-cloudflare.gpg` | Cloudflare's package key, pinned in the SuperMgmt build (fingerprint `CC94B39C77AE7342A68B89628A682D308D4E5E73`); setup aborts if the installed key differs. The path is SuperMgmt's own: setup never touches a `cloudflare-main.gpg` that Cloudflare's guide may have placed (`TestSetupNeverTouchesTheSharedCloudflareKeyring`) |
| the `cloudflared` package | Installed with `apt-get`; updates come from apt, not from `cloudflared` itself |

If `cloudflared` is already installed and setup's own source file is absent, setup uses it, adds no repository and removes nothing later (`TestAnExistingCloudflaredIsUsedAndNeverManaged`). This includes one installed from Cloudflare's own guide, with that guide's repository entry and key: setup leaves them alone, and `tunnel disable` never removes them (`TestAnInstalledCloudflaredWithTheGuidesSourceIsUsedAndLeftAlone`). The tunnel credential never appears in a command line, the unit, a plan, a log or an error: it travels as the standard input of one staging command whose remote output is withheld (`TestTheTokenReachesTheNodeOnlyAsSensitiveStdinOfTheTokenStagingStep`). Whether `cloudflared tunnel run` logs it at its default level is not verified; the checklist inspects the node's journal.

### Using a tunnel node

Probes, service actions, logs and deployments work with the same commands. Interactive sessions (`sm ssh web1`, and `s` in the TUI) use **your** Access login through your own `cloudflared`, never SuperMgmt's service token; a person who is not in `owner_emails` is denied by Access. Admission by Access grants neither an SSH login (your key must still be authorised on the node) nor any SuperMgmt privilege. Before spawning `cloudflared`, the daemon asks Access with the service token and refuses to dial when Access answers 401 or 403, or redirects to its login page under `/cdn-cgi/access/login`, with "Cloudflare Access did not admit the service token" (`TestPreflightRefusesWhatCloudflaredWouldTurnIntoALoginFlow`). The tunnel hostname and the `cloudflared` path are validated before any process starts (`TestInteractiveCommandCloudflareRefusesHostileHostnamesAndUnknownTransports`).

`sm nodes list` shows a transport column once any node uses a tunnel; `sm nodes get` always shows the transport.

A node whose direct path is closed now depends on Cloudflare being available, and `sm` needs to find `cloudflared` on the daemon host.

### Who can open `sm ssh`

For an owner to get a shell, all of these must hold. Which of them hold on a real account is **not verified**; the [checklist](manual-checks/cloudflare-tunnel.md) covers them.

1. The owner's address is in `owner_emails`, and the owners policy is in place (a tunnel setup applies it).
2. The owner can complete a login method the application allows. With `access_identity_providers` empty, SuperMgmt looks up the account's One-time PIN provider and allows exactly that one; Cloudflare then emails a code to the address. If the account has no One-time PIN login method, the setup fails before the application is created, telling you to enable One-time PIN in Zero Trust (Settings, Authentication) or to set `access_identity_providers` (`TestAccess_EmptyIdentityProvidersMeanOneTimePINOnly`, `TestAccess_NoOneTimePINFailsBeforeTheApplicationIsCreated`). With provider IDs listed, only those are allowed; where the dashboard shows an ID is not verified here.
3. `cloudflared` is installed on the owner's machine. On the first `sm ssh` to a hostname, `cloudflared access ssh` runs the Access login through the browser (Cloudflare's design; not observed here). The login page belongs to the Zero Trust team domain.
4. The owner's SSH key is authorised on the node. Access admission opens the path only.

### Return a node to direct SSH

```bash
sm nodes tunnel disable web1
```

The node must be reachable directly again, because it is dialled directly from then on. The job is approval-gated and resumable, and it also abandons an unfinished setup ([above](#when-a-setup-does-not-finish)):

1. It verifies the direct path for both the admin and the dedicated account before changing anything.
2. It commits `transport: direct`.
3. It stops and removes the `cloudflared` service and only the files setup installed; the package and repository go only if setup installed them. A `cloudflared` that was already there, including one installed from Cloudflare's guide, stays (`TestRemoveTunnelRemovesOnlyWhatSetupInstalled`, `TestRemoveTunnelLeavesAForeignRepositoryAndItsPackage`).
4. It removes the DNS record and ingress (the route closes first), then the Access application, then the tunnel. The application and the tunnel are deleted by their recorded ID only.

**Stays after disable:** the instance's service token, its two policies and the stored service-token secret. A node with no tunnel and no unfinished setup is refused before anything changes (`TestDisableOfANodeWithoutATunnelIsRefusedBeforeAnythingChanges`, `TestADisableOfANodeWithoutAnyEnableStillSaysThereIsNothingToDisable`).

### Stop using Cloudflare

1. Run `sm nodes tunnel disable <node>` for every tunnel node while the `cloudflare:` block is still configured; without the block, disable is refused as not configured.
2. In the Cloudflare dashboard, delete what disable keeps: the Access policies `supermgmt service <instance>` and `supermgmt owners <instance>`, and the service token `supermgmt-<instance>` (it expires after a year anyway). Revoke the API token if you have not.
3. Remove the `cloudflare:` block. Nothing then calls Cloudflare, and `cloudflared` is not needed on the daemon host; uninstall it yourself if nothing else uses it.
4. The sealed secrets at `cloudflare/api-token` and `cloudflare/access-service-token` stay in the store, which is append-only and has no delete command. They are useless once revoked.

### Change who can open `sm ssh`

`owner_emails` and `access_identity_providers` reach Cloudflare only when a tunnel setup runs, with a valid API token in the store. Until then the old owners keep access.

- **`owner_emails`**: the owners policy is per instance, so one `sm nodes setup <node> --tunnel` run on any tunnel node updates it for every node.
- **`access_identity_providers`**: the allowed login methods are set on each node's own Access application, so a run updates only the node it runs on. To narrow them, run `sm nodes setup <node> --tunnel` on **every** tunnel node; a node you skip keeps admitting the old providers.

A re-run keeps what the node already has: its unit grants, Docker access, logs mode and tunnel, unless you pass `--unit`, `--docker-access`, `--logs-mode` or `--tunnel` (`--docker-access=false` removes Docker access; `TestNodesSetupRerunKeepsDockerLogsAndTunnelUnlessGiven`). In the TUI palette the words are `docker`/`no-docker` and `broker`/`journal`. A setup without the tunnel on a tunnelled node is refused (`TestASetupWithoutTheTunnelOnATunnelledNodeIsRefused`). Check the plan preview before approving.

### Rotate the service token

```bash
sm cloudflare rotate-access-token
```

The job creates a new service token, admits it next to the old one, switches the dialler to it, removes the old one from the policy and deletes it last, so probes keep working throughout (`TestRotationOverlapsTheTokensAndDeletesTheOldOneLast`, `TestRotationUnderEveryFaultNeverLeavesTheDialerWithoutAnAdmittedToken`). The service token is created with a lifetime of one year. `sm doctor` warns 30 days before it expires and fails when it has expired while a node uses it (`TestDoctorServiceTokenExpiry`). Rotation needs a valid API token in the store, so you must be able to create one again ([below](#revoke-the-api-token-after-provisioning)). A finished rotation writes a non-credential value over the pending secret, but its older sealed versions stay in the append-only store (`TestAFinishedRotationOverwritesThePendingCredential`).

### Revoke the API token after provisioning

Dialling never reads the API token; only tunnel jobs do (setup with `--tunnel`, disable, rotation, and changing owners). The secret store is append-only and `sm secrets` has no delete command, so the stored value cannot be removed. Once your nodes are set up, revoke the token in the Cloudflare dashboard instead.

What `sm doctor` then shows: Cloudflare rejects the stored token, and as long as at least one node uses the tunnel and no tunnel operation is unfinished, `cloudflare_api_token` and the reads row are **warnings** ("provisioning unavailable (not needed for dialling)"), not failures (`TestDoctorRevokedAPITokenIsOnlyAWarningOnceEveryTunnelIsProvisioned`). With no node on the tunnel yet, or while an operation is unfinished, they stay failures. A token that is not in the store at all is a warning too (`TestDoctorAPITokenRemovedFromTheStoreIsOnlyAWarning`).

To provision, disable or rotate again, create a new API token with the same permissions and store it with `sm secrets import --name cloudflare/api-token`; that stores the next version of the secret. Doctor reports what it can prove about a valid token (valid, which reads succeed) and says "not verifiable" about edit rights, because Cloudflare offers no way to prove them without changing something (`TestDoctorAPITokenProvesValidityAndReadsAndNeverClaimsEditRights`).

### Backup and restore

Backups keep the operation records and the Cloudflare object IDs, and keep secrets as the existing encrypted records, never in plaintext (`TestArchiveKeepsTunnelRecordsAndNeverTheirPlaintextCredentials`). While the restore hold lasts, writes are refused, so no tunnel job runs. After `sm admin restore-complete` the daemon compares its records with Cloudflare and writes audit events for objects that are missing or were recreated; it changes nothing by itself, and the next `sm nodes setup <node> --tunnel` repairs them. Do not run a restored copy next to the original against the same account: both would manage the same names.

### What Cloudflare can and cannot do

- **It sees** connection metadata: which hostname, when, how much. It performs the Access check and carries the SSH stream.
- **It can** deny service or route to the wrong place. The node is then unreachable, or fails verification.
- **It cannot** impersonate a node: SuperMgmt checks the node's SSH host key over the tunnel against the pinned one. A tunnel that reaches a different key fails, and the key is never repinned.
- **It cannot** read the SSH session contents, which are encrypted between SuperMgmt and the node's `sshd`.
- **Whoever controls your Cloudflare account** can change Access policies and DNS for your hostnames, and so can open the path to your nodes' SSH port. A login there still needs a valid key, but the account is part of your trust base. Protect it like the nodes.

The three credentials, where each lives and what it can do: [Security](security.md#cloudflare-tunnel-nodes).

### What it does not do

- Add a node that was never directly reachable (`sm nodes add` has no tunnel option yet).
- ProxyJump or a bastion, WARP or private-network routing, tunnelling the SuperMgmt server itself.
- More than one account or zone, a service token per node, or nodes other than Debian 13 and Ubuntu 24.04.

Problems: [Troubleshooting](troubleshooting.md#cloudflare-tunnel-nodes). Network destinations and what triggers them: [Dependencies](dependencies.md#egress).

## Put the SuperMgmt server behind Cloudflare

This part is a **guide only**. It is a different matter from node tunnels: SuperMgmt has no connector for it, and nothing in this section has been run against a real Cloudflare account (status: **not verified**; see [Project status](project-status.md)). Core operation works with localhost, a LAN, a VPN or any reverse proxy. Cloudflare product behaviour changes: check the current Cloudflare documentation before relying on any statement about it here.

### Topology

```text
sm client / TUI  --HTTPS-->  Cloudflare (Tunnel, optionally Access)  --->  cloudflared  --http-->  127.0.0.1:8787  sm server
```

- `cloudflared` runs on the SuperMgmt host and makes an outbound connection to Cloudflare, so no inbound port has to be opened for SuperMgmt.
- SuperMgmt runs in **proxy mode**: `server.tls.mode: proxy`, `server.listen: 127.0.0.1:8787`, plain HTTP on loopback, TLS terminated by Cloudflare.
- Install it that way: `install.sh server --tls proxy --public-url https://mgmt.example.com` (the default), where the public URL is the hostname the tunnel serves. See [installation.md](installation.md).

Sketch of the tunnel's ingress rule (the file layout and keys are Cloudflare's; verify them in their documentation):

```yaml
ingress:
  - hostname: mgmt.example.com
    service: http://127.0.0.1:8787
  - service: http_status:404
```

### What SuperMgmt requires from the proxy

These come from SuperMgmt's own proxy rules ([Server transport and TLS](configuration.md#server-transport-and-tls)), not from Cloudflare:

- The TCP peer must be inside `server.trusted_proxies`. With `cloudflared` on the same host the default `127.0.0.1/32` is what you want. Only requests from a trusted peer may carry forwarding headers that SuperMgmt believes.
- From a trusted peer, `X-Forwarded-Proto` **must** be `https`. Anything else, including a missing header, is answered with `400`. Whether `cloudflared` forwards that header to the origin is **not verified**; if every request gets a 400, this is the first thing to check, and the fix belongs in the proxy, not in SuperMgmt.
- The client address is taken from `X-Forwarded-For` (rightmost entry that is not itself a trusted proxy). `CF-Connecting-IP` is not read. The address feeds rate limiting and the `source_cidrs` check of join tokens; how Cloudflare composes `X-Forwarded-For` for the client address is **not verified**, so test a join with `--source-cidr` before depending on it.
- A request from loopback gets no special trust or privilege. Running `cloudflared` on the same host does not make Cloudflare traffic "local".

### Trust boundary

State it precisely, because it is easy to assume otherwise:

- **SuperMgmt consumes no Cloudflare identity assertion.** The `Cf-Access-Jwt-Assertion`, `Cf-Access-Authenticated-User-Email` and every other `Cf-Access-*` header are ignored; no code reads them (a search of `internal/` finds none). The specification says the same: validation applies only if a later version consumes such assertions.
- **Every request is authenticated by SuperMgmt itself**: an OIDC-issued session or an API token, checked against SuperMgmt's own tables, then authorized by its policy. A request that reaches SuperMgmt through the tunnel without a valid bearer credential is `401`, whatever Cloudflare let through.
- Therefore **Cloudflare Access is an extra gate in front, not an identity source.** It can decide who may reach the hostname at all; it cannot grant anything inside SuperMgmt, and a misconfigured Access policy cannot give anyone SuperMgmt privileges.
- If a future version validates Access assertions, it must verify the JWT signature against the team's JWKS, the team domain and the application audience (AUD) according to current Cloudflare documentation. None of that exists today.
- What does cross the trust boundary: bearer tokens (visible to Cloudflare, which terminates TLS), the client address from forwarding headers, and the plain-HTTP hop on loopback. Cloudflare can read and alter traffic; use it only if you accept that.

### Access and the `sm` client

`sm` is not a browser. It sends `Authorization: Bearer ...` and has **no way to add other headers** (such as Access service-token headers) or to follow an Access login page; nothing in `internal/client` does either (a search finds no such code). Consequences, none of them verified against real Access:

- An Access application in front of the whole hostname with a login-page policy will block `sm`, `sm join` and the `join.sh` enrollment from nodes.
- Options: leave the API hostname outside Access and rely on SuperMgmt's authentication, OIDC and rate limits (SuperMgmt has no browser UI); or use an Access policy that lets these paths through. Either way the decision is yours, and the first option is simply "Tunnel without Access".
- Event streams (`GET /events/stream`) send a heartbeat comment every 15 seconds; whether Cloudflare keeps the connection open for that pattern is not verified.

### Hardening checklist

- Bind SuperMgmt to loopback (the installer default); do not add a public listener next to the tunnel.
- Keep `server.trusted_proxies` as narrow as the proxy's address.
- Use OIDC with `auth.oidc.allowed_domains`; bearer tokens leave the machine in clear to Cloudflare's edge.
- Restrict `join` tokens with `--source-cidr` only after confirming the client address SuperMgmt sees ([operations.md](operations.md)).
- Treat the Cloudflare account and the tunnel credentials as part of your trust base; SuperMgmt cannot protect against their compromise.

## References

- Binding specification: [`docs/spec/SUPERMGMT-SPEC.md`](spec/SUPERMGMT-SPEC.md), section 23.1 (proxy mode and forwarded headers) and section 25 (Cloudflare and identity assertions).
- Decision record: [ADR-0017](adr/0017-server-transport-credentials-sessions.md) server transport, credentials and sessions.
- Decision record for node tunnels: [ADR-0037](adr/0037-cloudflare-tunnel-transport.md) Cloudflare Tunnel transport.
- Real-account checklist: [Cloudflare Tunnel](manual-checks/cloudflare-tunnel.md).
